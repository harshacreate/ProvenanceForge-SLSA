# ProvenanceForge-SLSA — Signed Supply-Chain Security Pipeline

## Run with Docker

```bash
docker compose up --build -d      # then open http://localhost:8093
docker compose down               # stop
```

This repository is standalone; the commands below build and run this project on its own.

A build pipeline that produces a **verifiable record of how software was built**
and a policy that refuses to ship a release when that record doesn't hold up.
For every build it emits:

- a **CycloneDX SBOM** (software bill of materials) inventorying dependencies,
- an **in-toto / SLSA-style provenance** statement recording the artifact digest,
  the builder identity, the invocation, and the materials that went in,
- **Ed25519 signatures** over both records.

A release-admission policy then verifies the bundle, and a set of **controlled
tamper experiments** confirms the policy catches real supply-chain attacks while
admitting clean builds. The provenance shape follows the
[SLSA v1 provenance spec](https://slsa.dev/spec/v1.0/provenance).

## Why this exists

"It built on my machine" is not a security property. This pipeline makes the
build *attestable*: you can prove an artifact came from an approved builder and
an unchanged set of inputs — and automatically reject it if any link in that
chain was tampered with. The tamper experiments turn that claim into a measured
detection rate instead of a promise.

## Trust model (read this first)

The root of trust is a **trust store pinned outside the bundle**
(`trust/trusted_builders.json`), mapping each approved builder identity to its
trusted public key. The key point:

> A bundle is **never** allowed to name the key that verifies it. Otherwise an
> attacker signs a forged bundle with their own key, points the bundle at that
> key, claims an approved builder, and every check passes.

Instead the verifier reads the builder identity the bundle *claims*, looks up the
pinned key for **that identity** in the trust store, and verifies signatures
against it. A bundle signed with any other key fails, even if it embeds its own
key and names an approved builder.

**The build never touches the trust store.** Enrolling a builder's key as trusted
is a separate admin step (`python -m pipeline.enroll`), so an ordinary build
cannot make its own key trusted — a build with no prior enrollment is rejected.
Likewise, **verification recomputes the artifact digest from the artifact itself**
(`python -m pipeline.verify`), never reading the "actual" digest from the bundle,
so adding or changing any release file fails verification. This follows
[SLSA verification guidance](https://slsa.dev/spec/v1.2/verifying-artifacts):
trusted builder identities are configured in the verifier, and provenance is
checked against the artifact.

> This is a **learning prototype**: signing keys and dependency hashes are
> generated locally rather than coming from a real KMS/registry. The trust and
> digest checks, however, are now independent of the build step.

## Policy checks

A bundle is admitted only if **all** of these pass:

| Check | Guarantee |
|-------|-----------|
| C1 signatures | SBOM + provenance verify against the **trust store's pinned key for the claimed builder** (resolved by identity, never from the bundle) |
| C2 builder | the claimed builder identity is present in the trust store |
| C3 artifact | provenance subject digest == the **full release digest** (a hash over every file in the release, not one entrypoint) |
| C4 consistency | SBOM components == provenance materials |
| C5 pinned | every dependency has a concrete version |

A rejected release reports exactly which check failed.

## Layout

```
sample_project/   the 'product' that gets built + its manifest
pipeline/
  build.py        orchestrates build -> sbom -> provenance -> sign (timed);
                  hashes the whole release tree; NEVER touches the trust store
  sbom.py         CycloneDX 1.5 SBOM generation
  provenance.py   in-toto/SLSA provenance statement
  signing.py      Ed25519 sign/verify over canonical JSON
  trust.py        the pinned trust store (builder identity -> trusted key)
  enroll.py       admin-only: enroll a builder key as trusted (separate from build)
  verify.py       the release-admission policy (C1..C5); recomputes the
                  artifact digest independently of the bundle
tamper/
  experiments.py  controlled attacks + detection-rate measurement
tests/            pytest over the pipeline and experiments
trust/            pinned trusted keys (populated by `enroll`; git-ignored)
```

## Quick start

```bash
make setup     # cryptography, pytest
make build     # produce out/release.json (signed bundle); does NOT enroll trust
make enroll    # admin step: enroll the builder key into the trust store
make verify    # build -> enroll -> verify against the ACTUAL artifact
make tamper    # run the controlled tamper experiments
make test      # pytest
```

The `build` → `enroll` → `verify` split is deliberate: run `make build` then
`make verify` without enrollment and the release is **rejected**, because a build
cannot make itself trusted.

Example `make tamper` output:

```
  OK      control (untampered)               checks fired: -
  CAUGHT  dependency swapped in SBOM         checks fired: C1,C4
  CAUGHT  artifact altered post-build        checks fired: C3
  CAUGHT  unapproved builder (re-signed)     checks fired: C2,C1
  CAUGHT  forged key, approved builder       checks fired: C1
  CAUGHT  provenance forged, stale signature checks fired: C1
  CAUGHT  hidden component in SBOM           checks fired: C1,C4
Attacks caught     : 6/6 (100%)
Control admitted   : True
Avg pipeline time  : ... ms/build
```

## The tamper experiments

Each experiment mutates one thing an attacker might change and confirms the
right policy check fires:

| Experiment | Models | Caught by |
|-----------|--------|-----------|
| dependency swapped in SBOM | altered dependency version | C4 (+C1: editing breaks the signature) |
| artifact altered post-build | a release file replaced after signing | C3 |
| unapproved builder (re-signed) | build from an untrusted identity | C2 |
| **forged key, approved builder** | **attacker signs with their own key but claims an approved builder** | **C1 (verified against the pinned key, not the bundle's)** |
| provenance forged, stale signature | record edited in transit | C1 |
| hidden component in SBOM | inventory/materials disagree | C4 |

The clean **control** build must still be admitted — this measures that the
policy isn't simply rejecting everything. The **forged key** case is the one that
matters most: a verifier that trusted the key carried in the bundle would accept
it; pinning the key by builder identity is what rejects it.

## Notes on fidelity

To stay dependency-light and fully reproducible offline, dependency hashes and
the signing keys are generated locally rather than pulled from a real registry or
KMS, and the trust store is onboarded by the build step rather than by a separate
admin tool. The *structure* — CycloneDX, in-toto/SLSA envelopes, detached
signatures, **keys pinned out-of-band and bound to builder identity**, a
full-release digest as the signed subject — matches how a production pipeline
(e.g. with `cosign`/Sigstore and a real SBOM generator such as `syft`) is wired.

## Scope & safety

Everything runs locally against the bundled sample project. No packages are
fetched and no external services are contacted.
