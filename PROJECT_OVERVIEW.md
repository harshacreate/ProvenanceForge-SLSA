# ProvenanceForge-SLSA — Project Overview

**Signed Supply-Chain Security Pipeline**
Project overview

## Project summary

ProvenanceForge-SLSA is a build pipeline that produces a verifiable record of how
software was built, and a policy that refuses to ship a release when that record
doesn't hold up. For every build it emits a CycloneDX SBOM, an in-toto / SLSA-style
provenance statement, and Ed25519 signatures. Trusted keys are pinned **outside**
the bundle (by builder identity), and verification recomputes the artifact digest
from the artifact itself — matching SLSA verification guidance.

## Main features

- **Pipeline dashboard (web UI):** forge a signed release and see the release tree
  with per-file digests, the SBOM, the SLSA provenance (builder, source, materials),
  the trust store, and the C1–C5 admission-policy result.
- **Tamper lab:** six controlled attacks (swapped dependency, altered artifact,
  unapproved builder, forged key with an approved builder, stale signature, hidden
  SBOM component) are run live, each revealing the policy check that catches it.
- **Trust is a configured input:** the build never enrolls its own key; enrollment
  is a separate admin step, so a build cannot make itself trusted.

## Run with Docker

```sh
docker compose up --build -d      # then open http://localhost:8093
docker compose ps
docker compose down
```

Runs in temporary sandboxes, binds to `127.0.0.1` only, non-root, dropped
capabilities.

## Scope

A learning prototype: signing keys and dependency hashes are generated locally
rather than from a real KMS/registry. The trust and digest checks, however, are
independent of the build step.
