"""Release-admission policy.

The trust anchor is a TrustStore pinned OUTSIDE the bundle, mapping each approved
builder identity to its trusted public key. The verifier reads the builder id the
bundle *claims*, looks up the key for that identity in the trust store, and
verifies signatures against THAT key. A bundle signed with any other key fails,
even if it points at its own key and names an approved builder.

A bundle is admitted only if ALL checks pass:

  C1 signatures    SBOM + provenance verify against the trust store's key for the
                   claimed builder (resolved by identity, not from the bundle)
  C2 builder       the claimed builder identity is present in the trust store
  C3 artifact      provenance subject digest == the actual release digest
  C4 consistency   SBOM components == provenance materials
  C5 pinned        every SBOM component has a concrete version
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from pipeline import provenance as prov_mod
from pipeline import sbom as sbom_mod
from pipeline import signing
from pipeline.trust import TrustStore


@dataclass
class Check:
    id: str
    name: str
    passed: bool
    reason: str


@dataclass
class Decision:
    admitted: bool
    checks: List[Check]

    def failed(self) -> List[Check]:
        return [c for c in self.checks if not c.passed]


def verify_bundle(
    bundle: Dict,
    actual_artifact_digest: str,
    trust_store: Optional[TrustStore] = None,
) -> Decision:
    store = trust_store if trust_store is not None else TrustStore.load()
    checks: List[Check] = []

    prov = bundle["provenance"]
    bom = bundle["sbom"]
    claimed_builder = prov_mod.builder_id(prov)

    # Resolve the trusted key by the CLAIMED identity -- from the pinned store,
    # never from the bundle. Unknown builder -> no key -> signatures cannot pass.
    trusted_pub = store.public_key(claimed_builder)
    approved = trusted_pub is not None

    # C2 - approved builder (membership in the trust store)
    checks.append(Check(
        "C2", "approved builder", approved,
        "builder=%s%s" % (claimed_builder, "" if approved else " NOT in trust store"),
    ))

    # C1 - signatures valid against the pinned key for that builder
    if trusted_pub is None:
        checks.append(Check(
            "C1", "signatures valid", False,
            "no pinned key for claimed builder; cannot verify",
        ))
    else:
        sbom_ok = signing.verify(bom, bundle["sbom_signature"], trusted_pub)
        prov_ok = signing.verify(prov, bundle["provenance_signature"], trusted_pub)
        checks.append(Check(
            "C1", "signatures valid", sbom_ok and prov_ok,
            "sbom=%s provenance=%s (vs pinned builder key)" % (sbom_ok, prov_ok),
        ))

    # C3 - artifact digest matches what provenance claims
    claimed = prov_mod.subject_digest(prov)
    digest_ok = claimed == actual_artifact_digest
    checks.append(Check(
        "C3", "artifact matches provenance", digest_ok,
        "claimed=%s actual=%s" % (claimed[:12], actual_artifact_digest[:12]),
    ))

    # C4 - SBOM <-> provenance materials agree
    sbom_set = sbom_mod.component_set(bom)
    mat_set = prov_mod.material_set(prov)
    consistent = sbom_set == mat_set
    checks.append(Check(
        "C4", "sbom/provenance consistent", consistent,
        "sbom=%d materials=%d diff=%s" % (
            len(sbom_set), len(mat_set), sorted(sbom_set ^ mat_set)),
    ))

    # C5 - everything pinned
    unpinned = [c["name"] for c in bom.get("components", []) if not c.get("version")]
    checks.append(Check(
        "C5", "dependencies pinned", not unpinned,
        "unpinned=%s" % (unpinned or "none"),
    ))

    return Decision(admitted=all(c.passed for c in checks), checks=checks)


def verify_release(out_dir: str, product_dir: str = None,
                   trust_path: str = None) -> Decision:
    """Verify a release.json bundle against the ACTUAL artifact and the pinned
    trust store -- both resolved independently of the bundle.

    The artifact digest is recomputed from `product_dir` here (not read from the
    bundle), so changing or adding any artifact file fails C3.
    """
    import json
    import os

    from pipeline.build import DEFAULT_PRODUCT_DIR, release_digest
    from pipeline.trust import DEFAULT_TRUST_FILE

    product_dir = product_dir or DEFAULT_PRODUCT_DIR
    with open(os.path.join(out_dir, "release.json"), "r", encoding="utf-8") as fh:
        bundle = json.load(fh)
    actual_digest = release_digest(product_dir)          # independent recompute
    store = TrustStore.load(trust_path or DEFAULT_TRUST_FILE)
    return verify_bundle(bundle, actual_digest, store)


def print_decision(decision: Decision) -> None:
    print("-" * 58)
    for c in sorted(decision.checks, key=lambda c: c.id):
        print("  [%s] %-28s %s" % ("PASS" if c.passed else "FAIL", c.name, c.reason))
    print("-" * 58)
    print("ADMITTED" if decision.admitted else "REJECTED")


def main(argv=None) -> None:
    import argparse
    import os

    ap = argparse.ArgumentParser(description="Verify a release bundle independently of the build.")
    ap.add_argument("--out", default=os.path.join(os.getcwd(), "out"),
                    help="directory containing release.json")
    ap.add_argument("--product", default=None, help="the artifact directory to digest")
    ap.add_argument("--trust", default=None, help="trust store path")
    args = ap.parse_args(argv)
    decision = verify_release(args.out, args.product, args.trust)
    print_decision(decision)
    raise SystemExit(0 if decision.admitted else 1)


if __name__ == "__main__":
    main()
