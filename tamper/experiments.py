"""Introduce controlled supply-chain problems, confirm the policy catches them.

Each experiment takes a freshly built, valid bundle, mutates one thing an
attacker might change, re-runs verification against the pinned trust store, and
records which policy check fired. A clean (un-tampered) control must be admitted.

Run:
  python -m tamper.experiments
  python -m tamper.experiments --json
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import tempfile
import time
from typing import Callable, Dict, List

from pipeline import build as build_mod
from pipeline import signing
from pipeline import verify as verify_mod
from pipeline.enroll import enroll_builder
from pipeline.trust import TrustStore


def exp_control(bundle, digest, store) -> Dict:
    """No tampering - must be admitted."""
    d = verify_mod.verify_bundle(bundle, digest, store)
    return {"name": "control (untampered)", "expect_reject": False,
            "rejected": not d.admitted, "fired": [c.id for c in d.failed()]}


def exp_swap_dependency(bundle, digest, store) -> Dict:
    """Attacker swaps a dependency version in the SBOM after build."""
    b = copy.deepcopy(bundle)
    b["sbom"]["components"][0]["version"] = "9.9.9-evil"
    d = verify_mod.verify_bundle(b, digest, store)
    return {"name": "dependency swapped in SBOM", "expect_reject": True,
            "rejected": not d.admitted, "fired": [c.id for c in d.failed()]}


def exp_alter_artifact(bundle, digest, store) -> Dict:
    """Artifact replaced after signing: the real digest no longer matches."""
    b = copy.deepcopy(bundle)
    d = verify_mod.verify_bundle(b, "0" * 64, store)
    return {"name": "artifact altered post-build", "expect_reject": True,
            "rejected": not d.admitted, "fired": [c.id for c in d.failed()]}


def exp_unapproved_builder(bundle, digest, store) -> Dict:
    """Provenance claims an unapproved builder; re-signed with the real key."""
    b = copy.deepcopy(bundle)
    b["provenance"]["predicate"]["runDetails"]["builder"]["id"] = "https://evil/ci@main"
    # Re-sign with the legitimate key so only the builder identity is the problem.
    priv_path = os.path.join(os.path.dirname(b["signing_key_hint"]), "builder_ed25519")
    priv = signing.load_private(priv_path)
    b["provenance_signature"] = signing.sign(b["provenance"], priv)
    d = verify_mod.verify_bundle(b, digest, store)
    return {"name": "unapproved builder (re-signed)", "expect_reject": True,
            "rejected": not d.admitted, "fired": [c.id for c in d.failed()]}


def exp_forged_key_approved_builder(bundle, digest, store) -> Dict:
    """THE key-trust attack: attacker signs with their OWN freshly-generated key
    but keeps the approved builder identity and points the bundle at their key.

    A verifier that trusted the bundle's key would accept this. Because the key is
    resolved from the pinned trust store by builder identity instead, signature
    verification (C1) is done against the real builder key and fails.
    """
    b = copy.deepcopy(bundle)
    atk_dir = tempfile.mkdtemp(prefix="attacker_key_")
    signing.generate_keypair(atk_dir)
    atk_priv = signing.load_private(os.path.join(atk_dir, "builder_ed25519"))
    # builder id left as the APPROVED one; re-sign everything with attacker key.
    b["sbom_signature"] = signing.sign(b["sbom"], atk_priv)
    b["provenance_signature"] = signing.sign(b["provenance"], atk_priv)
    b["signing_key_hint"] = os.path.join(atk_dir, "builder_ed25519.pub")
    d = verify_mod.verify_bundle(b, digest, store)
    return {"name": "forged key, approved builder", "expect_reject": True,
            "rejected": not d.admitted, "fired": [c.id for c in d.failed()]}


def exp_forge_provenance_keep_signature(bundle, digest, store) -> Dict:
    """Provenance content changed but the OLD signature is kept -> invalid sig."""
    b = copy.deepcopy(bundle)
    b["provenance"]["predicate"]["buildDefinition"]["externalParameters"]["ref"] = "refs/heads/attacker"
    d = verify_mod.verify_bundle(b, digest, store)
    return {"name": "provenance forged, stale signature", "expect_reject": True,
            "rejected": not d.admitted, "fired": [c.id for c in d.failed()]}


def exp_sbom_provenance_mismatch(bundle, digest, store) -> Dict:
    """Extra component added to SBOM only -> SBOM/provenance disagree."""
    b = copy.deepcopy(bundle)
    b["sbom"]["components"].append(
        {"type": "library", "name": "backdoor", "version": "1.0.0",
         "purl": "pkg:generic/backdoor@1.0.0", "hashes": []}
    )
    d = verify_mod.verify_bundle(b, digest, store)
    return {"name": "hidden component in SBOM", "expect_reject": True,
            "rejected": not d.admitted, "fired": [c.id for c in d.failed()]}


EXPERIMENTS: List[Callable] = [
    exp_control,
    exp_swap_dependency,
    exp_alter_artifact,
    exp_unapproved_builder,
    exp_forged_key_approved_builder,
    exp_forge_provenance_keep_signature,
    exp_sbom_provenance_mismatch,
]


def run() -> Dict:
    with tempfile.TemporaryDirectory() as tmp:
        trust_path = os.path.join(tmp, "trusted_builders.json")
        bundle = build_mod.run_build(tmp)
        # Admin step (separate from the build): enroll the legit builder's key.
        enroll_builder(build_mod.DEFAULT_BUILDER, bundle["signing_key_hint"], trust_path)
        digest = bundle["artifact"]["sha256"]
        store = TrustStore.load(trust_path)

        # Measure pipeline overhead over a few builds for a stable number.
        t = time.perf_counter()
        for _ in range(5):
            build_mod.run_build(tmp)
        avg_build_ms = (time.perf_counter() - t) / 5 * 1000

        rows = [exp(bundle, digest, store) for exp in EXPERIMENTS]

    attacks = [r for r in rows if r["expect_reject"]]
    caught = [r for r in attacks if r["rejected"]]
    control_ok = all(not r["rejected"] for r in rows if not r["expect_reject"])
    return {
        "summary": {
            "attacks": len(attacks),
            "caught": len(caught),
            "detection_rate": round(len(caught) / len(attacks), 3) if attacks else 0.0,
            "control_admitted": control_ok,
            "avg_pipeline_ms": round(avg_build_ms, 2),
        },
        "experiments": rows,
    }


def _print(result: Dict) -> None:
    s = result["summary"]
    print("=" * 64)
    print("Supply-chain pipeline - tamper experiments")
    print("=" * 64)
    for r in result["experiments"]:
        if r["expect_reject"]:
            ok = r["rejected"]
            label = "CAUGHT " if ok else "MISSED "
        else:
            ok = not r["rejected"]
            label = "OK     " if ok else "BROKE  "
        fired = ",".join(r["fired"]) or "-"
        print("  %s %-34s checks fired: %s" % (label, r["name"], fired))
    print("-" * 64)
    print("Attacks caught     : %d/%d (%.0f%%)" % (
        s["caught"], s["attacks"], s["detection_rate"] * 100))
    print("Control admitted   : %s" % s["control_admitted"])
    print("Avg pipeline time  : %.2f ms/build" % s["avg_pipeline_ms"])
    print("=" * 64)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Run controlled supply-chain tamper experiments.")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    result = run()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print(result)


if __name__ == "__main__":
    main()
