"""Orchestrate a build and emit a signed release bundle.

Stages (each timed):
  1. build       - hash the COMPLETE release artifact into an artifact digest
  2. sbom        - inventory declared dependencies (CycloneDX)
  3. provenance  - record how/where/by-whom it was built (SLSA-style)
  4. sign        - detached Ed25519 signatures over SBOM and provenance

The build NEVER modifies the trust store. Enrolling the builder's key as trusted
is a separate admin step (`pipeline.enroll`), and verification computes the
artifact digest independently (`pipeline.verify`). The result is a `release.json`
bundle plus timing data, under out/.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Dict, List, Tuple

from pipeline import provenance, sbom, signing

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_BUILDER = "https://example/pipeline/github-actions@refs/heads/main"
DEFAULT_PRODUCT_DIR = os.path.join(ROOT, "sample_project")


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def release_digest(product_dir: str) -> str:
    """Deterministic digest over the ENTIRE release tree.

    Hashes a sorted manifest of (relative path, file digest) for every file in
    the product, so adding, removing, or modifying any file changes the digest --
    not just a change to a single entrypoint.
    """
    entries: List[Tuple[str, str]] = []
    for root, _, files in os.walk(product_dir):
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, product_dir)
            entries.append((rel.replace(os.sep, "/"), _sha256_file(full)))
    entries.sort()
    h = hashlib.sha256()
    for rel, digest in entries:
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(digest.encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def run_build(
    out_dir: str,
    builder_id: str = DEFAULT_BUILDER,
    source_uri: str = "git+https://example/repo",
    source_ref: str = "refs/heads/main",
    product_dir: str = DEFAULT_PRODUCT_DIR,
) -> Dict:
    os.makedirs(out_dir, exist_ok=True)
    key_dir = os.path.join(out_dir, "keys")
    manifest_path = os.path.join(product_dir, "manifest.txt")

    timings: Dict[str, float] = {}

    # 0. ensure the builder has a signing key. The build NEVER touches the trust
    #    store: enrolling a key as trusted is a separate admin action
    #    (pipeline.enroll), so an ordinary build cannot make itself trusted.
    priv_path = os.path.join(key_dir, "builder_ed25519")
    pub_path = os.path.join(key_dir, "builder_ed25519.pub")
    if not os.path.exists(priv_path):
        signing.generate_keypair(key_dir)

    # 1. build - hash the complete release artifact
    t = time.perf_counter()
    digest = release_digest(product_dir)
    product_name = os.path.basename(os.path.normpath(product_dir))
    timings["build"] = time.perf_counter() - t

    # 2. sbom
    t = time.perf_counter()
    with open(manifest_path, "r", encoding="utf-8") as fh:
        deps = sbom.parse_manifest(fh.read())
    bom = sbom.build_sbom(product_name, digest, deps)
    timings["sbom"] = time.perf_counter() - t

    # 3. provenance
    t = time.perf_counter()
    prov = provenance.build_provenance(
        product_name, digest, builder_id, source_uri, source_ref, deps
    )
    timings["provenance"] = time.perf_counter() - t

    # 4. sign
    t = time.perf_counter()
    priv = signing.load_private(priv_path)
    sbom_sig = signing.sign(bom, priv)
    prov_sig = signing.sign(prov, priv)
    timings["sign"] = time.perf_counter() - t

    bundle = {
        "artifact": {"name": product_name, "sha256": digest},
        "sbom": bom,
        "sbom_signature": sbom_sig,
        "provenance": prov,
        "provenance_signature": prov_sig,
        # For transparency only. The verifier does NOT trust this; it resolves the
        # key from the pinned trust store by builder identity.
        "signing_key_hint": pub_path,
        "timings_ms": {k: round(v * 1000, 3) for k, v in timings.items()},
    }

    with open(os.path.join(out_dir, "release.json"), "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2)
    return bundle


def main(argv=None) -> None:
    out = os.path.join(ROOT, "out")
    bundle = run_build(out)
    print("built %s" % bundle["artifact"]["name"])
    print("  release digest : %s" % bundle["artifact"]["sha256"])
    print("  components     : %d" % len(bundle["sbom"]["components"]))
    print("  builder        : %s" % bundle["provenance"]["predicate"]["runDetails"]["builder"]["id"])
    total = sum(bundle["timings_ms"].values())
    print("  stage timings (ms): %s" % bundle["timings_ms"])
    print("  pipeline overhead  : %.3f ms" % total)
    print("  bundle written to  : %s" % os.path.join(out, "release.json"))
    print("  (build did NOT touch the trust store; enroll with pipeline.enroll,")
    print("   then verify with pipeline.verify)")


if __name__ == "__main__":
    main()
