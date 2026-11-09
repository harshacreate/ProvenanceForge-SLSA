import copy
import os
import shutil
import tempfile

from pipeline import build as build_mod
from pipeline import signing
from pipeline import verify as verify_mod
from pipeline.build import release_digest
from pipeline.enroll import enroll_builder
from pipeline.provenance import material_set
from pipeline.sbom import component_set
from pipeline.trust import TrustStore
from tamper import experiments


def _build(tmp):
    """Build, then perform the SEPARATE admin enrollment step."""
    trust_path = os.path.join(tmp, "trusted_builders.json")
    bundle = build_mod.run_build(tmp)
    enroll_builder(build_mod.DEFAULT_BUILDER, bundle["signing_key_hint"], trust_path)
    store = TrustStore.load(trust_path)
    return bundle, bundle["artifact"]["sha256"], store


def test_clean_bundle_is_admitted():
    with tempfile.TemporaryDirectory() as tmp:
        bundle, digest, store = _build(tmp)
        decision = verify_mod.verify_bundle(bundle, digest, store)
        assert decision.admitted, [c.reason for c in decision.failed()]


def test_sbom_matches_provenance_materials():
    with tempfile.TemporaryDirectory() as tmp:
        bundle, _, _ = _build(tmp)
        assert component_set(bundle["sbom"]) == material_set(bundle["provenance"])


def test_tampering_detection_rate_is_total():
    result = experiments.run()
    s = result["summary"]
    assert s["detection_rate"] == 1.0, result["experiments"]
    assert s["control_admitted"] is True


def test_altered_artifact_fails_digest_check():
    with tempfile.TemporaryDirectory() as tmp:
        bundle, _, store = _build(tmp)
        d = verify_mod.verify_bundle(bundle, "0" * 64, store)
        assert "C3" in [c.id for c in d.failed()]


def test_forged_key_with_approved_builder_is_rejected():
    """Signing with a non-pinned key while claiming an approved builder must fail
    signature verification against the pinned key."""
    with tempfile.TemporaryDirectory() as tmp:
        bundle, digest, store = _build(tmp)
        atk = os.path.join(tmp, "attacker")
        signing.generate_keypair(atk)
        atk_priv = signing.load_private(os.path.join(atk, "builder_ed25519"))

        forged = copy.deepcopy(bundle)
        forged["sbom_signature"] = signing.sign(forged["sbom"], atk_priv)
        forged["provenance_signature"] = signing.sign(forged["provenance"], atk_priv)
        forged["signing_key_hint"] = os.path.join(atk, "builder_ed25519.pub")

        decision = verify_mod.verify_bundle(forged, digest, store)
        assert not decision.admitted
        assert "C1" in [c.id for c in decision.failed()]


def test_unknown_builder_is_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        bundle, digest, store = _build(tmp)
        b = copy.deepcopy(bundle)
        b["provenance"]["predicate"]["runDetails"]["builder"]["id"] = "https://evil/ci@main"
        decision = verify_mod.verify_bundle(b, digest, store)
        assert not decision.admitted
        assert "C2" in [c.id for c in decision.failed()]


def test_release_digest_covers_whole_tree():
    """Digest must reflect the entire release, not a single entrypoint file."""
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "app.py"), "w") as fh:
            fh.write("x = 1\n")
        h1 = release_digest(d)
        with open(os.path.join(d, "extra.txt"), "w") as fh:
            fh.write("another file\n")
        h2 = release_digest(d)
        assert h1 != h2


# --- Regression tests for the trust-enrollment separation (review fixes) -----


def test_build_alone_cannot_enroll_trust():
    """An ordinary build must NOT be able to make its own key trusted; without the
    separate admin enrollment step the bundle cannot be verified."""
    with tempfile.TemporaryDirectory() as tmp:
        trust_path = os.path.join(tmp, "trusted_builders.json")
        bundle = build_mod.run_build(tmp)          # build only, NO enroll
        # The build created no trust store / enrolled no key.
        assert not os.path.exists(trust_path)
        store = TrustStore.load(trust_path)
        assert store.builders() == []
        decision = verify_mod.verify_bundle(bundle, bundle["artifact"]["sha256"], store)
        assert not decision.admitted
        failed = [c.id for c in decision.failed()]
        assert "C2" in failed and "C1" in failed


def test_verify_recomputes_digest_and_detects_added_file():
    """Verification computes the artifact digest itself, so adding a file to the
    release tree after building must fail C3 even though the bundle is unchanged."""
    with tempfile.TemporaryDirectory() as tmp:
        product = os.path.join(tmp, "product")
        shutil.copytree(os.path.join(build_mod.ROOT, "sample_project"), product)
        out = os.path.join(tmp, "out")
        trust_path = os.path.join(tmp, "trusted_builders.json")

        bundle = build_mod.run_build(out, product_dir=product)
        enroll_builder(build_mod.DEFAULT_BUILDER, bundle["signing_key_hint"], trust_path)

        clean = verify_mod.verify_release(out, product_dir=product, trust_path=trust_path)
        assert clean.admitted, [c.reason for c in clean.failed()]

        # Inject an extra file into the artifact tree.
        with open(os.path.join(product, "extra_payload.txt"), "w") as fh:
            fh.write("sneaky addition\n")
        tampered = verify_mod.verify_release(out, product_dir=product, trust_path=trust_path)
        assert not tampered.admitted
        assert "C3" in [c.id for c in tampered.failed()]
