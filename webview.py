"""ProvenanceForge-SLSA — interactive pipeline dashboard (Flask).

Shows a real build → enroll → verify flow (release tree with per-file digests,
SBOM, SLSA provenance, signature status, trust store) and a tamper lab where each
controlled attack is run and the failing policy check is revealed. Runs entirely
in temporary directories; nothing leaves the container.
"""

from __future__ import annotations

import hashlib
import os
import tempfile

from flask import Flask, jsonify, send_from_directory

from pipeline import build as build_mod
from pipeline import verify as verify_mod
from pipeline.enroll import enroll_builder
from pipeline.trust import TrustStore
from tamper import experiments

STATIC = os.path.join(os.path.dirname(__file__), "static")
app = Flask(__name__, static_folder=STATIC, static_url_path="/static")


def _file_digests(product_dir):
    out = []
    for root, _, files in os.walk(product_dir):
        for name in sorted(files):
            p = os.path.join(root, name)
            rel = os.path.relpath(p, product_dir).replace(os.sep, "/")
            h = hashlib.sha256()
            with open(p, "rb") as fh:
                h.update(fh.read())
            out.append({"path": rel, "sha256": h.hexdigest()})
    return out


@app.route("/")
def index():
    return send_from_directory(STATIC, "index.html")


@app.route("/api/pipeline")
def pipeline():
    with tempfile.TemporaryDirectory() as tmp:
        trust_path = os.path.join(tmp, "trust.json")
        bundle = build_mod.run_build(tmp)
        enroll_builder(build_mod.DEFAULT_BUILDER, bundle["signing_key_hint"], trust_path)
        store = TrustStore.load(trust_path)
        decision = verify_mod.verify_bundle(bundle, bundle["artifact"]["sha256"], store)

        prov = bundle["provenance"]["predicate"]
        return jsonify({
            "artifact": bundle["artifact"],
            "files": _file_digests(build_mod.DEFAULT_PRODUCT_DIR),
            "sbom": [{"name": c["name"], "version": c["version"]} for c in bundle["sbom"]["components"]],
            "provenance": {
                "builder": prov["runDetails"]["builder"]["id"],
                "source": prov["buildDefinition"]["externalParameters"].get("source", ""),
                "ref": prov["buildDefinition"]["externalParameters"].get("ref", ""),
                "materials": [m["uri"] for m in prov["buildDefinition"]["resolvedDependencies"]],
            },
            "trust_store": store.builders(),
            "decision": {
                "admitted": decision.admitted,
                "checks": [{"id": c.id, "name": c.name, "passed": c.passed, "reason": c.reason}
                           for c in sorted(decision.checks, key=lambda c: c.id)],
            },
            "timings_ms": bundle["timings_ms"],
        })


@app.route("/api/tamper")
def tamper():
    result = experiments.run()
    rows = []
    for r in result["experiments"]:
        rows.append({
            "name": r["name"], "is_attack": r["expect_reject"],
            "caught": (r["rejected"] if r["expect_reject"] else (not r["rejected"])),
            "fired": r["fired"],
        })
    return jsonify({"summary": result["summary"], "experiments": rows})


@app.route("/health")
def health():
    return "ok"


if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "8000")))
