"""Generate an in-toto / SLSA-style provenance statement.

Shape follows the in-toto Statement v1 envelope with a SLSA Provenance v1
predicate (https://slsa.dev/spec/v1.0/provenance). It records *what* was built
(subject digest), *who* built it (builder id), *how* it was invoked, and the
materials (resolved dependencies) that went in.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Tuple

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"


def build_provenance(
    product_name: str,
    product_digest: str,
    builder_id: str,
    source_uri: str,
    source_ref: str,
    deps: List[Tuple[str, str]],
) -> Dict:
    materials = [
        {"uri": "pkg:generic/%s@%s" % (name, version), "digest": {"version": version}}
        for name, version in deps
    ]
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": product_name, "digest": {"sha256": product_digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://example/pipeline/v1",
                "externalParameters": {"source": source_uri, "ref": source_ref},
                "resolvedDependencies": materials,
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {
                    "invocationId": "run-%s" % datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
                    "startedOn": datetime.now(timezone.utc).isoformat(),
                },
            },
        },
    }


def subject_digest(prov: Dict) -> str:
    return prov["subject"][0]["digest"]["sha256"]


def builder_id(prov: Dict) -> str:
    return prov["predicate"]["runDetails"]["builder"]["id"]


def material_set(prov: Dict) -> set:
    out = set()
    for m in prov["predicate"]["buildDefinition"]["resolvedDependencies"]:
        # uri looks like pkg:generic/name@version
        tail = m["uri"].split("/", 1)[1]
        name, version = tail.split("@", 1)
        out.add((name, version))
    return out
