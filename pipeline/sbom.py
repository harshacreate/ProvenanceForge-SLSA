"""Generate a CycloneDX software bill of materials from a manifest.

Output is a minimal but schema-shaped CycloneDX 1.5 JSON document. Each declared
dependency becomes a component with a pinned version and a (synthetic) hash, plus
the primary artifact as the document subject.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Tuple


def parse_manifest(text: str) -> List[Tuple[str, str]]:
    deps: List[Tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line:
            raise ValueError("manifest line not pinned (name==version): %r" % line)
        name, version = line.split("==", 1)
        deps.append((name.strip(), version.strip()))
    return deps


def _component_hash(name: str, version: str) -> str:
    # Stand-in for a real registry digest; deterministic from name+version.
    return hashlib.sha256(("%s@%s" % (name, version)).encode()).hexdigest()


def build_sbom(product_name: str, product_digest: str, deps: List[Tuple[str, str]]) -> Dict:
    components = [
        {
            "type": "library",
            "name": name,
            "version": version,
            "purl": "pkg:generic/%s@%s" % (name, version),
            "hashes": [{"alg": "SHA-256", "content": _component_hash(name, version)}],
        }
        for name, version in deps
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:%s" % uuid.uuid4(),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "name": product_name,
                "hashes": [{"alg": "SHA-256", "content": product_digest}],
            },
        },
        "components": components,
    }


def component_set(sbom: Dict) -> set:
    """The set of (name, version) pairs recorded in an SBOM."""
    return {(c["name"], c["version"]) for c in sbom.get("components", [])}
