"""Trust store: the pinned root of trust, kept OUTSIDE release bundles.

The key lesson of signature verification is that a bundle cannot be allowed to
name the key that verifies it -- otherwise an attacker signs a forged bundle
with their own key, points the bundle at that key, and every check passes.

Instead, trusted public keys are pinned here, keyed by builder identity, and
established out-of-band (an admin onboards an approved builder's key). The
verifier looks up the key for the *claimed* builder from this store; it never
reads a key out of the bundle. A bundle that claims an approved builder but is
signed by a different key fails signature verification against the pinned key.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TRUST_FILE = os.path.join(ROOT, "trust", "trusted_builders.json")


class TrustStore:
    """Maps builder identity -> trusted Ed25519 public key (PEM)."""

    def __init__(self, entries: Optional[Dict[str, str]] = None):
        self._entries: Dict[str, str] = dict(entries or {})

    # --- persistence ---
    @classmethod
    def load(cls, path: str = DEFAULT_TRUST_FILE) -> "TrustStore":
        if not os.path.exists(path):
            return cls({})
        with open(path, "r", encoding="utf-8") as fh:
            return cls(json.load(fh))

    def save(self, path: str = DEFAULT_TRUST_FILE) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self._entries, fh, indent=2, sort_keys=True)

    # --- out-of-band onboarding (a trusted admin action, NOT the attacker's) ---
    def register(self, builder_id: str, public_pem: str) -> None:
        self._entries[builder_id] = public_pem

    # --- lookup used by the verifier ---
    def is_approved(self, builder_id: str) -> bool:
        return builder_id in self._entries

    def public_key(self, builder_id: str) -> Optional[Ed25519PublicKey]:
        pem = self._entries.get(builder_id)
        if pem is None:
            return None
        key = serialization.load_pem_public_key(pem.encode("utf-8"))
        assert isinstance(key, Ed25519PublicKey)
        return key

    def builders(self) -> List[str]:
        return sorted(self._entries)
