"""Ed25519 signing helpers.

Build records (SBOM, provenance) are serialized canonically and signed with a
detached signature. Verification recomputes the canonical bytes and checks the
signature against a trusted public key.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical_bytes(obj) -> bytes:
    """Deterministic JSON encoding so signing is stable across runs."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_keypair(key_dir: str) -> Tuple[str, str]:
    os.makedirs(key_dir, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    priv_path = os.path.join(key_dir, "builder_ed25519")
    pub_path = os.path.join(key_dir, "builder_ed25519.pub")

    with open(priv_path, "wb") as fh:
        fh.write(
            priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(pub_path, "wb") as fh:
        fh.write(
            priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    os.chmod(priv_path, 0o600)
    return priv_path, pub_path


def load_private(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    assert isinstance(key, Ed25519PrivateKey)
    return key


def load_public(path: str) -> Ed25519PublicKey:
    with open(path, "rb") as fh:
        key = serialization.load_pem_public_key(fh.read())
    assert isinstance(key, Ed25519PublicKey)
    return key


def sign(obj, priv: Ed25519PrivateKey) -> str:
    sig = priv.sign(canonical_bytes(obj))
    return base64.b64encode(sig).decode("ascii")


def verify(obj, signature_b64: str, pub: Ed25519PublicKey) -> bool:
    try:
        pub.verify(base64.b64decode(signature_b64), canonical_bytes(obj))
        return True
    except (InvalidSignature, ValueError):
        return False
