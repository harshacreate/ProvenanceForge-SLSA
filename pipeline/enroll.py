"""Admin-only trust enrollment.

Enrolling a builder's public key as *trusted* is an administrative action that is
deliberately separate from building. An ordinary build (`pipeline.build`) never
touches the trust store, so a build cannot make its own key trusted; only this
step can, and in a real deployment it would be gated by admin access controls.

This matches SLSA verification guidance: trusted builder identities are
configured in the verifier, independently of the build that produced an artifact.

Usage:
  python -m pipeline.enroll --builder <id> --key <path-to-public.pem>
  python -m pipeline.enroll --builder <id> --key out/keys/builder_ed25519.pub
"""

from __future__ import annotations

import argparse

from pipeline.trust import DEFAULT_TRUST_FILE, TrustStore


def enroll_builder(builder_id: str, public_key_path: str,
                   trust_path: str = DEFAULT_TRUST_FILE) -> str:
    """Register a builder identity -> trusted public key in the trust store."""
    with open(public_key_path, "r", encoding="utf-8") as fh:
        public_pem = fh.read()
    store = TrustStore.load(trust_path)
    store.register(builder_id, public_pem)
    store.save(trust_path)
    return trust_path


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Admin: enroll a builder's public key as trusted.")
    ap.add_argument("--builder", required=True, help="builder identity to trust")
    ap.add_argument("--key", required=True, help="path to the builder's PEM public key")
    ap.add_argument("--trust", default=DEFAULT_TRUST_FILE, help="trust store path")
    args = ap.parse_args(argv)
    path = enroll_builder(args.builder, args.key, args.trust)
    print("enrolled builder %r into trust store %s" % (args.builder, path))


if __name__ == "__main__":
    main()
