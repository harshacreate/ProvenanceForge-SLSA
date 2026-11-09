"""A minimal, verifiable build pipeline.

Stages:
  build       produce the artifact and record its digest
  sbom        emit a CycloneDX software bill of materials
  provenance  emit an in-toto / SLSA-style provenance statement
  signing     sign the SBOM and provenance with an Ed25519 key
  verify      enforce a release policy over the signed records
"""
