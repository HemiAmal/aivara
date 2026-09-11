"""Master Model Fingerprint Cryptographic Engine (H_model).

Implements ADR-040: RFC 8785 JCS canonical binding of artifact identity,
structural identity, and contract identity into the authoritative Master Model Fingerprint.
"""

from __future__ import annotations

from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import is_valid_sha256, sha256_bytes
from aivara.model_integrity.fingerprinting.exceptions import FingerprintingError
from aivara.model_integrity.fingerprinting.schemas import MasterFingerprintBinding


def compute_master_fingerprint(
    artifact_hash: str,
    structural_hash: str,
    contract_hash: str,
    schema_version: str = "1.0",
) -> str:
    """Compute 64-char lowercase hex Master Model Fingerprint via RFC 8785 JCS binding.

    Formulation:
      Payload = {
          "schema_version": "1.0",
          "artifact_hash": "<64 hex>",
          "structural_hash": "<64 hex>",
          "contract_hash": "<64 hex>"
      }
      MasterFingerprint = SHA-256(RFC_8785_JCS(Payload))

    Args:
        artifact_hash: 64-char lowercase hex digest of raw file.
        structural_hash: 64-char lowercase hex digest of structural representation.
        contract_hash: 64-char lowercase hex digest of operational contract.
        schema_version: Canonical schema version string (default "1.0").

    Returns:
        64-character lowercase hexadecimal master model fingerprint.
    """
    if not is_valid_sha256(artifact_hash):
        raise FingerprintingError(f"Invalid artifact_hash format: '{artifact_hash}'")
    if not is_valid_sha256(structural_hash):
        raise FingerprintingError(f"Invalid structural_hash format: '{structural_hash}'")
    if not is_valid_sha256(contract_hash):
        raise FingerprintingError(f"Invalid contract_hash format: '{contract_hash}'")

    binding = MasterFingerprintBinding(
        schema_version=schema_version,
        artifact_hash=artifact_hash.lower(),
        structural_hash=structural_hash.lower(),
        contract_hash=contract_hash.lower(),
    )

    canonical_bytes = canonicalize(binding.model_dump())
    return sha256_bytes(canonical_bytes)
