"""Test 12.12.8: Cryptographic Proof & Scope-Aware Provenance Verification."""

from pathlib import Path
import pytest

from aivara.crypto.keys import KeyManager
from aivara.crypto.chain import ProvenanceChain
from aivara.universal.proof.engine import UniversalProofIntegrationEngine
from aivara.universal.proof.enums import ProofVerificationStatus
from aivara.universal.normalizer import UniversalEvidenceNormalizer


def test_proof_confidence_inviolability(tmp_path: Path):
    """Verify proof layer evidence verification produces VERIFIED status with cryptographic guarantee."""
    km = KeyManager(keys_dir=tmp_path / "keys")
    handle = km.generate_key(passphrase="Passphrase123!")
    chain = ProvenanceChain(project_id="proj-prf", key_handle=handle)

    rec = chain.append(
        record_type="MODEL_INTEGRITY",
        action="VERIFY_MODEL",
        actor="test-system",
        metadata_json={"evidence_id": "ev-prf-1", "model_fingerprint": "fp123"},
        key_handle=handle,
        sign=True,
    )

    norm = UniversalEvidenceNormalizer()
    ev = norm.normalize_single({
        "evidence_id": "ev-prf-1",
        "domain": "MODEL_INTEGRITY",
        "evidence_layer": "proof",
        "primary_asset_id": "model-1",
        "severity": "info",
        "confidence": 1.0,
        "ancestry_keys": {"model_fingerprint": "fp123"},
    }, project_id="proj-prf")

    proof_eng = UniversalProofIntegrationEngine(key_manager=km)
    res = proof_eng.verify_evidence_provenance(envelope_or_node=ev, provenance_records=[rec])
    assert res.proof_status == ProofVerificationStatus.VERIFIED
    assert res.proof_confidence == 1.0

