"""Tests for Ed25519 Signature Verification & Mutation Handling (REQ-12-PROOF-010)."""

from pathlib import Path
import pytest

from aivara.crypto.chain import ProvenanceChain
from aivara.crypto.keys import KeyManager
from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.enums import SubsystemDomain
from aivara.universal.proof.engine import UniversalProofIntegrationEngine
from aivara.universal.proof.enums import ProofVerificationStatus
from aivara.universal.schemas import UniversalEvidenceEnvelope

TEST_PASSPHRASE = "Phase12.8_Test_Passphrase_2026!"


@pytest.fixture
def key_manager(tmp_path: Path) -> KeyManager:
    return KeyManager(keys_dir=tmp_path / "keys")


@pytest.fixture
def proof_engine(key_manager):
    return UniversalProofIntegrationEngine(key_manager=key_manager)


def test_corrupted_signature_detected(proof_engine, key_manager):
    """Mutating signature bytes flags the result as INVALID."""
    key_alpha = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
    chain = ProvenanceChain(project_id="proj_sig", key_handle=key_alpha)

    rec = chain.append(
        record_type="MODEL",
        action="SIGN",
        actor="system",
        target_id="ev_sig_01",
        metadata_json={"evidence_id": "ev_sig_01"},
        sign=True,
    )

    # Corrupt signature in dict
    rec_dict = rec.model_dump()
    sig_b64 = rec_dict["signature"]
    # Invert first character
    rec_dict["signature"] = ("A" if sig_b64[0] != "A" else "B") + sig_b64[1:]

    envelope = UniversalEvidenceEnvelope(
        evidence_id="ev_sig_01",
        project_id="proj_sig",
        domain=SubsystemDomain.MODEL_INTEGRITY,
        evidence_type="model_proof",
        evidence_layer=EvidenceLayer.PROOF,
        severity=Severity.HIGH,
        confidence=1.0,
        primary_asset_id="model_01",
        source_payload_hash="1" * 64,
        normalized_payload_hash="2" * 64,
    )

    res = proof_engine.verify_evidence_provenance(
        envelope_or_node=envelope,
        provenance_records=[rec_dict],
    )

    assert res.proof_status == ProofVerificationStatus.INVALID
    assert res.proof_confidence != 1.0


def test_wrong_public_key_verification_fails(proof_engine, key_manager, tmp_path: Path):
    """Verifying with a different public key fails signature verification."""
    key_alpha = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
    km_beta = KeyManager(keys_dir=tmp_path / "keys_beta")
    key_beta = km_beta.generate_key(passphrase=TEST_PASSPHRASE)

    chain = ProvenanceChain(project_id="proj_sig_wrong_key", key_handle=key_alpha)
    signed_rec = chain.append(
        record_type="MODEL",
        action="SIGN",
        actor="system",
        target_id="ev_sig_02",
        metadata_json={"evidence_id": "ev_sig_02"},
        sign=True,
    )

    envelope = UniversalEvidenceEnvelope(
        evidence_id="ev_sig_02",
        project_id="proj_sig_wrong_key",
        domain=SubsystemDomain.MODEL_INTEGRITY,
        evidence_type="model_proof",
        evidence_layer=EvidenceLayer.PROOF,
        severity=Severity.HIGH,
        confidence=1.0,
        primary_asset_id="model_01",
        source_payload_hash="1" * 64,
        normalized_payload_hash="2" * 64,
    )

    # Pass beta's public key explicitly -> mismatch with signature made by alpha
    res = proof_engine.verify_evidence_provenance(
        envelope_or_node=envelope,
        provenance_records=[signed_rec],
        public_key=key_beta.public_key,
    )

    assert res.proof_status == ProofVerificationStatus.INVALID
