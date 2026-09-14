"""Tests for Proof Verification Status Taxonomy Distinction (REQ-12-PROOF-003)."""

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


def test_missing_status_when_no_records(proof_engine):
    """Proof evidence without attached provenance records resolves to MISSING."""
    envelope = UniversalEvidenceEnvelope(
        evidence_id="ev_missing",
        project_id="proj_tax",
        domain=SubsystemDomain.MODEL_INTEGRITY,
        evidence_type="model_proof",
        evidence_layer=EvidenceLayer.PROOF,
        severity=Severity.HIGH,
        confidence=1.0,
        primary_asset_id="model_01",
        source_payload_hash="1" * 64,
        normalized_payload_hash="2" * 64,
    )
    res = proof_engine.verify_evidence_provenance(envelope, provenance_records=None)
    assert res.proof_status == ProofVerificationStatus.MISSING
    assert res.proof_confidence is None


def test_tampered_status_when_hash_mismatch(proof_engine, key_manager):
    """Provenance record with altered payload hash resolves specifically to TAMPERED."""
    chain = ProvenanceChain(project_id="proj_tax")
    rec = chain.append(
        record_type="MODEL",
        action="VERIFY", actor="system", target_id="ev_tamper",
        metadata_json={"evidence_id": "ev_tamper", "k": "v1"},
    )
    rec_dict = rec.model_dump()
    rec_dict["metadata_json"]["k"] = "v2"  # Tampered!

    envelope = UniversalEvidenceEnvelope(
        evidence_id="ev_tamper",
        project_id="proj_tax",
        domain=SubsystemDomain.MODEL_INTEGRITY,
        evidence_type="model_proof",
        evidence_layer=EvidenceLayer.PROOF,
        severity=Severity.HIGH,
        confidence=1.0,
        primary_asset_id="model_01",
        source_payload_hash="1" * 64,
        normalized_payload_hash="2" * 64,
    )
    res = proof_engine.verify_evidence_provenance(envelope, provenance_records=[rec_dict])
    assert res.proof_status == ProofVerificationStatus.TAMPERED


def test_invalid_status_when_wrong_key(proof_engine, key_manager, tmp_path: Path):
    """Provenance record with wrong key/signature resolves to INVALID (distinct from TAMPERED)."""
    km2 = KeyManager(keys_dir=tmp_path / "keys_unauth")
    key_unauth = km2.generate_key(passphrase=TEST_PASSPHRASE)

    chain = ProvenanceChain(project_id="proj_tax", key_handle=key_unauth)
    signed_rec = chain.append(
        record_type="MODEL",
        action="VERIFY", actor="system", target_id="ev_inv",
        metadata_json={"evidence_id": "ev_inv"},
        sign=True,
    )

    envelope = UniversalEvidenceEnvelope(
        evidence_id="ev_inv",
        project_id="proj_tax",
        domain=SubsystemDomain.MODEL_INTEGRITY,
        evidence_type="model_proof",
        evidence_layer=EvidenceLayer.PROOF,
        severity=Severity.HIGH,
        confidence=1.0,
        primary_asset_id="model_01",
        source_payload_hash="1" * 64,
        normalized_payload_hash="2" * 64,
    )
    # proof_engine uses key_manager (which does NOT contain key_unauth)
    res = proof_engine.verify_evidence_provenance(envelope, provenance_records=[signed_rec])
    assert res.proof_status == ProofVerificationStatus.INVALID
