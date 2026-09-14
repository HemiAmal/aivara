"""Tests for Hash Chain Tampering & Integrity Verification (REQ-12-PROOF-008, 009)."""

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


def test_tampered_payload_detected(proof_engine, key_manager):
    """Modifying the record payload after hashing flags the result as TAMPERED."""
    chain = ProvenanceChain(project_id="proj_tamper")
    rec = chain.append(
        record_type="MODEL",
        action="VERIFY",
        actor="system",
        target_id="ev_tamper_01",
        metadata_json={"evidence_id": "ev_tamper_01", "weight_sum": 42.0},
    )

    rec_dict = rec.model_dump()
    rec_dict["metadata_json"]["weight_sum"] = 999.0  # TAMPERED!

    envelope = UniversalEvidenceEnvelope(
        evidence_id="ev_tamper_01",
        project_id="proj_tamper",
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

    assert res.proof_status == ProofVerificationStatus.TAMPERED
    assert res.proof_confidence != 1.0
    assert "Canonical record hash mismatch" in (res.failure_reason or "")


def test_tampered_record_hash_detected(proof_engine, key_manager):
    """Modifying the stored record_hash flags the result as TAMPERED."""
    chain = ProvenanceChain(project_id="proj_tamper")
    rec = chain.append(
        record_type="MODEL",
        action="VERIFY",
        actor="system",
        target_id="ev_tamper_02",
        metadata_json={"evidence_id": "ev_tamper_02"},
    )

    rec_dict = rec.model_dump()
    rec_dict["record_hash"] = "0" * 64  # TAMPERED hash!

    envelope = UniversalEvidenceEnvelope(
        evidence_id="ev_tamper_02",
        project_id="proj_tamper",
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

    assert res.proof_status == ProofVerificationStatus.TAMPERED


def test_tampered_chain_triggers_override(proof_engine, key_manager):
    """A tampered record on proof layer causes UniversalProofAssessment to trigger REJECT override."""
    chain = ProvenanceChain(project_id="proj_tamper_chain")
    rec = chain.append(
        record_type="MODEL",
        action="VERIFY",
        actor="system",
        target_id="ev_tamper_03",
        metadata_json={"evidence_id": "ev_tamper_03"},
    )
    rec_dict = rec.model_dump()
    rec_dict["metadata_json"]["extra_field"] = "malicious_injection"

    envelope = UniversalEvidenceEnvelope(
        evidence_id="ev_tamper_03",
        project_id="proj_tamper_chain",
        domain=SubsystemDomain.MODEL_INTEGRITY,
        evidence_type="model_proof",
        evidence_layer=EvidenceLayer.PROOF,
        severity=Severity.CRITICAL,
        confidence=1.0,
        primary_asset_id="model_01",
        source_payload_hash="1" * 64,
        normalized_payload_hash="2" * 64,
    )

    assessment = proof_engine.integrate_proof_assessment(
        project_id="proj_tamper_chain",
        asset_id="model_01",
        evidence_items=[envelope],
        provenance_records_map={"ev_tamper_03": [rec_dict]},
    )

    assert assessment.overall_proof_status == ProofVerificationStatus.TAMPERED
    assert assessment.tampered_count == 1
    assert assessment.proof_override_required is True
    from aivara.universal.policy.enums import UniversalDecision
    assert assessment.override_decision == UniversalDecision.REJECT
