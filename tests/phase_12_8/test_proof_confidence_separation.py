"""Tests for Detection/Proof Confidence Segregation & Non-Compensability (REQ-12-PROOF-004, 005, 006, 007)."""

from pathlib import Path
import pytest

from aivara.crypto.chain import ProvenanceChain
from aivara.crypto.keys import KeyManager
from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.enums import SubsystemDomain
from aivara.universal.policy.enums import UniversalDecision
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


def test_detection_confidence_preserved(proof_engine):
    """Detection evidence maintains its statistical detection confidence untouched during proof evaluation."""
    envelope = UniversalEvidenceEnvelope(
        evidence_id="ev_det_01",
        project_id="proj_conf",
        domain=SubsystemDomain.BEHAVIORAL_ANALYSIS,
        evidence_type="anomaly_detection",
        evidence_layer=EvidenceLayer.DETECTION,
        severity=Severity.HIGH,
        confidence=0.825,  # Statistical detection confidence
        primary_asset_id="model_01",
        source_payload_hash="1" * 64,
        normalized_payload_hash="2" * 64,
    )

    res = proof_engine.verify_evidence_provenance(envelope, provenance_records=None)

    assert res.detection_confidence == 0.825
    assert res.proof_confidence is None
    assert res.proof_status == ProofVerificationStatus.MISSING


def test_proof_failure_non_compensability_forces_reject(proof_engine, key_manager):
    """Proof failure on a proof-layer evidence forces UniversalDecision.REJECT override regardless of detection."""
    chain = ProvenanceChain(project_id="proj_non_comp")
    rec = chain.append(
        record_type="MODEL",
        action="VERIFY", actor="system", target_id="ev_proof_fail",
        metadata_json={"evidence_id": "ev_proof_fail"},
    )
    rec_dict = rec.model_dump()
    rec_dict["metadata_json"]["corrupt"] = True

    proof_envelope = UniversalEvidenceEnvelope(
        evidence_id="ev_proof_fail",
        project_id="proj_non_comp",
        domain=SubsystemDomain.MODEL_INTEGRITY,
        evidence_type="model_weights_proof",
        evidence_layer=EvidenceLayer.PROOF,
        severity=Severity.CRITICAL,
        confidence=1.0,
        primary_asset_id="model_01",
        source_payload_hash="1" * 64,
        normalized_payload_hash="2" * 64,
    )

    detection_envelope = UniversalEvidenceEnvelope(
        evidence_id="ev_det_ok",
        project_id="proj_non_comp",
        domain=SubsystemDomain.DATASET_INTEGRITY,
        evidence_type="clean_detection",
        evidence_layer=EvidenceLayer.DETECTION,
        severity=Severity.LOW,
        confidence=0.10,
        primary_asset_id="model_01",
        source_payload_hash="3" * 64,
        normalized_payload_hash="4" * 64,
    )

    assessment = proof_engine.integrate_proof_assessment(
        project_id="proj_non_comp",
        asset_id="model_01",
        evidence_items=[proof_envelope, detection_envelope],
        provenance_records_map={"ev_proof_fail": [rec_dict]},
    )

    assert assessment.proof_override_required is True
    assert assessment.override_decision == UniversalDecision.REJECT
    assert assessment.overall_proof_status == ProofVerificationStatus.TAMPERED
