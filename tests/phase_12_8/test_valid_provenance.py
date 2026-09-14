"""Tests for Valid Signed Provenance Verification & Evidence Binding (REQ-12-PROOF-001, 002, 010, 012)."""

from pathlib import Path
import pytest

from aivara.crypto.chain import ProvenanceChain
from aivara.crypto.keys import KeyManager
from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.enums import SubsystemDomain
from aivara.universal.proof.engine import UniversalProofIntegrationEngine
from aivara.universal.proof.enums import ProofVerificationStatus
from aivara.universal.schemas import AncestryPath, UniversalEvidenceEnvelope

TEST_PASSPHRASE = "Phase12.8_Test_Passphrase_2026!"


@pytest.fixture
def key_manager(tmp_path: Path) -> KeyManager:
    return KeyManager(keys_dir=tmp_path / "keys")


@pytest.fixture
def proof_engine(key_manager):
    return UniversalProofIntegrationEngine(key_manager=key_manager)


def test_valid_signed_provenance_verification(proof_engine, key_manager):
    """A valid Ed25519 signed provenance record correctly verifies proof evidence to VERIFIED with confidence 1.0."""
    project_id = "proj_verified_01"
    asset_id = "model_bert_v1"
    ev_id = "ev_model_int_01"

    ancestry = AncestryPath(
        model_fingerprint="fp_abc123",
        dataset_version_id="ds_v1",
        sample_id="s_001",
    )

    handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
    chain = ProvenanceChain(project_id=project_id, key_handle=handle)

    payload = {
        "evidence_id": ev_id,
        "action": "MODEL_VERIFICATION",
        "model_fingerprint": "fp_abc123",
        "dataset_version_id": "ds_v1",
        "sample_id": "s_001",
    }
    rec = chain.append(
        record_type="MODEL_INTEGRITY",
        action="MODEL_VERIFICATION",
        actor="system",
        target_id=ev_id,
        metadata_json=payload,
        sign=True,
    )

    envelope = UniversalEvidenceEnvelope(
        evidence_id=ev_id,
        project_id=project_id,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        evidence_type="model_weights_proof",
        evidence_layer=EvidenceLayer.PROOF,
        severity=Severity.CRITICAL,
        confidence=1.0,
        primary_asset_type="model",
        primary_asset_id=asset_id,
        ancestry_path=ancestry,
        source_payload_hash="a" * 64,
        normalized_payload_hash="b" * 64,
        provenance_record_ids=[rec.nonce],
        provenance_hashes=[rec.record_hash],
    )

    result = proof_engine.verify_evidence_provenance(
        envelope_or_node=envelope,
        provenance_records=[rec],
    )

    assert result.proof_status == ProofVerificationStatus.VERIFIED
    assert result.proof_confidence == 1.0
    assert result.evidence_id == ev_id
    assert result.project_id == project_id
    assert result.failure_reason is None
    assert len(result.checks) >= 4


def test_integrate_proof_assessment_all_verified(proof_engine, key_manager):
    """UniversalProofAssessment correctly aggregates verified proof evidence."""
    project_id = "proj_verified_02"
    asset_id = "dataset_mnist"
    ev_id = "ev_ds_01"

    handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
    chain = ProvenanceChain(project_id=project_id, key_handle=handle)
    rec = chain.append(
        record_type="DATASET_INTEGRITY",
        action="DATASET_INGEST",
        actor="system",
        target_id=ev_id,
        metadata_json={"evidence_id": ev_id},
        sign=True,
    )

    envelope = UniversalEvidenceEnvelope(
        evidence_id=ev_id,
        project_id=project_id,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        evidence_type="merkle_dataset_proof",
        evidence_layer=EvidenceLayer.PROOF,
        severity=Severity.HIGH,
        confidence=1.0,
        primary_asset_type="dataset",
        primary_asset_id=asset_id,
        source_payload_hash="1" * 64,
        normalized_payload_hash="2" * 64,
    )

    assessment = proof_engine.integrate_proof_assessment(
        project_id=project_id,
        asset_id=asset_id,
        evidence_items=[envelope],
        provenance_records_map={ev_id: [rec]},
    )

    assert assessment.overall_proof_status == ProofVerificationStatus.VERIFIED
    assert assessment.total_evidence_evaluated == 1
    assert assessment.verified_count == 1
    assert assessment.proof_override_required is False
    assert assessment.override_decision is None
