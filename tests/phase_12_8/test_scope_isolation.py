"""Tests for Scope & Cross-Project Isolation (REQ-12-PROOF-014, 015)."""

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


def test_cross_project_contamination_rejected(proof_engine, key_manager):
    """Using a provenance record from Project Alpha for evidence in Project Beta flags INVALID."""
    key = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
    chain_alpha = ProvenanceChain(project_id="proj_alpha", key_handle=key)

    signed_rec = chain_alpha.append(
        record_type="MODEL",
        action="VERIFY",
        actor="system",
        target_id="ev_cross_01",
        metadata_json={"evidence_id": "ev_cross_01"},
        sign=True,
    )

    # Envelope in Project Beta
    envelope = UniversalEvidenceEnvelope(
        evidence_id="ev_cross_01",
        project_id="proj_beta",  # Different project!
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
        provenance_records=[signed_rec],
    )

    assert res.proof_status == ProofVerificationStatus.INVALID
    assert "Scope mismatch: project_id does not match" in (res.failure_reason or "")


def test_asset_isolation_unrelated_assets(proof_engine, key_manager):
    """A proof failure on Asset A does not contaminate the assessment of unrelated Asset B."""
    key = key_manager.generate_key(passphrase=TEST_PASSPHRASE)

    # Asset A: Has invalid proof
    chain_a = ProvenanceChain(project_id="proj_iso")
    rec_a = chain_a.append(
        record_type="MODEL",
        action="VERIFY", actor="system", target_id="ev_a",
        metadata_json={"evidence_id": "ev_a"},
    )
    rec_a_dict = rec_a.model_dump()
    rec_a_dict["metadata_json"]["extra"] = "tampered"  # Tampered!

    envelope_a = UniversalEvidenceEnvelope(
        evidence_id="ev_a",
        project_id="proj_iso",
        domain=SubsystemDomain.MODEL_INTEGRITY,
        evidence_type="model_proof",
        evidence_layer=EvidenceLayer.PROOF,
        severity=Severity.HIGH,
        confidence=1.0,
        primary_asset_id="asset_A",
        source_payload_hash="1" * 64,
        normalized_payload_hash="2" * 64,
    )

    # Asset B: Has valid signed proof
    chain_b = ProvenanceChain(project_id="proj_iso", key_handle=key)
    signed_rec_b = chain_b.append(
        record_type="DATASET",
        action="VERIFY", actor="system", target_id="ev_b",
        metadata_json={"evidence_id": "ev_b"},
        sign=True,
    )

    envelope_b = UniversalEvidenceEnvelope(
        evidence_id="ev_b",
        project_id="proj_iso",
        domain=SubsystemDomain.DATASET_INTEGRITY,
        evidence_type="dataset_proof",
        evidence_layer=EvidenceLayer.PROOF,
        severity=Severity.HIGH,
        confidence=1.0,
        primary_asset_id="asset_B",
        source_payload_hash="3" * 64,
        normalized_payload_hash="4" * 64,
    )

    # Evaluate Asset A
    ass_a = proof_engine.integrate_proof_assessment(
        project_id="proj_iso",
        asset_id="asset_A",
        evidence_items=[envelope_a],
        provenance_records_map={"ev_a": [rec_a_dict]},
    )
    assert ass_a.overall_proof_status == ProofVerificationStatus.TAMPERED
    assert ass_a.proof_override_required is True

    # Evaluate Asset B
    ass_b = proof_engine.integrate_proof_assessment(
        project_id="proj_iso",
        asset_id="asset_B",
        evidence_items=[envelope_b],
        provenance_records_map={"ev_b": [signed_rec_b]},
    )
    assert ass_b.overall_proof_status == ProofVerificationStatus.VERIFIED
    assert ass_b.proof_override_required is False
    assert ass_b.override_decision is None
