"""Tests for Evidence Payload & Identity Binding (REQ-12-PROOF-012)."""

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


def test_evidence_id_mismatch_detected(proof_engine, key_manager):
    """Binding provenance referencing evidence_id 'ev_AAA' to envelope 'ev_BBB' flags INVALID."""
    key = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
    chain = ProvenanceChain(project_id="proj_bind", key_handle=key)

    signed_rec = chain.append(
        record_type="MODEL",
        action="VERIFY",
        actor="system",
        target_id="ev_AAA",
        metadata_json={"evidence_id": "ev_AAA"},
        sign=True,
    )

    # Envelope with ev_BBB
    envelope = UniversalEvidenceEnvelope(
        evidence_id="ev_BBB",  # Mismatch!
        project_id="proj_bind",
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
    assert "Evidence identity/hash binding mismatch" in (res.failure_reason or "")


def test_evidence_hash_mismatch_detected(proof_engine, key_manager):
    """Binding provenance referencing hash '1111...' to envelope with hash '2222...' flags INVALID."""
    key = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
    chain = ProvenanceChain(project_id="proj_bind", key_handle=key)

    signed_rec = chain.append(
        record_type="MODEL",
        action="VERIFY",
        actor="system",
        target_id="ev_CCC",
        metadata_json={"evidence_id": "ev_CCC", "evidence_hash": "1" * 64},
        sign=True,
    )

    envelope = UniversalEvidenceEnvelope(
        evidence_id="ev_CCC",
        project_id="proj_bind",
        domain=SubsystemDomain.MODEL_INTEGRITY,
        evidence_type="model_proof",
        evidence_layer=EvidenceLayer.PROOF,
        severity=Severity.HIGH,
        confidence=1.0,
        primary_asset_id="model_01",
        source_payload_hash="1" * 64,
        normalized_payload_hash="2" * 64,  # Different normalized hash
    )

    res = proof_engine.verify_evidence_provenance(
        envelope_or_node=envelope,
        provenance_records=[signed_rec],
    )

    assert res.proof_status == ProofVerificationStatus.INVALID
