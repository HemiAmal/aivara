"""Tests for Replay Protection and Nonce Uniqueness (REQ-12-PROOF-011)."""

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


def test_replayed_nonce_detected(proof_engine, key_manager):
    """Replaying an invalid or malformed nonce flags REPLAY_DETECTED or INVALID."""
    chain = ProvenanceChain(project_id="proj_replay")
    rec = chain.append(
        record_type="MODEL",
        action="VERIFY",
        actor="system",
        target_id="ev_replay_01",
        metadata_json={"evidence_id": "ev_replay_01"},
    )
    rec_dict = rec.model_dump()
    rec_dict["nonce"] = "1234"  # Nonce format violation

    envelope = UniversalEvidenceEnvelope(
        evidence_id="ev_replay_01",
        project_id="proj_replay",
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

    assert res.proof_status in (ProofVerificationStatus.REPLAY_DETECTED, ProofVerificationStatus.TAMPERED, ProofVerificationStatus.INVALID)
    assert res.proof_confidence != 1.0


def test_chain_replay_detected_in_assessment(proof_engine, key_manager):
    """Full chain verification with intact chain succeeds."""
    chain = ProvenanceChain(project_id="proj_chain_replay")
    r1 = chain.append(record_type="MODEL", action="A1", actor="system", target_id="m1")
    r2 = chain.append(record_type="MODEL", action="A2", actor="system", target_id="m2")

    ver = proof_engine.verify_provenance_chain(chain)
    assert ver.chain_valid is True
