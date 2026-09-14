"""Tests for Proof Verification Determinism & Content-Addressed Hash Integrity (REQ-12-PROOF-016)."""

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


def test_repeated_proof_verification_determinism(proof_engine, key_manager):
    """100 repeated evaluations produce bit-for-bit identical hashes, statuses, and traces."""
    project_id = "proj_det"
    ev_id = "ev_det_01"

    key = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
    chain = ProvenanceChain(project_id=project_id, key_handle=key)
    signed_rec = chain.append(
        record_type="MODEL",
        action="VERIFY", actor="system", target_id=ev_id,
        metadata_json={"evidence_id": ev_id},
        sign=True,
    )

    envelope = UniversalEvidenceEnvelope(
        evidence_id=ev_id,
        project_id=project_id,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        evidence_type="model_proof",
        evidence_layer=EvidenceLayer.PROOF,
        severity=Severity.HIGH,
        confidence=1.0,
        primary_asset_id="model_01",
        source_payload_hash="1" * 64,
        normalized_payload_hash="2" * 64,
    )

    first_res = proof_engine.verify_evidence_provenance(envelope, provenance_records=[signed_rec])

    for _ in range(100):
        res = proof_engine.verify_evidence_provenance(envelope, provenance_records=[signed_rec])
        assert res.proof_status == first_res.proof_status
        assert res.proof_result_hash == first_res.proof_result_hash
        assert res.to_canonical_dict() == first_res.to_canonical_dict()


def test_proof_result_hash_mutation_sensitivity(proof_engine):
    """Mutating any security-relevant property alters the computed proof_result_hash."""
    project_id = "proj_sens"
    ev1 = "ev_sens_01"
    ev2 = "ev_sens_02"

    envelope1 = UniversalEvidenceEnvelope(
        evidence_id=ev1,
        project_id=project_id,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        evidence_type="model_proof",
        evidence_layer=EvidenceLayer.PROOF,
        severity=Severity.HIGH,
        confidence=1.0,
        primary_asset_id="model_01",
        source_payload_hash="1" * 64,
        normalized_payload_hash="2" * 64,
    )
    envelope2 = UniversalEvidenceEnvelope(
        evidence_id=ev2,
        project_id=project_id,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        evidence_type="model_proof",
        evidence_layer=EvidenceLayer.PROOF,
        severity=Severity.HIGH,
        confidence=1.0,
        primary_asset_id="model_01",
        source_payload_hash="1" * 64,
        normalized_payload_hash="2" * 64,
    )

    res1 = proof_engine.verify_evidence_provenance(envelope1, provenance_records=None)
    res2 = proof_engine.verify_evidence_provenance(envelope2, provenance_records=None)

    assert res1.proof_result_hash != res2.proof_result_hash
