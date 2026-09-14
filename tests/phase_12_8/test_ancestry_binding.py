"""Tests for Ancestry Path 5-Tuple Binding & Mutation Verification (REQ-12-PROOF-013)."""

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


@pytest.mark.parametrize("mutated_field,original_val,mutated_val", [
    ("sample_id", "sample_001", "sample_002_mutated"),
    ("dataset_version_id", "ds_v1.0", "ds_v2.0_mutated"),
    ("model_fingerprint", "fp_sha256_aaa", "fp_sha256_bbb_mutated"),
    ("window_id", "win_2026_q1", "win_2026_q2_mutated"),
    ("source_id", "src_camera_01", "src_camera_02_mutated"),
])
def test_ancestry_field_substitution_detected(proof_engine, key_manager, mutated_field, original_val, mutated_val):
    """Mutating any field in the 5-tuple ancestry path fails ancestry binding and flags INVALID."""
    project_id = "proj_ancestry"
    ev_id = f"ev_anc_{mutated_field}"

    payload = {
        "evidence_id": ev_id,
        "sample_id": "sample_001",
        "dataset_version_id": "ds_v1.0",
        "model_fingerprint": "fp_sha256_aaa",
        "window_id": "win_2026_q1",
        "source_id": "src_camera_01",
    }

    key = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
    chain = ProvenanceChain(project_id=project_id, key_handle=key)

    signed_rec = chain.append(
        record_type="MODEL",
        action="INSPECT",
        actor="system",
        target_id=ev_id,
        metadata_json=payload,
        sign=True,
    )

    ancestry_dict = {
        "sample_id": "sample_001",
        "dataset_version_id": "ds_v1.0",
        "model_fingerprint": "fp_sha256_aaa",
        "window_id": "win_2026_q1",
        "source_id": "src_camera_01",
    }
    ancestry_dict[mutated_field] = mutated_val
    mutated_ancestry = AncestryPath(**ancestry_dict)

    envelope = UniversalEvidenceEnvelope(
        evidence_id=ev_id,
        project_id=project_id,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        evidence_type="model_proof",
        evidence_layer=EvidenceLayer.PROOF,
        severity=Severity.HIGH,
        confidence=1.0,
        primary_asset_id="model_01",
        ancestry_path=mutated_ancestry,
        source_payload_hash="1" * 64,
        normalized_payload_hash="2" * 64,
    )

    res = proof_engine.verify_evidence_provenance(
        envelope_or_node=envelope,
        provenance_records=[signed_rec],
    )

    assert res.proof_status == ProofVerificationStatus.INVALID
    assert "Ancestry path identity mismatch" in (res.failure_reason or "")
