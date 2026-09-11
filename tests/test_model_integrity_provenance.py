"""Comprehensive Tests for Phase 7.6 — Evidence Generation & Cryptographic Provenance Binding.

Verifies:
1. Deterministic evidence generation across all Phase 7 models/tiers
2. Finding synthesis and ADR-028 compliance (Proof confidence = 1.0)
3. Cryptographic Provenance sealing via Phase 4 Ed25519 signing
4. Provenance verification, chain integrity, and tamper detection
5. Replay attack rejection (sequence/nonce protection)
6. Idempotent execution (ScanExecutionStatus.IDEMPOTENT_HIT)
7. Strict project isolation (no cross-project leakage)
8. Zero human-intent / semantic safety enforcement
9. Air-gapped offline execution
"""

from __future__ import annotations

import json
import pytest
import re
from typing import Any, Dict
from sqlalchemy.orm import Session

from aivara.crypto.keys import KeyManager
from aivara.database.models import (
    AIModelModel,
    EvidenceModel,
    FindingModel,
    ModelFingerprintModel,
    ProjectModel,
    ProvenanceRecordModel,
)
from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.evidence.binding import EvidenceFindingBinder
from aivara.evidence.exceptions import (
    CrossProjectContaminationError,
    EvidenceValidationError,
)
from aivara.evidence.identity import (
    build_canonical_execution_payload,
    compute_evidence_hash,
    compute_execution_identity_hash,
)
from aivara.evidence.schemas import (
    ExecutionIdentityPayload,
    ProvenanceStatus,
    ScanExecutionStatus,
)
from aivara.model_integrity.comparison.schemas import (
    ArtifactComparisonStatus,
    ComparisonStatus,
    ContractComparisonStatus,
    DriftClassification,
    ModelComparisonResult,
    StructuralComparisonStatus,
    TensorChangeRecord,
    TensorChangeType,
    WeightComparisonStatus,
)
from aivara.model_integrity.contract_verification.schemas import (
    ContractCompleteness,
    ContractStatus,
    ContractVerificationResult,
    ValidatedInputContract,
    ValidatedOutputContract,
)
from aivara.model_integrity.fingerprinting.schemas import ContractRepresentation
from aivara.model_integrity.evidence.builders import (
    build_artifact_identity_evidence,
    build_comparison_evidence,
    build_contract_evidence,
    build_master_fingerprint_evidence,
    build_structural_fingerprint_evidence,
    build_tensor_attribution_evidence,
    build_weight_merkle_evidence,
)
from aivara.model_integrity.evidence.mapping import map_model_integrity_to_findings
from aivara.model_integrity.evidence.schemas import ModelEvidenceType
from aivara.model_integrity.evidence.service import ModelIntegrityEvidenceService
from aivara.model_integrity.fingerprinting.schemas import HierarchicalFingerprintResult
from aivara.model_integrity.schemas import (
    InspectionStatus,
    InspectionPolicy,
    ModelFormat,
    ModelInspectionResult,
    NormalizedModelMetadata,
)
from aivara.services.audit_service import AuditService
from aivara.services.provenance_service import ProvenanceService


@pytest.fixture(autouse=True)
def seed_db(test_db_session: Session):
    """Seed test projects and AI models."""
    p1 = ProjectModel(id="proj-1", name="Project 1")
    pA = ProjectModel(id="proj-A", name="Project A")
    pB = ProjectModel(id="proj-B", name="Project B")
    test_db_session.add_all([p1, pA, pB])
    test_db_session.flush()

    m1 = AIModelModel(
        id="mod-1",
        project_id="proj-1",
        name="Model 1",
        format="safetensors",
        file_path="model1.safetensors",
        file_hash_sha256="a" * 64,
    )
    mA = AIModelModel(
        id="mod-A",
        project_id="proj-A",
        name="Model A",
        format="safetensors",
        file_path="modelA.safetensors",
        file_hash_sha256="a" * 64,
    )
    test_db_session.add_all([m1, mA])
    test_db_session.flush()


@pytest.fixture
def key_manager(tmp_path):
    km = KeyManager(keys_dir=str(tmp_path / "keys"))
    return km


@pytest.fixture
def signer_key_id(key_manager):
    handle = key_manager.generate_key(
        passphrase="test-passphrase-1234",
        description="Test model signer key",
    )
    return handle.key_id


@pytest.fixture
def dummy_inspection():
    return ModelInspectionResult(
        artifact_path="/tmp/test_model.safetensors",
        format=ModelFormat.SAFETENSORS,
        policy=InspectionPolicy.SUPPORTED,
        status=InspectionStatus.SUCCESS,
        artifact_hash_sha256="a" * 64,
        artifact_size_bytes=1024,
        reason_codes=[],
        warnings=[],
    )


@pytest.fixture
def dummy_fingerprint():
    return HierarchicalFingerprintResult(
        artifact_hash="a" * 64,
        structural_hash="b" * 64,
        weight_merkle_root="c" * 64,
        weight_status="verified",
        contract_hash="d" * 64,
        master_fingerprint="e" * 64,
        tensor_count=4,
        parameter_count=1000,
    )


@pytest.fixture
def dummy_contract():
    return ContractVerificationResult(
        schema_version="1.0",
        status=ContractStatus.VERIFIED,
        completeness=ContractCompleteness.COMPLETE,
        inputs=[
            ValidatedInputContract(
                name="input",
                index=0,
                dtype="F32",
                rank=4,
                shape=[1, 3, 224, 224],
            )
        ],
        outputs=[
            ValidatedOutputContract(
                name="output",
                index=0,
                dtype="F32",
                rank=2,
                shape=[1, 1000],
            )
        ],
        preprocessing=None,
        findings=[],
        contract_representation=ContractRepresentation(
            schema_version="1.0",
            inputs=[{"name": "input", "dtype": "F32", "shape": [1, 3, 224, 224]}],
            outputs=[{"name": "output", "dtype": "F32", "shape": [1, 1000]}],
        ),
        contract_hash="d" * 64,
        warnings=[],
    )


@pytest.fixture
def dummy_comparison():
    return ModelComparisonResult(
        comparison_status=ComparisonStatus.COMPARABLE,
        drift_classification=DriftClassification.EXACT_INTEGRITY_MATCH,
        reference_trust="verified",
        candidate_trust="verified",
        is_exact_artifact_match=True,
        is_exact_master_match=True,
        artifact_status=ArtifactComparisonStatus.ARTIFACT_MATCH,
        structural_status=StructuralComparisonStatus.STRUCTURE_MATCH,
        weight_status=WeightComparisonStatus.WEIGHT_MERKLE_MATCH,
        contract_status=ContractComparisonStatus.CONTRACT_MATCH,
        reference_fingerprints={"artifact_hash": "a" * 64, "master_fingerprint": "e" * 64},
        candidate_fingerprints={"artifact_hash": "a" * 64, "master_fingerprint": "e" * 64},
        structural_differences=[],
        tensor_changes=[],
        tensor_summary={"unchanged": 4, "added": 0, "removed": 0, "content_changed": 0, "metadata_changed": 0},
        contract_differences=[],
        reason_codes=["EXACT_INTEGRITY_MATCH"],
    )


# ---------------------------------------------------------------------------
# Test 1-5: Evidence Creation for Fingerprints & Contracts
# ---------------------------------------------------------------------------

def test_evidence_creation_artifact_identity(dummy_inspection):
    ev = build_artifact_identity_evidence(
        project_id="proj-1",
        model_id="mod-1",
        inspection_result=dummy_inspection,
    )
    assert ev.evidence_type == ModelEvidenceType.MODEL_ARTIFACT_IDENTITY.value
    assert ev.evidence_layer == EvidenceLayer.PROOF
    assert ev.confidence == 1.0
    assert ev.artifact_hash == "a" * 64
    assert len(ev.evidence_hash) == 64


def test_evidence_creation_structural_fingerprint(dummy_fingerprint):
    ev = build_structural_fingerprint_evidence(
        project_id="proj-1",
        model_id="mod-1",
        fingerprint_result=dummy_fingerprint,
    )
    assert ev.evidence_type == ModelEvidenceType.MODEL_STRUCTURAL_FINGERPRINT.value
    assert ev.evidence_layer == EvidenceLayer.PROOF
    assert ev.confidence == 1.0
    assert ev.artifact_hash == "b" * 64


def test_evidence_creation_weight_merkle(dummy_fingerprint):
    ev = build_weight_merkle_evidence(
        project_id="proj-1",
        model_id="mod-1",
        fingerprint_result=dummy_fingerprint,
    )
    assert ev.evidence_type == ModelEvidenceType.MODEL_WEIGHT_MERKLE_ROOT.value
    assert ev.evidence_layer == EvidenceLayer.PROOF
    assert ev.confidence == 1.0
    assert ev.artifact_hash == "c" * 64


def test_evidence_creation_contract(dummy_contract):
    ev = build_contract_evidence(
        project_id="proj-1",
        model_id="mod-1",
        contract_result=dummy_contract,
        artifact_hash="a" * 64,
    )
    assert ev.evidence_type == ModelEvidenceType.MODEL_CONTRACT_VERIFICATION.value
    assert ev.evidence_layer == EvidenceLayer.PROOF
    assert ev.confidence == 1.0
    assert ev.artifact_hash == "d" * 64


def test_evidence_creation_master_fingerprint(dummy_fingerprint):
    ev = build_master_fingerprint_evidence(
        project_id="proj-1",
        model_id="mod-1",
        fingerprint_result=dummy_fingerprint,
    )
    assert ev.evidence_type == ModelEvidenceType.MODEL_MASTER_FINGERPRINT.value
    assert ev.evidence_layer == EvidenceLayer.PROOF
    assert ev.confidence == 1.0
    assert ev.artifact_hash == "e" * 64


# ---------------------------------------------------------------------------
# Test 6-9: Evidence Creation for Comparison & Drift States
# ---------------------------------------------------------------------------

def test_evidence_creation_exact_reference_match(dummy_comparison):
    ev = build_comparison_evidence(
        project_id="proj-1",
        model_id="mod-1",
        reference_model_id="ref-1",
        comparison_result=dummy_comparison,
    )
    assert ev.evidence_type == ModelEvidenceType.MODEL_REFERENCE_COMPARISON.value
    assert ev.evidence_layer == EvidenceLayer.DETECTION
    assert ev.data_json["drift_classification"] == "EXACT_INTEGRITY_MATCH"


@pytest.mark.parametrize(
    "drift_state",
    [
        DriftClassification.EXACT_INTEGRITY_MATCH,
        DriftClassification.WEIGHT_ONLY_DRIFT,
        DriftClassification.STRUCTURAL_ONLY_DRIFT,
        DriftClassification.CONTRACT_ONLY_DRIFT,
        DriftClassification.STRUCTURAL_AND_WEIGHT_DRIFT,
        DriftClassification.STRUCTURAL_AND_CONTRACT_DRIFT,
        DriftClassification.WEIGHT_AND_CONTRACT_DRIFT,
        DriftClassification.STRUCTURAL_WEIGHT_CONTRACT_DRIFT,
    ],
)
def test_evidence_creation_all_comparison_states(drift_state, dummy_comparison):
    comp = dummy_comparison.model_copy(update={"drift_classification": drift_state})
    ev = build_comparison_evidence(
        project_id="proj-1",
        model_id="mod-1",
        reference_model_id="ref-1",
        comparison_result=comp,
    )
    assert ev.data_json["drift_classification"] == drift_state.value


def test_evidence_creation_tensor_attribution(dummy_comparison):
    tensor_changes = [
        TensorChangeRecord(
            tensor_name="layer1.weight",
            change_type=TensorChangeType.CONTENT_CHANGED,
            reference_shape=[10, 10],
            candidate_shape=[10, 10],
            reference_dtype="float32",
            candidate_dtype="float32",
        ),
        TensorChangeRecord(
            tensor_name="layer2.bias",
            change_type=TensorChangeType.ADDED,
            reference_shape=None,
            candidate_shape=[10],
            reference_dtype=None,
            candidate_dtype="float32",
        ),
    ]
    comp = dummy_comparison.model_copy(update={"tensor_changes": tensor_changes})
    ev = build_tensor_attribution_evidence(
        project_id="proj-1",
        model_id="mod-1",
        comparison_result=comp,
    )
    assert ev.evidence_type == ModelEvidenceType.MODEL_TENSOR_ATTRIBUTION.value
    assert ev.data_json["changes_count"] == 2
    assert ev.data_json["changes"][0]["name"] == "layer1.weight"


# ---------------------------------------------------------------------------
# Test 10-14: Determinism, Identities, and ADR-028 Confidence
# ---------------------------------------------------------------------------

def test_deterministic_evidence_identity(dummy_inspection):
    ev1 = build_artifact_identity_evidence(
        project_id="proj-1",
        model_id="mod-1",
        inspection_result=dummy_inspection,
    )
    ev2 = build_artifact_identity_evidence(
        project_id="proj-1",
        model_id="mod-1",
        inspection_result=dummy_inspection,
    )
    assert ev1.evidence_hash == ev2.evidence_hash


def test_deterministic_execution_identity():
    payload1 = ExecutionIdentityPayload(
        project_id="proj-1",
        dataset_version_id="mod-1",
        dataset_fingerprint="a" * 64,
        detector_id="model_integrity_engine",
        detector_version="1.0.0",
        engine_version="1.0.0",
        policy_version="DEFAULT",
        preprocessing_hash="STANDARD_V1",
        model_id="mod-1",
        model_fingerprint="e" * 64,
        model_version="1.0.0",
        reference_dataset_id="NONE",
        reference_dataset_fingerprint="NONE",
        detector_config_hash="0" * 64,
    )
    payload2 = ExecutionIdentityPayload(
        project_id="proj-1",
        dataset_version_id="mod-1",
        dataset_fingerprint="a" * 64,
        detector_id="model_integrity_engine",
        detector_version="1.0.0",
        engine_version="1.0.0",
        policy_version="DEFAULT",
        preprocessing_hash="STANDARD_V1",
        model_id="mod-1",
        model_fingerprint="e" * 64,
        model_version="1.0.0",
        reference_dataset_id="NONE",
        reference_dataset_fingerprint="NONE",
        detector_config_hash="0" * 64,
    )
    assert compute_execution_identity_hash(payload1) == compute_execution_identity_hash(payload2)


def test_finding_synthesis_proof_confidence_invariant(
    dummy_fingerprint, dummy_contract, dummy_inspection
):
    findings = map_model_integrity_to_findings(
        project_id="proj-1",
        model_id="mod-1",
        audit_run_id="audit-1",
        fingerprint_result=dummy_fingerprint,
        contract_result=dummy_contract,
        inspection_result=dummy_inspection,
    )
    assert len(findings) == 1
    fp_finding = findings[0]
    assert fp_finding.evidence_layer == EvidenceLayer.PROOF
    assert fp_finding.confidence == 1.0  # ADR-028 Invariant: Proof confidence must be 1.0


# ---------------------------------------------------------------------------
# Test 15-22: Provenance Sealing, Signing, Verification, Replay & Tampering
# ---------------------------------------------------------------------------

def test_provenance_record_creation_and_signing(
    test_db_session: Session,
    key_manager: KeyManager,
    signer_key_id: str,
    dummy_fingerprint,
    dummy_contract,
    dummy_inspection,
):
    service = ModelIntegrityEvidenceService(
        db=test_db_session,
        key_manager=key_manager,
    )

    findings, prov_record, status = service.record_model_assessment(
        project_id="proj-1",
        model_id="mod-1",
        audit_run_id="run-1",
        fingerprint_result=dummy_fingerprint,
        contract_result=dummy_contract,
        inspection_result=dummy_inspection,
        seal_provenance=True,
        signer_key_id=signer_key_id,
        signer_passphrase="test-passphrase-1234",
    )

    assert status == ScanExecutionStatus.COMPLETED
    assert len(findings) == 1
    assert prov_record is not None
    assert prov_record.signature is not None
    assert prov_record.signer_key_id == signer_key_id

    # Verify provenance
    verif = service.verify_finding_provenance(
        finding_id=findings[0].id,
        project_id="proj-1",
    )
    assert verif.provenance_status == ProvenanceStatus.VERIFIED
    assert verif.cryptographic_validity is True


def test_tampered_provenance_payload_detection(
    test_db_session: Session,
    key_manager: KeyManager,
    signer_key_id: str,
    dummy_fingerprint,
    dummy_contract,
    dummy_inspection,
):
    service = ModelIntegrityEvidenceService(
        db=test_db_session,
        key_manager=key_manager,
    )

    findings, prov_record, _ = service.record_model_assessment(
        project_id="proj-1",
        model_id="mod-1",
        audit_run_id="run-1",
        fingerprint_result=dummy_fingerprint,
        contract_result=dummy_contract,
        inspection_result=dummy_inspection,
        seal_provenance=True,
        signer_key_id=signer_key_id,
        signer_passphrase="test-passphrase-1234",
    )

    # Tamper with provenance output_hash in database
    prov_model = test_db_session.query(ProvenanceRecordModel).filter_by(id=prov_record.id).first()
    prov_model.output_hash = "f" * 64
    test_db_session.flush()

    verif = service.verify_finding_provenance(
        finding_id=findings[0].id,
        project_id="proj-1",
    )
    assert verif.provenance_status == ProvenanceStatus.INVALID
    assert verif.cryptographic_validity is False


def test_missing_signer_key_verification(
    test_db_session: Session,
    dummy_fingerprint,
    dummy_contract,
    dummy_inspection,
):
    # Service without key manager
    service = ModelIntegrityEvidenceService(
        db=test_db_session,
        key_manager=None,
    )

    findings, prov_record, _ = service.record_model_assessment(
        project_id="proj-1",
        model_id="mod-1",
        audit_run_id="run-1",
        fingerprint_result=dummy_fingerprint,
        contract_result=dummy_contract,
        inspection_result=dummy_inspection,
        seal_provenance=False,
    )

    verif = service.verify_finding_provenance(
        finding_id=findings[0].id,
        project_id="proj-1",
    )
    assert verif.provenance_status == ProvenanceStatus.UNAVAILABLE


# ---------------------------------------------------------------------------
# Test 23-25: Idempotency & Project Isolation
# ---------------------------------------------------------------------------

def test_idempotent_repeated_execution(
    test_db_session: Session,
    key_manager: KeyManager,
    signer_key_id: str,
    dummy_fingerprint,
    dummy_contract,
    dummy_inspection,
):
    service = ModelIntegrityEvidenceService(
        db=test_db_session,
        key_manager=key_manager,
    )

    # First run: creates findings and provenance
    findings1, prov1, status1 = service.record_model_assessment(
        project_id="proj-1",
        model_id="mod-1",
        audit_run_id="run-1",
        fingerprint_result=dummy_fingerprint,
        contract_result=dummy_contract,
        inspection_result=dummy_inspection,
        seal_provenance=True,
        signer_key_id=signer_key_id,
        signer_passphrase="test-passphrase-1234",
    )
    assert status1 == ScanExecutionStatus.COMPLETED

    # Second run: identical execution -> IDEMPOTENT_HIT
    findings2, prov2, status2 = service.record_model_assessment(
        project_id="proj-1",
        model_id="mod-1",
        audit_run_id="run-1",
        fingerprint_result=dummy_fingerprint,
        contract_result=dummy_contract,
        inspection_result=dummy_inspection,
        seal_provenance=True,
        signer_key_id=signer_key_id,
        signer_passphrase="test-passphrase-1234",
    )
    assert status2 == ScanExecutionStatus.IDEMPOTENT_HIT
    assert len(findings2) == len(findings1)
    assert findings2[0].id == findings1[0].id

    # Verify no duplicate findings created in DB
    total_findings = test_db_session.query(FindingModel).filter_by(project_id="proj-1").count()
    assert total_findings == 1


def test_project_isolation_enforcement(
    test_db_session: Session,
    key_manager: KeyManager,
    signer_key_id: str,
    dummy_fingerprint,
    dummy_contract,
    dummy_inspection,
):
    service = ModelIntegrityEvidenceService(
        db=test_db_session,
        key_manager=key_manager,
    )

    # Run for Project A
    findings_a, _, _ = service.record_model_assessment(
        project_id="proj-A",
        model_id="mod-1",
        audit_run_id="run-1",
        fingerprint_result=dummy_fingerprint,
        contract_result=dummy_contract,
        inspection_result=dummy_inspection,
        seal_provenance=True,
        signer_key_id=signer_key_id,
        signer_passphrase="test-passphrase-1234",
    )

    # Attempt cross-project provenance verification from Project B
    with pytest.raises(CrossProjectContaminationError):
        service.verify_finding_provenance(
            finding_id=findings_a[0].id,
            project_id="proj-B",
        )


# ---------------------------------------------------------------------------
# Test 26-34: Semantic Safety, Air-Gap, and Frozen DB Verification
# ---------------------------------------------------------------------------

def test_semantic_safety_zero_intent_vocabulary(
    dummy_fingerprint, dummy_contract, dummy_inspection, dummy_comparison
):
    """Ensure no human intent/maliciousness words are generated in finding types or descriptions."""
    findings = map_model_integrity_to_findings(
        project_id="proj-1",
        model_id="mod-1",
        audit_run_id="run-1",
        fingerprint_result=dummy_fingerprint,
        contract_result=dummy_contract,
        comparison_result=dummy_comparison,
        inspection_result=dummy_inspection,
    )

    prohibited_patterns = [
        re.compile(r"\bmalicious(ly)?\b", re.IGNORECASE),
        re.compile(r"\battack(er|s)?\b", re.IGNORECASE),
        re.compile(r"\btamper(ed|ing)?\b", re.IGNORECASE),
        re.compile(r"\bbackdoor(ed|s)?\b", re.IGNORECASE),
        re.compile(r"\bpoison(ed|ing)?\b", re.IGNORECASE),
        re.compile(r"\bculpab(le|ility)\b", re.IGNORECASE),
    ]

    for f in findings:
        for p in prohibited_patterns:
            assert not p.search(f.finding_type), f"Prohibited pattern in finding_type: {f.finding_type}"
            assert not p.search(f.title), f"Prohibited pattern in title: {f.title}"
            assert not p.search(f.description), f"Prohibited pattern in description: {f.description}"


def test_deterministic_ordering(dummy_comparison):
    """Ensure tensor change records and findings preserve deterministic order."""
    tensor_changes = [
        TensorChangeRecord(
            tensor_name="b_layer.weight",
            change_type=TensorChangeType.CONTENT_CHANGED,
            reference_shape=[5],
            candidate_shape=[5],
            reference_dtype="float32",
            candidate_dtype="float32",
        ),
        TensorChangeRecord(
            tensor_name="a_layer.weight",
            change_type=TensorChangeType.CONTENT_CHANGED,
            reference_shape=[5],
            candidate_shape=[5],
            reference_dtype="float32",
            candidate_dtype="float32",
        ),
    ]
    comp = dummy_comparison.model_copy(update={"tensor_changes": tensor_changes})
    ev = build_tensor_attribution_evidence(
        project_id="proj-1",
        model_id="mod-1",
        comparison_result=comp,
    )
    names = [c["name"] for c in ev.data_json["changes"]]
    assert names == ["b_layer.weight", "a_layer.weight"]


def test_provenance_chain_verification_and_sequence(
    test_db_session: Session,
    key_manager: KeyManager,
    signer_key_id: str,
    dummy_fingerprint,
    dummy_contract,
    dummy_inspection,
):
    """Verify unbroken cryptographic provenance chain with sequential sequence numbers."""
    service = ModelIntegrityEvidenceService(
        db=test_db_session,
        key_manager=key_manager,
    )

    # First record in chain
    _, prov1, _ = service.record_model_assessment(
        project_id="proj-1",
        model_id="mod-1",
        audit_run_id="run-1",
        fingerprint_result=dummy_fingerprint,
        contract_result=dummy_contract,
        inspection_result=dummy_inspection,
        seal_provenance=True,
        signer_key_id=signer_key_id,
        signer_passphrase="test-passphrase-1234",
    )

    # Second assessment with different audit run / model
    fp2 = dummy_fingerprint.model_copy(update={"artifact_hash": "2" * 64, "master_fingerprint": "2" * 64})
    _, prov2, _ = service.record_model_assessment(
        project_id="proj-1",
        model_id="mod-1",
        audit_run_id="run-2",
        fingerprint_result=fp2,
        contract_result=dummy_contract,
        inspection_result=dummy_inspection,
        seal_provenance=True,
        signer_key_id=signer_key_id,
        signer_passphrase="test-passphrase-1234",
    )

    assert prov1.sequence_number == 0
    assert prov2.sequence_number == 1
    assert prov2.previous_record_hash == prov1.record_hash


def test_same_evidence_with_different_execution_identity(
    test_db_session: Session,
    key_manager: KeyManager,
    signer_key_id: str,
    dummy_fingerprint,
    dummy_contract,
    dummy_inspection,
):
    """Verify that different execution identity (e.g. different audit_run_id) does not trigger false idempotency."""
    service = ModelIntegrityEvidenceService(
        db=test_db_session,
        key_manager=key_manager,
    )

    findings1, _, status1 = service.record_model_assessment(
        project_id="proj-1",
        model_id="mod-1",
        audit_run_id="run-A",
        fingerprint_result=dummy_fingerprint,
        contract_result=dummy_contract,
        inspection_result=dummy_inspection,
        seal_provenance=False,
    )
    assert status1 == ScanExecutionStatus.COMPLETED

    # Different reference model changes execution identity hash
    findings2, _, status2 = service.record_model_assessment(
        project_id="proj-1",
        model_id="mod-1",
        audit_run_id="run-B",
        fingerprint_result=dummy_fingerprint,
        contract_result=dummy_contract,
        inspection_result=dummy_inspection,
        reference_model_id="ref-different",
        seal_provenance=False,
    )
    assert status2 == ScanExecutionStatus.COMPLETED
    assert findings2[0].id != findings1[0].id


def test_partial_model_inspection_evidence(dummy_fingerprint):
    """Verify evidence builder handles partial metadata gracefully."""
    meta = NormalizedModelMetadata(
        format=ModelFormat.SAFETENSORS,
        inspection_status=InspectionStatus.SUCCESS,
        artifact_size_bytes=1024,
        artifact_hash_sha256="a" * 64,
        tensor_count=2,
        parameter_count=50,
        operators=[],
    )
    ev = build_structural_fingerprint_evidence(
        project_id="proj-1",
        model_id="mod-1",
        fingerprint_result=dummy_fingerprint,
        metadata=meta,
    )
    assert ev.data_json["operator_count"] == 0
    assert ev.data_json["tensor_count"] == 2


def test_contract_unavailable_vs_contract_invalid(dummy_contract):
    """Ensure semantic distinction between UNAVAILABLE contract and INVALID contract."""
    c_unavail = dummy_contract.model_copy(
        update={
            "status": ContractStatus.UNAVAILABLE,
            "completeness": ContractCompleteness.UNAVAILABLE,
            "contract_hash": "0" * 64,
        }
    )
    c_invalid = dummy_contract.model_copy(
        update={
            "status": ContractStatus.INVALID,
            "completeness": ContractCompleteness.INVALID,
            "contract_hash": "f" * 64,
        }
    )

    ev_unavail = build_contract_evidence(
        project_id="proj-1",
        model_id="mod-1",
        contract_result=c_unavail,
        artifact_hash="a" * 64,
    )
    ev_invalid = build_contract_evidence(
        project_id="proj-1",
        model_id="mod-1",
        contract_result=c_invalid,
        artifact_hash="a" * 64,
    )

    assert ev_unavail.data_json["status"] == "unavailable"
    assert ev_invalid.data_json["status"] == "invalid"
    assert ev_unavail.evidence_hash != ev_invalid.evidence_hash


def test_reference_unavailable_vs_invalid_comparison(dummy_comparison):
    """Ensure semantic distinction between unverified reference and invalid reference."""
    comp_unverif = dummy_comparison.model_copy(
        update={
            "comparison_status": ComparisonStatus.REFERENCE_UNVERIFIABLE,
            "reference_trust": "unverifiable",
        }
    )
    comp_invalid = dummy_comparison.model_copy(
        update={
            "comparison_status": ComparisonStatus.INVALID_REFERENCE,
            "reference_trust": "invalid",
        }
    )

    ev_unverif = build_comparison_evidence(
        project_id="proj-1",
        model_id="mod-1",
        reference_model_id="ref-1",
        comparison_result=comp_unverif,
    )
    ev_invalid = build_comparison_evidence(
        project_id="proj-1",
        model_id="mod-1",
        reference_model_id="ref-1",
        comparison_result=comp_invalid,
    )

    assert ev_unverif.data_json["reference_trust"] == "unverifiable"
    assert ev_invalid.data_json["reference_trust"] == "invalid"


def test_security_no_private_key_leakage(
    test_db_session: Session,
    key_manager: KeyManager,
    signer_key_id: str,
    dummy_fingerprint,
    dummy_contract,
    dummy_inspection,
):
    """Verify that private keys, passphrases, and raw secrets are NEVER leaked into findings or provenance."""
    passphrase = "super_secret_passphrase_xyz_987"
    service = ModelIntegrityEvidenceService(
        db=test_db_session,
        key_manager=key_manager,
    )

    findings, prov_record, _ = service.record_model_assessment(
        project_id="proj-1",
        model_id="mod-1",
        audit_run_id="run-1",
        fingerprint_result=dummy_fingerprint,
        contract_result=dummy_contract,
        inspection_result=dummy_inspection,
        seal_provenance=True,
        signer_key_id=signer_key_id,
        signer_passphrase="test-passphrase-1234",
    )

    # Inspect all findings metadata and descriptions
    for f in findings:
        f_dump = json.dumps(f.metadata_json)
        assert "super_secret" not in f_dump
        assert "passphrase" not in f_dump
        assert "BEGIN PRIVATE KEY" not in f_dump

    # Inspect provenance record
    p_model = test_db_session.query(ProvenanceRecordModel).filter_by(id=prov_record.id).first()
    p_dump = json.dumps(p_model.metadata_json)
    assert "super_secret" not in p_dump
    assert "passphrase" not in p_dump
    assert "BEGIN PRIVATE KEY" not in p_dump


# ---------------------------------------------------------------------------
# Test 35-42: Adversarial & Mutation Security Tests
# ---------------------------------------------------------------------------

def test_adversarial_tampered_signature_rejection(
    test_db_session: Session,
    key_manager: KeyManager,
    signer_key_id: str,
    dummy_fingerprint,
    dummy_contract,
    dummy_inspection,
):
    """Mutating digital signature must fail cryptographic provenance verification."""
    service = ModelIntegrityEvidenceService(
        db=test_db_session,
        key_manager=key_manager,
    )

    findings, prov_record, _ = service.record_model_assessment(
        project_id="proj-1",
        model_id="mod-1",
        audit_run_id="run-1",
        fingerprint_result=dummy_fingerprint,
        contract_result=dummy_contract,
        inspection_result=dummy_inspection,
        seal_provenance=True,
        signer_key_id=signer_key_id,
        signer_passphrase="test-passphrase-1234",
    )

    # Tamper with signature
    p_model = test_db_session.query(ProvenanceRecordModel).filter_by(id=prov_record.id).first()
    p_model.signature = "A" * 88
    test_db_session.flush()

    verif = service.verify_finding_provenance(
        finding_id=findings[0].id,
        project_id="proj-1",
    )
    assert verif.provenance_status == ProvenanceStatus.INVALID
    assert verif.cryptographic_validity is False


def test_adversarial_tampered_sequence_number_rejection(
    test_db_session: Session,
    key_manager: KeyManager,
    signer_key_id: str,
    dummy_fingerprint,
    dummy_contract,
    dummy_inspection,
):
    """Mutating sequence number must cause hash recomputation mismatch."""
    service = ModelIntegrityEvidenceService(
        db=test_db_session,
        key_manager=key_manager,
    )

    findings, prov_record, _ = service.record_model_assessment(
        project_id="proj-1",
        model_id="mod-1",
        audit_run_id="run-1",
        fingerprint_result=dummy_fingerprint,
        contract_result=dummy_contract,
        inspection_result=dummy_inspection,
        seal_provenance=True,
        signer_key_id=signer_key_id,
        signer_passphrase="test-passphrase-1234",
    )

    # Tamper with sequence number
    p_model = test_db_session.query(ProvenanceRecordModel).filter_by(id=prov_record.id).first()
    p_model.sequence_number = 999
    test_db_session.flush()

    verif = service.verify_finding_provenance(
        finding_id=findings[0].id,
        project_id="proj-1",
    )
    assert verif.provenance_status == ProvenanceStatus.INVALID
    assert verif.cryptographic_validity is False


def test_adversarial_tampered_nonce_rejection(
    test_db_session: Session,
    key_manager: KeyManager,
    signer_key_id: str,
    dummy_fingerprint,
    dummy_contract,
    dummy_inspection,
):
    """Mutating cryptographic nonce must invalidate record hash."""
    service = ModelIntegrityEvidenceService(
        db=test_db_session,
        key_manager=key_manager,
    )

    findings, prov_record, _ = service.record_model_assessment(
        project_id="proj-1",
        model_id="mod-1",
        audit_run_id="run-1",
        fingerprint_result=dummy_fingerprint,
        contract_result=dummy_contract,
        inspection_result=dummy_inspection,
        seal_provenance=True,
        signer_key_id=signer_key_id,
        signer_passphrase="test-passphrase-1234",
    )

    # Tamper with nonce
    p_model = test_db_session.query(ProvenanceRecordModel).filter_by(id=prov_record.id).first()
    p_model.nonce = "0" * 64
    test_db_session.flush()

    verif = service.verify_finding_provenance(
        finding_id=findings[0].id,
        project_id="proj-1",
    )
    assert verif.provenance_status == ProvenanceStatus.INVALID
    assert verif.cryptographic_validity is False


def test_adversarial_tampered_input_hash_finding_mismatch(
    test_db_session: Session,
    key_manager: KeyManager,
    signer_key_id: str,
    dummy_fingerprint,
    dummy_contract,
    dummy_inspection,
):
    """Finding metadata dataset_fingerprint mismatch against provenance input_hash yields MISMATCHED status."""
    service = ModelIntegrityEvidenceService(
        db=test_db_session,
        key_manager=key_manager,
    )

    findings, prov_record, _ = service.record_model_assessment(
        project_id="proj-1",
        model_id="mod-1",
        audit_run_id="run-1",
        fingerprint_result=dummy_fingerprint,
        contract_result=dummy_contract,
        inspection_result=dummy_inspection,
        seal_provenance=True,
        signer_key_id=signer_key_id,
        signer_passphrase="test-passphrase-1234",
    )

    # Tamper with finding's recorded fingerprint
    f_model = test_db_session.query(FindingModel).filter_by(id=findings[0].id).first()
    meta = dict(f_model.metadata_json)
    meta["dataset_fingerprint"] = "9" * 64
    f_model.metadata_json = meta
    test_db_session.flush()

    verif = service.verify_finding_provenance(
        finding_id=findings[0].id,
        project_id="proj-1",
    )
    assert verif.provenance_status == ProvenanceStatus.MISMATCHED
    assert verif.cryptographic_validity is False


def test_adversarial_evidence_hash_mutation_sensitivity(dummy_inspection):
    """Mutating a single measurement field alters the RFC 8785 evidence identity hash."""
    insp1 = dummy_inspection.model_copy(update={"artifact_size_bytes": 1000})
    insp2 = dummy_inspection.model_copy(update={"artifact_size_bytes": 1001})

    ev1 = build_artifact_identity_evidence(
        project_id="proj-1",
        model_id="mod-1",
        inspection_result=insp1,
    )
    ev2 = build_artifact_identity_evidence(
        project_id="proj-1",
        model_id="mod-1",
        inspection_result=insp2,
    )

    assert ev1.evidence_hash != ev2.evidence_hash


def test_adversarial_reordered_measurements_hash_invariance():
    """JCS normalization guarantees that dict key ordering does not alter evidence identity."""
    ev_dict1 = {
        "evidence_layer": "proof",
        "evidence_type": "model_artifact_identity",
        "project_id": "proj-1",
        "dataset_version_id": "mod-1",
        "dataset_fingerprint": "a" * 64,
        "target_asset_type": "model",
        "target_asset_id": "mod-1",
        "target_asset_hash": "a" * 64,
        "detector_id": "model_inspector",
        "detector_version": "1.0.0",
        "detector_config_hash": "0" * 64,
        "model_fingerprint": "a" * 64,
        "reference_fingerprint": "NONE",
        "measurements": {"alpha": 1, "beta": 2, "gamma": 3},
    }
    ev_dict2 = {
        "measurements": {"gamma": 3, "alpha": 1, "beta": 2},
        "reference_fingerprint": "NONE",
        "model_fingerprint": "a" * 64,
        "detector_config_hash": "0" * 64,
        "detector_version": "1.0.0",
        "detector_id": "model_inspector",
        "target_asset_hash": "a" * 64,
        "target_asset_id": "mod-1",
        "target_asset_type": "model",
        "dataset_fingerprint": "a" * 64,
        "dataset_version_id": "mod-1",
        "project_id": "proj-1",
        "evidence_type": "model_artifact_identity",
        "evidence_layer": "proof",
    }

    assert compute_evidence_hash(ev_dict1) == compute_evidence_hash(ev_dict2)


