"""Test suite for Phase 10.10 Evidence & Provenance Binding subsystem."""

import ast
import hashlib
import json
import os
import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from aivara.crypto.canonical import canonicalize
from aivara.crypto.chain import ChainRecord, generate_nonce
from aivara.crypto.hashing import hash_canonical_data
from aivara.crypto.keys import KeyManager
from aivara.database.models import (
    AIModelModel,
    Base,
    DatasetModel,
    DatasetVersionModel,
    EvidenceModel,
    FindingModel,
    InferenceRecordModel,
    ProjectModel,
    ProvenanceRecordModel,
)
from aivara.domain.schemas import Disposition, EvidenceLayer, Severity
from aivara.evidence.schemas import EvidencePayload, FindingSynthesisPayload
from aivara.inference.composite_binding.engine import create_inference_binding
from aivara.inference.composite_binding.models import InferenceBinding
from aivara.inference.enums import InferenceIntegrityStatus
from aivara.inference.evidence.engine import (
    build_canonical_evidence_descriptor,
    build_inference_provenance_payload,
    compute_evidence_hash,
    compute_provenance_binding_hash,
    create_inference_evidence,
    create_phase5_evidence_and_finding_payloads,
    validate_sha256_hex_format,
    verify_inference_evidence,
)
from aivara.inference.evidence.enums import (
    InferenceEvidenceStatus,
    InferenceEvidenceType,
    InferenceFindingType,
)
from aivara.inference.evidence.models import (
    InferenceEvidence,
    InferenceEvidenceVerificationResult,
    InferenceProvenanceBindingPayload,
)
from aivara.inference.evidence.repository import InferenceEvidenceRepository
from aivara.inference.evidence.service import InferenceEvidenceService
from aivara.inference.exceptions import (
    InferenceEvidenceError,
    InferenceEvidenceHashMismatchError,
    InferenceEvidenceProjectMismatchError,
    InferenceEvidenceTamperedError,
    InferenceEvidenceValidationError,
    InvalidHashFormatError,
)
from aivara.inference.execution.models import InferenceExecution
from aivara.inference.input.models import InputIdentity, InputKind, InputLayout
from aivara.inference.output.models import (
    ModelOutputContract,
    OutputIntegrityAssessment,
    OutputTensorContract,
    ValidatedTensorSummary,
)
from aivara.inference.preprocessing.models import (
    PreprocessingContract,
    TransformedInputIdentity,
)
from aivara.inference.records.engine import create_inference_record
from aivara.inference.records.models import InferenceRecord
from aivara.inference.replay.enums import (
    ComparisonStatus,
    ReplayConsistencyStatus,
    ReplayEligibilityStatus,
    ReplayMode,
)
from aivara.inference.replay.models import (
    ReplayComparisonResult,
    ReplayEnvironment,
    ReplayVerificationResult,
)


@pytest.fixture
def db_session():
    """In-memory SQLite database session fixture."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Seed baseline Project
    project = ProjectModel(
        id="proj-alpha-001",
        name="Project Alpha",
        description="Assurance test project",
    )
    session.add(project)

    # Seed AIModel
    model = AIModelModel(
        id="model-resnet-001",
        project_id="proj-alpha-001",
        name="ResNet-50",
        format="onnx",
        file_path="/models/resnet50.onnx",
        file_hash_sha256="a" * 64,
    )
    session.add(model)
    session.commit()

    yield session
    session.close()


@pytest.fixture
def sample_components():
    """Build a complete set of valid Phase 10 component objects."""
    project_id = "proj-alpha-001"
    model_id = "model-resnet-001"
    input_id = "11" * 32
    input_canon_hash = "12" * 32
    raw_file_hash = "13" * 32

    # Model Hashes
    master_fingerprint = "20" * 32
    artifact_hash = "21" * 32
    structural_hash = "22" * 32
    model_contract_hash = "23" * 32

    input_model_binding_hash = "31" * 32
    prep_contract_hash = "32" * 32
    transformed_input_hash = "33" * 32
    execution_identity_hash = "41" * 32
    raw_output_hash = "42" * 32
    validated_output_id = "51" * 32
    output_contract_hash = "52" * 32

    # Phase 10.7: InferenceBinding
    binding = create_inference_binding(
        project_id=project_id,
        input_id=input_id,
        input_canonical_hash=input_canon_hash,
        input_raw_hash=raw_file_hash,
        model_id=model_id,
        model_master_fingerprint=master_fingerprint,
        model_artifact_hash=artifact_hash,
        model_structural_hash=structural_hash,
        model_contract_hash=model_contract_hash,
        input_model_binding_hash=input_model_binding_hash,
        preprocessing_contract_hash=prep_contract_hash,
        transformed_input_hash=transformed_input_hash,
        execution_identity_hash=execution_identity_hash,
        raw_output_hash=raw_output_hash,
        validated_output_identity=validated_output_id,
        output_contract_hash=output_contract_hash,
    )

    # Phase 10.8: InferenceRecord
    record = create_inference_record(
        record_id="rec-alpha-001",
        project_id=project_id,
        binding=binding,
    )

    return {
        "project_id": project_id,
        "model_id": model_id,
        "binding": binding,
        "record": record,
    }



    # Phase 10.8: InferenceRecord
    record = create_inference_record(
        record_id="rec-alpha-001",
        project_id=project_id,
        binding=binding,
    )

    return {
        "project_id": project_id,
        "model_id": model_id,
        "binding": binding,
        "record": record,
    }


# =====================================================================
# Category A: Evidence Construction & Immutability
# =====================================================================


def test_category_a_evidence_construction_and_immutability(sample_components):
    """Test valid construction and strict immutability of InferenceEvidence."""
    record = sample_components["record"]
    binding = sample_components["binding"]

    evidence = create_inference_evidence(record=record, binding=binding)

    assert evidence.project_id == "proj-alpha-001"
    assert evidence.record_id == "rec-alpha-001"
    assert evidence.evidence_layer == EvidenceLayer.PROOF
    assert evidence.confidence == 1.0
    assert evidence.finding_status == "VERIFIED"
    assert len(evidence.evidence_id) == 64

    # Immutability verification
    with pytest.raises((ValidationError, TypeError)):
        evidence.confidence = 0.5

    with pytest.raises((ValidationError, TypeError)):
        evidence.project_id = "hacked"


# =====================================================================
# Category B: Evidence Canonicalization & Hash Mutation Matrix
# =====================================================================


def test_category_b_canonicalization_and_hash_mutation(sample_components):
    """Prove that mutating ANY identity field in the canonical descriptor alters the evidence_id."""
    record = sample_components["record"]
    binding = sample_components["binding"]

    base_evidence = create_inference_evidence(record=record, binding=binding)
    base_hash = base_evidence.evidence_id

    # Canonical descriptor dict
    descriptor = build_canonical_evidence_descriptor(
        project_id=base_evidence.project_id,
        record_id=base_evidence.record_id,
        record_integrity_hash=base_evidence.record_integrity_hash,
        inference_binding_hash=base_evidence.inference_binding_hash,
        input_id=base_evidence.input_id,
        input_canonical_hash=base_evidence.input_canonical_hash,
        input_raw_hash=base_evidence.input_raw_hash,
        model_id=base_evidence.model_id,
        model_master_fingerprint=base_evidence.model_master_fingerprint,
        model_artifact_hash=base_evidence.model_artifact_hash,
        model_structural_hash=base_evidence.model_structural_hash,
        model_contract_hash=base_evidence.model_contract_hash,
        preprocessing_contract_hash=base_evidence.preprocessing_contract_hash,
        transformed_input_hash=base_evidence.transformed_input_hash,
        execution_identity_hash=base_evidence.execution_identity_hash,
        raw_output_hash=base_evidence.raw_output_hash,
        validated_output_identity=base_evidence.validated_output_identity,
        output_contract_hash=base_evidence.output_contract_hash,
        replay_status=base_evidence.replay_status,
        replay_mode=base_evidence.replay_mode,
        evidence_type=base_evidence.evidence_type.value,
        evidence_layer=base_evidence.evidence_layer.value,
        finding_type=base_evidence.finding_type,
        finding_status=base_evidence.finding_status,
    )

    fields_to_test = [
        ("project_id", "proj-beta-999"),
        ("record_id", "rec-mutated-002"),
        ("record_integrity_hash", "0" * 64),
        ("inference_binding_hash", "1" * 64),
        ("input_id", "2" * 64),
        ("input_canonical_hash", "3" * 64),
        ("input_raw_hash", "4" * 64),
        ("model_id", "model-vgg16-002"),
        ("model_master_fingerprint", "5" * 64),
        ("model_artifact_hash", "6" * 64),
        ("model_structural_hash", "7" * 64),
        ("model_contract_hash", "8" * 64),
        ("preprocessing_contract_hash", "9" * 64),
        ("transformed_input_hash", "a" * 64),
        ("execution_identity_hash", "b" * 64),
        ("raw_output_hash", "c" * 64),
        ("validated_output_identity", "d" * 64),
        ("output_contract_hash", "e" * 64),
        ("replay_status", "CONSISTENT_TOLERANT"),
        ("replay_mode", "NUMERICALLY_TOLERANT"),
        ("evidence_type", "input_integrity"),
        ("evidence_layer", "detection"),
        ("finding_type", "INFERENCE_RECORD_TAMPERED"),
        ("finding_status", "TAMPERED"),
    ]

    for field_name, mutated_val in fields_to_test:
        mutated_desc = dict(descriptor)
        mutated_desc[field_name] = mutated_val
        mutated_hash = hash_canonical_data(mutated_desc)
        assert (
            mutated_hash != base_hash
        ), f"Mutation of field '{field_name}' failed to change canonical evidence hash!"


# =====================================================================
# Category C: Phase 10.7 Binding Integration
# =====================================================================


def test_category_c_binding_integration_and_mismatch(sample_components):
    """Test binding hash verification and fail-closed rejection on mismatch."""
    record = sample_components["record"]
    binding = sample_components["binding"]

    # Valid binding succeeds
    evidence = create_inference_evidence(record=record, binding=binding)
    result = verify_inference_evidence(evidence, record=record, binding=binding)
    assert result.is_valid is True
    assert result.binding_verified is True
    assert result.status == InferenceEvidenceStatus.VERIFIED

    # Binding with tampered model fingerprint
    tampered_binding_dict = binding.model_dump()
    tampered_binding_dict["model_master_fingerprint"] = "f" * 64
    tampered_binding = InferenceBinding(**tampered_binding_dict)

    # Verification detects contradiction / invalid binding
    mismatch_result = verify_inference_evidence(evidence, record=record, binding=tampered_binding)
    assert mismatch_result.is_valid is False
    assert mismatch_result.binding_verified is False


# =====================================================================
# Category D: Phase 10.8 Inference Record Integration
# =====================================================================


def test_category_d_inference_record_tampering(sample_components):
    """Test detection and rejection of tampered inference records."""
    record = sample_components["record"]
    binding = sample_components["binding"]

    evidence = create_inference_evidence(record=record, binding=binding)

    # Tamper record hash
    tampered_record_dict = record.model_dump()
    tampered_record_dict["record_integrity_hash"] = "9" * 64
    tampered_record = InferenceRecord(**tampered_record_dict)

    res = verify_inference_evidence(evidence, record=tampered_record, binding=binding)
    assert res.is_valid is False
    assert res.record_verified is False
    assert res.status == InferenceEvidenceStatus.TAMPERED


# =====================================================================
# Category E: Phase 10.9 Replay Integration
# =====================================================================


def test_category_e_replay_integration(sample_components):
    """Test integration of exact, tolerant, and divergent replay results."""
    record = sample_components["record"]
    binding = sample_components["binding"]

    # 1. Exact consistent replay
    exact_replay = ReplayVerificationResult(
        is_consistent=True,
        consistency_status=ReplayConsistencyStatus.CONSISTENT_EXACT,
        eligibility_status=ReplayEligibilityStatus.ELIGIBLE,
        record_id=record.record_id,
        project_id=record.project_id,
        inference_binding_hash=record.inference_binding_hash,
        recorded_execution_identity="exec-rec-001",
        replay_execution_identity="exec-rep-001",
        environment_match=True,
        comparison=ReplayComparisonResult(
            recorded_raw_output_hash="42" * 32,
            replay_raw_output_hash="42" * 32,
            exact_hash_match=True,
            numerical_match=True,
            structural_match=True,
            comparison_status=ComparisonStatus.EXACT_MATCH,
        ),
        details={"replay_mode": "DETERMINISTIC"},
    )

    evidence_exact = create_inference_evidence(
        record=record,
        binding=binding,
        replay_result=exact_replay,
    )
    assert evidence_exact.replay_status == "CONSISTENT_EXACT"
    ver_exact = verify_inference_evidence(
        evidence_exact,
        record=record,
        binding=binding,
        replay_result=exact_replay,
    )
    assert ver_exact.is_valid is True
    assert ver_exact.replay_verified is True

    # 2. Contradiction between evidence replay status and replay result
    divergent_replay = ReplayVerificationResult(
        is_consistent=False,
        consistency_status=ReplayConsistencyStatus.NUMERICAL_DIVERGENCE,
        eligibility_status=ReplayEligibilityStatus.ELIGIBLE,
        record_id=record.record_id,
        project_id=record.project_id,
        inference_binding_hash=record.inference_binding_hash,
        recorded_execution_identity="exec-rec-001",
        replay_execution_identity="exec-rep-001",
        environment_match=True,
        comparison=ReplayComparisonResult(
            recorded_raw_output_hash="42" * 32,
            replay_raw_output_hash="43" * 32,
            exact_hash_match=False,
            numerical_match=False,
            structural_match=True,
            comparison_status=ComparisonStatus.NUMERICAL_MISMATCH,
        ),
    )


    # Verifying evidence (which says CONSISTENT_EXACT) against divergent_replay fails
    ver_contradict = verify_inference_evidence(
        evidence_exact,
        record=record,
        binding=binding,
        replay_result=divergent_replay,
    )
    assert ver_contradict.is_valid is False
    assert ver_contradict.replay_verified is False


# =====================================================================
# Category F: Phase 4 Provenance Sealing & Service Integration
# =====================================================================


def test_category_f_provenance_sealing_and_verification(db_session, sample_components):
    """Test full Phase 4 provenance sealing, signature, and finding synthesis."""
    record = sample_components["record"]
    binding = sample_components["binding"]

    service = InferenceEvidenceService(db=db_session)

    sealed_ev, prov_rec, finding = service.seal_and_bind_evidence(
        record=record,
        binding=binding,
        expected_project_id="proj-alpha-001",
    )

    assert sealed_ev.provenance_record_id is not None
    assert sealed_ev.provenance_record_hash is not None
    assert prov_rec.project_id == "proj-alpha-001"
    assert prov_rec.record_type == "INFERENCE_TRANSACTION_ASSURANCE"
    assert finding is not None
    assert finding.confidence == 1.0

    # Verify provenance payload
    prov_payload = prov_rec.metadata_json
    assert prov_payload["record_id"] == record.record_id
    assert prov_payload["inference_binding_hash"] == binding.inference_binding_hash

    # Verify through engine
    ver_res = service.verify_evidence(
        sealed_ev,
        record=record,
        binding=binding,
        expected_project_id="proj-alpha-001",
    )
    assert ver_res.is_valid is True
    assert ver_res.status == InferenceEvidenceStatus.VERIFIED


# =====================================================================
# Category G: Multi-Tenant Project Isolation
# =====================================================================


def test_category_g_project_isolation(sample_components):
    """Test that cross-project evidence access fails closed with PROJECT_MISMATCH."""
    record = sample_components["record"]
    binding = sample_components["binding"]

    evidence = create_inference_evidence(record=record, binding=binding)

    # Verification with wrong expected_project_id
    res = verify_inference_evidence(
        evidence,
        record=record,
        binding=binding,
        expected_project_id="proj-victim-999",
    )
    assert res.is_valid is False
    assert res.status == InferenceEvidenceStatus.PROJECT_MISMATCH


# =====================================================================
# Category H: Cross-Component Contradiction Matrix
# =====================================================================


def test_category_h_cross_component_contradictions(sample_components):
    """Test that contradictions between evidence claims and underlying records fail closed."""
    record = sample_components["record"]
    binding = sample_components["binding"]

    evidence = create_inference_evidence(record=record, binding=binding)

    # Contradictory raw output hash in binding
    tampered_binding_dict = binding.model_dump()
    tampered_binding_dict["raw_output_hash"] = "0" * 64
    tampered_binding = InferenceBinding(**tampered_binding_dict)

    res = verify_inference_evidence(evidence, record=record, binding=tampered_binding)
    assert res.is_valid is False
    assert res.status == InferenceEvidenceStatus.INVALID


# =====================================================================
# Category I: End-to-End Verification
# =====================================================================


def test_category_i_end_to_end_verification(sample_components):
    """Test full valid end-to-end chain verification."""
    record = sample_components["record"]
    binding = sample_components["binding"]

    evidence = create_inference_evidence(record=record, binding=binding)
    res = verify_inference_evidence(evidence, record=record, binding=binding)

    assert res.is_valid is True
    assert res.status == InferenceEvidenceStatus.VERIFIED
    assert res.record_verified is True
    assert res.binding_verified is True
    assert res.findings[0]["code"] == "INFERENCE_INTEGRITY_VERIFIED"


# =====================================================================
# Category J: Security & Offline Ast Scan
# =====================================================================


def test_category_j_security_and_offline():
    """Ensure no forbidden constructs (eval, exec, pickle, subprocess, network) exist in Phase 10.10 codebase."""
    evidence_dir = os.path.join(
        os.path.dirname(__file__),
        "..",
        "backend",
        "aivara",
        "inference",
        "evidence",
    )

    forbidden_calls = {"eval", "exec", "pickle", "subprocess", "os.system", "urllib", "requests", "httpx"}

    for root, _, files in os.walk(evidence_dir):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                # Parse AST
                tree = ast.parse(content, filename=file_path)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name) and node.func.id in forbidden_calls:
                            pytest.fail(f"Forbidden call '{node.func.id}' found in {file_path}")
                        elif isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_calls:
                            pytest.fail(f"Forbidden attribute call '{node.func.attr}' found in {file_path}")
                    elif isinstance(node, ast.Import):
                        for alias in node.names:
                            if alias.name in forbidden_calls:
                                pytest.fail(f"Forbidden import '{alias.name}' found in {file_path}")
                    elif isinstance(node, ast.ImportFrom):
                        if node.module and node.module.split(".")[0] in forbidden_calls:
                            pytest.fail(f"Forbidden import from '{node.module}' found in {file_path}")


# =====================================================================
# Category K: Phase 5 Synthesis & ADR-028 Adherence
# =====================================================================


def test_category_k_phase5_payload_synthesis(sample_components):
    """Test conversion of InferenceEvidence into Phase 5.9 EvidencePayload and FindingSynthesisPayload."""
    record = sample_components["record"]
    binding = sample_components["binding"]

    evidence = create_inference_evidence(record=record, binding=binding)
    ev_payload, finding_payload = create_phase5_evidence_and_finding_payloads(
        evidence, audit_run_id="run-001"
    )

    assert isinstance(ev_payload, EvidencePayload)
    assert isinstance(finding_payload, FindingSynthesisPayload)
    assert ev_payload.evidence_layer == EvidenceLayer.PROOF
    assert ev_payload.confidence == 1.0
    assert finding_payload.evidence_layer == EvidenceLayer.PROOF
    assert finding_payload.confidence == 1.0
    assert finding_payload.affected_asset_type == "model"
    assert finding_payload.affected_asset_id == "model-resnet-001"
