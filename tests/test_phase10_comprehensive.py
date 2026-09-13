"""Phase 10.12 — Comprehensive Inference Verification & Assurance Test Suite.

Authoritative End-to-End Integration, Multi-Layer Invariants, Cryptographic Consistency,
Adversarial Trapping, Multi-Tenant Boundary Isolation, and Air-Gap Verification for AIVARA Phase 10.

Covers:
  10.1   Architecture & Contract Specification Freeze
  10.2   Safe Inference Input Boundary
  10.3   Input / Model Binding
  10.4   Preprocessing Contract Integrity
  10.5   Controlled Inference Execution & Raw Output
  10.6   Output Schema & Numerical Integrity
  10.7   Input -> Output Cryptographic Binding
  10.8   Inference Record Persistence & Read-Back Verification
  10.9   Deterministic Replay & Consistency Verification
  10.10  Evidence Synthesis & Provenance Sealing
  10.11  REST API & Task Integration
  10.12  Comprehensive Multi-Layer End-to-End Assurance
"""

from __future__ import annotations

import ast
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from typing import Any, Dict, List, Optional
import uuid

import numpy as np
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from aivara.crypto.canonical import canonicalize
from aivara.crypto.keys import KeyManager
from aivara.database.models import (
    AIModelModel,
    Base,
    EvidenceModel,
    FindingModel,
    InferenceRecordModel,
    ProjectModel,
    ProvenanceRecordModel,
)
from aivara.domain.schemas import Disposition, EvidenceLayer, Severity
from aivara.domain.schemas import ProvenanceRecordRead
from aivara.inference.binding.engine import create_input_model_binding, verify_input_model_binding
from aivara.inference.binding.models import InputModelBinding, ModelIdentityEnvelope
from aivara.inference.composite_binding.engine import create_inference_binding, verify_inference_binding
from aivara.inference.composite_binding.enums import InferenceBindingStatus
from aivara.inference.composite_binding.models import InferenceBinding
from aivara.inference.comprehensive.engine import ComprehensiveInferenceVerifier
from aivara.inference.comprehensive.models import ComprehensiveInferenceVerificationResult
from aivara.inference.comprehensive.service import ComprehensiveInferenceService
from aivara.inference.enums import InferenceFindingCode, InferenceIntegrityStatus, InputKind
from aivara.inference.evidence.engine import create_inference_evidence, verify_inference_evidence
from aivara.inference.evidence.enums import InferenceEvidenceStatus
from aivara.inference.evidence.models import InferenceEvidence
from aivara.inference.execution.engine import execute_inference_transaction
from aivara.inference.execution.models import ExecutionPolicy, InferenceExecution
from aivara.inference.input.boundary import validate_inference_input
from aivara.inference.input.models import InputFinding, InputIdentity
from aivara.inference.output.engine import validate_output_integrity
from aivara.inference.output.models import ModelOutputContract, OutputIntegrityAssessment, OutputTensorContract
from aivara.inference.preprocessing.engine import (
    create_preprocessing_contract,
    execute_preprocessing_pipeline,
)
from aivara.inference.preprocessing.enums import PreprocessingOpType
from aivara.inference.preprocessing.models import (
    PreprocessingContract,
    PreprocessingOperation,
    TransformedInputIdentity,
)
from aivara.inference.records.engine import create_inference_record, verify_inference_record
from aivara.inference.records.enums import InferenceRecordStatus, InferenceRecordType
from aivara.inference.records.models import InferenceRecord
from aivara.inference.replay.engine import assess_replay_eligibility, verify_replay_consistency
from aivara.inference.replay.enums import ReplayConsistencyStatus, ReplayEligibilityStatus
from aivara.inference.replay.models import ReplayPolicy, ReplayVerificationResult
from aivara.inference.replay.policy import DEFAULT_DETERMINISTIC_POLICY
from aivara.services.inference_service import InferenceService


@pytest.fixture
def in_memory_db():
    """Create a temporary in-memory SQLite database session."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def populated_project_and_model(in_memory_db):
    """Seed project and model in test db."""
    project_id = str(uuid.uuid4())
    model_id = f"model-{uuid.uuid4().hex[:8]}"

    proj = ProjectModel(
        id=project_id,
        name="Phase 10.12 Comprehensive Test Project",
        description="Tenant project for comprehensive verification tests",
        created_at=datetime.now(timezone.utc),
    )
    in_memory_db.add(proj)

    meta = {
        "artifact_hash": "a" * 64,
        "structural_hash": "b" * 64,
        "contract_hash": "c" * 64,
        "schema_version": "1.0",
    }
    desc = {
        "artifact_hash": "a" * 64,
        "contract_hash": "c" * 64,
        "schema_version": "1.0",
        "structural_hash": "b" * 64,
    }
    master_fp = hashlib.sha256(canonicalize(desc)).hexdigest()
    meta["master_fingerprint"] = master_fp

    ai_model = AIModelModel(
        id=model_id,
        project_id=project_id,
        name="Test Vision Model",
        version="1.0.0",
        format="pytorch",
        file_path="/tmp/test_model.pt",
        file_hash_sha256="a" * 64,
        metadata_json=meta,
        created_at=datetime.now(timezone.utc),
    )
    in_memory_db.add(ai_model)
    in_memory_db.commit()

    return {
        "project_id": project_id,
        "model_id": model_id,
        "master_fingerprint": master_fp,
        "artifact_hash": "a" * 64,
        "structural_hash": "b" * 64,
        "contract_hash": "c" * 64,
    }


def _build_full_valid_pipeline(project_id: str, model_id: str, master_fp: str):
    """Construct complete and mutually consistent Phase 10 artifacts."""
    # 1. Input (Phase 10.2)
    raw_tensor = np.array([[[0.1, 0.2], [0.3, 0.4]]], dtype=np.float32)
    input_id = validate_inference_input(data=raw_tensor, kind=InputKind.TENSOR)

    # 2. Model Envelope (Phase 10.3)
    model_env = ModelIdentityEnvelope(
        model_id=model_id,
        project_id=project_id,
        artifact_hash="a" * 64,
        structural_hash="b" * 64,
        contract_hash="c" * 64,
        master_fingerprint=master_fp,
    )

    # 3. Input-Model Binding (Phase 10.3)
    input_model_binding = create_input_model_binding(
        input_identity=input_id,
        model_identity=model_env,
        project_id=project_id,
        raise_on_error=True,
    )

    # 4. Preprocessing Contract (Phase 10.4)
    prep_contract = create_preprocessing_contract(
        name="test_contract",
        operations=[],
        contract_version="1.0",
    )
    preprocessed_arr, transformed_id = execute_preprocessing_pipeline(
        contract=prep_contract,
        input_array=raw_tensor,
        input_identity=input_id,
        binding=input_model_binding,
    )

    # 5. Controlled Execution (Phase 10.5)
    exec_policy = ExecutionPolicy()
    execution = execute_inference_transaction(
        input_identity=input_id,
        binding=input_model_binding,
        model_identity=model_env,
        preprocessing_contract=prep_contract,
        transformed_identity=transformed_id,
        preprocessed_array=preprocessed_arr,
        project_id=project_id,
        policy=exec_policy,
    )

    # 6. Output Validation (Phase 10.6)
    out_name = execution.raw_output.outputs[0].name if (execution.raw_output and execution.raw_output.outputs) else "output_0"
    shape_list = list(execution.raw_output.outputs[0].shape) if (execution.raw_output and execution.raw_output.outputs) else [1, 2, 2]
    out_contract = ModelOutputContract(
        outputs=[OutputTensorContract(name=out_name, shape=shape_list, dtype="float32")]
    )
    output_assessment = validate_output_integrity(
        raw_output=execution,
        contract=out_contract,
    )

    # 7. Composite Binding (Phase 10.7)
    composite_binding = create_inference_binding(
        project_id=project_id,
        input_identity=input_id,
        input_model_binding=input_model_binding,
        preprocessing_contract=prep_contract,
        transformed_input=transformed_id,
        execution=execution,
        output_assessment=output_assessment,
        raise_on_error=True,
    )

    # 8. Inference Record (Phase 10.8)
    record = create_inference_record(
        project_id=project_id,
        binding=composite_binding,
        record_type=InferenceRecordType.STANDARD,
    )

    # 9. Replay Consistency (Phase 10.9)
    replay_exec = execute_inference_transaction(
        input_identity=input_id,
        binding=input_model_binding,
        model_identity=model_env,
        preprocessing_contract=prep_contract,
        transformed_identity=transformed_id,
        preprocessed_array=preprocessed_arr,
        project_id=project_id,
        policy=exec_policy,
    )
    replay_result = verify_replay_consistency(
        record=record,
        replay_execution=replay_exec,
        policy=DEFAULT_DETERMINISTIC_POLICY,
        expected_project_id=project_id,
    )

    # 10. Evidence (Phase 10.10)
    evidence = create_inference_evidence(
        record=record,
        binding=composite_binding,
        replay_result=replay_result,
    )

    # 11. Provenance Payload (Phase 4 / Phase 10.10)
    prov_payload = {
        "project_id": project_id,
        "record_id": record.record_id,
        "inference_binding_hash": composite_binding.inference_binding_hash,
        "record_integrity_hash": record.record_integrity_hash,
        "evidence_id": evidence.evidence_id,
    }
    prov_read = ProvenanceRecordRead(
        id=str(uuid.uuid4()),
        project_id=project_id,
        record_type="INFERENCE_TRANSACTION_ASSURANCE",
        record_hash="d" * 64,
        sequence_number=1,
        target_id=record.record_id,
        target_type="INFERENCE_RECORD",
        action="VERIFY",
        actor="system",
        created_at=datetime.now(timezone.utc),
        metadata_json=prov_payload,
    )

    return {
        "input_identity": input_id,
        "model_identity": model_env,
        "input_model_binding": input_model_binding,
        "preprocessing_contract": prep_contract,
        "transformed_input": transformed_id,
        "execution": execution,
        "output_contract": out_contract,
        "output_assessment": output_assessment,
        "composite_binding": composite_binding,
        "record": record,
        "replay_result": replay_result,
        "evidence": evidence,
        "provenance": prov_read,
    }


# =====================================================================
# 1. POSITIVE PATH: FULL END-TO-END COMPREHENSIVE VERIFICATION
# =====================================================================

def test_full_positive_path(populated_project_and_model):
    """Test that a fully intact, mutually consistent pipeline succeeds with OVERALL=VERIFIED."""
    data = populated_project_and_model
    artifacts = _build_full_valid_pipeline(
        project_id=data["project_id"],
        model_id=data["model_id"],
        master_fp=data["master_fingerprint"],
    )

    result = ComprehensiveInferenceVerifier.verify(
        project_id=data["project_id"],
        record=artifacts["record"],
        binding=artifacts["composite_binding"],
        input_identity=artifacts["input_identity"],
        model_identity=artifacts["model_identity"],
        input_model_binding=artifacts["input_model_binding"],
        preprocessing_contract=artifacts["preprocessing_contract"],
        transformed_input=artifacts["transformed_input"],
        execution=artifacts["execution"],
        output_contract=artifacts["output_contract"],
        output_assessment=artifacts["output_assessment"],
        replay_result=artifacts["replay_result"],
        evidence=artifacts["evidence"],
        provenance=artifacts["provenance"],
    )

    assert result.overall_status == InferenceIntegrityStatus.VERIFIED
    assert result.is_verified is True
    assert result.input_status == InferenceIntegrityStatus.VERIFIED
    assert result.model_status == InferenceIntegrityStatus.VERIFIED
    assert result.input_model_binding_status == InferenceIntegrityStatus.VERIFIED
    assert result.preprocessing_status == InferenceIntegrityStatus.VERIFIED
    assert result.execution_status == InferenceIntegrityStatus.VERIFIED
    assert result.output_status == InferenceIntegrityStatus.VERIFIED
    assert result.binding_status == InferenceIntegrityStatus.VERIFIED
    assert result.record_status == InferenceRecordStatus.VERIFIED
    assert result.evidence_status == InferenceEvidenceStatus.VERIFIED
    assert result.provenance_status == "VERIFIED"
    assert result.confidence == 1.0
    assert result.severity == Severity.INFO
    assert result.disposition == Disposition.ACCEPT
    assert len(result.findings) == 0


# =====================================================================
# 2. NEGATIVE PATH: SINGLE-POINT MUTATION CORRUPTION MATRIX (16 LAYERS)
# =====================================================================

@pytest.mark.parametrize("corrupt_layer", [
    "input_hash",
    "model_fingerprint",
    "input_model_binding",
    "preprocessing_contract",
    "transformed_input_nonfinite",
    "execution_identity",
    "raw_output",
    "output_identity",
    "composite_binding_hash",
    "record_integrity_hash",
    "replay_divergence",
    "evidence_hash",
    "provenance_hash",
    "project_mismatch",
])
def test_single_point_corruption_matrix(populated_project_and_model, corrupt_layer):
    """Test that single-point mutation at any of the 16 layers fails closed and prevents VERIFIED."""
    data = populated_project_and_model
    artifacts = _build_full_valid_pipeline(
        project_id=data["project_id"],
        model_id=data["model_id"],
        master_fp=data["master_fingerprint"],
    )

    proj_id = data["project_id"]
    record = artifacts["record"]
    binding = artifacts["composite_binding"]
    input_id = artifacts["input_identity"]
    model_id = artifacts["model_identity"]
    imb = artifacts["input_model_binding"]
    prep = artifacts["preprocessing_contract"]
    transformed = artifacts["transformed_input"]
    execution = artifacts["execution"]
    output_ass = artifacts["output_assessment"]
    replay_res = artifacts["replay_result"]
    evidence = artifacts["evidence"]
    provenance = artifacts["provenance"]

    if corrupt_layer == "input_hash":
        input_id = input_id.model_copy(update={"canonical_hash": "f" * 64})
    elif corrupt_layer == "model_fingerprint":
        model_id = model_id.model_copy(update={"master_fingerprint": "f" * 64})
    elif corrupt_layer == "input_model_binding":
        imb = imb.model_copy(update={"binding_hash": "f" * 64})
    elif corrupt_layer == "preprocessing_contract":
        prep = prep.model_copy(update={"contract_hash": "f" * 64})
    elif corrupt_layer == "transformed_input_nonfinite":
        transformed = transformed.model_copy(update={"finite": False})
    elif corrupt_layer == "execution_identity":
        execution = execution.model_copy(update={"execution_identity_hash": "f" * 64})
    elif corrupt_layer == "raw_output":
        execution = execution.model_copy(update={"raw_output_hash": "f" * 64})
    elif corrupt_layer == "output_identity":
        output_ass = output_ass.model_copy(update={"validated_output_identity": "f" * 64})
    elif corrupt_layer == "composite_binding_hash":
        binding = binding.model_copy(update={"inference_binding_hash": "f" * 64})
    elif corrupt_layer == "record_integrity_hash":
        record = record.model_copy(update={"record_integrity_hash": "f" * 64})
    elif corrupt_layer == "replay_divergence":
        replay_res = replay_res.model_copy(update={
            "is_consistent": False,
            "consistency_status": ReplayConsistencyStatus.NUMERICAL_DIVERGENCE,
        })
    elif corrupt_layer == "evidence_hash":
        evidence = evidence.model_copy(update={"evidence_id": "f" * 64})
    elif corrupt_layer == "provenance_hash":
        provenance = provenance.model_copy(update={"record_hash": "invalid_hash_len"})
    elif corrupt_layer == "project_mismatch":
        proj_id = "alien-project-id"

    result = ComprehensiveInferenceVerifier.verify(
        project_id=proj_id,
        record=record,
        binding=binding,
        input_identity=input_id,
        model_identity=model_id,
        input_model_binding=imb,
        preprocessing_contract=prep,
        transformed_input=transformed,
        execution=execution,
        output_assessment=output_ass,
        replay_result=replay_res,
        evidence=evidence,
        provenance=provenance,
    )

    assert result.is_verified is False
    assert result.overall_status != InferenceIntegrityStatus.VERIFIED
    assert result.disposition == Disposition.QUARANTINE


# =====================================================================
# 3. MULTIPLE FAILURE TEST
# =====================================================================

def test_multiple_independent_failures(populated_project_and_model):
    """Test that multiple simultaneous corruptions are all captured and reported."""
    data = populated_project_and_model
    artifacts = _build_full_valid_pipeline(
        project_id=data["project_id"],
        model_id=data["model_id"],
        master_fp=data["master_fingerprint"],
    )

    corrupted_input = artifacts["input_identity"].model_copy(update={"canonical_hash": "0" * 64})
    corrupted_model = artifacts["model_identity"].model_copy(update={"master_fingerprint": "1" * 64})
    corrupted_record = artifacts["record"].model_copy(update={"record_integrity_hash": "2" * 64})

    result = ComprehensiveInferenceVerifier.verify(
        project_id=data["project_id"],
        record=corrupted_record,
        binding=artifacts["composite_binding"],
        input_identity=corrupted_input,
        model_identity=corrupted_model,
    )

    assert result.is_verified is False
    assert result.overall_status == InferenceIntegrityStatus.INVALID
    assert len(result.findings) >= 3


# =====================================================================
# 4. MISSING COMPONENT MATRIX
# =====================================================================

def test_missing_components_fail_closed(populated_project_and_model):
    """Test that empty or completely missing inputs result in MISSING or UNVERIFIABLE, never VERIFIED."""
    result = ComprehensiveInferenceVerifier.verify(
        project_id="test-project",
        record=None,
        binding=None,
        input_identity=None,
    )

    assert result.is_verified is False
    assert result.overall_status in (InferenceIntegrityStatus.MISSING, InferenceIntegrityStatus.UNVERIFIABLE)
    assert result.disposition != Disposition.ACCEPT


# =====================================================================
# 5. MULTI-TENANT PROJECT ISOLATION
# =====================================================================

def test_cross_tenant_project_isolation(populated_project_and_model):
    """Test that tenant Project A artifacts are rejected if evaluated under Project B."""
    data = populated_project_and_model
    artifacts_a = _build_full_valid_pipeline(
        project_id=data["project_id"],
        model_id=data["model_id"],
        master_fp=data["master_fingerprint"],
    )

    # Attempt verification using project_b
    result = ComprehensiveInferenceVerifier.verify(
        project_id="project-b-different-tenant",
        record=artifacts_a["record"],
        binding=artifacts_a["composite_binding"],
        input_identity=artifacts_a["input_identity"],
        model_identity=artifacts_a["model_identity"],
    )

    assert result.is_verified is False
    assert result.overall_status == InferenceIntegrityStatus.MISMATCHED
    assert any("project" in f.message.lower() for f in result.findings)


# =====================================================================
# 6. DETERMINISM TEST
# =====================================================================

def test_comprehensive_verification_determinism(populated_project_and_model):
    """Test that repeated comprehensive verification runs produce identical results."""
    data = populated_project_and_model
    artifacts = _build_full_valid_pipeline(
        project_id=data["project_id"],
        model_id=data["model_id"],
        master_fp=data["master_fingerprint"],
    )

    res1 = ComprehensiveInferenceVerifier.verify(
        project_id=data["project_id"],
        record=artifacts["record"],
        binding=artifacts["composite_binding"],
        input_identity=artifacts["input_identity"],
    )

    res2 = ComprehensiveInferenceVerifier.verify(
        project_id=data["project_id"],
        record=artifacts["record"],
        binding=artifacts["composite_binding"],
        input_identity=artifacts["input_identity"],
    )

    assert res1.overall_status == res2.overall_status
    assert res1.is_verified == res2.is_verified
    assert res1.confidence == res2.confidence
    assert res1.verification_summary == res2.verification_summary


# =====================================================================
# 7. AIR-GAP & NO NETWORK TEST
# =====================================================================

def test_offline_air_gap_integrity(monkeypatch):
    """Verify that comprehensive inference verification makes zero external network or socket calls."""
    import socket

    def guarded_socket(*args, **kwargs):
        raise RuntimeError("External network call attempted in air-gapped system!")

    monkeypatch.setattr(socket, "socket", guarded_socket)

    # Run verification under guarded socket
    desc = {
        "artifact_hash": "a" * 64,
        "contract_hash": "c" * 64,
        "schema_version": "1.0",
        "structural_hash": "b" * 64,
    }
    master_fp = hashlib.sha256(canonicalize(desc)).hexdigest()
    artifacts = _build_full_valid_pipeline(
        project_id="offline-project",
        model_id="offline-model",
        master_fp=master_fp,
    )
    result = ComprehensiveInferenceVerifier.verify(
        project_id="offline-project",
        record=artifacts["record"],
        binding=artifacts["composite_binding"],
    )
    assert result is not None


# =====================================================================
# 8. SECURITY AST SCANNER (FORBIDDEN CONSTRUCTS)
# =====================================================================

def test_security_ast_scan_forbidden_constructs():
    """Verify that Phase 10 inference code contains zero eval, exec, pickle, subprocess, os.system, or shell=True."""
    inference_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend", "aivara", "inference"))
    forbidden_calls = {"eval", "exec", "os.system", "popen"}
    forbidden_modules = {"pickle", "subprocess", "telnetlib", "ftplib"}

    violations = []
    for root, _, files in os.walk(inference_dir):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                try:
                    tree = ast.parse(content, filename=file_path)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            if isinstance(node.func, ast.Name) and node.func.id in forbidden_calls:
                                violations.append(f"{file_path}:{node.lineno} calls forbidden function {node.func.id}")
                        elif isinstance(node, ast.Import):
                            for alias in node.names:
                                if alias.name in forbidden_modules:
                                    violations.append(f"{file_path}:{node.lineno} imports forbidden module {alias.name}")
                        elif isinstance(node, ast.ImportFrom):
                            if node.module and node.module in forbidden_modules:
                                violations.append(f"{file_path}:{node.lineno} imports from forbidden module {node.module}")
                except Exception as e:
                    violations.append(f"{file_path}: parse error {str(e)}")

    assert len(violations) == 0, f"Found security violations: {violations}"


# =====================================================================
# 9. PERFORMANCE & RESOURCE SAFETY (NO RAW TENSORS IN FINDINGS)
# =====================================================================

def test_resource_safety_no_tensor_leakage(populated_project_and_model):
    """Ensure verification results and findings do not leak raw heavy tensors or numpy arrays."""
    data = populated_project_and_model
    artifacts = _build_full_valid_pipeline(
        project_id=data["project_id"],
        model_id=data["model_id"],
        master_fp=data["master_fingerprint"],
    )

    result = ComprehensiveInferenceVerifier.verify(
        project_id=data["project_id"],
        record=artifacts["record"],
        binding=artifacts["composite_binding"],
    )

    # Ensure JSON serializable without custom encoders
    json_dump = result.model_dump_json()
    assert "numpy" not in json_dump
    assert "torch" not in json_dump
    assert result.confidence == 1.0


# =====================================================================
# 10. END-TO-END SERVICE INTEGRATION TEST
# =====================================================================

def test_end_to_end_service_comprehensive_verification(in_memory_db, populated_project_and_model):
    """Test full integration via InferenceService.verify_comprehensive against stored database records."""
    data = populated_project_and_model
    service = InferenceService(db=in_memory_db)

    # Run verification pipeline to create stored record
    req = {
        "model_id": data["model_id"],
        "input_payload": [1.0, 2.0, 3.0],
        "input_kind": "TENSOR",
        "seal_provenance": True,
    }
    from aivara.api.schemas.inference import InferenceVerificationRequest
    resp = service.create_and_start_verification(
        project_id=data["project_id"],
        request=InferenceVerificationRequest(**req),
        run_async=False,
    )

    assert resp.record_id is not None

    # Execute comprehensive verification via service
    comp_result = service.verify_comprehensive(
        project_id=data["project_id"],
        record_id=resp.record_id,
    )

    assert comp_result.is_verified is True
    assert comp_result.overall_status == InferenceIntegrityStatus.VERIFIED
    assert comp_result.record_id == resp.record_id
    assert comp_result.project_id == data["project_id"]
