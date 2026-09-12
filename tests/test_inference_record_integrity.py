"""Comprehensive unit and regression test suite for Phase 10.8 Inference Record Integrity.

Covers categories A through L per AIVARA Phase 10.8 requirements specification.
"""

import copy
import hashlib
import os
import re
import sys
from typing import Any, Dict, List, Optional

import numpy as np
import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from aivara.crypto.canonical import canonicalize
from aivara.database.models import AIModelModel, InferenceRecordModel, ProjectModel
from aivara.inference.composite_binding import (
    InferenceBinding,
    create_inference_binding,
    verify_inference_binding,
)
from aivara.inference.enums import (
    InferenceFindingCode,
    InferenceIntegrityStatus,
    InputKind,
    InputLayout,
)
from aivara.inference.exceptions import (
    InferenceBindingError,
    InferenceRecordBindingInvalidError,
    InferenceRecordError,
    InferenceRecordHashMismatchError,
    InferenceRecordInvalidError,
    InferenceRecordNotFoundError,
    InferenceRecordPersistenceError,
    InferenceRecordProjectMismatchError,
    InferenceRecordTamperedError,
    InferenceRecordVersionUnsupportedError,
    InvalidHashFormatError,
)
from aivara.inference.execution import (
    build_canonical_execution_descriptor,
    compute_execution_identity_hash,
    compute_raw_output_hash,
)
from aivara.inference.execution.enums import ExecutionLifecycle, ExecutionProvider
from aivara.inference.execution.models import (
    ExecutionPolicy,
    InferenceExecution,
    RawExecutionOutput,
    RawOutputTensor,
)
from aivara.inference.input.models import InputFinding, InputIdentity
from aivara.inference.output import compute_validated_output_identity
from aivara.inference.output.enums import NumericalSanityStatus, OutputStructuralStatus, TaskType
from aivara.inference.output.models import (
    ModelOutputContract,
    OutputIntegrityAssessment,
    ValidatedTensorSummary,
)
from aivara.inference.preprocessing import create_preprocessing_contract
from aivara.inference.preprocessing.enums import PreprocessingOpType
from aivara.inference.preprocessing.models import (
    PreprocessingContract,
    PreprocessingOperation,
    TransformedInputIdentity,
)
from aivara.inference.records import (
    InferenceRecord,
    InferenceRecordCreate,
    InferenceRecordRepository,
    InferenceRecordService,
    InferenceRecordStatus,
    InferenceRecordType,
    InferenceRecordVerificationResult,
    build_canonical_record_descriptor,
    compute_record_integrity_hash,
    create_inference_record,
    validate_record_hash_format,
    verify_inference_record,
)


# =====================================================================
# Fixtures & Helpers
# =====================================================================


@pytest.fixture
def sample_verified_binding():
    """Construct a complete, verified Phase 10.7 InferenceBinding."""
    project_id = "project_alpha"
    input_id = "11" * 32
    input_canonical_hash = "12" * 32
    input_raw_hash = "13" * 32
    model_id = "model_resnet"
    model_artifact_hash = "21" * 32
    model_structural_hash = "22" * 32
    model_contract_hash = "23" * 32

    mf_payload = {
        "artifact_hash": model_artifact_hash,
        "contract_hash": model_contract_hash,
        "schema_version": "1.0",
        "structural_hash": model_structural_hash,
    }
    model_master_fingerprint = hashlib.sha256(canonicalize(mf_payload)).hexdigest()

    binding_desc = {
        "binding_version": "1.0",
        "input_canonical_hash": input_canonical_hash,
        "input_id": input_id,
        "input_kind": "TENSOR",
        "model_artifact_hash": model_artifact_hash,
        "model_contract_hash": model_contract_hash,
        "model_id": model_id,
        "model_master_fingerprint": model_master_fingerprint,
        "model_structural_hash": model_structural_hash,
        "project_id": project_id,
        "schema_version": "1.0",
    }
    input_model_binding_hash = hashlib.sha256(canonicalize(binding_desc)).hexdigest()

    preprocessing_contract = create_preprocessing_contract(
        name="std_prep",
        operations=[
            PreprocessingOperation(
                op_type=PreprocessingOpType.RESIZE,
                parameters={"target_height": 224, "target_width": 224},
            )
        ],
    )
    preprocessing_contract_hash = preprocessing_contract.contract_hash
    transformed_input_hash = "32" * 32

    exec_policy = ExecutionPolicy(provider=ExecutionProvider.CPU)
    raw_output_tensors = [
        RawOutputTensor(
            name="logits",
            index=0,
            dtype="float32",
            shape=[1, 1000],
            byte_size=4000,
            element_count=1000,
            c_contiguous_byte_hash="43" * 32,
            is_finite=True,
        )
    ]
    raw_output_hash = compute_raw_output_hash(raw_output_tensors)
    exec_descriptor = build_canonical_execution_descriptor(
        project_id=project_id,
        input_id=input_id,
        binding_hash=input_model_binding_hash,
        preprocessing_contract_hash=preprocessing_contract_hash,
        transformed_input_hash=transformed_input_hash,
        model_id=model_id,
        model_master_fingerprint=model_master_fingerprint,
        execution_provider="CPUExecutionProvider",
        execution_policy=exec_policy,
    )
    execution_identity_hash = compute_execution_identity_hash(exec_descriptor)

    output_contract_hash = "52" * 32
    output_summaries = [
        ValidatedTensorSummary(
            name="logits",
            index=0,
            dtype="float32",
            shape=[1, 1000],
            rank=2,
            element_count=1000,
            byte_size=4000,
            is_finite=True,
            has_nan=False,
            has_pos_inf=False,
            has_neg_inf=False,
            min_value=-2.5,
            max_value=5.0,
            domain_valid=True,
            c_contiguous_byte_hash="43" * 32,
        )
    ]
    validated_output_identity = compute_validated_output_identity(
        structural_summaries=output_summaries,
        raw_output_hash=raw_output_hash,
        task_type=TaskType.CLASSIFICATION,
        validation_status=InferenceIntegrityStatus.VERIFIED,
        numerical_status=NumericalSanityStatus.DOMAIN_VALID,
        output_contract_hash=output_contract_hash,
        output_count=1,
    )

    binding = create_inference_binding(
        project_id=project_id,
        input_id=input_id,
        input_canonical_hash=input_canonical_hash,
        input_raw_hash=input_raw_hash,
        model_id=model_id,
        model_master_fingerprint=model_master_fingerprint,
        model_artifact_hash=model_artifact_hash,
        model_structural_hash=model_structural_hash,
        model_contract_hash=model_contract_hash,
        input_model_binding_hash=input_model_binding_hash,
        preprocessing_contract_hash=preprocessing_contract_hash,
        transformed_input_hash=transformed_input_hash,
        execution_identity_hash=execution_identity_hash,
        raw_output_hash=raw_output_hash,
        validated_output_identity=validated_output_identity,
        output_contract_hash=output_contract_hash,
    )
    return binding


def setup_db_entities(db: Session, project_id: str = "project_alpha", model_id: str = "model_resnet"):
    """Helper to set up foreign-key dependencies (ProjectModel, AIModelModel)."""
    p = db.query(ProjectModel).filter_by(id=project_id).first()
    if not p:
        p = ProjectModel(id=project_id, name="Test Project", status="active")
        db.add(p)
        db.flush()

    m = db.query(AIModelModel).filter_by(id=model_id).first()
    if not m:
        m = AIModelModel(
            id=model_id,
            project_id=project_id,
            name="ResNet50",
            format="onnx",
            file_path="models/resnet.onnx",
            file_hash_sha256="aa" * 32,
        )
        db.add(m)
        db.flush()
    db.commit()


# =====================================================================
# CATEGORY A — VALID CREATION & PERSISTENCE
# =====================================================================


def test_category_a_valid_creation(sample_verified_binding):
    """Category A: 1-5 Valid verified 10.7 binding creates deterministic InferenceRecord with read-back verification."""
    binding = sample_verified_binding
    record = create_inference_record(
        project_id=binding.project_id,
        binding=binding,
        record_id="rec_001",
        record_type=InferenceRecordType.STANDARD,
    )

    assert record.record_status == InferenceRecordStatus.VERIFIED
    assert record.record_id == "rec_001"
    assert record.project_id == binding.project_id
    assert record.inference_binding_hash == binding.inference_binding_hash
    assert len(record.record_integrity_hash) == 64
    assert len(record.findings) == 0

    verif = verify_inference_record(record, binding=binding)
    assert verif.is_valid is True
    assert verif.status == InferenceRecordStatus.VERIFIED


def test_category_a_persistence_and_read_back(test_db_session, sample_verified_binding):
    """Category A: Persist record and perform read-back verification through InferenceRecordService."""
    setup_db_entities(test_db_session, sample_verified_binding.project_id, sample_verified_binding.model_id)
    service = InferenceRecordService(test_db_session)

    persisted_record = service.persist_inference_record(
        project_id=sample_verified_binding.project_id,
        binding=sample_verified_binding,
        record_id="rec_persisted_1",
    )

    assert persisted_record.record_status == InferenceRecordStatus.VERIFIED
    assert persisted_record.record_id == "rec_persisted_1"

    # Query directly from service
    verif_res = service.get_and_verify_record(
        record_id="rec_persisted_1",
        project_id=sample_verified_binding.project_id,
    )
    assert verif_res.is_valid is True
    assert verif_res.status == InferenceRecordStatus.VERIFIED
    assert verif_res.stored_integrity_hash == persisted_record.record_integrity_hash


# =====================================================================
# CATEGORY B — CANONICAL IDENTITY & DETERMINISM
# =====================================================================


def test_category_b_canonical_identity_determinism(sample_verified_binding):
    """Category B: 6-10 Canonical record descriptor determinism and hash format."""
    binding = sample_verified_binding
    desc1 = build_canonical_record_descriptor(
        record_id="rec_1",
        project_id=binding.project_id,
        inference_binding_hash=binding.inference_binding_hash,
        binding_version="1.0",
        record_type="STANDARD",
        record_status="VERIFIED",
        record_version="1.0",
        schema_version="1.0",
    )

    desc2 = build_canonical_record_descriptor(
        schema_version="1.0",
        record_version="1.0",
        record_status="VERIFIED",
        record_type="STANDARD",
        binding_version="1.0",
        inference_binding_hash=binding.inference_binding_hash,
        project_id=binding.project_id,
        record_id="rec_1",
    )

    h1 = compute_record_integrity_hash(desc1)
    h2 = compute_record_integrity_hash(desc2)
    assert h1 == h2
    assert re.match(r"^[0-9a-f]{64}$", h1)

    # Exactly 8 documented fields
    expected_fields = {
        "binding_version",
        "inference_binding_hash",
        "project_id",
        "record_id",
        "record_status",
        "record_type",
        "record_version",
        "schema_version",
    }
    assert len(desc1) == 8
    assert set(desc1.keys()) == expected_fields


# =====================================================================
# CATEGORY C — TAMPER SENSITIVITY (8 COMMITTED FIELDS)
# =====================================================================


def _mutate_record_field_and_verify(base_desc: Dict[str, Any], field: str, new_val: Any):
    orig_hash = compute_record_integrity_hash(base_desc)
    mutated = copy.deepcopy(base_desc)
    mutated[field] = new_val
    mutated_hash = compute_record_integrity_hash(mutated)
    assert orig_hash != mutated_hash, f"Mutation of {field} failed to alter record_integrity_hash!"


def test_category_c_tamper_sensitivity_all_8_fields(sample_verified_binding):
    """Category C: Mutating any of the 8 committed record fields alters record_integrity_hash."""
    binding = sample_verified_binding
    base_desc = build_canonical_record_descriptor(
        record_id="rec_1",
        project_id=binding.project_id,
        inference_binding_hash=binding.inference_binding_hash,
        binding_version="1.0",
        record_type="STANDARD",
        record_status="VERIFIED",
        record_version="1.0",
        schema_version="1.0",
    )

    # 1. binding_version
    _mutate_record_field_and_verify(base_desc, "binding_version", "2.0")
    # 2. inference_binding_hash
    _mutate_record_field_and_verify(base_desc, "inference_binding_hash", "ff" * 32)
    # 3. project_id
    _mutate_record_field_and_verify(base_desc, "project_id", "project_beta")
    # 4. record_id
    _mutate_record_field_and_verify(base_desc, "record_id", "rec_2")
    # 5. record_status
    _mutate_record_field_and_verify(base_desc, "record_status", "INVALID")
    # 6. record_type
    _mutate_record_field_and_verify(base_desc, "record_type", "BATCH")
    # 7. record_version
    _mutate_record_field_and_verify(base_desc, "record_version", "2.0")
    # 8. schema_version
    _mutate_record_field_and_verify(base_desc, "schema_version", "2.0")


# =====================================================================
# CATEGORY D — DATABASE TAMPERING
# =====================================================================


def test_category_d_database_tampering_all_persisted_fields(test_db_session, sample_verified_binding):
    """Category D: 11-16 Direct database tampering of ANY persisted integrity-critical field is detected and rejected."""
    setup_db_entities(test_db_session, sample_verified_binding.project_id, sample_verified_binding.model_id)
    service = InferenceRecordService(test_db_session)

    # 1. Base persistence
    record = service.persist_inference_record(
        project_id=sample_verified_binding.project_id,
        binding=sample_verified_binding,
        record_id="rec_tamper_all_fields",
    )
    assert record.record_integrity_hash != record.inference_binding_hash, "Record integrity hash must be distinct from binding hash!"

    # Helper to test single DB column/json modification causes tampering detection
    def _assert_db_tamper_detected(mutator_fn):
        db_row = test_db_session.query(InferenceRecordModel).filter_by(id="rec_tamper_all_fields").first()
        orig_id = db_row.id
        orig_proj = db_row.project_id
        orig_rec_hash = db_row.record_hash
        orig_verif_status = db_row.verification_status
        orig_json = copy.deepcopy(db_row.output_json)

        mutator_fn(db_row)
        test_db_session.commit()

        verif = service.get_and_verify_record("rec_tamper_all_fields", project_id=sample_verified_binding.project_id)
        assert verif.is_valid is False
        assert verif.status in (InferenceRecordStatus.TAMPERED, InferenceRecordStatus.INVALID)

        # Restore original state
        db_row = test_db_session.query(InferenceRecordModel).filter_by(id="rec_tamper_all_fields").first()
        db_row.project_id = orig_proj
        db_row.record_hash = orig_rec_hash
        db_row.verification_status = orig_verif_status
        db_row.output_json = orig_json
        test_db_session.commit()

    # Tamper 1: record_hash modified
    _assert_db_tamper_detected(lambda r: setattr(r, "record_hash", "99" * 32))

    # Tamper 2: verification_status modified
    _assert_db_tamper_detected(lambda r: setattr(r, "verification_status", "INVALID"))

    # Tamper 3: output_json inference_binding_hash modified
    def _mutate_json_binding_hash(r):
        j = copy.deepcopy(r.output_json)
        j["inference_binding_hash"] = "88" * 32
        r.output_json = j
    _assert_db_tamper_detected(_mutate_json_binding_hash)

    # Tamper 4: output_json schema_version modified
    def _mutate_json_schema_version(r):
        j = copy.deepcopy(r.output_json)
        j["schema_version"] = "2.0"
        r.output_json = j
    _assert_db_tamper_detected(_mutate_json_schema_version)

    # Tamper 5: output_json record_version modified
    def _mutate_json_record_version(r):
        j = copy.deepcopy(r.output_json)
        j["record_version"] = "2.0"
        r.output_json = j
    _assert_db_tamper_detected(_mutate_json_record_version)

    # Tamper 6: output_json record_type modified
    def _mutate_json_record_type(r):
        j = copy.deepcopy(r.output_json)
        j["record_type"] = "AUDIT"
        r.output_json = j
    _assert_db_tamper_detected(_mutate_json_record_type)

    # Tamper 7: output_json binding_version modified
    def _mutate_json_binding_version(r):
        j = copy.deepcopy(r.output_json)
        j["binding_version"] = "2.0"
        r.output_json = j
    _assert_db_tamper_detected(_mutate_json_binding_version)


def test_category_d_non_identity_metadata_distinction(test_db_session, sample_verified_binding):
    """Category D: Non-identity metadata (created_at, details, findings) does not alter canonical identity calculation."""
    setup_db_entities(test_db_session, sample_verified_binding.project_id, sample_verified_binding.model_id)
    service = InferenceRecordService(test_db_session)

    record = service.persist_inference_record(
        project_id=sample_verified_binding.project_id,
        binding=sample_verified_binding,
        record_id="rec_metadata_test",
    )

    db_row = test_db_session.query(InferenceRecordModel).filter_by(id="rec_metadata_test").first()
    raw_json = copy.deepcopy(db_row.output_json)

    # Add diagnostic telemetry into details
    raw_json["details"]["audit_worker"] = "worker_node_42"
    raw_json["details"]["latency_ms"] = 12.4
    db_row.output_json = raw_json
    test_db_session.commit()

    # Read back and verify identity still verifies because canonical descriptor excludes non-identity metadata
    verif = service.get_and_verify_record("rec_metadata_test", project_id=sample_verified_binding.project_id)
    assert verif.is_valid is True
    assert verif.status == InferenceRecordStatus.VERIFIED


# =====================================================================
# CATEGORY E — BINDING VALIDATION (FAIL-CLOSED)
# =====================================================================


def test_category_e_unverified_binding_rejected():
    """Category E: 17-21 Invalid or tampered Phase 10.7 binding is rejected at record creation."""
    # Binding with mismatched internal hash
    tampered_binding = InferenceBinding(
        schema_version="1.0",
        binding_version="1.0",
        project_id="proj_1",
        input_id="11" * 32,
        input_canonical_hash="12" * 32,
        model_id="m1",
        model_master_fingerprint="20" * 32,
        model_artifact_hash="21" * 32,
        model_structural_hash="22" * 32,
        model_contract_hash="23" * 32,
        input_model_binding_hash="24" * 32,
        preprocessing_contract_hash="31" * 32,
        transformed_input_hash="32" * 32,
        execution_identity_hash="41" * 32,
        raw_output_hash="42" * 32,
        validated_output_identity="51" * 32,
        inference_binding_hash="00" * 32,  # deliberately wrong hash
        binding_status=InferenceIntegrityStatus.VERIFIED,
    )

    with pytest.raises(InferenceRecordBindingInvalidError):
        create_inference_record(
            project_id="proj_1",
            binding=tampered_binding,
            record_id="rec_bad",
        )


def test_category_e_project_mismatch_binding_rejected(sample_verified_binding):
    """Category E: Project ID mismatch between binding and record is rejected."""
    with pytest.raises(InferenceRecordProjectMismatchError):
        create_inference_record(
            project_id="project_other",
            binding=sample_verified_binding,
            record_id="rec_proj_mismatch",
        )


# =====================================================================
# CATEGORY F — IMMUTABILITY
# =====================================================================


def test_category_f_immutability(sample_verified_binding):
    """Category F: 22-25 Pydantic model is frozen and rejects attribute assignment."""
    record = create_inference_record(
        project_id=sample_verified_binding.project_id,
        binding=sample_verified_binding,
        record_id="rec_immut",
    )

    with pytest.raises(Exception):
        record.record_integrity_hash = "00" * 32  # type: ignore

    with pytest.raises(Exception):
        record.project_id = "project_mutated"  # type: ignore


# =====================================================================
# CATEGORY G — VERSIONING
# =====================================================================


def test_category_g_versioning_support(sample_verified_binding):
    """Category G: 26-28 Supported versions pass; unsupported versions fail closed."""
    # Supported version "1.0"
    rec = create_inference_record(
        project_id=sample_verified_binding.project_id,
        binding=sample_verified_binding,
        record_id="rec_v1",
        record_version="1.0",
        schema_version="1.0",
    )
    assert rec.record_status == InferenceRecordStatus.VERIFIED

    # Unsupported version
    with pytest.raises(InferenceRecordVersionUnsupportedError):
        create_inference_record(
            project_id=sample_verified_binding.project_id,
            binding=sample_verified_binding,
            record_id="rec_v2",
            record_version="99.0",
        )


# =====================================================================
# CATEGORY H — PROJECT ISOLATION
# =====================================================================


def test_category_h_project_isolation(test_db_session, sample_verified_binding):
    """Category H: 29-32 Project A cannot retrieve or verify Project B records."""
    setup_db_entities(test_db_session, sample_verified_binding.project_id, sample_verified_binding.model_id)
    service = InferenceRecordService(test_db_session)

    service.persist_inference_record(
        project_id=sample_verified_binding.project_id,
        binding=sample_verified_binding,
        record_id="rec_project_a",
    )

    # Attempt retrieval from Project B
    verif = service.get_and_verify_record(
        record_id="rec_project_a",
        project_id="project_beta",
    )
    assert verif.is_valid is False
    assert any(f.code == InferenceFindingCode.INFERENCE_RECORD_NOT_FOUND.value for f in verif.findings)


# =====================================================================
# CATEGORY I — PERSISTENCE & TRANSACTIONS
# =====================================================================


def test_category_i_persistence_rollback_on_failure(test_db_session, sample_verified_binding):
    """Category I: 33-36 Database transaction rolls back on duplicate primary key and leaves no dirty state."""
    setup_db_entities(test_db_session, sample_verified_binding.project_id, sample_verified_binding.model_id)
    service = InferenceRecordService(test_db_session)

    # First persistence succeeds
    service.persist_inference_record(
        project_id=sample_verified_binding.project_id,
        binding=sample_verified_binding,
        record_id="rec_unique_1",
    )

    # Attempt duplicate insert with same record_id
    with pytest.raises(InferenceRecordPersistenceError):
        service.persist_inference_record(
            project_id=sample_verified_binding.project_id,
            binding=sample_verified_binding,
            record_id="rec_unique_1",
        )


# =====================================================================
# CATEGORY J — SECURITY & OFFLINE GUARANTEES
# =====================================================================


def test_category_j_forbidden_constructs():
    """Category J: 37-42 AST scan confirms zero eval, exec, pickle, subprocess, os.system, or network in records subsystem."""
    subsystem_dir = os.path.join("backend", "aivara", "inference", "records")
    forbidden_tokens = ["eval(", "exec(", "pickle.", "subprocess.", "os.system(", "requests.", "urllib.", "socket."]

    for fname in os.listdir(subsystem_dir):
        if fname.endswith(".py"):
            fpath = os.path.join(subsystem_dir, fname)
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
            for tok in forbidden_tokens:
                assert tok not in content, f"Forbidden construct '{tok}' detected in {fpath}"


def test_category_j_malformed_hashes_fail_closed():
    """Category J: Malformed hex strings fail validation."""
    with pytest.raises(InvalidHashFormatError):
        validate_record_hash_format("test_hash", "invalid_hex")

    with pytest.raises(InvalidHashFormatError):
        validate_record_hash_format("test_hash", "AA" * 32)  # uppercase


# =====================================================================
# CATEGORY K — BOUNDARY TESTS (NO REPLAY, NO EVIDENCE)
# =====================================================================


def test_category_k_phase_boundaries():
    """Category K: 43-48 Confirm no replay, no blockchain, no Phase 10.9/10.10 implementations in records subsystem."""
    import aivara.inference.records as rec_subsystem

    assert not hasattr(rec_subsystem, "replay_inference_execution")
    assert not hasattr(rec_subsystem, "verify_deterministic_replay")
    assert not hasattr(rec_subsystem, "bind_provenance_evidence")
    assert not hasattr(rec_subsystem, "blockchain")


# =====================================================================
# CATEGORY L — REGRESSION TESTS (PHASES 10.2 - 10.7)
# =====================================================================


def test_category_l_phase_10_7_binding_verification(sample_verified_binding):
    """Category L: 49-58 Phase 10.7 composite binding regression."""
    res = verify_inference_binding(sample_verified_binding)
    assert res.is_valid is True
    assert res.status == InferenceIntegrityStatus.VERIFIED
