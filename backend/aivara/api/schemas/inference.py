"""Inference Verification and Assurance API Schemas (Phase 10.11).

Defines Pydantic v2 schemas for:
  - Inference verification request and summary response
  - In-memory inference task management and stage transitions
  - Real-time Server-Sent Events (SSE) progress broadcasting
  - Inference record retrieval and read-back verification
  - Controlled inference replay and consistency evaluation
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field

from aivara.inference.enums import InputKind, InputLayout
from aivara.inference.input.models import ImageFileMetadata, StructuredInputMetadata, TensorMetadata
from aivara.inference.records.enums import InferenceRecordStatus, InferenceRecordType
from aivara.inference.replay.enums import ReplayConsistencyStatus, ReplayEligibilityStatus


class InferenceTaskStageEnum(str, Enum):
    """Execution lifecycle stages for an inference verification task."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    INPUT_VALIDATION = "INPUT_VALIDATION"
    INPUT_MODEL_BINDING = "INPUT_MODEL_BINDING"
    PREPROCESSING = "PREPROCESSING"
    EXECUTION = "EXECUTION"
    OUTPUT_VALIDATION = "OUTPUT_VALIDATION"
    INFERENCE_BINDING = "INFERENCE_BINDING"
    RECORD_PERSISTENCE = "RECORD_PERSISTENCE"
    REPLAY_VERIFICATION = "REPLAY_VERIFICATION"
    EVIDENCE_BINDING = "EVIDENCE_BINDING"
    PROVENANCE_SEALING = "PROVENANCE_SEALING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


# =====================================================================
# 1. Verification Request & Response Schemas
# =====================================================================

class InferenceVerificationRequest(BaseModel):
    """Request payload to initiate inference verification and assurance."""

    model_config = ConfigDict(extra="forbid")

    model_id: str = Field(..., description="Unique identifier of the target model artifact")
    input_payload: Optional[Any] = Field(
        None,
        description="Direct input payload (tensor array / list, structured dict, or base64 raw string)",
    )
    input_path: Optional[str] = Field(
        None,
        description="Path to input artifact file (e.g. image or tensor file) on safe storage boundary",
    )
    input_kind: Optional[str] = Field(
        None,
        description="Explicit input modality discriminator (IMAGE_FILE, STRUCTURED, TENSOR, etc.)",
    )
    input_metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional input metadata descriptors",
    )
    preprocessing_contract: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Preprocessing contract specification (operations, assumptions, guarantees)",
    )
    execution_policy: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Controlled execution policy overrides (device, timeout, limits)",
    )
    output_contract: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Output schema and numerical contract specification",
    )
    perform_replay: bool = Field(
        default=False,
        description="Whether to perform immediate replay and consistency check",
    )
    replay_policy: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Replay consistency policy parameters (mode, tolerances)",
    )
    seal_provenance: bool = Field(
        default=True,
        description="Whether to seal evidence into Phase 4 cryptographic provenance ledger",
    )
    signer_key_id: Optional[str] = Field(
        default=None,
        description="Optional cryptographic key identifier for provenance signing",
    )
    signer_passphrase: Optional[str] = Field(
        default=None,
        description="Optional passphrase for unlocking signing key",
    )
    config_overrides: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Optional engine configuration overrides",
    )


class FindingSummaryItem(BaseModel):
    """Structured view of an inference verification finding."""

    model_config = ConfigDict(extra="ignore")

    code: str
    message: str
    severity: str = "INFO"
    location: Optional[str] = None
    context: Optional[Dict[str, Any]] = None


class InferenceVerificationResponse(BaseModel):
    """Authoritative result of an inference integrity and assurance verification."""

    model_config = ConfigDict(extra="ignore")

    task_id: Optional[str] = None
    record_id: Optional[str] = None
    project_id: str
    model_id: str
    verification_status: str
    binding_status: str
    input_canonical_hash: Optional[str] = None
    model_master_fingerprint: Optional[str] = None
    input_model_binding_hash: Optional[str] = None
    preprocessing_contract_hash: Optional[str] = None
    transformed_input_hash: Optional[str] = None
    execution_identity_hash: Optional[str] = None
    raw_output_hash: Optional[str] = None
    output_contract_hash: Optional[str] = None
    validated_output_identity: Optional[str] = None
    inference_binding_hash: Optional[str] = None
    record_integrity_hash: Optional[str] = None
    evidence_hash: Optional[str] = None
    provenance_record_id: Optional[str] = None
    provenance_record_hash: Optional[str] = None
    replay_status: Optional[str] = None
    replay_consistency_status: Optional[str] = None
    findings: List[FindingSummaryItem] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)
    executed_at: Optional[str] = None


# =====================================================================
# 2. Record Read & Verify Schemas
# =====================================================================

class InferenceRecordReadResponse(BaseModel):
    """Structured response for reading a sealed inference record."""

    model_config = ConfigDict(extra="ignore")

    record_id: str
    project_id: str
    model_id: str
    record_type: str
    schema_version: str
    record_version: str
    binding_version: str
    inference_binding_hash: str
    record_integrity_hash: str
    record_status: str
    created_at: str
    input_hash: str
    output_hash: str
    sequence_number: Optional[int] = None
    binding: Optional[Dict[str, Any]] = None
    findings: List[FindingSummaryItem] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


class InferenceRecordVerifyResponse(BaseModel):
    """Result of verifying a stored inference record's cryptographic integrity."""

    model_config = ConfigDict(extra="ignore")

    is_valid: bool
    status: str
    record_id: str
    project_id: str
    stored_integrity_hash: str
    computed_integrity_hash: str
    inference_binding_hash: str
    binding_verification_status: str
    findings: List[FindingSummaryItem] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


# =====================================================================
# 3. Replay Request & Response Schemas
# =====================================================================

class InferenceReplayRequest(BaseModel):
    """Request payload to trigger controlled replay on an existing inference record."""

    model_config = ConfigDict(extra="forbid")

    replay_policy: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Replay consistency policy parameters (mode, tolerances)",
    )
    execution_policy: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Controlled execution policy overrides for the replay",
    )
    input_payload: Optional[Any] = Field(
        default=None,
        description="Optional input payload override if not retrievable from record descriptor",
    )
    input_path: Optional[str] = Field(
        default=None,
        description="Optional input artifact path override",
    )


class InferenceReplayResponse(BaseModel):
    """Authoritative result of an inference replay consistency evaluation."""

    model_config = ConfigDict(extra="ignore")

    record_id: str
    project_id: str
    status: str
    eligibility: str
    is_consistent: bool
    execution_identity_hash: Optional[str] = None
    replay_execution_identity_hash: Optional[str] = None
    original_raw_output_hash: Optional[str] = None
    replay_raw_output_hash: Optional[str] = None
    comparison_status: Optional[str] = None
    max_absolute_error: Optional[float] = None
    max_relative_error: Optional[float] = None
    findings: List[FindingSummaryItem] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


# =====================================================================
# 4. In-Memory Task & Progress Schemas
# =====================================================================

class InferenceProgressEvent(BaseModel):
    """Safe, sanitized real-time progress broadcast event for SSE streaming."""

    model_config = ConfigDict(extra="ignore")

    task_id: str
    stage: InferenceTaskStageEnum
    progress_percent: float
    message: str
    timestamp: str
    payload: Optional[Dict[str, Any]] = None


class InferenceTaskReadResponse(BaseModel):
    """Structured view of an active, completed, or failed inference verification task."""

    model_config = ConfigDict(extra="ignore")

    task_id: str
    project_id: str
    model_id: Optional[str] = None
    status: InferenceTaskStageEnum
    progress_percent: float
    current_stage: str
    record_id: Optional[str] = None
    result: Optional[InferenceVerificationResponse] = None
    error_message: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
