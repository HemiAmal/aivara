"""Data models for Phase 10.8 Inference Record Integrity subsystem."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from aivara.inference.composite_binding.models import InferenceBinding
from aivara.inference.enums import InferenceIntegrityStatus
from aivara.inference.input.models import InputFinding
from aivara.inference.records.enums import InferenceRecordStatus, InferenceRecordType


class InferenceRecord(BaseModel):
    """Immutable domain model for a cryptographically verified and persistent inference record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field("1.0", max_length=16, description="Schema specification version")
    record_version: str = Field("1.0", max_length=16, description="Record format version")
    record_id: str = Field(..., min_length=1, max_length=64, description="Unique record identifier")
    project_id: str = Field(..., min_length=1, max_length=64, description="Tenant project identifier")
    record_type: InferenceRecordType = Field(
        InferenceRecordType.STANDARD, description="Categorical classification of record"
    )
    binding_version: str = Field("1.0", max_length=16, description="Phase 10.7 binding algorithm version")
    inference_binding_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Authoritative Phase 10.7 canonical inference binding hash",
    )
    record_integrity_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Deterministic SHA-256 digest of canonical RFC 8785 record descriptor",
    )
    record_status: InferenceRecordStatus = Field(
        InferenceRecordStatus.VERIFIED, description="Record integrity and persistence verification status"
    )
    created_at: Optional[str] = Field(
        None,
        description="ISO 8601 UTC creation timestamp (classified as persistence metadata)",
    )
    binding: Optional[InferenceBinding] = Field(
        None,
        description="Embedded Phase 10.7 composite inference binding if available",
    )
    findings: List[InputFinding] = Field(
        default_factory=list,
        description="Observational findings generated during record creation or verification",
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Audit telemetry and storage metadata",
    )


class InferenceRecordVerificationResult(BaseModel):
    """Immutable assessment result of verifying an InferenceRecord's integrity and binding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    is_valid: bool = Field(..., description="Overall verification outcome (True if strictly VERIFIED)")
    status: InferenceRecordStatus = Field(..., description="Integrity assessment status")
    record_id: str = Field(..., description="Record identifier evaluated")
    project_id: str = Field(..., description="Project identifier evaluated")
    stored_integrity_hash: str = Field(..., description="Integrity hash recorded on the record")
    computed_integrity_hash: str = Field(..., description="Integrity hash recomputed over canonical descriptor")
    inference_binding_hash: str = Field(..., description="Phase 10.7 binding hash committed in the record")
    binding_verification_status: InferenceIntegrityStatus = Field(
        InferenceIntegrityStatus.VERIFIED,
        description="Verification status of the underlying Phase 10.7 binding",
    )
    findings: List[InputFinding] = Field(
        default_factory=list,
        description="Observational findings from record or binding verification",
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Diagnostic details and canonical serialization telemetry",
    )


class InferenceRecordCreate(BaseModel):
    """Specification payload for creating an immutable InferenceRecord."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    project_id: str = Field(..., min_length=1, max_length=64, description="Target project identifier")
    binding: InferenceBinding = Field(..., description="Verified Phase 10.7 InferenceBinding")
    record_id: Optional[str] = Field(None, min_length=1, max_length=64, description="Optional custom record ID")
    record_type: InferenceRecordType = Field(
        InferenceRecordType.STANDARD, description="Categorical record type"
    )
    record_version: str = Field("1.0", max_length=16, description="Record format version")
    schema_version: str = Field("1.0", max_length=16, description="Schema version")
