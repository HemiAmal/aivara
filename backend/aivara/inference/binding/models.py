"""Domain models for Phase 10.3 Input / Model Binding."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from aivara.inference.enums import InferenceIntegrityStatus, InputKind
from aivara.inference.input.models import InputFinding


class ModelIdentityEnvelope(BaseModel):
    """Encapsulates the authoritative Phase 7 model identity and cryptographic fingerprint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    model_id: str = Field(..., min_length=1, max_length=255, description="Unique model identifier")
    project_id: str = Field(..., min_length=1, max_length=255, description="Owning project identifier")
    master_fingerprint: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase hex master model fingerprint (ADR-040)",
    )
    artifact_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase hex SHA-256 of raw model artifact",
    )
    structural_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase hex SHA-256 of canonical structural representation",
    )
    contract_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase hex SHA-256 of canonical contract representation",
    )
    version: Optional[str] = Field(None, max_length=100, description="Model version label")
    format: Optional[str] = Field(None, max_length=50, description="Model container format")
    status: str = Field("verified", description="Phase 7 verification status (verified, partial, unavailable)")
    metadata_json: Dict[str, Any] = Field(default_factory=dict, description="Bounded model metadata properties")


class InputModelBinding(BaseModel):
    """Deterministic, immutable cryptographic binding between a validated input and verified model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field("1.0", description="Schema version of the binding specification")
    binding_version: str = Field("1.0", description="Binding algorithm version")
    project_id: str = Field(..., min_length=1, max_length=255, description="Owning project identifier")
    input_id: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase hex validated input identity (ADR-092)",
    )
    input_kind: InputKind = Field(..., description="Category of input (TENSOR, BATCHED_TENSOR, IMAGE_FILE, STRUCTURED)")
    input_canonical_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase hex canonical input hash",
    )
    input_raw_hash: Optional[str] = Field(
        None,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase hex raw file hash if applicable",
    )
    model_id: str = Field(..., min_length=1, max_length=255, description="Unique model identifier")
    model_master_fingerprint: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase hex master model fingerprint",
    )
    model_artifact_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase hex model artifact SHA-256",
    )
    model_structural_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase hex model structural SHA-256",
    )
    model_contract_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase hex model contract SHA-256",
    )
    binding_status: InferenceIntegrityStatus = Field(
        InferenceIntegrityStatus.VERIFIED,
        description="Binding integrity status",
    )
    binding_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase hex SHA-256 digest of canonical binding descriptor",
    )
    findings: List[InputFinding] = Field(default_factory=list, description="Observational validation findings")
    details: Dict[str, Any] = Field(default_factory=dict, description="Bounded audit and diagnostic details")


class BindingVerificationResult(BaseModel):
    """Result of pure cryptographic verification of an InputModelBinding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    is_valid: bool = Field(..., description="Whether the binding cryptographic hash and integrity checks match")
    status: InferenceIntegrityStatus = Field(..., description="Overall verification status")
    computed_hash: str = Field(..., description="Locally recomputed binding hash")
    expected_hash: str = Field(..., description="Recorded binding hash from the envelope")
    findings: List[InputFinding] = Field(default_factory=list, description="Observational findings")
    details: Dict[str, Any] = Field(default_factory=dict, description="Verification telemetry")
