"""Domain models for Phase 10.5 Inference Execution Integrity."""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aivara.inference.enums import InferenceIntegrityStatus
from aivara.inference.execution.enums import (
    ExecutionLifecycle,
    ExecutionProvider,
    NumericalSanityStatus,
)
from aivara.inference.input.models import InputFinding


class ExecutionPolicy(BaseModel):
    """Declarative execution policy defining provider, timeout, and resource bounds."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: ExecutionProvider = Field(
        ExecutionProvider.CPU,
        description="Target execution provider (CPU is safe default; CUDA requires explicit opt-in)",
    )
    timeout_seconds: float = Field(
        10.0,
        gt=0.0,
        le=30.0,
        description="Hard execution timeout ceiling in seconds (max 30.0s)",
    )
    max_batch_size: int = Field(
        32,
        gt=0,
        le=64,
        description="Maximum permissible batch size",
    )
    max_tensor_elements: int = Field(
        50_000_000,
        gt=0,
        description="Maximum permissible input/output tensor element count",
    )
    max_output_bytes: int = Field(
        100_000_000,
        gt=0,
        description="Maximum permissible raw output byte size",
    )
    deterministic: bool = Field(
        True,
        description="Whether deterministic execution flags are requested",
    )
    memory_limit_bytes: int = Field(
        1_000_000_000,
        gt=0,
        description="Maximum allocated memory ceiling in bytes",
    )

    @field_validator("timeout_seconds")
    @classmethod
    def validate_finite_timeout(cls, v: float) -> float:
        if not math.isfinite(v):
            raise ValueError("Timeout must be a finite floating-point number")
        return v


class RawOutputTensor(BaseModel):
    """Metadata and cryptographic byte digest of a single raw output tensor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(..., min_length=1, max_length=128, description="Output tensor interface name")
    index: int = Field(..., ge=0, description="Sequential index in model output signature")
    dtype: str = Field(..., min_length=1, max_length=32, description="Output tensor data type")
    shape: List[int] = Field(..., description="Output tensor dimensions")
    byte_size: int = Field(..., ge=0, description="Contiguous byte size")
    element_count: int = Field(..., ge=0, description="Total element count")
    c_contiguous_byte_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="SHA-256 digest of C-contiguous output tensor bytes",
    )
    is_finite: bool = Field(True, description="Whether output tensor contains only finite numbers (no NaN/Inf)")


class RawExecutionOutput(BaseModel):
    """Container for all raw output tensors preserving model-declared sequence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    outputs: List[RawOutputTensor] = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Ordered list of raw output tensors preserving declared model graph order",
    )
    raw_output_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Deterministic SHA-256 digest over JCS descriptor of raw output tensors",
    )
    numerical_sanity: NumericalSanityStatus = Field(
        NumericalSanityStatus.FINITE,
        description="Execution boundary numerical sanity classification",
    )


class InferenceExecution(BaseModel):
    """Deterministic, immutable record of a controlled inference execution transaction."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field("1.0", max_length=16, description="Schema version")
    execution_version: str = Field("1.0", max_length=16, description="Execution engine version")
    execution_id: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase hex unique execution identifier",
    )
    project_id: str = Field(..., min_length=1, max_length=255, description="Tenant project identifier")
    input_id: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Validated Phase 10.2 input identifier",
    )
    binding_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Verified Phase 10.3 InputModelBinding hash",
    )
    preprocessing_contract_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Verified Phase 10.4 PreprocessingContract hash",
    )
    transformed_input_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Verified Phase 10.4 Transformed input byte hash",
    )
    model_id: str = Field(..., min_length=1, max_length=255, description="Model identifier")
    model_master_fingerprint: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 7 master model fingerprint",
    )
    execution_provider: str = Field(..., max_length=64, description="Execution provider used (e.g. CPUExecutionProvider)")
    execution_policy: ExecutionPolicy = Field(default_factory=ExecutionPolicy, description="Execution safety policy")
    lifecycle: ExecutionLifecycle = Field(
        ExecutionLifecycle.SUCCEEDED,
        description="Execution lifecycle state",
    )
    status: InferenceIntegrityStatus = Field(
        InferenceIntegrityStatus.VERIFIED,
        description="Integrity status of execution",
    )
    execution_identity_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="SHA-256 digest of canonical RFC 8785 execution descriptor",
    )
    raw_output: Optional[RawExecutionOutput] = Field(
        None,
        description="Captured raw execution output envelope if successful",
    )
    raw_output_hash: Optional[str] = Field(
        None,
        pattern=r"^[0-9a-f]{64}$",
        description="Canonical hash of captured raw output tensors",
    )
    findings: List[InputFinding] = Field(default_factory=list, description="Observational findings")
    details: Dict[str, Any] = Field(default_factory=dict, description="Audit telemetry")


class ExecutionVerificationResult(BaseModel):
    """Result of pure cryptographic verification of an InferenceExecution transaction."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    is_valid: bool = Field(..., description="Whether execution identity and raw output hashes match recomputation")
    status: InferenceIntegrityStatus = Field(..., description="Overall verification status")
    computed_execution_hash: str = Field(..., description="Locally recomputed execution identity hash")
    expected_execution_hash: str = Field(..., description="Recorded execution identity hash")
    computed_raw_output_hash: Optional[str] = Field(None, description="Locally recomputed raw output hash if present")
    expected_raw_output_hash: Optional[str] = Field(None, description="Recorded raw output hash if present")
    findings: List[InputFinding] = Field(default_factory=list, description="Observational findings")
    details: Dict[str, Any] = Field(default_factory=dict, description="Verification telemetry")
