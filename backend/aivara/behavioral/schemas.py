"""Pydantic schemas and enums for AIVARA Safe Model Execution Boundary (Phase 8.2)."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from aivara.behavioral.limits import DEFAULT_EXECUTION_LIMITS, ExecutionLimits


class ExecutionStatus(str, Enum):
    """Outcome status of model runtime execution."""

    SUCCESS = "SUCCESS"
    EXECUTION_UNAVAILABLE = "EXECUTION_UNAVAILABLE"
    UNSUPPORTED = "UNSUPPORTED"
    TIMEOUT = "TIMEOUT"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    EXECUTION_ERROR = "EXECUTION_ERROR"
    INVALID_INPUT = "INVALID_INPUT"
    INVALID_OUTPUT = "INVALID_OUTPUT"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    MODEL_LOAD_ERROR = "MODEL_LOAD_ERROR"
    CANCELLED = "CANCELLED"


class ExecutionProvider(str, Enum):
    """Supported hardware execution providers for runtime inference."""

    CPU = "CPUExecutionProvider"
    CUDA = "CUDAExecutionProvider"


class DeterminismStatus(str, Enum):
    """Categorization of model execution numerical determinism."""

    DETERMINISTIC = "DETERMINISTIC"
    NUMERICALLY_STABLE = "NUMERICALLY_STABLE"
    NONDETERMINISTIC = "NONDETERMINISTIC"
    UNVERIFIABLE = "UNVERIFIABLE"


class OutputMetadata(BaseModel):
    """Summary characteristics of model execution output tensors."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    output_names: List[str] = Field(..., description="Canonical names of output tensors")
    output_shapes: Dict[str, List[int]] = Field(..., description="Shapes of output tensors")
    output_dtypes: Dict[str, str] = Field(..., description="DTypes of output tensors (e.g., float32)")
    element_counts: Dict[str, int] = Field(..., description="Number of elements per tensor")
    is_finite: bool = Field(True, description="Whether all values in outputs are finite (no NaN/Inf)")
    summary_stats: Dict[str, Dict[str, float]] = Field(
        default_factory=dict,
        description="Basic statistics per output (min, max, mean) where applicable",
    )


class ResourceUsage(BaseModel):
    """Telemetry detailing resource consumption during inference."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    execution_duration_ms: float = Field(..., ge=0.0, description="Total wall-clock duration in milliseconds")
    peak_memory_bytes: Optional[int] = Field(None, ge=0, description="Estimated peak memory in bytes")
    batch_size: int = Field(..., ge=1, description="Number of samples evaluated in batch")
    total_input_elements: int = Field(0, ge=0, description="Total count of input elements processed")
    total_output_elements: int = Field(0, ge=0, description="Total count of output elements produced")


class ExecutionRequest(BaseModel):
    """Strongly-typed request to execute a model under the controlled execution boundary."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    execution_id: str = Field(..., description="Unique UUID for this execution invocation")
    project_id: str = Field(..., description="Associated multi-tenant project identifier")
    model_id: str = Field(..., description="AI model asset identifier")
    model_fingerprint: Optional[str] = Field(None, description="Expected Master Model Fingerprint (H_master)")
    model_path: str = Field(..., description="Sanitized path to executable model artifact")
    inputs: Dict[str, Any] = Field(..., description="Mapping of input tensor name to numpy ndarray or structured tensor")
    task_type: Optional[str] = Field(None, description="Optional task classification (classification, detection, etc.)")
    execution_provider: ExecutionProvider = Field(
        default=ExecutionProvider.CPU,
        description="Target execution provider (Default: CPUExecutionProvider; CUDA requires explicit opt-in)",
    )
    device: str = Field("cpu", description="Execution device identifier (e.g. cpu, cuda:0)")
    precision: str = Field("float32", description="Execution floating-point precision")
    seed: Optional[int] = Field(42, description="Deterministic PRNG seed for execution environment")
    timeout_seconds: float = Field(
        default=10.0,
        ge=0.1,
        le=10.0,
        description="Per-execution timeout (Hard ceiling: 10.0s)",
    )
    max_batch_size: int = Field(
        default=64,
        ge=1,
        le=64,
        description="Maximum batch size (Hard ceiling: 64)",
    )
    resource_policy: Optional[str] = Field("DEFAULT", description="Identifier of applied resource limit policy")
    preprocessing_hash: Optional[str] = Field(None, description="Cryptographic hash of applied preprocessing contract")


class ExecutionResult(BaseModel):
    """Canonical sealed result of a model inference execution."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    execution_id: str = Field(..., description="Execution invocation identifier")
    status: ExecutionStatus = Field(..., description="Outcome status of execution")
    provider: str = Field(..., description="Applied execution provider name")
    device: str = Field(..., description="Device on which inference was run")
    runtime_version: str = Field(..., description="Version of underlying runtime engine")
    precision: str = Field(..., description="Floating-point precision applied")
    duration_ms: float = Field(..., ge=0.0, description="Total execution wall-clock time in milliseconds")
    output_metadata: Optional[OutputMetadata] = Field(None, description="Summary metadata of outputs")
    outputs: Optional[Dict[str, Any]] = Field(None, description="Extracted output tensors if execution succeeded")
    output_hash: Optional[str] = Field(None, description="Deterministic 64-char lowercase SHA-256 digest of outputs")
    determinism_status: DeterminismStatus = Field(
        default=DeterminismStatus.DETERMINISTIC,
        description="Determinism classification of execution",
    )
    error_code: Optional[str] = Field(None, description="Technical error code if status != SUCCESS")
    error_message_safe: Optional[str] = Field(None, description="Sanitized, safe error description without secrets")
    resource_usage: Optional[ResourceUsage] = Field(None, description="Telemetry of resource consumption")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp of execution completion")
