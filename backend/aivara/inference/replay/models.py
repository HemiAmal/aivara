"""Data models for Phase 10.9 Replay & Consistency Verification subsystem."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from aivara.inference.input.models import InputFinding
from aivara.inference.replay.enums import (
    ComparisonStatus,
    ReplayConsistencyStatus,
    ReplayEligibilityStatus,
    ReplayMode,
)


class ReplayPolicy(BaseModel):
    """Immutable policy governing replay execution and tolerance comparison semantics."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_version: str = Field("1.0", max_length=16, description="Policy semantic specification version")
    mode: ReplayMode = Field(
        ReplayMode.DETERMINISTIC,
        description="Operational replay mode (DETERMINISTIC, NUMERICALLY_TOLERANT, etc.)",
    )
    atol: float = Field(1e-5, ge=0.0, description="Absolute error tolerance ceiling for numerical comparisons")
    rtol: float = Field(1e-4, ge=0.0, description="Relative error tolerance ceiling for numerical comparisons")
    allow_dtype_variance: bool = Field(
        False, description="Whether to permit equivalent dtype representations (e.g. float32 vs float64)"
    )
    allow_provider_variance: bool = Field(
        False, description="Whether to permit execution on a different backend provider than recorded"
    )
    allow_nonfinite_if_recorded: bool = Field(
        False, description="Whether to permit non-finite (NaN/Inf) values if recorded baseline also had them"
    )
    timeout_seconds: float = Field(30.0, gt=0.0, le=300.0, description="Hard timeout ceiling for replay execution")
    max_batch_size: int = Field(64, gt=0, le=1024, description="Maximum batch size permitted in replay")
    max_tensor_elements: int = Field(10000000, gt=0, description="Maximum total tensor elements allowed")


class ReplayEnvironment(BaseModel):
    """Immutable snapshot of the replay execution environment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: str = Field("CPUExecutionProvider", description="Active execution backend provider name")
    device: str = Field("CPU", description="Target hardware execution device (CPU, CUDA)")
    runtime_version: Optional[str] = Field(None, description="Inference engine or runtime version string")
    deterministic: bool = Field(True, description="Whether deterministic runtime settings are enforced")
    precision: Optional[str] = Field("FP32", description="Operating numerical precision descriptor")


class ReplayComparisonResult(BaseModel):
    """Immutable detailed output of structural and numerical comparison between recorded and replay outputs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    recorded_raw_output_hash: str = Field(..., description="Recorded baseline raw output digest (64-char hex)")
    replay_raw_output_hash: str = Field(..., description="Newly computed replay raw output digest (64-char hex)")
    exact_hash_match: bool = Field(..., description="True if byte-identical raw output hashes match exactly")
    structural_match: bool = Field(..., description="True if output tensor count, shapes, ranks, and types match")
    numerical_match: bool = Field(..., description="True if all tensor elements fall within declared error tolerances")
    max_absolute_error: float = Field(0.0, ge=0.0, description="Maximum absolute pointwise deviation observed")
    max_relative_error: float = Field(0.0, ge=0.0, description="Maximum relative pointwise deviation observed")
    mismatch_count: int = Field(0, ge=0, description="Count of tensor elements exceeding declared tolerances")
    total_elements: int = Field(0, ge=0, description="Total count of scalar tensor elements evaluated")
    comparison_status: ComparisonStatus = Field(..., description="Categorical comparison assessment outcome")
    details: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic comparison telemetry")


class ReplayVerificationResult(BaseModel):
    """Immutable authoritative assessment of an inference replay consistency evaluation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    record_id: str = Field(..., description="Persistent inference record identifier under evaluation")
    project_id: str = Field(..., description="Tenant project identifier boundary")
    inference_binding_hash: str = Field(..., description="Committed Phase 10.7 composite binding digest")
    is_consistent: bool = Field(..., description="Overall boolean verdict: True if CONSISTENT_EXACT or CONSISTENT_TOLERANT")
    consistency_status: ReplayConsistencyStatus = Field(..., description="Authoritative consistency classification")
    eligibility_status: ReplayEligibilityStatus = Field(..., description="Pre-execution record eligibility assessment")
    recorded_execution_identity: str = Field(..., description="Original recorded execution identity hash")
    replay_execution_identity: Optional[str] = Field(
        None, description="Newly generated independent execution identity hash from replay run"
    )
    environment_match: bool = Field(True, description="True if execution environment matched recorded baseline")
    comparison: Optional[ReplayComparisonResult] = Field(None, description="Detailed comparison telemetry if replayed")
    findings: List[InputFinding] = Field(default_factory=list, description="Observational findings generated during replay")
    failure_code: Optional[str] = Field(None, description="Primary failure code if replay was not consistent")
    explanation: str = Field("", description="Human-readable audit explanation of verification verdict")
    details: Dict[str, Any] = Field(default_factory=dict, description="Audit telemetry and metadata")
