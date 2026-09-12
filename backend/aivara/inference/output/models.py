"""Domain models for Phase 10.6 Output Schema & Numerical Integrity."""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aivara.inference.enums import InferenceIntegrityStatus
from aivara.inference.input.models import InputFinding
from aivara.inference.output.enums import (
    NumericalSanityStatus,
    OutputKind,
    OutputStructuralStatus,
    TaskType,
)


class OutputTensorContract(BaseModel):
    """Specification of expected attributes for a single model output tensor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(..., min_length=1, max_length=128, description="Output tensor name")
    shape: List[Optional[int]] = Field(..., description="Expected shape; None or -1 represents dynamic dimension")
    dtype: str = Field(..., min_length=1, max_length=32, description="Expected data type (e.g., float32)")
    output_kind: Optional[OutputKind] = Field(None, description="Categorical kind of output (LOGITS, PROBABILITIES, etc.)")
    activation_type: Optional[str] = Field(None, description="Declared activation (logits, softmax, sigmoid, etc.)")
    min_value: Optional[float] = Field(None, description="Minimum permissible numerical value if bounded")
    max_value: Optional[float] = Field(None, description="Maximum permissible numerical value if bounded")
    unit_norm_required: bool = Field(False, description="Whether embedding output requires unit L2 norm")
    normalized_coordinates: bool = Field(True, description="Whether detection box coordinates are normalized to [0.0, 1.0]")


class ModelOutputContract(BaseModel):
    """Authoritative declaration of expected outputs for a target model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: str = Field("1.0", max_length=16, description="Contract schema version")
    task_type: TaskType = Field(TaskType.GENERIC, description="Target machine learning task category")
    expected_output_count: Optional[int] = Field(None, ge=1, le=64, description="Expected number of output tensors")
    outputs: List[OutputTensorContract] = Field(default_factory=list, description="Sorted list of tensor contracts")
    strict_ordering: bool = Field(True, description="Whether output tensor order must strictly match contract")
    strict_names: bool = Field(True, description="Whether output tensor names must strictly match contract")
    class_count: Optional[int] = Field(None, ge=1, description="Number of target classes when applicable")
    require_finite: bool = Field(True, description="Whether non-finite outputs (NaN/Inf) fail closed")
    require_probability_normalization: bool = Field(False, description="Whether probabilities must sum to 1.0")
    probability_normalization_tolerance: float = Field(
        1e-4,
        gt=0.0,
        le=0.1,
        description="Tolerance for probability sum constraint (|sum - 1.0| <= tol)",
    )


class OutputIntegrityPolicy(BaseModel):
    """Execution bounds and validation tolerances for output evaluation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_outputs: int = Field(64, gt=0, le=256, description="Maximum permissible output tensor count")
    max_tensor_elements: int = Field(50_000_000, gt=0, description="Maximum total output tensor elements")
    max_rank: int = Field(8, gt=0, le=16, description="Maximum permissible tensor rank")
    max_dimension_size: int = Field(65536, gt=0, description="Maximum individual dimension size")
    max_structured_nesting_depth: int = Field(5, gt=0, le=10, description="Maximum nested depth for structured outputs")
    max_string_length: int = Field(1024, gt=0, le=65536, description="Maximum string length in structured outputs")
    max_metadata_bytes: int = Field(1_000_000, gt=0, description="Maximum serialized metadata bytes")
    probability_sum_tolerance: float = Field(1e-4, gt=0.0, le=0.1, description="Probability sum tolerance")
    box_coordinate_tolerance: float = Field(0.01, ge=0.0, le=0.1, description="Normalized coordinate margin tolerance (1%)")


class ValidatedTensorSummary(BaseModel):
    """Extracted structural and numerical telemetry for a validated output tensor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(..., min_length=1, max_length=128, description="Output tensor name")
    index: int = Field(..., ge=0, description="Sequential output index")
    dtype: str = Field(..., min_length=1, max_length=32, description="Output tensor data type")
    shape: List[int] = Field(..., description="Observed tensor dimensions")
    rank: int = Field(..., ge=0, description="Tensor rank (number of dimensions)")
    element_count: int = Field(..., ge=0, description="Total elements in tensor")
    byte_size: int = Field(..., ge=0, description="Total memory byte size")
    is_finite: bool = Field(True, description="Whether all elements are finite (no NaN/Inf)")
    has_nan: bool = Field(False, description="Whether tensor contains NaN values")
    has_pos_inf: bool = Field(False, description="Whether tensor contains +Inf values")
    has_neg_inf: bool = Field(False, description="Whether tensor contains -Inf values")
    min_value: Optional[float] = Field(None, description="Observed minimum finite value")
    max_value: Optional[float] = Field(None, description="Observed maximum finite value")
    domain_valid: bool = Field(True, description="Whether values conform to task/contract domain rules")
    c_contiguous_byte_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="SHA-256 digest of C-contiguous raw tensor bytes",
    )


class OutputIntegrityAssessment(BaseModel):
    """Immutable, comprehensive result of Phase 10.6 output schema and numerical integrity evaluation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field("1.0", max_length=16, description="Assessment schema version")
    task_type: TaskType = Field(TaskType.GENERIC, description="Evaluated task category")
    raw_output_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 10.5 raw output identity hash",
    )
    output_contract_hash: Optional[str] = Field(
        None,
        pattern=r"^[0-9a-f]{64}$",
        description="Deterministic hash of applied output contract if available",
    )
    output_count: int = Field(..., ge=0, description="Observed output tensor count")
    output_metadata: List[ValidatedTensorSummary] = Field(
        default_factory=list,
        description="Extracted tensor telemetry summaries",
    )
    numerical_status: NumericalSanityStatus = Field(
        NumericalSanityStatus.FINITE,
        description="Overall numerical sanity classification",
    )
    structural_status: OutputStructuralStatus = Field(
        OutputStructuralStatus.VALID,
        description="Overall structural contract status",
    )
    integrity_status: InferenceIntegrityStatus = Field(
        InferenceIntegrityStatus.VERIFIED,
        description="Authoritative output verification status",
    )
    validated_output_identity: Optional[str] = Field(
        None,
        pattern=r"^[0-9a-f]{64}$",
        description="Deterministic SHA-256 digest over canonical validated output descriptor",
    )
    findings: List[InputFinding] = Field(default_factory=list, description="Observational validation findings")
    details: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic validation telemetry")
