"""Pydantic schemas and enums for AIVARA Model Integrity Subsystem (Phase 7).

Defines deterministic data structures for format detection, safe inspection,
tensor descriptors, contract descriptors, and normalized model representations.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ModelFormat(str, Enum):
    """Recognized model artifact container and serialization formats."""

    SAFETENSORS = "safetensors"
    ONNX = "onnx"
    PYTORCH_STATE_DICT = "pytorch_state_dict"
    TORCHSCRIPT = "torchscript"
    PICKLE = "pickle"
    UNKNOWN = "unknown"
    CORRUPTED = "corrupted"


class InspectionPolicy(str, Enum):
    """Safety and execution governance policy assigned to a format."""

    SUPPORTED = "supported"        # Full safe static inspection permitted
    RESTRICTED = "restricted"      # Restricted inspect-only / safe loading only
    PROHIBITED = "prohibited"      # Immediate rejection (zero loading permitted)
    UNKNOWN = "unknown"            # Unrecognized format


class InspectionStatus(str, Enum):
    """Outcome status of model artifact inspection."""

    SUCCESS = "success"                        # Valid artifact, complete safe inspection
    INVALID_ARTIFACT = "invalid_artifact"      # Missing, traversal attempt, or unreadable
    UNSUPPORTED_FORMAT = "unsupported_format"  # Format not recognized
    RESTRICTED = "restricted"                  # Inspected under restricted constraints
    PROHIBITED = "prohibited"                  # Prohibited format rejected
    UNAVAILABLE = "unavailable"                # Inspection environment/engine unavailable
    UNVERIFIABLE = "unverifiable"              # Cannot be safely verified without risk


class ReasonCode(str, Enum):
    """Deterministic, granular reason codes for inspection outcomes."""

    # Success / Valid
    SAFE_INSPECTION_PASSED = "SAFE_INSPECTION_PASSED"
    RESTRICTED_INSPECTION_ONLY = "RESTRICTED_INSPECTION_ONLY"

    # Security & Path Violations
    PATH_TRAVERSAL_ATTEMPT = "PATH_TRAVERSAL_ATTEMPT"
    UNRESOLVABLE_SYMLINK = "UNRESOLVABLE_SYMLINK"
    FORBIDDEN_PATH_TYPE = "FORBIDDEN_PATH_TYPE"
    MISSING_ARTIFACT = "MISSING_ARTIFACT"
    NOT_A_REGULAR_FILE = "NOT_A_REGULAR_FILE"

    # Prohibited Formats & Safety Boundaries
    PROHIBITED_FORMAT = "PROHIBITED_FORMAT"
    ARBITRARY_CODE_EXECUTION_RISK = "ARBITRARY_CODE_EXECUTION_RISK"
    UNRESTRICTED_PICKLE_DETECTED = "UNRESTRICTED_PICKLE_DETECTED"
    TORCHSCRIPT_EXECUTION_FORBIDDEN = "TORCHSCRIPT_EXECUTION_FORBIDDEN"

    # Resource Limits
    FILE_SIZE_LIMIT_EXCEEDED = "FILE_SIZE_LIMIT_EXCEEDED"
    HEADER_SIZE_LIMIT_EXCEEDED = "HEADER_SIZE_LIMIT_EXCEEDED"
    TENSOR_COUNT_LIMIT_EXCEEDED = "TENSOR_COUNT_LIMIT_EXCEEDED"
    DIMENSION_LIMIT_EXCEEDED = "DIMENSION_LIMIT_EXCEEDED"
    ARCHIVE_MEMBER_COUNT_EXCEEDED = "ARCHIVE_MEMBER_COUNT_EXCEEDED"
    ARCHIVE_BOMB_DETECTED = "ARCHIVE_BOMB_DETECTED"
    STRING_LENGTH_LIMIT_EXCEEDED = "STRING_LENGTH_LIMIT_EXCEEDED"

    # Structural & Parsing Issues
    CORRUPTED_CONTAINER = "CORRUPTED_CONTAINER"
    MALFORMED_HEADER = "MALFORMED_HEADER"
    MALFORMED_PROTOBUF = "MALFORMED_PROTOBUF"
    MALFORMED_ARCHIVE = "MALFORMED_ARCHIVE"
    INVALID_TENSOR_OFFSET = "INVALID_TENSOR_OFFSET"
    DUPLICATE_TENSOR_NAME = "DUPLICATE_TENSOR_NAME"
    UNSUPPORTED_OPSET_VERSION = "UNSUPPORTED_OPSET_VERSION"

    # Engine Status
    SAFE_PARSER_UNAVAILABLE = "SAFE_PARSER_UNAVAILABLE"
    INCOMPLETE_METADATA = "INCOMPLETE_METADATA"
    UNKNOWN_FORMAT = "UNKNOWN_FORMAT"


class TensorDescriptor(BaseModel):
    """Deterministic description of a single model parameter tensor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(..., description="Unique parameter name / key")
    shape: List[int] = Field(..., description="Tensor dimension sizes")
    dtype: str = Field(..., description="Data type representation (e.g. F32, I64, F16)")
    element_count: int = Field(..., ge=0, description="Total number of elements in tensor")
    byte_size: int = Field(..., ge=0, description="Size of tensor in bytes")
    data_offset_start: Optional[int] = Field(None, ge=0, description="Byte start offset if available")
    data_offset_end: Optional[int] = Field(None, ge=0, description="Byte end offset if available")


class InputContractDescriptor(BaseModel):
    """Deterministic description of a model input tensor contract."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(..., description="Input tensor name")
    shape: List[Optional[int]] = Field(..., description="Expected shape; None represents dynamic dimension")
    dtype: str = Field(..., description="Expected input data type")
    channel_order: Optional[str] = Field(None, description="NCHW, NHWC, or None if non-spatial")
    is_dynamic: bool = Field(False, description="Whether input contains dynamic dimensions")


class OutputContractDescriptor(BaseModel):
    """Deterministic description of a model output tensor contract."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(..., description="Output tensor name")
    shape: List[Optional[int]] = Field(..., description="Output shape; None represents dynamic dimension")
    dtype: str = Field(..., description="Output data type")
    activation_type: Optional[str] = Field(None, description="Observed or declared activation (logits, softmax, etc.)")


class OperatorDescriptor(BaseModel):
    """Summary of an operator type utilized within the model computation graph."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    op_type: str = Field(..., description="Operator type identifier (e.g. Conv, Relu, Gemm)")
    count: int = Field(..., ge=1, description="Number of occurrences in graph")
    domain: str = Field("", description="OpSet domain (e.g. ai.onnx)")


class FormatDetectionResult(BaseModel):
    """Outcome of content-based and header-based model format identification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format: ModelFormat = Field(..., description="Identified format")
    policy: InspectionPolicy = Field(..., description="Governing safety policy")
    detected_by: str = Field(..., description="Method of identification (e.g. magic_bytes, protobuf_schema, zip_index)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence score")
    container_type: str = Field("flat", description="flat, zip, tar, or protobuf")
    details: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic format details")


class NormalizedModelMetadata(BaseModel):
    """Deterministic, format-agnostic normalized model metadata representation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field("1.0", description="Schema version of normalized metadata")
    format: ModelFormat = Field(..., description="Source format")
    inspection_status: InspectionStatus = Field(..., description="Inspection outcome status")
    artifact_size_bytes: int = Field(..., ge=0, description="Total size in bytes")
    artifact_hash_sha256: str = Field(..., description="64-char lowercase SHA-256 of raw file")
    tensor_count: int = Field(0, ge=0, description="Total number of parameter tensors")
    parameter_count: int = Field(0, ge=0, description="Total parameter count (sum of elements)")
    inputs: List[InputContractDescriptor] = Field(default_factory=list, description="Sorted model input contracts")
    outputs: List[OutputContractDescriptor] = Field(default_factory=list, description="Sorted model output contracts")
    operators: List[OperatorDescriptor] = Field(default_factory=list, description="Sorted operator usage summary")
    tensors: List[TensorDescriptor] = Field(default_factory=list, description="Sorted tensor parameter descriptors")
    metadata_props: Dict[str, str] = Field(default_factory=dict, description="Sorted key-value metadata properties")
    warnings: List[str] = Field(default_factory=list, description="Non-fatal diagnostic warnings")
    reason_codes: List[ReasonCode] = Field(default_factory=list, description="Granular reason codes")


class ModelInspectionResult(BaseModel):
    """Complete, sealed result of a model artifact static inspection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: InspectionStatus = Field(..., description="Overall inspection status")
    format: ModelFormat = Field(..., description="Identified format")
    policy: InspectionPolicy = Field(..., description="Applicable policy")
    artifact_path: str = Field(..., description="Validated sanitized artifact path")
    artifact_size_bytes: int = Field(..., ge=0, description="File size in bytes")
    artifact_hash_sha256: Optional[str] = Field(None, description="SHA-256 hash if file was readable")
    normalized_metadata: Optional[NormalizedModelMetadata] = Field(None, description="Normalized metadata if parsed")
    reason_codes: List[ReasonCode] = Field(default_factory=list, description="Diagnostic reason codes")
    warnings: List[str] = Field(default_factory=list, description="Diagnostic warnings")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional inspection telemetry")
