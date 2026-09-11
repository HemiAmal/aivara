"""Pydantic schemas and enums for Model Input/Output Contract & Preprocessing Verification (Phase 7.4).

Defines deterministic data structures for validated input contracts, output contracts,
preprocessing declarations, contract findings, completeness classifications, and verification outcomes.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from aivara.model_integrity.fingerprinting.schemas import ContractRepresentation


class ContractStatus(str, Enum):
    """Outcome status of model interface and contract verification."""

    VERIFIED = "verified"          # Contract is complete/partial, valid, and consistent
    PARTIAL = "partial"            # Contract is partially specified without contradictions
    MISSING = "missing"            # Contract interface metadata is missing from artifact
    UNAVAILABLE = "unavailable"    # Format does not expose operational interface statically
    MISMATCHED = "mismatched"      # Contract contradicts preprocessing or tensor parameters
    UNVERIFIABLE = "unverifiable"  # Cannot be safely verified statically
    INVALID = "invalid"            # Malformed, contradictory, or impossible contract definitions


class ContractCompleteness(str, Enum):
    """Categorization of contract specification completeness."""

    COMPLETE = "complete"          # Inputs, outputs, shapes, and dtypes fully specified
    PARTIAL = "partial"            # Dynamic dimensions or partially specified attributes
    UNKNOWN = "unknown"            # No contract metadata declared
    UNAVAILABLE = "unavailable"    # Extraction unsupported statically for this container format
    INVALID = "invalid"            # Contradictory or impossible contract specifications


class PreprocessingSource(str, Enum):
    """Origin of preprocessing parameter declarations."""

    EXPLICITLY_DECLARED = "explicitly_declared"              # Supplied via verification config
    INFERRED_FROM_STATIC_STRUCTURE = "inferred_from_static"  # Extracted from artifact metadata properties
    UNKNOWN = "unknown"                                      # No preprocessing information found


class FindingSeverity(str, Enum):
    """Severity classification for contract verification findings."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ContractFindingCode(str, Enum):
    """Deterministic, granular technical finding codes for contract verification."""

    # Missing / Partial
    CONTRACT_METADATA_MISSING = "CONTRACT_METADATA_MISSING"
    CONTRACT_METADATA_PARTIAL = "CONTRACT_METADATA_PARTIAL"
    SHAPE_METADATA_UNAVAILABLE = "SHAPE_METADATA_UNAVAILABLE"

    # Shape & Dimension Issues
    INVALID_DIMENSION = "INVALID_DIMENSION"
    RANK_MISMATCH = "RANK_MISMATCH"
    INPUT_SHAPE_MISMATCH = "INPUT_SHAPE_MISMATCH"
    OUTPUT_SHAPE_MISMATCH = "OUTPUT_SHAPE_MISMATCH"
    SYMBOLIC_DIMENSION_CONFLICT = "SYMBOLIC_DIMENSION_CONFLICT"
    UNSUPPORTED_DYNAMIC_SHAPE = "UNSUPPORTED_DYNAMIC_SHAPE"

    # Data Type Issues
    DTYPE_MISMATCH = "DTYPE_MISMATCH"
    UNSUPPORTED_DTYPE = "UNSUPPORTED_DTYPE"

    # Interface & Graph Structure
    DUPLICATE_INTERFACE_NAME = "DUPLICATE_INTERFACE_NAME"
    INITIALIZER_INTERFACE_COLLISION = "INITIALIZER_INTERFACE_COLLISION"
    INTERFACE_TENSOR_TYPE_CONFLICT = "INTERFACE_TENSOR_TYPE_CONFLICT"
    INVALID_CONTRACT_METADATA = "INVALID_CONTRACT_METADATA"
    UNSUPPORTED_CONTRACT_FEATURE = "UNSUPPORTED_CONTRACT_FEATURE"

    # Preprocessing & Layout
    CHANNEL_COUNT_MISMATCH = "CHANNEL_COUNT_MISMATCH"
    LAYOUT_MISMATCH = "LAYOUT_MISMATCH"
    PREPROCESSING_MISMATCH = "PREPROCESSING_MISMATCH"
    PREPROCESSING_INCONSISTENT_WITH_INPUT = "PREPROCESSING_INCONSISTENT_WITH_INPUT"
    NORMALIZATION_PARAMETER_MISMATCH = "NORMALIZATION_PARAMETER_MISMATCH"
    NORMALIZATION_LENGTH_MISMATCH = "NORMALIZATION_LENGTH_MISMATCH"
    RESIZE_SHAPE_MISMATCH = "RESIZE_SHAPE_MISMATCH"
    VALUE_RANGE_INVALID = "VALUE_RANGE_INVALID"


class ContractFinding(BaseModel):
    """Deterministic technical finding representing a contract discrepancy or property."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: ContractFindingCode = Field(..., description="Standardized finding identifier")
    message: str = Field(..., description="Neutral, objective technical description")
    severity: FindingSeverity = Field(..., description="Severity level")
    target_field: Optional[str] = Field(None, description="Affected field or tensor name")
    details: Dict[str, Any] = Field(default_factory=dict, description="Deterministic diagnostic details")


class ValidatedInputContract(BaseModel):
    """Deterministic, validated representation of a model input contract."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(..., description="Input tensor interface name")
    index: int = Field(..., ge=0, description="Sequential graph input order index")
    dtype: str = Field(..., description="Canonical normalized data type (e.g. F32, I64, U8)")
    rank: int = Field(..., ge=0, description="Number of dimensions (tensor rank)")
    shape: List[Optional[int]] = Field(..., description="Dimension sizes; None represents dynamic dimension")
    symbolic_dimensions: List[Optional[str]] = Field(
        default_factory=list,
        description="Symbolic parameter names for dynamic dimensions",
    )
    dynamic_dimensions: List[int] = Field(
        default_factory=list,
        description="0-based indices of dynamic or variable dimensions",
    )
    dimension_constraints: Dict[str, Any] = Field(
        default_factory=dict,
        description="Explicitly declared constraints (min, max, step)",
    )
    layout: Optional[str] = Field(None, description="Explicitly established layout (e.g. NCHW, NHWC)")
    channel_count: Optional[int] = Field(None, ge=1, description="Explicitly established channel count")
    channel_ordering: Optional[str] = Field(None, description="Channel order (e.g. RGB, BGR) if explicitly declared")
    color_space: Optional[str] = Field(None, description="Color space if explicitly declared")
    value_range: Optional[List[float]] = Field(None, description="Declared input range [min, max]")
    normalization_mean: Optional[List[float]] = Field(None, description="Declared normalization mean vector")
    normalization_std: Optional[List[float]] = Field(None, description="Declared normalization std vector")
    batch_dimension_semantics: Optional[str] = Field(None, description="Explicit batch semantics descriptor")
    sequence_dimension_semantics: Optional[str] = Field(None, description="Explicit sequence semantics descriptor")
    is_dynamic: bool = Field(False, description="True if any dimension is dynamic or symbolic")


class ValidatedOutputContract(BaseModel):
    """Deterministic, validated representation of a model output contract."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(..., description="Output tensor interface name")
    index: int = Field(..., ge=0, description="Sequential graph output order index")
    dtype: str = Field(..., description="Canonical normalized data type (e.g. F32, I64)")
    rank: int = Field(..., ge=0, description="Number of dimensions (tensor rank)")
    shape: List[Optional[int]] = Field(..., description="Dimension sizes; None represents dynamic dimension")
    symbolic_dimensions: List[Optional[str]] = Field(
        default_factory=list,
        description="Symbolic parameter names for dynamic dimensions",
    )
    dynamic_dimensions: List[int] = Field(
        default_factory=list,
        description="0-based indices of dynamic or variable dimensions",
    )
    dimension_constraints: Dict[str, Any] = Field(
        default_factory=dict,
        description="Explicitly declared constraints",
    )
    activation_type: Optional[str] = Field(None, description="Declared activation (e.g. logits, softmax, sigmoid)")
    semantic_descriptors: List[str] = Field(
        default_factory=list,
        description="Declared semantic descriptors (metadata only, not runtime proof)",
    )
    is_dynamic: bool = Field(False, description="True if any dimension is dynamic")


class PreprocessingDeclaration(BaseModel):
    """Deterministic declaration of model preprocessing parameters."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: PreprocessingSource = Field(..., description="Origin of preprocessing declaration")
    resize_shape: Optional[List[int]] = Field(None, description="Spatial target dimensions [H, W] or [C, H, W]")
    crop_size: Optional[List[int]] = Field(None, description="Crop dimensions [H, W]")
    padding: Optional[List[int]] = Field(None, description="Padding sizes [top, bottom, left, right]")
    interpolation: Optional[str] = Field(None, description="Interpolation algorithm (bilinear, bicubic, nearest)")
    color_conversion: Optional[str] = Field(None, description="Color conversion type (e.g. RGB_TO_BGR)")
    channel_order: Optional[str] = Field(None, description="Target channel ordering (e.g. RGB, BGR)")
    channels: Optional[int] = Field(None, ge=1, description="Expected channel count")
    normalization_mean: Optional[List[float]] = Field(None, description="Per-channel normalization mean")
    normalization_std: Optional[List[float]] = Field(None, description="Per-channel normalization standard deviation")
    scaling_factor: Optional[float] = Field(None, description="Multiplicative scaling factor (e.g. 1/255.0)")
    value_range: Optional[List[float]] = Field(None, description="Target numeric value range [min, max]")
    target_dtype: Optional[str] = Field(None, description="Target preprocessed data type")
    target_layout: Optional[str] = Field(None, description="Target spatial layout (e.g. NCHW, NHWC)")
    quantization_params: Dict[str, Any] = Field(default_factory=dict, description="Quantization scale/zero_point")
    image_orientation: Optional[str] = Field(None, description="Orientation / EXIF handling policy")


class ContractVerificationResult(BaseModel):
    """Complete outcome of static model contract and preprocessing verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field("1.0", description="Contract verification schema version")
    status: ContractStatus = Field(..., description="Overall contract verification status")
    completeness: ContractCompleteness = Field(..., description="Contract completeness level")
    inputs: List[ValidatedInputContract] = Field(
        default_factory=list,
        description="Validated input contracts sorted deterministically or by graph order",
    )
    outputs: List[ValidatedOutputContract] = Field(
        default_factory=list,
        description="Validated output contracts",
    )
    preprocessing: Optional[PreprocessingDeclaration] = Field(
        None,
        description="Validated preprocessing declaration if present",
    )
    findings: List[ContractFinding] = Field(
        default_factory=list,
        description="Standardized technical integrity findings",
    )
    contract_representation: ContractRepresentation = Field(
        ...,
        description="Phase 7.3 canonical ContractRepresentation",
    )
    contract_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase SHA-256 contract identity hash",
    )
    warnings: List[str] = Field(
        default_factory=list,
        description="Diagnostic non-fatal warnings",
    )
