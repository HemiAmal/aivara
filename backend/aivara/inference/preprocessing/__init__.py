"""Preprocessing & Contract Integrity subsystem for AIVARA Phase 10 Inference Integrity."""

from __future__ import annotations

from aivara.inference.preprocessing.engine import (
    build_canonical_preprocessing_descriptor,
    check_contract_compatibility,
    compute_preprocessing_contract_hash,
    create_preprocessing_contract,
    execute_preprocessing_pipeline,
    validate_operation_parameters,
    verify_preprocessing_contract,
)
from aivara.inference.exceptions import (
    ContractCompatibilityError,
    InvalidPreprocessingContractError,
    PreprocessingError,
    PreprocessingExecutionError,
    PreprocessingResourceLimitError,
    UnsupportedPreprocessingOpError,
)
from aivara.inference.preprocessing.enums import (
    AspectRatioPolicy,
    ClippingPolicy,
    ColorSpace,
    InterpolationMode,
    PaddingMode,
    PreprocessingOpType,
    RoundingPolicy,
)

from aivara.inference.preprocessing.models import (
    ChannelConvertParams,
    CompatibilityAssessment,
    ContractVerificationResult,
    CropParams,
    DtypeConvertParams,
    InputAssumption,
    NormalizeParams,
    OutputGuarantee,
    PadParams,
    PreprocessingContract,
    PreprocessingOperation,
    ResizeParams,
    TransformedInputIdentity,
    ValueRangeScaleParams,
)

__all__ = [
    # Enums
    "PreprocessingOpType",
    "InterpolationMode",
    "PaddingMode",
    "ColorSpace",
    "AspectRatioPolicy",
    "RoundingPolicy",
    "ClippingPolicy",
    # Exceptions
    "PreprocessingError",
    "InvalidPreprocessingContractError",
    "UnsupportedPreprocessingOpError",
    "ContractCompatibilityError",
    "PreprocessingExecutionError",
    "PreprocessingResourceLimitError",

    # Models
    "ResizeParams",
    "CropParams",
    "PadParams",
    "ChannelConvertParams",
    "DtypeConvertParams",
    "NormalizeParams",
    "ValueRangeScaleParams",
    "PreprocessingOperation",
    "InputAssumption",
    "OutputGuarantee",
    "PreprocessingContract",
    "ContractVerificationResult",
    "CompatibilityAssessment",
    "TransformedInputIdentity",
    # Engine functions
    "validate_operation_parameters",
    "build_canonical_preprocessing_descriptor",
    "compute_preprocessing_contract_hash",
    "create_preprocessing_contract",
    "verify_preprocessing_contract",
    "check_contract_compatibility",
    "execute_preprocessing_pipeline",
]
