"""Structured domain exceptions for AIVARA Phase 10 Inference Integrity."""

from __future__ import annotations

from typing import Any, Dict, Optional

from aivara.core.exceptions import AivaraException


class InferenceError(AivaraException):
    """Base exception for all inference integrity failures."""

    def __init__(
        self,
        message: str,
        code: str = "INFERENCE_ERROR",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message=message, code=code, details=details or {})


# =====================================================================
# Input Boundary Exceptions (Phase 10.2)
# =====================================================================


class InferenceInputError(InferenceError):
    """Base exception for input boundary validation errors."""

    def __init__(
        self,
        message: str,
        code: str = "INFERENCE_INPUT_ERROR",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message=message, code=code, details=details)


class MalformedInputError(InferenceInputError):
    """Raised when input data structure is malformed or cannot be parsed."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="MALFORMED_INPUT", details=details)


class NonFiniteValueError(InferenceInputError):
    """Raised when tensor or image inputs contain NaN or Infinite values."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="NON_FINITE_VALUE", details=details)


class UnsupportedInputTypeError(InferenceInputError):
    """Raised when input kind or object type is unsupported."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="UNSUPPORTED_INPUT_TYPE", details=details)


class UnsupportedDtypeError(InferenceInputError):
    """Raised when tensor dtype is not in the approved numeric whitelist."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="UNSUPPORTED_DTYPE", details=details)


class ResourceLimitExceededError(InferenceInputError):
    """Raised when input dimensions, element count, or memory bounds are exceeded."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="RESOURCE_LIMIT_EXCEEDED", details=details)


class InferencePathSecurityError(InferenceInputError):
    """Raised on path traversal, UNC paths, or symlink boundary escape attempts."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="PATH_SECURITY_ERROR", details=details)


class InputFileNotFoundError(InferenceInputError):
    """Raised when the specified input file does not exist."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="INPUT_FILE_NOT_FOUND", details=details)


class InputFileUnreadableError(InferenceInputError):
    """Raised when the input file cannot be accessed due to I/O or permissions."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="INPUT_FILE_UNREADABLE", details=details)


class ImageDecodingError(InferenceInputError):
    """Raised when an image file cannot be parsed or decoded safely."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="IMAGE_DECODING_ERROR", details=details)


class UnsupportedImageFormatError(InferenceInputError):
    """Raised when an image file extension or header format is unsupported."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="UNSUPPORTED_IMAGE_FORMAT", details=details)


class ValueRangeMismatchError(InferenceInputError):
    """Raised when input values contradict the declared value range specification."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="VALUE_RANGE_MISMATCH", details=details)


class AmbiguousLayoutError(InferenceInputError):
    """Raised when tensor shape layout cannot be resolved or is ambiguous."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="AMBIGUOUS_LAYOUT", details=details)


class InputContractMismatchError(InferenceInputError):
    """Raised when input fails to conform to declared contract expectations."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="INPUT_CONTRACT_MISMATCH", details=details)


# =====================================================================
# Binding Exceptions (Phase 10.3)
# =====================================================================


class BindingError(InferenceError):
    """Base exception for input-model binding failures."""

    def __init__(
        self,
        message: str,
        code: str = "BINDING_ERROR",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message=message, code=code, details=details)


class ProjectMismatchError(BindingError):
    """Raised when attempting to bind input and model across different project boundaries."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="PROJECT_MISMATCH", details=details)


class ModelIntegrityBindingError(BindingError):
    """Raised when referenced model identity is unverified, missing, or corrupted."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="MODEL_INTEGRITY_BINDING_ERROR", details=details)


class BindingInconsistencyError(BindingError):
    """Raised when binding components fail cryptographic consistency checks."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="BINDING_INCONSISTENCY", details=details)


class InvalidHashFormatError(BindingError):
    """Raised when a cryptographic hash format does not conform to 64-character lowercase hex."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="INVALID_HASH_FORMAT", details=details)


# =====================================================================
# Preprocessing & Contract Exceptions (Phase 10.4)
# =====================================================================


class PreprocessingError(InferenceError):
    """Base exception for preprocessing specification and contract failures."""

    def __init__(
        self,
        message: str,
        code: str = "PREPROCESSING_ERROR",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message=message, code=code, details=details)


class InvalidPreprocessingContractError(PreprocessingError):
    """Raised when a preprocessing contract violates schema, parameters, or limits."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="INVALID_PREPROCESSING_CONTRACT", details=details)


class UnsupportedPreprocessingOpError(PreprocessingError):
    """Raised when an unrecognized or unapproved preprocessing operation is specified."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="UNSUPPORTED_PREPROCESSING_OP", details=details)


class ContractCompatibilityError(PreprocessingError):
    """Raised when input or model contract properties contradict preprocessing requirements."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="CONTRACT_COMPATIBILITY_ERROR", details=details)


class PreprocessingExecutionError(PreprocessingError):
    """Raised when deterministic preprocessing execution fails unexpectedly."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="PREPROCESSING_EXECUTION_ERROR", details=details)


class PreprocessingResourceLimitError(PreprocessingError):
    """Raised when preprocessing pipeline exceeds dimension, operation count, or memory bounds."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="PREPROCESSING_RESOURCE_LIMIT_EXCEEDED", details=details)


# =====================================================================
# Execution Integrity Exceptions (Phase 10.5)
# =====================================================================


class InferenceExecutionError(InferenceError):
    """Base exception for inference execution failures."""

    def __init__(
        self,
        message: str,
        code: str = "INFERENCE_EXECUTION_ERROR",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message=message, code=code, details=details)


class ExecutionPolicyError(InferenceExecutionError):
    """Raised when execution parameters violate safety policy."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="EXECUTION_POLICY_ERROR", details=details)


class ExecutionProviderUnavailableError(InferenceExecutionError):
    """Raised when the requested execution provider is not installed or available."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="EXECUTION_PROVIDER_UNAVAILABLE", details=details)


class ExecutionTimeoutError(InferenceExecutionError):
    """Raised when model execution exceeds the hard timeout ceiling."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="EXECUTION_TIMEOUT", details=details)


class ExecutionCancelledError(InferenceExecutionError):
    """Raised when execution is cancelled via cooperative cancellation handle."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="EXECUTION_CANCELLED", details=details)


class ExecutionResourceLimitError(InferenceExecutionError):
    """Raised when batch size, tensor element count, or output byte size exceeds policy ceiling."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="EXECUTION_RESOURCE_LIMIT_EXCEEDED", details=details)


class ModelExecutionIntegrityError(InferenceExecutionError):
    """Raised when model identity, input binding, or preprocessing integrity cannot be established."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="MODEL_EXECUTION_INTEGRITY_ERROR", details=details)


# =====================================================================
# Output Schema & Numerical Integrity Exceptions (Phase 10.6)
# =====================================================================


class OutputIntegrityError(InferenceError):
    """Base exception for output schema and numerical integrity validation failures."""

    def __init__(
        self,
        message: str,
        code: str = "OUTPUT_INTEGRITY_ERROR",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message=message, code=code, details=details)


class OutputSchemaValidationError(OutputIntegrityError):
    """Raised when output count, names, ordering, dtypes, ranks, or shapes violate contract."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="OUTPUT_SCHEMA_INVALID", details=details)


class OutputNumericalIntegrityError(OutputIntegrityError):
    """Raised when output tensors contain non-finite numbers (NaN, Inf) or violate task domains."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="OUTPUT_NUMERICAL_INVALID", details=details)


class OutputContractMismatchError(OutputIntegrityError):
    """Raised when output fails explicit model-declared contract checks."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="OUTPUT_CONTRACT_MISMATCH", details=details)


class OutputResourceLimitError(OutputIntegrityError):
    """Raised when output elements, tensor count, dimensions, or nesting depth exceed limits."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="OUTPUT_RESOURCE_LIMIT_EXCEEDED", details=details)


class OutputContractUnavailableError(OutputIntegrityError):
    """Raised when authoritative model output contract is missing/unavailable."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="OUTPUT_CONTRACT_UNAVAILABLE", details=details)


class OutputContractUnverifiableError(OutputIntegrityError):
    """Raised when output contract cannot be verified deterministically."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="OUTPUT_CONTRACT_UNVERIFIABLE", details=details)


# =====================================================================
# Input-Output Binding Exceptions (Phase 10.7)
# =====================================================================


class InferenceBindingError(InferenceError):
    """Base exception for composite input-to-output inference binding failures."""

    def __init__(
        self,
        message: str,
        code: str = "INFERENCE_BINDING_ERROR",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message=message, code=code, details=details)


class InferenceBindingProjectMismatchError(InferenceBindingError):
    """Raised when components from different projects are bound together."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="INFERENCE_BINDING_PROJECT_MISMATCH", details=details)


class InferenceBindingComponentMismatchError(InferenceBindingError):
    """Raised when constituent identity envelopes diverge across pipeline stages."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="INFERENCE_BINDING_COMPONENT_MISMATCH", details=details)


class InferenceBindingHashMismatchError(InferenceBindingError):
    """Raised when computed inference binding hash deviates from recorded hash."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="INFERENCE_BINDING_HASH_MISMATCH", details=details)


class InferenceBindingMissingComponentError(InferenceBindingError):
    """Raised when a mandatory transaction identity component is missing."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="INFERENCE_BINDING_MISSING_COMPONENT", details=details)


class InferenceBindingUnavailableError(InferenceBindingError):
    """Raised when binding components are unavailable."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="INFERENCE_BINDING_UNAVAILABLE", details=details)


class InferenceBindingUnverifiableError(InferenceBindingError):
    """Raised when binding cannot be verified deterministically."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, code="INFERENCE_BINDING_UNVERIFIABLE", details=details)


