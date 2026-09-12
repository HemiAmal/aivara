"""Inference Execution Integrity subsystem for AIVARA Phase 10 (Phase 10.5)."""

from __future__ import annotations

from aivara.inference.exceptions import (
    ExecutionCancelledError,
    ExecutionPolicyError,
    ExecutionProviderUnavailableError,
    ExecutionResourceLimitError,
    ExecutionTimeoutError,
    InferenceExecutionError,
    ModelExecutionIntegrityError,
)
from aivara.inference.execution.engine import (
    build_canonical_execution_descriptor,
    build_canonical_raw_output_descriptor,
    compute_execution_identity_hash,
    compute_raw_output_hash,
    execute_inference_transaction,
    get_available_execution_providers,
    is_cuda_available,
    verify_execution_identity,
)
from aivara.inference.execution.enums import (
    ExecutionDevice,
    ExecutionLifecycle,
    ExecutionProvider,
    NumericalSanityStatus,
)
from aivara.inference.execution.models import (
    ExecutionPolicy,
    ExecutionVerificationResult,
    InferenceExecution,
    RawExecutionOutput,
    RawOutputTensor,
)

__all__ = [
    # Enums
    "ExecutionLifecycle",
    "ExecutionProvider",
    "ExecutionDevice",
    "NumericalSanityStatus",
    # Exceptions
    "InferenceExecutionError",
    "ExecutionPolicyError",
    "ExecutionProviderUnavailableError",
    "ExecutionTimeoutError",
    "ExecutionCancelledError",
    "ExecutionResourceLimitError",
    "ModelExecutionIntegrityError",
    # Models
    "ExecutionPolicy",
    "RawOutputTensor",
    "RawExecutionOutput",
    "InferenceExecution",
    "ExecutionVerificationResult",
    # Engine functions
    "build_canonical_execution_descriptor",
    "compute_execution_identity_hash",
    "build_canonical_raw_output_descriptor",
    "compute_raw_output_hash",
    "verify_execution_identity",
    "execute_inference_transaction",
    "get_available_execution_providers",
    "is_cuda_available",
]
