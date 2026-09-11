"""Execution provider and resource limit policy enforcement (Phase 8.2)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

from aivara.behavioral.exceptions import (
    ExecutionProviderUnavailableError,
    ResourceLimitExceededError,
    UnsupportedExecutionFormatError,
    SecuritySandboxViolationError,
)
from aivara.behavioral.limits import DEFAULT_EXECUTION_LIMITS, ExecutionLimits
from aivara.behavioral.schemas import ExecutionProvider, ExecutionRequest


def get_available_execution_providers() -> List[str]:
    """Retrieve list of supported and installed execution providers in the local runtime."""
    try:
        import onnxruntime as ort
        return ort.get_available_providers()
    except Exception:
        return ["CPUExecutionProvider"]


def is_cuda_available() -> bool:
    """Check if CUDA execution provider is available in the local runtime."""
    available = get_available_execution_providers()
    return "CUDAExecutionProvider" in available


def validate_execution_request_policy(
    request: ExecutionRequest,
    limits: Optional[ExecutionLimits] = None,
) -> None:
    """Validate an execution request against strict provider, format, and resource policies.

    Enforces:
    1. CPUExecutionProvider is the default.
    2. CUDAExecutionProvider requires explicit opt-in and fails closed if unavailable (no silent fallback).
    3. Timeout cannot exceed the global hard ceiling (10.0 seconds).
    4. Batch size cannot exceed the global ceiling (64).
    5. Prohibited execution formats (pickle, raw python scripts) are rejected immediately.
    """
    effective_limits = limits or DEFAULT_EXECUTION_LIMITS

    # 1. Timeout Ceiling Enforcement
    if request.timeout_seconds > effective_limits.max_execution_time_seconds:
        raise ResourceLimitExceededError(
            f"Requested execution timeout of {request.timeout_seconds}s exceeds global safety maximum of "
            f"{effective_limits.max_execution_time_seconds}s.",
            details={"requested_timeout": request.timeout_seconds, "max_timeout": effective_limits.max_execution_time_seconds},
        )

    # 2. Batch Size Ceiling Enforcement
    if request.max_batch_size > effective_limits.max_batch_size:
        raise ResourceLimitExceededError(
            f"Requested max_batch_size of {request.max_batch_size} exceeds global safety ceiling of "
            f"{effective_limits.max_batch_size}.",
            details={"requested_batch_size": request.max_batch_size, "max_batch_size": effective_limits.max_batch_size},
        )

    # 3. Execution Provider Policy Enforcement
    if request.execution_provider == ExecutionProvider.CUDA:
        if not is_cuda_available():
            raise ExecutionProviderUnavailableError(
                "CUDAExecutionProvider was explicitly requested but is not available in the current environment. "
                "AIVARA policy strictly forbids silent fallback to CPU.",
                details={"requested_provider": request.execution_provider.value, "available_providers": get_available_execution_providers()},
            )
    elif request.execution_provider != ExecutionProvider.CPU:
        raise ExecutionProviderUnavailableError(
            f"Unsupported execution provider '{request.execution_provider}'. Only CPUExecutionProvider and CUDAExecutionProvider are supported.",
            details={"requested_provider": str(request.execution_provider)},
        )

    # 4. Prohibited Format & Script Path Enforcement
    p = Path(request.model_path)
    suffix = p.suffix.lower()
    prohibited_suffixes = {".pkl", ".pickle", ".py", ".sh", ".bat", ".exe", ".bin"}
    if suffix in prohibited_suffixes:
        raise UnsupportedExecutionFormatError(
            f"Execution of artifact with extension '{suffix}' is prohibited under the Phase 8.2 execution boundary.",
            details={"file_path": str(request.model_path), "extension": suffix},
        )
