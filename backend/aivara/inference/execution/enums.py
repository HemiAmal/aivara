"""Authoritative enums for AIVARA Phase 10.5 Inference Execution Integrity."""

from __future__ import annotations

from enum import Enum


class ExecutionLifecycle(str, Enum):
    """Lifecycle states of an inference execution transaction."""

    CREATED = "CREATED"
    VALIDATING = "VALIDATING"
    READY = "READY"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"
    UNAVAILABLE = "UNAVAILABLE"
    UNVERIFIABLE = "UNVERIFIABLE"


class ExecutionProvider(str, Enum):
    """Supported execution providers for model forward passes."""

    CPU = "CPUExecutionProvider"
    CUDA = "CUDAExecutionProvider"


class ExecutionDevice(str, Enum):
    """Target execution compute device."""

    CPU = "CPU"
    CUDA = "CUDA"


class NumericalSanityStatus(str, Enum):
    """Execution-boundary numerical sanity status (finiteness)."""

    FINITE = "FINITE"
    NONFINITE = "NONFINITE"
    UNCHECKED = "UNCHECKED"
