"""Resource and execution limits for the AIVARA Behavioral Analysis Subsystem (Phase 8)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ExecutionLimits(BaseModel):
    """Immutable configuration limits governing controlled model execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_batch_size: int = Field(64, ge=1, le=64, description="Global ceiling for inference batch size")
    max_execution_time_seconds: float = Field(10.0, ge=0.1, le=10.0, description="Global ceiling for execution timeout")
    max_input_dimensions: int = Field(8, ge=1, le=16, description="Maximum tensor rank permitted")
    max_tensor_elements: int = Field(100_000_000, ge=1, description="Maximum total elements in a single tensor")
    max_output_bytes: int = Field(500 * 1024 * 1024, ge=1, description="Maximum total output payload in bytes (500MB)")
    max_memory_bytes: int = Field(4 * 1024 * 1024 * 1024, ge=1, description="Memory ceiling for worker process (4GB)")
    max_temporary_storage_bytes: int = Field(1024 * 1024 * 1024, ge=1, description="Scratch storage limit (1GB)")


# Canonical frozen default limits
DEFAULT_EXECUTION_LIMITS = ExecutionLimits()
