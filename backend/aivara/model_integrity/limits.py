"""Resource limits and fail-closed guardrails for untrusted model artifacts.

Provides configurable threshold enforcement to defend against memory exhaustion,
decompression bombs, oversized headers, and excessive tensor counts.
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, ConfigDict, Field

from aivara.model_integrity.exceptions import ResourceLimitExceededError


class ModelIngestionLimits(BaseModel):
    """Configurable resource bounds for model ingestion and static inspection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_artifact_size_bytes: int = Field(
        default=5 * 1024 * 1024 * 1024,  # 5 GB
        gt=0,
        description="Maximum allowed size of raw model artifact on disk",
    )
    max_header_size_bytes: int = Field(
        default=100 * 1024 * 1024,  # 100 MB
        gt=0,
        description="Maximum allowed size for Safetensors JSON header or container index",
    )
    max_tensor_count: int = Field(
        default=100_000,
        gt=0,
        description="Maximum number of individual parameter tensors in model",
    )
    max_tensor_dimensions: int = Field(
        default=16,
        gt=0,
        description="Maximum rank (number of dimensions) for any tensor",
    )
    max_string_length: int = Field(
        default=65_536,  # 64 KB
        gt=0,
        description="Maximum length for any individual tensor name, attribute, or property string",
    )
    max_archive_members: int = Field(
        default=10_000,
        gt=0,
        description="Maximum number of entries allowed inside a container archive",
    )
    max_archive_uncompressed_bytes: int = Field(
        default=10 * 1024 * 1024 * 1024,  # 10 GB
        gt=0,
        description="Maximum cumulative uncompressed size of archive members",
    )
    max_archive_compression_ratio: float = Field(
        default=100.0,
        gt=1.0,
        description="Maximum allowed decompression expansion ratio (uncompressed/compressed)",
    )
    max_graph_nodes: int = Field(
        default=100_000,
        gt=0,
        description="Maximum number of operator nodes in computational graph (ONNX)",
    )

    def check_file_size(self, size_bytes: int, filename: str = "") -> None:
        """Validate that file size is within limits."""
        if size_bytes > self.max_artifact_size_bytes:
            raise ResourceLimitExceededError(
                f"Artifact size {size_bytes} bytes exceeds maximum allowed limit of "
                f"{self.max_artifact_size_bytes} bytes ({filename}).",
                code="FILE_SIZE_LIMIT_EXCEEDED",
                details={
                    "observed_size_bytes": size_bytes,
                    "max_allowed_bytes": self.max_artifact_size_bytes,
                    "filename": filename,
                },
            )

    def check_header_size(self, header_bytes: int, format_name: str = "") -> None:
        """Validate that metadata/header size is within limits."""
        if header_bytes > self.max_header_size_bytes:
            raise ResourceLimitExceededError(
                f"Header size {header_bytes} bytes exceeds maximum allowed limit of "
                f"{self.max_header_size_bytes} bytes for format '{format_name}'.",
                code="HEADER_SIZE_LIMIT_EXCEEDED",
                details={
                    "observed_header_bytes": header_bytes,
                    "max_allowed_bytes": self.max_header_size_bytes,
                    "format": format_name,
                },
            )

    def check_tensor_count(self, count: int) -> None:
        """Validate that total tensor count does not exceed limit."""
        if count > self.max_tensor_count:
            raise ResourceLimitExceededError(
                f"Tensor count {count} exceeds maximum allowed limit of {self.max_tensor_count}.",
                code="TENSOR_COUNT_LIMIT_EXCEEDED",
                details={
                    "observed_tensor_count": count,
                    "max_allowed_tensor_count": self.max_tensor_count,
                },
            )

    def check_tensor_shape(self, shape: list[int], tensor_name: str = "") -> None:
        """Validate tensor rank."""
        if len(shape) > self.max_tensor_dimensions:
            raise ResourceLimitExceededError(
                f"Tensor '{tensor_name}' rank {len(shape)} exceeds maximum allowed dimension limit of "
                f"{self.max_tensor_dimensions}.",
                code="DIMENSION_LIMIT_EXCEEDED",
                details={
                    "tensor_name": tensor_name,
                    "observed_rank": len(shape),
                    "max_rank": self.max_tensor_dimensions,
                },
            )

    def check_string_length(self, value: str, field_name: str = "") -> None:
        """Validate string length."""
        if len(value) > self.max_string_length:
            raise ResourceLimitExceededError(
                f"String in field '{field_name}' of length {len(value)} exceeds maximum allowed limit of "
                f"{self.max_string_length}.",
                code="STRING_LENGTH_LIMIT_EXCEEDED",
                details={
                    "field_name": field_name,
                    "observed_length": len(value),
                    "max_length": self.max_string_length,
                },
            )

    def check_archive_members(self, count: int) -> None:
        """Validate archive member count."""
        if count > self.max_archive_members:
            raise ResourceLimitExceededError(
                f"Archive member count {count} exceeds maximum allowed limit of {self.max_archive_members}.",
                code="ARCHIVE_MEMBER_COUNT_EXCEEDED",
                details={
                    "observed_member_count": count,
                    "max_allowed_members": self.max_archive_members,
                },
            )

    def check_archive_bomb(self, compressed_bytes: int, uncompressed_bytes: int) -> None:
        """Check for archive decompression bomb."""
        if uncompressed_bytes > self.max_archive_uncompressed_bytes:
            raise ResourceLimitExceededError(
                f"Uncompressed archive size {uncompressed_bytes} bytes exceeds maximum allowed limit of "
                f"{self.max_archive_uncompressed_bytes} bytes.",
                code="ARCHIVE_BOMB_DETECTED",
                details={
                    "observed_uncompressed_bytes": uncompressed_bytes,
                    "max_uncompressed_bytes": self.max_archive_uncompressed_bytes,
                },
            )
        if compressed_bytes > 0:
            ratio = uncompressed_bytes / compressed_bytes
            if ratio > self.max_archive_compression_ratio:
                raise ResourceLimitExceededError(
                    f"Archive compression ratio {ratio:.1f}:1 exceeds maximum allowed limit of "
                    f"{self.max_archive_compression_ratio:.1f}:1.",
                    code="ARCHIVE_BOMB_DETECTED",
                    details={
                        "compressed_bytes": compressed_bytes,
                        "uncompressed_bytes": uncompressed_bytes,
                        "ratio": ratio,
                        "max_ratio": self.max_archive_compression_ratio,
                    },
                )


# Default shared limits instance
DEFAULT_LIMITS = ModelIngestionLimits()
