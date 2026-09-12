"""Configuration and resource boundaries for AIVARA Phase 10 Inference Integrity."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Set, Tuple


@dataclass(frozen=True)
class InferenceInputLimits:
    """Bounded resource constraints for safe inference input ingestion."""

    # File and Image Limits
    max_file_size_bytes: int = 50 * 1024 * 1024       # 50 MB
    max_image_width: int = 8192                       # 8192 px
    max_image_height: int = 8192                      # 8192 px
    max_image_pixels: int = 8192 * 8192               # ~67.1 MP
    allowed_image_extensions: Tuple[str, ...] = (
        ".png",
        ".jpg",
        ".jpeg",
        ".webp",
        ".bmp",
        ".tif",
        ".tiff",
    )

    # Tensor Limits
    max_tensor_rank: int = 6                          # Up to 6D tensors
    max_tensor_elements: int = 50_000_000             # 50M numerical elements
    max_tensor_memory_bytes: int = 200 * 1024 * 1024  # 200 MB
    max_batch_size: int = 128                         # Batch size bound
    allowed_tensor_dtypes: Tuple[str, ...] = (
        "float32",
        "float64",
        "float16",
        "int32",
        "int64",
        "int16",
        "int8",
        "uint8",
        "bool",
    )

    # Structured Input Limits
    max_structured_byte_size: int = 10 * 1024 * 1024  # 10 MB
    max_structured_nesting_depth: int = 16            # Max JSON depth
    max_structured_keys: int = 100_000                # Max total keys/elements


DEFAULT_INFERENCE_LIMITS = InferenceInputLimits()
