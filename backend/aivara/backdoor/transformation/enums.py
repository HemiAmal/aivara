"""Enumerations for Phase 9.3 Trigger Transformation Engine."""

from __future__ import annotations

from enum import Enum


class InputLayoutEnum(str, Enum):
    """Explicit tensor input and output layout taxonomy (ADR-087)."""
    GRAYSCALE_2D = "GRAYSCALE_2D"  # (H, W)
    HWC = "HWC"                    # (H, W, C)
    CHW = "CHW"                    # (C, H, W)
    NHWC = "NHWC"                  # (N, H, W, C)
    NCHW = "NCHW"                  # (N, C, H, W)
