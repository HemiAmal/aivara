"""Fast deterministic Hamming distance computation for 64-bit perceptual hashes (Phase 5.4)."""

from __future__ import annotations

import re
from typing import Union

from aivara.dataset.duplicates.exceptions import InvalidPerceptualHashError

_HEX_16_REGEX = re.compile(r"^[0-9a-fA-F]{16}$")


def hex_to_uint64(hex_str: str) -> int:
    """Convert a 16-character hexadecimal hash to a 64-bit unsigned integer.

    Args:
        hex_str: 16-character hex string.

    Returns:
        Unsigned 64-bit integer.

    Raises:
        InvalidPerceptualHashError: If format is invalid.
    """
    if not isinstance(hex_str, str) or not _HEX_16_REGEX.match(hex_str):
        raise InvalidPerceptualHashError(
            f"Expected 16-character hexadecimal hash, got '{hex_str}'."
        )
    return int(hex_str, 16)


def uint64_to_hex(val: int) -> str:
    """Format a 64-bit unsigned integer as a 16-character lowercase hex string."""
    if not isinstance(val, int) or val < 0 or val > 0xFFFFFFFFFFFFFFFF:
        raise InvalidPerceptualHashError(
            f"Value must be a 64-bit unsigned integer in [0, 2^64-1], got '{val}'."
        )
    return f"{val:016x}"


def hamming_distance_uint64(a: int, b: int) -> int:
    """Compute exact Hamming distance between two 64-bit unsigned integers.

    Utilizes hardware POPCNT instruction via Python's built-in bit_count().

    Args:
        a: First 64-bit unsigned integer.
        b: Second 64-bit unsigned integer.

    Returns:
        Integer Hamming distance in [0, 64].
    """
    return (a ^ b).bit_count()


def hamming_distance(a: Union[str, int], b: Union[str, int]) -> int:
    """Compute exact Hamming distance between two perceptual hashes.

    Accepts either 16-character hexadecimal strings or 64-bit unsigned integers.

    Args:
        a: First perceptual hash.
        b: Second perceptual hash.

    Returns:
        Integer Hamming distance in [0, 64].
    """
    val_a = hex_to_uint64(a) if isinstance(a, str) else a
    val_b = hex_to_uint64(b) if isinstance(b, str) else b
    return hamming_distance_uint64(val_a, val_b)
