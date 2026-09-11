"""Deterministic normalization mappings and serializers for model contracts and dtypes (Phase 7.4).

Provides canonical data type normalization, dimension standardization, and
deterministic canonical payload serialization compatible with Phase 7.3 and RFC 8785 JCS.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Union

from aivara.crypto.canonical import canonicalize
from aivara.model_integrity.contract_verification.schemas import (
    ValidatedInputContract,
    ValidatedOutputContract,
)
from aivara.model_integrity.fingerprinting.schemas import ContractRepresentation

# Comprehensive canonical dtype alias lookup map
DTYPE_CANONICAL_MAP: Dict[str, str] = {
    # Floating point
    "float32": "F32",
    "float": "F32",
    "f32": "F32",
    "single": "F32",
    "tensor(float)": "F32",
    "torch.float32": "F32",
    "torch.float": "F32",
    "float16": "F16",
    "f16": "F16",
    "half": "F16",
    "tensor(float16)": "F16",
    "torch.float16": "F16",
    "torch.half": "F16",
    "bfloat16": "BF16",
    "bf16": "BF16",
    "tensor(bfloat16)": "BF16",
    "torch.bfloat16": "BF16",
    "float64": "F64",
    "double": "F64",
    "f64": "F64",
    "tensor(double)": "F64",
    "torch.float64": "F64",
    "torch.double": "F64",
    # Signed integers
    "int64": "I64",
    "i64": "I64",
    "long": "I64",
    "tensor(int64)": "I64",
    "torch.int64": "I64",
    "torch.long": "I64",
    "int32": "I32",
    "i32": "I32",
    "int": "I32",
    "tensor(int32)": "I32",
    "torch.int32": "I32",
    "torch.int": "I32",
    "int16": "I16",
    "i16": "I16",
    "short": "I16",
    "tensor(int16)": "I16",
    "torch.int16": "I16",
    "torch.short": "I16",
    "int8": "I8",
    "i8": "I8",
    "byte": "I8",
    "tensor(int8)": "I8",
    "torch.int8": "I8",
    # Unsigned integers
    "uint8": "U8",
    "u8": "U8",
    "tensor(uint8)": "U8",
    "torch.uint8": "U8",
    "uint16": "U16",
    "u16": "U16",
    "tensor(uint16)": "U16",
    "uint32": "U32",
    "u32": "U32",
    "tensor(uint32)": "U32",
    "uint64": "U64",
    "u64": "U64",
    "tensor(uint64)": "U64",
    # Booleans
    "bool": "BOOL",
    "boolean": "BOOL",
    "tensor(bool)": "BOOL",
    "torch.bool": "BOOL",
    # Strings
    "string": "STRING",
    "str": "STRING",
    "tensor(string)": "STRING",
    # Complex
    "complex64": "C64",
    "c64": "C64",
    "tensor(complex64)": "C64",
    "torch.complex64": "C64",
    "complex128": "C128",
    "c128": "C128",
    "tensor(complex128)": "C128",
    "torch.complex128": "C128",
}

# Standard ONNX TensorProto integer code mapping
ONNX_PROTO_INT_MAP: Dict[int, str] = {
    1: "F32",
    2: "U8",
    3: "I8",
    4: "U16",
    5: "I16",
    6: "I32",
    7: "I64",
    8: "STRING",
    9: "BOOL",
    10: "F16",
    11: "F64",
    12: "U32",
    13: "U64",
    14: "C64",
    15: "C128",
    16: "BF16",
}


def normalize_dtype(raw_dtype: Union[str, int]) -> Tuple[str, bool]:
    """Normalize any format-specific dtype representation to canonical internal uppercase format.

    Returns:
        Tuple of (canonical_dtype_str, is_recognized_bool).
    """
    if isinstance(raw_dtype, int):
        if raw_dtype in ONNX_PROTO_INT_MAP:
            return ONNX_PROTO_INT_MAP[raw_dtype], True
        return f"UNKNOWN_INT_{raw_dtype}", False

    cleaned = str(raw_dtype).strip()
    lookup_key = cleaned.lower()

    if lookup_key in DTYPE_CANONICAL_MAP:
        return DTYPE_CANONICAL_MAP[lookup_key], True

    # Check if already canonical uppercase
    canonical_set = set(DTYPE_CANONICAL_MAP.values())
    if cleaned.upper() in canonical_set:
        return cleaned.upper(), True

    return cleaned.upper() if cleaned else "UNKNOWN", False


def normalize_shape_entry(dim: Any) -> Tuple[Optional[int], Optional[str]]:
    """Normalize a single dimension entry to (dimension_int_or_None, symbolic_name_or_None)."""
    if dim is None:
        return None, None
    if isinstance(dim, int):
        if dim < 0:
            # -1 represents dynamic dimension in ONNX / PyTorch conventions
            if dim == -1:
                return None, None
            return dim, None
        return dim, None
    if isinstance(dim, str):
        cleaned = dim.strip()
        if not cleaned or cleaned.lower() in ("none", "null", "dynamic", "?", "-1"):
            return None, None
        if cleaned.isdigit():
            return int(cleaned), None
        return None, cleaned

    return None, str(dim)


def build_canonical_contract_representation(
    inputs: List[ValidatedInputContract],
    outputs: List[ValidatedOutputContract],
) -> ContractRepresentation:
    """Build Phase 7.3 ContractRepresentation strictly sorted lexicographically by name.

    Guarantees bit-for-bit compatibility with Phase 7.3 H_contract computation.
    """
    sorted_inputs: List[Dict[str, Any]] = [
        {
            "channel_order": inp.channel_ordering or inp.layout or "",
            "dtype": inp.dtype,
            "is_dynamic": inp.is_dynamic,
            "name": inp.name,
            "shape": inp.shape,
        }
        for inp in sorted(inputs, key=lambda x: x.name)
    ]

    sorted_outputs: List[Dict[str, Any]] = [
        {
            "activation_type": out.activation_type or "",
            "dtype": out.dtype,
            "name": out.name,
            "shape": out.shape,
        }
        for out in sorted(outputs, key=lambda x: x.name)
    ]

    return ContractRepresentation(
        schema_version="1.0",
        inputs=sorted_inputs,
        outputs=sorted_outputs,
    )
