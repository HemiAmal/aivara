"""Safe zero-execution static parser for Safetensors model artifacts.

Parses 8-byte uint64 header length and JSON descriptor without loading full tensor
buffers into memory or executing any code.
"""

from __future__ import annotations

import json
import math
import struct
from pathlib import Path
from typing import Any, Dict, List

from aivara.model_integrity.exceptions import (
    ModelCorruptionError,
    ResourceLimitExceededError,
)
from aivara.model_integrity.limits import DEFAULT_LIMITS, ModelIngestionLimits
from aivara.model_integrity.parsers.base import BaseModelParser, ParsedModelData
from aivara.model_integrity.schemas import (
    ModelFormat,
    ReasonCode,
    TensorDescriptor,
)

# Standard Safetensors dtype size map (in bytes)
DTYPE_BYTE_SIZES: Dict[str, int] = {
    "BOOL": 1,
    "U8": 1,
    "I8": 1,
    "I16": 2,
    "U16": 2,
    "F16": 2,
    "BF16": 2,
    "I32": 4,
    "U32": 4,
    "F32": 4,
    "F64": 8,
    "I64": 8,
    "U64": 8,
}


class SafetensorsParser(BaseModelParser):
    """Safe, zero-execution parser for Safetensors format."""

    def parse(
        self,
        artifact_path: Path,
        limits: ModelIngestionLimits = DEFAULT_LIMITS,
    ) -> ParsedModelData:
        """Statically inspect Safetensors header and extract tensor descriptors."""
        file_size = artifact_path.stat().st_size

        if file_size < 8:
            raise ModelCorruptionError(
                f"Safetensors file is too small ({file_size} bytes, minimum 8 bytes required).",
                code="CORRUPTED_CONTAINER",
                details={"file_size": file_size, "path": str(artifact_path)},
            )

        with open(artifact_path, "rb") as f:
            # 1. Read 8-byte uint64 header length (little-endian)
            header_len_bytes = f.read(8)
            if len(header_len_bytes) < 8:
                raise ModelCorruptionError(
                    "Truncated Safetensors header length prefix.",
                    code="CORRUPTED_CONTAINER",
                )
            (header_len,) = struct.unpack("<Q", header_len_bytes)

            # 2. Check header size limit
            limits.check_header_size(header_len, format_name="safetensors")

            # 3. Check that header fits within file bounds
            if 8 + header_len > file_size:
                raise ModelCorruptionError(
                    f"Safetensors header length ({header_len} bytes) extends beyond file boundary "
                    f"(file size: {file_size} bytes).",
                    code="CORRUPTED_CONTAINER",
                    details={"header_len": header_len, "file_size": file_size},
                )

            # 4. Read raw header JSON
            raw_header = f.read(header_len)
            if len(raw_header) < header_len:
                raise ModelCorruptionError(
                    "Unexpected EOF reading Safetensors header.",
                    code="CORRUPTED_CONTAINER",
                )

        # 5. Decode UTF-8
        try:
            header_str = raw_header.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ModelCorruptionError(
                f"Safetensors header contains invalid UTF-8: {e}",
                code="MALFORMED_HEADER",
                details={"error": str(e)},
            )

        # 6. Parse JSON
        try:
            header_data = json.loads(header_str)
        except json.JSONDecodeError as e:
            raise ModelCorruptionError(
                f"Safetensors header is not valid JSON: {e}",
                code="MALFORMED_HEADER",
                details={"error": str(e)},
            )

        if not isinstance(header_data, dict):
            raise ModelCorruptionError(
                "Safetensors header root must be a JSON object.",
                code="MALFORMED_HEADER",
            )

        # 7. Extract metadata properties and tensor entries
        metadata_props: Dict[str, str] = {}
        tensors: List[TensorDescriptor] = []
        warnings: List[str] = []

        if "__metadata__" in header_data:
            meta_obj = header_data["__metadata__"]
            if isinstance(meta_obj, dict):
                for k, v in meta_obj.items():
                    k_str = str(k)
                    v_str = str(v)
                    limits.check_string_length(k_str, "metadata_key")
                    limits.check_string_length(v_str, "metadata_value")
                    metadata_props[k_str] = v_str
            else:
                warnings.append("Header '__metadata__' is not a JSON object; ignored.")

        # Extract tensors
        tensor_keys = [k for k in header_data.keys() if k != "__metadata__"]
        limits.check_tensor_count(len(tensor_keys))

        data_buffer_start = 8 + header_len

        for name in tensor_keys:
            limits.check_string_length(name, "tensor_name")
            entry = header_data[name]

            if not isinstance(entry, dict):
                raise ModelCorruptionError(
                    f"Tensor descriptor for '{name}' must be a JSON object.",
                    code="MALFORMED_HEADER",
                    details={"tensor_name": name},
                )

            if "dtype" not in entry or "shape" not in entry or "data_offsets" not in entry:
                raise ModelCorruptionError(
                    f"Tensor descriptor for '{name}' missing required fields (dtype, shape, data_offsets).",
                    code="MALFORMED_HEADER",
                    details={"tensor_name": name, "entry": entry},
                )

            dtype = str(entry["dtype"])
            shape = entry["shape"]
            data_offsets = entry["data_offsets"]

            if not isinstance(shape, list) or not all(isinstance(dim, int) and dim >= 0 for dim in shape):
                raise ModelCorruptionError(
                    f"Tensor '{name}' has invalid shape {shape}.",
                    code="MALFORMED_HEADER",
                    details={"tensor_name": name, "shape": shape},
                )

            limits.check_tensor_shape(shape, tensor_name=name)

            if not isinstance(data_offsets, list) or len(data_offsets) != 2:
                raise ModelCorruptionError(
                    f"Tensor '{name}' data_offsets must be a list of 2 integers, got {data_offsets}.",
                    code="INVALID_TENSOR_OFFSET",
                    details={"tensor_name": name, "data_offsets": data_offsets},
                )

            start_off, end_off = data_offsets[0], data_offsets[1]
            if not isinstance(start_off, int) or not isinstance(end_off, int) or start_off < 0 or end_off < start_off:
                raise ModelCorruptionError(
                    f"Tensor '{name}' has invalid offset range [{start_off}, {end_off}].",
                    code="INVALID_TENSOR_OFFSET",
                    details={"tensor_name": name, "start": start_off, "end": end_off},
                )

            # Check that tensor offset fits within file size
            if data_buffer_start + end_off > file_size:
                raise ModelCorruptionError(
                    f"Tensor '{name}' end offset ({data_buffer_start + end_off}) exceeds file size ({file_size}).",
                    code="INVALID_TENSOR_OFFSET",
                    details={"tensor_name": name, "end_offset": end_off, "file_size": file_size},
                )

            byte_size = end_off - start_off
            element_count = math.prod(shape) if shape else (1 if byte_size > 0 else 0)

            # Cross-check byte size against dtype if known
            if dtype in DTYPE_BYTE_SIZES:
                expected_bytes = element_count * DTYPE_BYTE_SIZES[dtype]
                if expected_bytes != byte_size:
                    warnings.append(
                        f"Tensor '{name}' size {byte_size} bytes does not match expected "
                        f"{expected_bytes} bytes for dtype {dtype} and shape {shape}."
                    )

            tensors.append(
                TensorDescriptor(
                    name=name,
                    shape=shape,
                    dtype=dtype,
                    element_count=element_count,
                    byte_size=byte_size,
                    data_offset_start=start_off,
                    data_offset_end=end_off,
                )
            )

        return ParsedModelData(
            format=ModelFormat.SAFETENSORS,
            tensors=tensors,
            inputs=[],
            outputs=[],
            operators=[],
            metadata_props=metadata_props,
            warnings=warnings,
            reason_codes=[ReasonCode.SAFE_INSPECTION_PASSED],
            details={"header_length_bytes": header_len, "raw_tensor_count": len(tensors)},
        )
