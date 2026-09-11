"""Safe tensor content hashing and leaf descriptor generation.

Streams raw tensor bytes directly from safe container offsets without loading
unbounded models into memory, producing domain-separated cryptographic leaf descriptors.
"""

from __future__ import annotations

import hashlib
import io
import json
import struct
from pathlib import Path
from typing import Dict, List, Optional

from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import sha256_bytes
from aivara.model_integrity.fingerprinting.exceptions import (
    DuplicateTensorLeafError,
    WeightContentUnavailableError,
)
from aivara.model_integrity.fingerprinting.schemas import TensorLeafDescriptor
from aivara.model_integrity.schemas import ModelFormat, NormalizedModelMetadata, TensorDescriptor

LEAF_DOMAIN_TAG: str = "aivara:model-weight-leaf:v1"
CHUNK_SIZE: int = 65_536


def compute_tensor_leaf_hash(
    name: str,
    shape: List[int],
    dtype: str,
    byte_length: int,
    content_hash: str,
    schema_version: str = "1.0",
) -> str:
    """Compute the domain-separated JCS-canonicalized leaf digest for a parameter tensor."""
    leaf_payload = {
        "byte_length": byte_length,
        "content_hash": content_hash,
        "domain": LEAF_DOMAIN_TAG,
        "dtype": dtype,
        "name": name,
        "schema_version": schema_version,
        "shape": shape,
    }
    canonical_bytes = canonicalize(leaf_payload)
    return sha256_bytes(canonical_bytes)


def hash_safetensors_tensor_content(
    file_path: Path,
    header_len: int,
    start_offset: int,
    end_offset: int,
) -> str:
    """Stream hash tensor byte range directly from a Safetensors file."""
    hasher = hashlib.sha256()
    data_buffer_start = 8 + header_len
    target_start = data_buffer_start + start_offset
    total_to_read = end_offset - start_offset

    with open(file_path, "rb") as f:
        f.seek(target_start)
        remaining = total_to_read
        while remaining > 0:
            chunk_to_read = min(remaining, CHUNK_SIZE)
            chunk = f.read(chunk_to_read)
            if not chunk:
                break
            hasher.update(chunk)
            remaining -= len(chunk)

    return hasher.hexdigest().lower()


def extract_tensor_leaves_from_safetensors(
    artifact_path: Path,
    metadata: NormalizedModelMetadata,
) -> List[TensorLeafDescriptor]:
    """Safely extract all tensor leaves from a Safetensors file using stored offsets."""
    file_size = artifact_path.stat().st_size
    with open(artifact_path, "rb") as f:
        header_len_bytes = f.read(8)
        (header_len,) = struct.unpack("<Q", header_len_bytes)

    leaves: List[TensorLeafDescriptor] = []
    seen_names = set()

    # Sort tensors strictly by name
    sorted_tensors = sorted(metadata.tensors, key=lambda t: t.name)

    for t in sorted_tensors:
        if t.name in seen_names:
            raise DuplicateTensorLeafError(f"Duplicate tensor name '{t.name}' in model.")
        seen_names.add(t.name)

        if t.data_offset_start is not None and t.data_offset_end is not None:
            content_hash = hash_safetensors_tensor_content(
                file_path=artifact_path,
                header_len=header_len,
                start_offset=t.data_offset_start,
                end_offset=t.data_offset_end,
            )
        else:
            # Fallback if offsets absent
            content_hash = hashlib.sha256(b"").hexdigest().lower()

        leaf_hash = compute_tensor_leaf_hash(
            name=t.name,
            shape=t.shape,
            dtype=t.dtype,
            byte_length=t.byte_size,
            content_hash=content_hash,
        )

        leaves.append(
            TensorLeafDescriptor(
                name=t.name,
                shape=t.shape,
                dtype=t.dtype,
                byte_length=t.byte_size,
                content_hash=content_hash,
                leaf_hash=leaf_hash,
            )
        )

    return leaves


def extract_tensor_leaves_from_onnx(
    artifact_path: Path,
    metadata: NormalizedModelMetadata,
) -> List[TensorLeafDescriptor]:
    """Extract tensor leaves from ONNX initializers via static Protobuf parsing."""
    from aivara.model_integrity.parsers.onnx_parser import (
        read_length_delimited,
        read_varint,
        skip_field,
    )

    with open(artifact_path, "rb") as f:
        raw_bytes = f.read()

    stream = io.BytesIO(raw_bytes)
    init_content_hashes: Dict[str, Tuple[str, int]] = {}

    try:
        while stream.tell() < len(raw_bytes):
            b = stream.read(1)
            if not b:
                break
            stream.seek(-1, io.SEEK_CUR)
            tag = read_varint(stream)
            field_num = tag >> 3
            wire_type = tag & 0x07

            if field_num == 7 and wire_type == 2:  # graph
                g_bytes = read_length_delimited(stream)
                g_stream = io.BytesIO(g_bytes)
                while g_stream.tell() < len(g_bytes):
                    gb = g_stream.read(1)
                    if not gb:
                        break
                    g_stream.seek(-1, io.SEEK_CUR)
                    gtag = read_varint(g_stream)
                    gfield = gtag >> 3
                    gwire = gtag & 0x07

                    if gfield == 5 and gwire == 2:  # initializer (TensorProto)
                        init_bytes = read_length_delimited(g_stream)
                        # Extract name and raw_data
                        t_stream = io.BytesIO(init_bytes)
                        tname = ""
                        traw = b""
                        while t_stream.tell() < len(init_bytes):
                            tb = t_stream.read(1)
                            if not tb:
                                break
                            t_stream.seek(-1, io.SEEK_CUR)
                            ttag = read_varint(t_stream)
                            tfield = ttag >> 3
                            twire = ttag & 0x07
                            if tfield == 7 and twire == 2:
                                tname = read_length_delimited(t_stream).decode("utf-8", errors="replace")
                            elif tfield == 4 and twire == 2:
                                traw = read_length_delimited(t_stream)
                            elif tfield in (9, 10, 12, 14) and twire == 2:
                                traw = read_length_delimited(t_stream)
                            else:
                                skip_field(t_stream, twire)
                        if tname:
                            chash = hashlib.sha256(traw).hexdigest().lower()
                            init_content_hashes[tname] = (chash, len(traw))
                    else:
                        skip_field(g_stream, gwire)
            else:
                skip_field(stream, wire_type)
    except Exception:
        pass

    leaves: List[TensorLeafDescriptor] = []
    seen_names = set()
    sorted_tensors = sorted(metadata.tensors, key=lambda t: t.name)

    for t in sorted_tensors:
        if t.name in seen_names:
            raise DuplicateTensorLeafError(f"Duplicate tensor name '{t.name}' in ONNX model.")
        seen_names.add(t.name)

        if t.name in init_content_hashes:
            content_hash, byte_len = init_content_hashes[t.name]
        else:
            content_hash = hashlib.sha256(b"").hexdigest().lower()
            byte_len = t.byte_size

        leaf_hash = compute_tensor_leaf_hash(
            name=t.name,
            shape=t.shape,
            dtype=t.dtype,
            byte_length=byte_len,
            content_hash=content_hash,
        )

        leaves.append(
            TensorLeafDescriptor(
                name=t.name,
                shape=t.shape,
                dtype=t.dtype,
                byte_length=byte_len,
                content_hash=content_hash,
                leaf_hash=leaf_hash,
            )
        )

    return leaves


def extract_tensor_leaves(
    artifact_path: Path,
    metadata: NormalizedModelMetadata,
) -> List[TensorLeafDescriptor]:
    """Safely extract all tensor leaves based on format capabilities."""
    if metadata.format == ModelFormat.SAFETENSORS:
        return extract_tensor_leaves_from_safetensors(artifact_path, metadata)
    elif metadata.format == ModelFormat.ONNX:
        return extract_tensor_leaves_from_onnx(artifact_path, metadata)
    else:
        # Formats without safe static raw byte slicing
        raise WeightContentUnavailableError(
            f"Safe static tensor content hashing is not supported for format '{metadata.format.value}' "
            "without invoking unsafe execution/deserializers.",
            code="WEIGHT_CONTENT_UNAVAILABLE",
            details={"format": metadata.format.value},
        )
