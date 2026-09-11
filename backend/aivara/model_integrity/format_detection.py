"""Deterministic model format detection via safe magic bytes, headers, and container inspection.

Detects model format from file content rather than trusting file extensions alone.
Enforces deterministic policy assignment (SUPPORTED, RESTRICTED, PROHIBITED, UNKNOWN).
"""

from __future__ import annotations

import io
import json
import struct
import zipfile
from pathlib import Path
from typing import Optional, Tuple

from aivara.model_integrity.limits import DEFAULT_LIMITS, ModelIngestionLimits
from aivara.model_integrity.schemas import (
    FormatDetectionResult,
    InspectionPolicy,
    ModelFormat,
)

# Format to Policy mapping
POLICY_MAP = {
    ModelFormat.SAFETENSORS: InspectionPolicy.SUPPORTED,
    ModelFormat.ONNX: InspectionPolicy.SUPPORTED,
    ModelFormat.PYTORCH_STATE_DICT: InspectionPolicy.RESTRICTED,
    ModelFormat.TORCHSCRIPT: InspectionPolicy.RESTRICTED,
    ModelFormat.PICKLE: InspectionPolicy.PROHIBITED,
    ModelFormat.UNKNOWN: InspectionPolicy.UNKNOWN,
    ModelFormat.CORRUPTED: InspectionPolicy.UNKNOWN,
}


def is_safetensors_content(file_path: Path, file_size: int) -> bool:
    """Check if file starts with valid Safetensors 8-byte length prefix and JSON header."""
    if file_size < 10:
        return False

    try:
        with open(file_path, "rb") as f:
            header_len_bytes = f.read(8)
            if len(header_len_bytes) < 8:
                return False
            (header_len,) = struct.unpack("<Q", header_len_bytes)

            if header_len <= 0 or 8 + header_len > file_size or header_len > 100 * 1024 * 1024:
                return False

            peek_bytes = f.read(min(header_len, 64))
            peek_str = peek_bytes.decode("utf-8", errors="ignore").strip()
            return peek_str.startswith("{")
    except Exception:
        return False


def is_onnx_protobuf_content(file_path: Path, file_size: int) -> bool:
    """Check if file has valid ONNX ModelProto wire structure."""
    if file_size < 4:
        return False

    try:
        with open(file_path, "rb") as f:
            header = f.read(min(file_size, 4096))

        stream = io.BytesIO(header)
        has_ir_version = False
        has_graph = False
        has_opset = False

        while stream.tell() < len(header):
            b = stream.read(1)
            if not b:
                break
            tag = b[0]
            if tag & 0x80:  # multi-byte tag
                tag2 = stream.read(1)
                if not tag2:
                    break
                tag = (tag & 0x7F) | ((tag2[0] & 0x7F) << 7)

            field_num = tag >> 3
            wire_type = tag & 0x07

            if wire_type not in (0, 1, 2, 5):
                return False

            if field_num == 1 and wire_type == 0:  # ir_version
                v_byte = stream.read(1)
                if v_byte and 1 <= (v_byte[0] & 0x7F) <= 50:
                    has_ir_version = True
            elif field_num == 7 and wire_type == 2:  # graph
                has_graph = True
                # Read length of graph
                l_bytes = bytearray()
                while True:
                    lb = stream.read(1)
                    if not lb:
                        break
                    l_bytes.append(lb[0])
                    if not (lb[0] & 0x80):
                        break
                # Skip graph content or read up to available
                gl = 0
                for idx, val in enumerate(l_bytes):
                    gl |= (val & 0x7F) << (7 * idx)
                stream.seek(min(gl, len(header) - stream.tell()), io.SEEK_CUR)
            elif field_num == 8 and wire_type == 2:  # opset_import
                has_opset = True
                lb = stream.read(1)
                if lb:
                    stream.seek(min(lb[0] & 0x7F, len(header) - stream.tell()), io.SEEK_CUR)
            elif wire_type == 0:
                # skip varint
                while True:
                    vb = stream.read(1)
                    if not vb or not (vb[0] & 0x80):
                        break
            elif wire_type == 1:
                stream.seek(8, io.SEEK_CUR)
            elif wire_type == 5:
                stream.seek(4, io.SEEK_CUR)
            elif wire_type == 2:
                # read length varint
                l_bytes = bytearray()
                while True:
                    lb = stream.read(1)
                    if not lb:
                        break
                    l_bytes.append(lb[0])
                    if not (lb[0] & 0x80):
                        break
                fl = 0
                for idx, val in enumerate(l_bytes):
                    fl |= (val & 0x7F) << (7 * idx)
                stream.seek(min(fl, len(header) - stream.tell()), io.SEEK_CUR)

        return (has_graph and (has_ir_version or has_opset)) or (has_ir_version and has_opset) or (has_graph and field_size_check(file_size))
    except Exception:
        return False


def field_size_check(file_size: int) -> bool:
    return file_size > 0


def is_pickle_content(file_path: Path) -> bool:
    """Check if file starts with standard Python pickle protocol markers."""
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
        if not magic:
            return False
        # Protocols 2, 3, 4, 5
        if magic[0] == 0x80 and magic[1] in (0x02, 0x03, 0x04, 0x05):
            return True
        # Protocol 0 text markers
        if magic.startswith((b"ccopy_reg", b"c__builtin__", b"cos\n", b"(dp", b"((l")):
            return True
        return False
    except Exception:
        return False


def inspect_zip_format(file_path: Path) -> Tuple[ModelFormat, str, dict]:
    """Inspect zip container members to differentiate TorchScript from PyTorch state_dict."""
    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            names = [info.filename for info in zf.infolist()]

        # TorchScript markers: code/ directory, model.json, constants.pkl, version
        has_code = any("/code/" in n or n.startswith("code/") for n in names)
        has_model_json = any(n.endswith("model.json") for n in names)
        has_version = any(n.endswith("version") for n in names)
        has_data_pkl = any(n.endswith("data.pkl") or n == "data.pkl" for n in names)

        if has_code or (has_model_json and has_version):
            return (
                ModelFormat.TORCHSCRIPT,
                "zip_index_torchscript_markers",
                {"member_count": len(names), "has_code": has_code},
            )

        if has_data_pkl:
            return (
                ModelFormat.PYTORCH_STATE_DICT,
                "zip_index_pytorch_state_dict",
                {"member_count": len(names), "has_data_pkl": True},
            )

        return (
            ModelFormat.UNKNOWN,
            "zip_index_generic",
            {"member_count": len(names)},
        )
    except zipfile.BadZipFile:
        return ModelFormat.CORRUPTED, "corrupted_zip", {}
    except Exception as e:
        return ModelFormat.CORRUPTED, f"zip_inspection_error_{e}", {}


def detect_model_format(
    file_path: Path,
    limits: ModelIngestionLimits = DEFAULT_LIMITS,
) -> FormatDetectionResult:
    """Deterministically detect the model format and assign safety policy.

    Args:
        file_path: Path to model artifact on disk.
        limits: Configurable resource limits.

    Returns:
        FormatDetectionResult with format, policy, method, and confidence.
    """
    file_size = file_path.stat().st_size
    ext = file_path.suffix.lower()

    # 1. Check for Zip Container (TorchScript or PyTorch Zip state_dict)
    if zipfile.is_zipfile(file_path):
        fmt, method, details = inspect_zip_format(file_path)
        policy = POLICY_MAP[fmt]
        return FormatDetectionResult(
            format=fmt,
            policy=policy,
            detected_by=method,
            confidence=0.98 if fmt != ModelFormat.UNKNOWN else 0.5,
            container_type="zip",
            details=details,
        )

    # 2. Check for Safetensors (magic header length + JSON header)
    if is_safetensors_content(file_path, file_size):
        return FormatDetectionResult(
            format=ModelFormat.SAFETENSORS,
            policy=POLICY_MAP[ModelFormat.SAFETENSORS],
            detected_by="safetensors_header_prefix",
            confidence=0.99,
            container_type="flat",
            details={"file_size": file_size},
        )

    # 3. Check for ONNX (Protobuf ModelProto wire tags)
    if is_onnx_protobuf_content(file_path, file_size):
        return FormatDetectionResult(
            format=ModelFormat.ONNX,
            policy=POLICY_MAP[ModelFormat.ONNX],
            detected_by="protobuf_wire_schema",
            confidence=0.95,
            container_type="protobuf",
            details={"file_size": file_size},
        )

    # 4. Check for Pickle (Magic bytes \x80\x02 ... \x80\x05)
    if is_pickle_content(file_path):
        # Even if extension is .onnx or .safetensors, actual content is pickle
        if ext in (".pt", ".pth", ".bin") and not ext.endswith(".pkl"):
            # Raw legacy PyTorch state_dict
            return FormatDetectionResult(
                format=ModelFormat.PYTORCH_STATE_DICT,
                policy=POLICY_MAP[ModelFormat.PYTORCH_STATE_DICT],
                detected_by="pickle_stream_pytorch_hint",
                confidence=0.90,
                container_type="flat",
                details={"extension": ext},
            )
        else:
            return FormatDetectionResult(
                format=ModelFormat.PICKLE,
                policy=POLICY_MAP[ModelFormat.PICKLE],
                detected_by="pickle_protocol_magic",
                confidence=0.99,
                container_type="flat",
                details={"extension": ext},
            )

    # 5. Extension fallback / Corrupted check
    if ext == ".safetensors":
        # Header check failed -> corrupted safetensors
        return FormatDetectionResult(
            format=ModelFormat.CORRUPTED,
            policy=POLICY_MAP[ModelFormat.CORRUPTED],
            detected_by="malformed_safetensors_extension_mismatch",
            confidence=0.85,
            container_type="flat",
            details={"extension": ext},
        )
    elif ext == ".onnx":
        return FormatDetectionResult(
            format=ModelFormat.CORRUPTED,
            policy=POLICY_MAP[ModelFormat.CORRUPTED],
            detected_by="malformed_onnx_extension_mismatch",
            confidence=0.85,
            container_type="flat",
            details={"extension": ext},
        )
    elif ext in (".pt", ".pth", ".bin", ".pt2"):
        return FormatDetectionResult(
            format=ModelFormat.CORRUPTED,
            policy=POLICY_MAP[ModelFormat.CORRUPTED],
            detected_by="malformed_pytorch_extension_mismatch",
            confidence=0.85,
            container_type="flat",
            details={"extension": ext},
        )
    elif ext in (".pkl", ".pickle"):
        return FormatDetectionResult(
            format=ModelFormat.PICKLE,
            policy=POLICY_MAP[ModelFormat.PICKLE],
            detected_by="pickle_extension",
            confidence=0.90,
            container_type="flat",
            details={"extension": ext},
        )

    return FormatDetectionResult(
        format=ModelFormat.UNKNOWN,
        policy=POLICY_MAP[ModelFormat.UNKNOWN],
        detected_by="unrecognized_magic_bytes",
        confidence=0.0,
        container_type="flat",
        details={"extension": ext, "file_size": file_size},
    )
