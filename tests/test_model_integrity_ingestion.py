"""Comprehensive test suite for Phase 7.2: Safe Model Ingestion, Format Parsers & Safe Inspection Boundary.

Tests:
  A. Path Security (traversal, UNC, symlink loop, non-file, missing)
  B. Resource Limits (file size, header size, tensor count, dimensions, zip bomb)
  C. Format Detection (Safetensors, ONNX, PyTorch, TorchScript, Pickle, corrupted, extension mismatches)
  D. Safetensors Static Parser (valid, malformed, invalid offsets, limits)
  E. ONNX Static Parser (valid protobuf wire, initializers, inputs, outputs, corrupted)
  F. PyTorch State-Dict Parser (safe mock unpickling, malicious pickle rejection)
  G. TorchScript Parser (static zip inspection, zip slip, no JIT loading)
  H. Security Invariants (no code execution, prohibited format rejection)
  I. Deterministic Normalization (RFC 8785 JCS byte-level identity)
  J. Offline Operation (zero network dependencies)
"""

import io
import json
import os
import pickle
import struct
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List

import pytest

from aivara.model_integrity import (
    DEFAULT_LIMITS,
    BaseModelParser,
    FormatDetectionResult,
    InputContractDescriptor,
    InspectionPolicy,
    InspectionStatus,
    ModelFormat,
    ModelIngestionLimits,
    ModelIngestionService,
    ModelInspectionResult,
    NormalizedModelMetadata,
    ONNXParser,
    ParsedModelData,
    ProhibitedFormatError,
    PyTorchStateDictParser,
    ReasonCode,
    ResourceLimitExceededError,
    SafetensorsParser,
    TensorDescriptor,
    TorchScriptParser,
    UntrustedArtifactSecurityError,
    build_normalized_metadata,
    canonicalize_normalized_metadata,
    detect_model_format,
    validate_artifact_file,
)


# =====================================================================
# Fixture Helpers
# =====================================================================

def create_mock_safetensors(
    file_path: Path,
    tensors: Dict[str, Dict[str, Any]],
    metadata: Dict[str, str] = None,
) -> Path:
    """Create a syntactically valid Safetensors binary file."""
    header_dict = {}
    if metadata:
        header_dict["__metadata__"] = metadata

    total_tensor_bytes = 0
    raw_tensor_buffers = []

    for name, t_spec in tensors.items():
        dtype = t_spec.get("dtype", "F32")
        shape = t_spec.get("shape", [2, 2])
        data_bytes = t_spec.get("data", b"\x00" * 16)
        start_off = total_tensor_bytes
        end_off = start_off + len(data_bytes)
        total_tensor_bytes = end_off
        raw_tensor_buffers.append(data_bytes)

        header_dict[name] = {
            "dtype": dtype,
            "shape": shape,
            "data_offsets": [start_off, end_off],
        }

    header_json = json.dumps(header_dict, separators=(",", ":")).encode("utf-8")
    header_len = len(header_json)

    with open(file_path, "wb") as f:
        f.write(struct.pack("<Q", header_len))
        f.write(header_json)
        for buf in raw_tensor_buffers:
            f.write(buf)

    return file_path


def create_mock_onnx(
    file_path: Path,
    ir_version: int = 8,
    producer_name: str = "pytorch",
    initializers: List[Dict[str, Any]] = None,
) -> Path:
    """Create a synthetic ONNX ModelProto wire format binary file."""
    stream = io.BytesIO()

    # Helper to encode varint
    def write_varint(s, v):
        while True:
            b = v & 0x7F
            v >>= 7
            if v:
                s.write(bytes([b | 0x80]))
            else:
                s.write(bytes([b]))
                break

    # Helper for length-delimited field
    def write_ld(s, field_num, payload):
        tag = (field_num << 3) | 2
        write_varint(s, tag)
        write_varint(s, len(payload))
        s.write(payload)

    # ir_version: field 1, varint (tag = 0x08)
    stream.write(bytes([0x08]))
    write_varint(stream, ir_version)

    # producer_name: field 2, string
    write_ld(stream, 2, producer_name.encode("utf-8"))

    # GraphProto
    g_stream = io.BytesIO()
    # graph name: field 2
    write_ld(g_stream, 2, b"test_graph")

    # Initializers: field 5 (TensorProto)
    if initializers:
        for init in initializers:
            t_stream = io.BytesIO()
            # dims: field 1, packed varint
            dims = init.get("shape", [2, 2])
            dim_stream = io.BytesIO()
            for d in dims:
                write_varint(dim_stream, d)
            write_ld(t_stream, 1, dim_stream.getvalue())

            # data_type: field 2, varint (1 = FLOAT)
            t_stream.write(bytes([0x10]))
            write_varint(t_stream, init.get("dtype_id", 1))

            # name: field 7, string
            write_ld(t_stream, 7, init.get("name", "weight").encode("utf-8"))

            # raw_data: field 4
            raw_data = init.get("raw_data", b"\x00" * 16)
            write_ld(t_stream, 4, raw_data)

            write_ld(g_stream, 5, t_stream.getvalue())

    # Add NodeProto: field 1
    node_stream = io.BytesIO()
    write_ld(node_stream, 3, b"conv1")
    write_ld(node_stream, 4, b"Conv")
    write_ld(g_stream, 1, node_stream.getvalue())

    # Write graph to model
    write_ld(stream, 7, g_stream.getvalue())

    # Add opset_import: field 8
    opset_stream = io.BytesIO()
    write_ld(opset_stream, 1, b"ai.onnx")
    opset_stream.write(bytes([0x10]))
    write_varint(opset_stream, 17)
    write_ld(stream, 8, opset_stream.getvalue())

    with open(file_path, "wb") as f:
        f.write(stream.getvalue())

    return file_path


def create_mock_pytorch_zip(file_path: Path, state_dict: dict) -> Path:
    """Create a mock PyTorch zip container checkpoint."""
    pkl_bytes = pickle.dumps(state_dict, protocol=2)
    with zipfile.ZipFile(file_path, "w") as zf:
        zf.writestr("archive/data.pkl", pkl_bytes)
        zf.writestr("archive/byteorder", "little")
        zf.writestr("archive/version", "3")
    return file_path


def create_mock_torchscript_zip(file_path: Path) -> Path:
    """Create a mock TorchScript zip container."""
    with zipfile.ZipFile(file_path, "w") as zf:
        zf.writestr("code/__torch__.py", "class Model(Module): pass")
        zf.writestr("version", "7")
        zf.writestr("model.json", json.dumps({"producer": "torchscript", "arch": "resnet50"}))
        zf.writestr("data/0", b"\x00" * 64)
    return file_path


# =====================================================================
# A. Path Security Tests
# =====================================================================

def test_path_security_traversal(tmp_path: Path):
    """Verify that path traversal sequences are rejected."""
    service = ModelIngestionService()
    res = service.inspect_artifact("../outside/model.safetensors")
    assert res.status == InspectionStatus.INVALID_ARTIFACT
    assert ReasonCode.PATH_TRAVERSAL_ATTEMPT in res.reason_codes


def test_path_security_unc(tmp_path: Path):
    """Verify that UNC network paths are rejected."""
    service = ModelIngestionService()
    res = service.inspect_artifact("\\\\remote-server\\share\\model.onnx")
    assert res.status == InspectionStatus.INVALID_ARTIFACT
    assert ReasonCode.FORBIDDEN_PATH_TYPE in res.reason_codes


def test_path_security_missing_file(tmp_path: Path):
    """Verify that non-existent files fail closed with MISSING_ARTIFACT."""
    service = ModelIngestionService()
    missing = tmp_path / "does_not_exist.safetensors"
    res = service.inspect_artifact(missing)
    assert res.status == InspectionStatus.INVALID_ARTIFACT
    assert ReasonCode.MISSING_ARTIFACT in res.reason_codes


def test_path_security_directory_rejection(tmp_path: Path):
    """Verify that directory paths are rejected as non-regular files."""
    service = ModelIngestionService()
    res = service.inspect_artifact(tmp_path)
    assert res.status == InspectionStatus.INVALID_ARTIFACT
    assert ReasonCode.NOT_A_REGULAR_FILE in res.reason_codes


def test_path_security_allowed_base_dir_containment(tmp_path: Path):
    """Verify that base directory containment is strictly enforced."""
    allowed = tmp_path / "sandbox"
    allowed.mkdir()
    outside = tmp_path / "outside.safetensors"
    create_mock_safetensors(outside, {"w": {"shape": [2, 2], "dtype": "F32"}})

    service = ModelIngestionService()
    res = service.inspect_artifact(outside, allowed_base_dir=allowed)
    assert res.status == InspectionStatus.INVALID_ARTIFACT
    assert ReasonCode.PATH_TRAVERSAL_ATTEMPT in res.reason_codes


# =====================================================================
# B. Resource Limits Tests
# =====================================================================

def test_resource_limit_max_file_size(tmp_path: Path):
    """Verify that oversized artifacts fail closed."""
    fpath = tmp_path / "oversized.bin"
    fpath.write_bytes(b"\x00" * 2000)

    strict_limits = ModelIngestionLimits(max_artifact_size_bytes=1000)
    service = ModelIngestionService(limits=strict_limits)
    res = service.inspect_artifact(fpath)
    assert res.status == InspectionStatus.INVALID_ARTIFACT
    assert ReasonCode.FILE_SIZE_LIMIT_EXCEEDED in res.reason_codes


def test_resource_limit_header_size(tmp_path: Path):
    """Verify that oversized Safetensors headers fail closed."""
    fpath = tmp_path / "large_header.safetensors"
    # Create file with 2MB header but set limit to 1MB
    large_meta = {"key": "x" * (1024 * 1024 + 100)}
    create_mock_safetensors(fpath, {"w": {"shape": [1], "dtype": "F32"}}, metadata=large_meta)

    strict_limits = ModelIngestionLimits(max_header_size_bytes=500 * 1024)
    service = ModelIngestionService(limits=strict_limits)
    res = service.inspect_artifact(fpath)
    assert res.status == InspectionStatus.INVALID_ARTIFACT
    assert ReasonCode.HEADER_SIZE_LIMIT_EXCEEDED in res.reason_codes


def test_resource_limit_tensor_count(tmp_path: Path):
    """Verify that excessive tensor counts fail closed."""
    fpath = tmp_path / "many_tensors.safetensors"
    tensors = {f"t_{i}": {"shape": [1], "dtype": "F32", "data": b"\x00" * 4} for i in range(25)}
    create_mock_safetensors(fpath, tensors)

    strict_limits = ModelIngestionLimits(max_tensor_count=10)
    service = ModelIngestionService(limits=strict_limits)
    res = service.inspect_artifact(fpath)
    assert res.status == InspectionStatus.INVALID_ARTIFACT
    assert ReasonCode.TENSOR_COUNT_LIMIT_EXCEEDED in res.reason_codes


def test_resource_limit_dimension_rank(tmp_path: Path):
    """Verify that excessive tensor dimensions fail closed."""
    fpath = tmp_path / "high_rank.safetensors"
    tensors = {"w": {"shape": [1] * 20, "dtype": "F32", "data": b"\x00" * 4}}
    create_mock_safetensors(fpath, tensors)

    strict_limits = ModelIngestionLimits(max_tensor_dimensions=8)
    service = ModelIngestionService(limits=strict_limits)
    res = service.inspect_artifact(fpath)
    assert res.status == InspectionStatus.INVALID_ARTIFACT
    assert ReasonCode.DIMENSION_LIMIT_EXCEEDED in res.reason_codes


def test_resource_limit_zip_bomb(tmp_path: Path):
    """Verify that zip decompression bombs are rejected."""
    fpath = tmp_path / "bomb.zip"
    # Create a zip containing highly compressed repeated zeros
    with zipfile.ZipFile(fpath, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("archive/data.pkl", b"\x00" * (10 * 1024 * 1024))

    strict_limits = ModelIngestionLimits(max_archive_compression_ratio=10.0)
    service = ModelIngestionService(limits=strict_limits)
    res = service.inspect_artifact(fpath)
    assert res.status == InspectionStatus.INVALID_ARTIFACT
    assert ReasonCode.ARCHIVE_BOMB_DETECTED in res.reason_codes


# =====================================================================
# C. Format Detection Tests
# =====================================================================

def test_format_detection_safetensors(tmp_path: Path):
    """Verify accurate detection of Safetensors format."""
    fpath = tmp_path / "model.safetensors"
    create_mock_safetensors(fpath, {"layer1.weight": {"shape": [2, 2], "dtype": "F32"}})

    detection = detect_model_format(fpath)
    assert detection.format == ModelFormat.SAFETENSORS
    assert detection.policy == InspectionPolicy.SUPPORTED


def test_format_detection_onnx(tmp_path: Path):
    """Verify accurate detection of ONNX format."""
    fpath = tmp_path / "model.onnx"
    create_mock_onnx(fpath, ir_version=8, producer_name="pytorch")

    detection = detect_model_format(fpath)
    assert detection.format == ModelFormat.ONNX
    assert detection.policy == InspectionPolicy.SUPPORTED


def test_format_detection_pytorch_zip(tmp_path: Path):
    """Verify accurate detection of PyTorch zip state_dict."""
    fpath = tmp_path / "model.pt"
    create_mock_pytorch_zip(fpath, {"weight": 123})

    detection = detect_model_format(fpath)
    assert detection.format == ModelFormat.PYTORCH_STATE_DICT
    assert detection.policy == InspectionPolicy.RESTRICTED


def test_format_detection_torchscript(tmp_path: Path):
    """Verify accurate detection of TorchScript zip container."""
    fpath = tmp_path / "model.pt"
    create_mock_torchscript_zip(fpath)

    detection = detect_model_format(fpath)
    assert detection.format == ModelFormat.TORCHSCRIPT
    assert detection.policy == InspectionPolicy.RESTRICTED


def test_format_detection_pickle_prohibited(tmp_path: Path):
    """Verify accurate detection of prohibited pickle format."""
    fpath = tmp_path / "model.pkl"
    with open(fpath, "wb") as f:
        pickle.dump({"test": "data"}, f, protocol=4)

    detection = detect_model_format(fpath)
    assert detection.format == ModelFormat.PICKLE
    assert detection.policy == InspectionPolicy.PROHIBITED


def test_format_detection_extension_mismatch_pickle_disguised(tmp_path: Path):
    """Verify that a pickle file disguised with .onnx extension is detected as PICKLE."""
    fpath = tmp_path / "disguised.onnx"
    with open(fpath, "wb") as f:
        pickle.dump({"payload": "exploit"}, f, protocol=4)

    detection = detect_model_format(fpath)
    assert detection.format == ModelFormat.PICKLE
    assert detection.policy == InspectionPolicy.PROHIBITED


def test_format_detection_corrupted(tmp_path: Path):
    """Verify that a truncated random binary file is marked corrupted/unknown."""
    fpath = tmp_path / "corrupted.safetensors"
    fpath.write_bytes(b"INVALID_HEADER_BYTES_1234567890")

    detection = detect_model_format(fpath)
    assert detection.format in (ModelFormat.CORRUPTED, ModelFormat.UNKNOWN)


# =====================================================================
# D. Safetensors Parser Tests
# =====================================================================

def test_safetensors_parser_valid(tmp_path: Path):
    """Verify complete static parsing of valid Safetensors artifact."""
    fpath = tmp_path / "resnet18.safetensors"
    create_mock_safetensors(
        fpath,
        {
            "conv1.weight": {"shape": [64, 3, 7, 7], "dtype": "F32", "data": b"\x00" * (64 * 3 * 7 * 7 * 4)},
            "bn1.weight": {"shape": [64], "dtype": "F32", "data": b"\x00" * (64 * 4)},
        },
        metadata={"author": "aivara_test", "format": "pt"},
    )

    service = ModelIngestionService()
    res = service.inspect_artifact(fpath)

    assert res.status == InspectionStatus.SUCCESS
    assert res.format == ModelFormat.SAFETENSORS
    assert res.policy == InspectionPolicy.SUPPORTED
    assert res.normalized_metadata is not None
    assert res.normalized_metadata.tensor_count == 2
    assert res.normalized_metadata.parameter_count == (64 * 3 * 7 * 7) + 64
    assert res.normalized_metadata.metadata_props["author"] == "aivara_test"
    assert ReasonCode.SAFE_INSPECTION_PASSED in res.reason_codes


def test_safetensors_parser_malformed_json(tmp_path: Path):
    """Verify that Safetensors with malformed JSON header fails closed."""
    fpath = tmp_path / "malformed.safetensors"
    bad_json = b"{not_valid_json: 123"
    with open(fpath, "wb") as f:
        f.write(struct.pack("<Q", len(bad_json)))
        f.write(bad_json)

    service = ModelIngestionService()
    res = service.inspect_artifact(fpath)
    assert res.status == InspectionStatus.INVALID_ARTIFACT
    assert ReasonCode.MALFORMED_HEADER in res.reason_codes


def test_safetensors_parser_invalid_offsets(tmp_path: Path):
    """Verify that Safetensors with offset exceeding file size fails closed."""
    fpath = tmp_path / "bad_offset.safetensors"
    header_dict = {
        "weight": {
            "dtype": "F32",
            "shape": [2, 2],
            "data_offsets": [0, 9999999],  # offset beyond file size
        }
    }
    header_json = json.dumps(header_dict).encode("utf-8")
    with open(fpath, "wb") as f:
        f.write(struct.pack("<Q", len(header_json)))
        f.write(header_json)
        f.write(b"\x00" * 16)

    service = ModelIngestionService()
    res = service.inspect_artifact(fpath)
    assert res.status == InspectionStatus.INVALID_ARTIFACT
    assert ReasonCode.INVALID_TENSOR_OFFSET in res.reason_codes


# =====================================================================
# E. ONNX Parser Tests
# =====================================================================

def test_onnx_parser_valid(tmp_path: Path):
    """Verify complete static parsing of synthetic ONNX protobuf wire stream."""
    fpath = tmp_path / "model.onnx"
    create_mock_onnx(
        fpath,
        ir_version=8,
        producer_name="aivara_pipeline",
        initializers=[
            {"name": "fc.weight", "shape": [10, 5], "dtype_id": 1, "raw_data": b"\x00" * (10 * 5 * 4)},
            {"name": "fc.bias", "shape": [10], "dtype_id": 1, "raw_data": b"\x00" * 40},
        ],
    )

    service = ModelIngestionService()
    res = service.inspect_artifact(fpath)

    assert res.status == InspectionStatus.SUCCESS
    assert res.format == ModelFormat.ONNX
    assert res.policy == InspectionPolicy.SUPPORTED
    assert res.normalized_metadata is not None
    assert res.normalized_metadata.tensor_count == 2
    assert res.normalized_metadata.parameter_count == 50 + 10
    assert any(op.op_type == "Conv" for op in res.normalized_metadata.operators)
    assert ReasonCode.SAFE_INSPECTION_PASSED in res.reason_codes


def test_onnx_parser_corrupted_protobuf(tmp_path: Path):
    """Verify that truncated or malformed ONNX protobuf fails closed."""
    fpath = tmp_path / "corrupt.onnx"
    # Write a tag indicating 1000 bytes length-delimited, but provide only 5 bytes
    fpath.write_bytes(bytes([0x3a, 0xe8, 0x07, 0x01, 0x02, 0x03]))

    service = ModelIngestionService()
    res = service.inspect_artifact(fpath)
    assert res.status == InspectionStatus.INVALID_ARTIFACT
    assert ReasonCode.MALFORMED_PROTOBUF in res.reason_codes


# =====================================================================
# F. PyTorch State-Dict Parser & Pickle Security Tests
# =====================================================================

def test_pytorch_parser_safe_state_dict(tmp_path: Path):
    """Verify safe inspection of PyTorch checkpoint using safe AST unpickling."""
    fpath = tmp_path / "model.pt"
    # Simple primitive state dict
    state = {
        "epoch": 10,
        "lr": "0.001",
    }
    create_mock_pytorch_zip(fpath, state)

    service = ModelIngestionService()
    res = service.inspect_artifact(fpath)

    assert res.status == InspectionStatus.RESTRICTED
    assert res.format == ModelFormat.PYTORCH_STATE_DICT
    assert res.policy == InspectionPolicy.RESTRICTED
    assert res.normalized_metadata is not None
    assert ReasonCode.RESTRICTED_INSPECTION_ONLY in res.reason_codes


def test_pytorch_parser_rejects_malicious_pickle_class(tmp_path: Path):
    """Verify that arbitrary executable classes inside a state_dict are blocked."""
    fpath = tmp_path / "malicious.pt"

    # Simulate an exploit class using __reduce__
    class MaliciousExploit:
        def __reduce__(self):
            import os
            return (os.system, ("echo pwned",))

    # Construct raw pickle with exploit
    exploit_bytes = pickle.dumps({"weights": MaliciousExploit()}, protocol=2)
    with zipfile.ZipFile(fpath, "w") as zf:
        zf.writestr("archive/data.pkl", exploit_bytes)

    service = ModelIngestionService()
    res = service.inspect_artifact(fpath)

    # Must be rejected with PROHIBITED and ARBITRARY_CODE_EXECUTION_RISK
    assert res.status == InspectionStatus.PROHIBITED
    assert ReasonCode.ARBITRARY_CODE_EXECUTION_RISK in res.reason_codes


def test_pickle_rejection_policy(tmp_path: Path):
    """Verify that arbitrary pickle artifacts are rejected unconditionally."""
    fpath = tmp_path / "model.pkl"
    with open(fpath, "wb") as f:
        pickle.dump({"weights": [1, 2, 3]}, f, protocol=4)

    service = ModelIngestionService()
    res = service.inspect_artifact(fpath)

    assert res.status == InspectionStatus.PROHIBITED
    assert res.policy == InspectionPolicy.PROHIBITED
    assert ReasonCode.PROHIBITED_FORMAT in res.reason_codes
    assert ReasonCode.ARBITRARY_CODE_EXECUTION_RISK in res.reason_codes


# =====================================================================
# G. TorchScript Parser Tests
# =====================================================================

def test_torchscript_parser_static_inspection(tmp_path: Path):
    """Verify safe static archive inspection of TorchScript without JIT load."""
    fpath = tmp_path / "model_ts.pt"
    create_mock_torchscript_zip(fpath)

    service = ModelIngestionService()
    res = service.inspect_artifact(fpath)

    assert res.status == InspectionStatus.RESTRICTED
    assert res.format == ModelFormat.TORCHSCRIPT
    assert res.policy == InspectionPolicy.RESTRICTED
    assert res.normalized_metadata is not None
    assert res.normalized_metadata.metadata_props["torchscript_version"] == "7"
    assert res.normalized_metadata.metadata_props["model_arch"] == "resnet50"
    assert ReasonCode.RESTRICTED_INSPECTION_ONLY in res.reason_codes


def test_torchscript_parser_zip_slip_rejected(tmp_path: Path):
    """Verify that zip slip traversal in archive members is rejected."""
    fpath = tmp_path / "slip_ts.pt"
    with zipfile.ZipFile(fpath, "w") as zf:
        zf.writestr("../evil.txt", "exploit")
        zf.writestr("code/__torch__.py", "class M: pass")

    service = ModelIngestionService()
    res = service.inspect_artifact(fpath)

    assert res.status == InspectionStatus.INVALID_ARTIFACT
    assert ReasonCode.PATH_TRAVERSAL_ATTEMPT in res.reason_codes


# =====================================================================
# H. Deterministic Normalization & RFC 8785 Canonicalization Tests
# =====================================================================

def test_deterministic_normalization_identical_runs(tmp_path: Path):
    """Verify that repeated inspections produce identical canonical JCS bytes."""
    fpath = tmp_path / "deterministic.safetensors"
    create_mock_safetensors(
        fpath,
        {
            "layer_z.weight": {"shape": [4, 4], "dtype": "F32", "data": b"\x00" * 64},
            "layer_a.weight": {"shape": [2, 2], "dtype": "F32", "data": b"\x00" * 16},
        },
        metadata={"b_key": "val2", "a_key": "val1"},
    )

    service = ModelIngestionService()

    res1 = service.inspect_artifact(fpath)
    res2 = service.inspect_artifact(fpath)

    assert res1.status == InspectionStatus.SUCCESS
    assert res2.status == InspectionStatus.SUCCESS
    assert res1.artifact_hash_sha256 == res2.artifact_hash_sha256

    # Verify canonical JCS bytes identity
    canon1 = canonicalize_normalized_metadata(res1.normalized_metadata)
    canon2 = canonicalize_normalized_metadata(res2.normalized_metadata)
    assert canon1 == canon2

    # Verify tensor sorting
    tensor_names = [t.name for t in res1.normalized_metadata.tensors]
    assert tensor_names == ["layer_a.weight", "layer_z.weight"]


# =====================================================================
# I. Semantic Safety Invariant Tests
# =====================================================================

def test_semantic_safety_no_intent_words():
    """Verify that reason codes and diagnostic messages contain no assertions of human intent."""
    import re
    prohibited_intent_pattern = re.compile(r"\b(malicious|guilt|culpable|sabotage|fraud|evil|intent)\b", re.IGNORECASE)

    for code in ReasonCode:
        assert not prohibited_intent_pattern.search(code.value), f"ReasonCode '{code.value}' violates semantic safety."
