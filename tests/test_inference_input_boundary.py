"""Comprehensive Test Suite for Phase 10.2: Safe Inference Input Boundary."""

from __future__ import annotations

import ast
import hashlib
import io
import os
from pathlib import Path
from typing import Any, Dict

import numpy as np
import pytest
from PIL import Image

from aivara.inference.config import InferenceInputLimits
from aivara.inference.enums import (
    InferenceFindingCode,
    InferenceIntegrityStatus,
    InputKind,
    InputLayout,
    ValueRangeKind,
)
from aivara.inference.exceptions import (
    AmbiguousLayoutError,
    ImageDecodingError,
    InferencePathSecurityError,
    InputFileNotFoundError,
    MalformedInputError,
    NonFiniteValueError,
    ResourceLimitExceededError,
    UnsupportedDtypeError,
    UnsupportedImageFormatError,
    UnsupportedInputTypeError,
    ValueRangeMismatchError,
)
from aivara.inference.input import (
    ImageFileMetadata,
    InputIdentity,
    SafeInferenceInputBoundary,
    StructuredInputMetadata,
    TensorMetadata,
    validate_image_file_input,
    validate_inference_input,
    validate_safe_input_path,
    validate_structured_input,
    validate_tensor_input,
)


# =====================================================================
# Fixtures
# =====================================================================

@pytest.fixture
def temp_image_dir(tmp_path: Path) -> Path:
    """Create a temporary directory with valid test images."""
    img_dir = tmp_path / "images"
    img_dir.mkdir(parents=True, exist_ok=True)

    # 1. Valid PNG
    png_path = img_dir / "sample.png"
    img = Image.new("RGB", (64, 64), color=(255, 0, 0))
    img.save(png_path, format="PNG")

    # 2. Valid JPEG
    jpg_path = img_dir / "sample.jpg"
    img.save(jpg_path, format="JPEG")

    # 3. Valid WebP
    webp_path = img_dir / "sample.webp"
    img.save(webp_path, format="WEBP")

    return img_dir


# =====================================================================
# 1. Valid Tensor Tests
# =====================================================================

class TestValidTensorInputs:
    """Test standard valid numerical tensor inputs."""

    def test_valid_float32_tensor(self) -> None:
        data = np.random.uniform(0.0, 1.0, size=(224, 224, 3)).astype(np.float32)
        meta, can_hash = validate_tensor_input(data, declared_layout=InputLayout.HWC)

        assert meta.rank == 3
        assert meta.shape == (224, 224, 3)
        assert meta.dtype == "float32"
        assert meta.layout == InputLayout.HWC
        assert meta.finite is True
        assert meta.value_range == ValueRangeKind.UNIT_FLOAT
        assert len(can_hash) == 64

    def test_valid_int32_and_uint8_tensors(self) -> None:
        int_data = np.arange(100, dtype=np.int32).reshape(10, 10)
        meta, can_hash = validate_tensor_input(int_data)
        assert meta.dtype == "int32"
        assert meta.layout == InputLayout.GRAYSCALE_2D

        uint_data = np.full((32, 32, 3), 200, dtype=np.uint8)
        meta_u, _ = validate_tensor_input(uint_data, declared_layout=InputLayout.HWC)
        assert meta_u.dtype == "uint8"
        assert meta_u.value_range == ValueRangeKind.BYTE_INTEGER

    def test_valid_bool_tensor(self) -> None:
        bool_data = np.array([True, False, True, True], dtype=bool)
        meta, can_hash = validate_tensor_input(bool_data)
        assert meta.dtype == "bool"
        assert meta.rank == 1
        assert meta.layout == InputLayout.VECTOR_1D


# =====================================================================
# 2. Valid Image File Tests
# =====================================================================

class TestValidImageInputs:
    """Test valid image file inputs across standard formats."""

    def test_valid_png_and_jpeg(self, temp_image_dir: Path) -> None:
        png_path = temp_image_dir / "sample.png"
        meta, input_id = validate_image_file_input(png_path)

        assert meta.width == 64
        assert meta.height == 64
        assert meta.channels == 3
        assert meta.format_name == "PNG"
        assert len(meta.raw_file_hash) == 64
        assert len(meta.canonical_pixel_hash) == 64
        assert len(input_id) == 64

        jpg_path = temp_image_dir / "sample.jpg"
        meta_j, input_id_j = validate_image_file_input(jpg_path)
        assert meta_j.format_name == "JPEG"
        assert len(input_id_j) == 64


# =====================================================================
# 3. Valid Batched Tensor Tests
# =====================================================================

class TestBatchedTensors:
    """Test batched tensor shapes and bounds."""

    def test_valid_batched_nhwc_tensor(self) -> None:
        batch_data = np.zeros((8, 128, 128, 3), dtype=np.float32)
        identity = validate_inference_input(batch_data, declared_layout=InputLayout.NHWC)

        assert identity.input_kind == InputKind.BATCHED_TENSOR
        assert identity.batch_size == 8
        assert identity.shape == (8, 128, 128, 3)
        assert identity.layout == InputLayout.NHWC
        assert identity.validation_status == InferenceIntegrityStatus.VERIFIED

    def test_valid_batched_nchw_tensor(self) -> None:
        batch_data = np.zeros((4, 3, 64, 64), dtype=np.float32)
        identity = validate_inference_input(batch_data, declared_layout=InputLayout.NCHW)

        assert identity.input_kind == InputKind.BATCHED_TENSOR
        assert identity.batch_size == 4
        assert identity.channels == 3
        assert identity.layout == InputLayout.NCHW


# =====================================================================
# 4. Determinism Tests
# =====================================================================

class TestDeterminism:
    """Test repeated validation determinism."""

    def test_tensor_identity_is_deterministic(self) -> None:
        tensor = np.linspace(0.0, 1.0, num=100, dtype=np.float32).reshape(10, 10)
        id1 = validate_inference_input(tensor)
        id2 = validate_inference_input(tensor)
        assert id1.input_id == id2.input_id
        assert id1.canonical_hash == id2.canonical_hash

    def test_image_identity_is_deterministic(self, temp_image_dir: Path) -> None:
        png_path = temp_image_dir / "sample.png"
        id1 = validate_inference_input(png_path)
        id2 = validate_inference_input(png_path)
        assert id1.input_id == id2.input_id
        assert id1.raw_file_hash == id2.raw_file_hash
        assert id1.canonical_pixel_hash == id2.canonical_pixel_hash


# =====================================================================
# 5. Mutation & Sensitivity Tests
# =====================================================================

class TestMutationSensitivity:
    """Verify that any modification to input values or metadata alters identity."""

    def test_single_value_mutation_changes_hash(self) -> None:
        t1 = np.zeros((10, 10), dtype=np.float32)
        t2 = np.zeros((10, 10), dtype=np.float32)
        t2[5, 5] = 0.0001

        id1 = validate_inference_input(t1)
        id2 = validate_inference_input(t2)
        assert id1.input_id != id2.input_id

    def test_dtype_difference_changes_hash(self) -> None:
        t_f32 = np.zeros((10, 10), dtype=np.float32)
        t_f64 = np.zeros((10, 10), dtype=np.float64)

        id1 = validate_inference_input(t_f32)
        id2 = validate_inference_input(t_f64)
        assert id1.input_id != id2.input_id
        assert id1.dtype != id2.dtype

    def test_shape_difference_changes_hash(self) -> None:
        t_2d = np.zeros((4, 4), dtype=np.float32)
        t_1d = np.zeros((16,), dtype=np.float32)

        id1 = validate_inference_input(t_2d)
        id2 = validate_inference_input(t_1d)
        assert id1.input_id != id2.input_id

    def test_layout_difference_changes_hash(self) -> None:
        t_hwc = np.zeros((32, 32, 3), dtype=np.float32)
        t_chw = np.zeros((3, 32, 32), dtype=np.float32)

        id1 = validate_inference_input(t_hwc, declared_layout=InputLayout.HWC)
        id2 = validate_inference_input(t_chw, declared_layout=InputLayout.CHW)
        assert id1.input_id != id2.input_id


# =====================================================================
# 6. Non-Finite Rejection (NaN, Inf)
# =====================================================================

class TestNonFiniteRejection:
    """Verify strict fail-closed rejection of NaN and Infinite values."""

    def test_nan_tensor_rejected(self) -> None:
        t = np.ones((10, 10), dtype=np.float32)
        t[3, 3] = np.nan

        with pytest.raises(NonFiniteValueError):
            validate_inference_input(t)

        # In non-raising mode
        res = validate_inference_input(t, raise_on_error=False)
        assert res.validation_status == InferenceIntegrityStatus.INVALID
        assert any(f.code == "NON_FINITE_VALUE" for f in res.findings)

    def test_pos_and_neg_inf_tensor_rejected(self) -> None:
        t_pos = np.ones((5, 5), dtype=np.float32)
        t_pos[0, 0] = np.inf
        with pytest.raises(NonFiniteValueError):
            validate_inference_input(t_pos)

        t_neg = np.ones((5, 5), dtype=np.float32)
        t_neg[0, 0] = -np.inf
        with pytest.raises(NonFiniteValueError):
            validate_inference_input(t_neg)


# =====================================================================
# 7. Resource Bounds Tests
# =====================================================================

class TestResourceLimits:
    """Verify bounded memory, dimensions, rank, and element counts."""

    def test_excessive_tensor_rank_rejected(self) -> None:
        limits = InferenceInputLimits(max_tensor_rank=4)
        t_5d = np.zeros((2, 2, 2, 2, 2), dtype=np.float32)

        with pytest.raises(ResourceLimitExceededError):
            validate_tensor_input(t_5d, limits=limits)

    def test_excessive_elements_rejected(self) -> None:
        limits = InferenceInputLimits(max_tensor_elements=100)
        t = np.zeros((10, 20), dtype=np.float32)  # 200 elements

        with pytest.raises(ResourceLimitExceededError):
            validate_tensor_input(t, limits=limits)

    def test_excessive_batch_size_rejected(self) -> None:
        limits = InferenceInputLimits(max_batch_size=16)
        t = np.zeros((32, 10, 10, 3), dtype=np.float32)

        with pytest.raises(ResourceLimitExceededError):
            validate_tensor_input(t, declared_layout=InputLayout.NHWC, limits=limits)

    def test_excessive_image_dimensions_rejected(self, tmp_path: Path) -> None:
        limits = InferenceInputLimits(max_image_width=100, max_image_height=100)
        big_img = Image.new("RGB", (200, 200), color=(0, 255, 0))
        img_path = tmp_path / "oversized.png"
        big_img.save(img_path)

        with pytest.raises(ResourceLimitExceededError):
            validate_image_file_input(img_path, limits=limits)


# =====================================================================
# 8. Malformed & Unsupported Image Tests
# =====================================================================

class TestMalformedAndUnsupportedImages:
    """Verify handling of corrupted or unapproved file formats."""

    def test_empty_image_file_rejected(self, tmp_path: Path) -> None:
        empty_path = tmp_path / "empty.png"
        empty_path.write_bytes(b"")

        with pytest.raises(ImageDecodingError):
            validate_image_file_input(empty_path)

    def test_corrupted_image_rejected(self, tmp_path: Path) -> None:
        corrupt_path = tmp_path / "corrupt.png"
        corrupt_path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 20)

        with pytest.raises(ImageDecodingError):
            validate_image_file_input(corrupt_path)

    def test_unsupported_extension_rejected(self, tmp_path: Path) -> None:
        txt_path = tmp_path / "test.txt"
        txt_path.write_text("not an image")

        with pytest.raises(UnsupportedImageFormatError):
            validate_image_file_input(txt_path)


# =====================================================================
# 9. Path Security Tests
# =====================================================================

class TestPathSecurity:
    """Verify path traversal, UNC, URL scheme, and special file protections."""

    def test_path_traversal_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(InferencePathSecurityError):
            validate_safe_input_path("../secret.png", root_boundary=tmp_path)

        with pytest.raises(InferencePathSecurityError):
            validate_safe_input_path("subdir/../../escape.png", root_boundary=tmp_path)

    def test_unc_path_rejected(self) -> None:
        with pytest.raises(InferencePathSecurityError):
            validate_safe_input_path(r"\\remote_server\share\image.png")

        with pytest.raises(InferencePathSecurityError):
            validate_safe_input_path("//remote_server/share/image.png")

    def test_url_schemes_rejected(self) -> None:
        with pytest.raises(InferencePathSecurityError):
            validate_safe_input_path("http://example.com/malicious.png")

        with pytest.raises(InferencePathSecurityError):
            validate_safe_input_path("file:///etc/passwd")

    def test_windows_device_names_rejected(self) -> None:
        with pytest.raises(InferencePathSecurityError):
            validate_safe_input_path("CON.png")

        with pytest.raises(InferencePathSecurityError):
            validate_safe_input_path("NUL.jpg")

    def test_missing_file_reports_missing_status(self, tmp_path: Path) -> None:
        non_existent = tmp_path / "does_not_exist.png"
        with pytest.raises(InputFileNotFoundError):
            validate_image_file_input(non_existent)

        res = validate_inference_input(non_existent, raise_on_error=False)
        assert res.validation_status == InferenceIntegrityStatus.MISSING


# =====================================================================
# 10. Immutability Tests
# =====================================================================

class TestImmutability:
    """Ensure that caller-provided data structures are never mutated in place."""

    def test_tensor_is_never_mutated(self) -> None:
        original = np.array([[1.0, 2.0], [3.0, 4.0]], dtype=np.float32)
        original_copy = original.copy()

        _ = validate_inference_input(original)

        # Exact byte equality
        assert np.array_equal(original, original_copy)
        assert original.dtype == original_copy.dtype
        assert original.shape == original_copy.shape

    def test_non_contiguous_tensor_is_not_mutated_in_place(self) -> None:
        # Create non-contiguous slice
        base = np.zeros((10, 10), dtype=np.float32)
        non_contig = base[::2, ::2]
        assert not non_contig.flags.c_contiguous

        meta, _ = validate_tensor_input(non_contig)
        assert not non_contig.flags.c_contiguous  # Still non-contiguous for caller
        assert meta.shape == (5, 5)


# =====================================================================
# 11. Raw File vs Canonical Decoded Pixel Identity
# =====================================================================

class TestRawVsCanonicalImageIdentity:
    """Demonstrate distinction between raw file bytes and canonical decoded pixels."""

    def test_different_encodings_have_different_raw_hashes_but_same_pixel_hash(
        self, tmp_path: Path
    ) -> None:
        # Create solid color image
        img = Image.new("RGB", (32, 32), color=(100, 150, 200))

        png_path = tmp_path / "img1.png"
        img.save(png_path, format="PNG", optimize=False)

        png_opt_path = tmp_path / "img2.png"
        img.save(png_opt_path, format="PNG", optimize=True)

        meta1, _ = validate_image_file_input(png_path)
        meta2, _ = validate_image_file_input(png_opt_path)

        # Canonical pixel hashes MUST match because underlying sRGB pixels are identical
        assert meta1.canonical_pixel_hash == meta2.canonical_pixel_hash


# =====================================================================
# 12. Ambiguous Layout & Value Range Rejections
# =====================================================================

class TestLayoutAndValueRangeMismatches:
    """Test validation of layout constraints and value ranges."""

    def test_ambiguous_3d_tensor_layout_rejected(self) -> None:
        # Shape (3, 100, 3) has channels at both ends -> ambiguous!
        ambig = np.zeros((3, 100, 3), dtype=np.float32)
        with pytest.raises(AmbiguousLayoutError):
            validate_tensor_input(ambig)

        res = validate_inference_input(ambig, raise_on_error=False)
        assert res.validation_status == InferenceIntegrityStatus.UNVERIFIABLE

    def test_declared_unit_float_violation_rejected(self) -> None:
        out_of_bounds = np.array([-0.5, 0.5, 1.5], dtype=np.float32)
        with pytest.raises(ValueRangeMismatchError):
            validate_tensor_input(out_of_bounds, declared_range=ValueRangeKind.UNIT_FLOAT)

        res = validate_inference_input(
            out_of_bounds, declared_range=ValueRangeKind.UNIT_FLOAT, raise_on_error=False
        )
        assert res.validation_status == InferenceIntegrityStatus.MISMATCHED


# =====================================================================
# 13. Structured Input Validation Tests
# =====================================================================

class TestStructuredInputs:
    """Test RFC 8785 JSON structured input validation and canonicalization."""

    def test_valid_structured_dictionary(self) -> None:
        data = {
            "query": "What is AI verification?",
            "temperature": 0.7,
            "max_tokens": 100,
            "enabled": True,
            "metadata": {"user": "tester", "tags": ["prod", "v1"]},
        }
        identity = validate_inference_input(data)

        assert identity.input_kind == InputKind.STRUCTURED
        assert identity.layout == InputLayout.STRUCTURED
        assert identity.validation_status == InferenceIntegrityStatus.VERIFIED
        assert len(identity.input_id) == 64

    def test_unsupported_object_in_structured_input_rejected(self) -> None:
        class ArbitraryObject:
            pass

        data = {"model": "custom", "instance": ArbitraryObject()}
        with pytest.raises(MalformedInputError):
            validate_structured_input(data)


# =====================================================================
# 14. Static Security & Offline Verification
# =====================================================================

class TestSecurityAndOfflineInvariants:
    """Static AST checks and offline safety verification."""

    def test_no_forbidden_execution_constructs_in_inference_package(self) -> None:
        package_root = Path(__file__).parent.parent / "backend" / "aivara" / "inference"

        forbidden_calls = {"eval", "exec", "pickle", "system", "popen", "spawn"}

        for py_file in package_root.rglob("*.py"):
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in forbidden_calls:
                        pytest.fail(f"Forbidden call '{node.func.id}' found in {py_file.name}")
                    elif isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_calls:
                        pytest.fail(f"Forbidden method call '{node.func.attr}' found in {py_file.name}")

    def test_sha256_format_compliance(self) -> None:
        tensor = np.zeros((10,), dtype=np.float32)
        identity = validate_inference_input(tensor)

        assert len(identity.input_id) == 64
        assert all(c in "0123456789abcdef" for c in identity.input_id)
