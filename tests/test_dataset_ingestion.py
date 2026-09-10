"""Comprehensive unit test suite for Phase 5.2: Dataset Ingestion & Normalization Engine.

Covers:
  - COCO happy path, malformed JSON, missing fields, invalid references, invalid bounding boxes.
  - YOLO happy path (list/dict names, images/labels splits), malformed YAML, malformed annotations, coordinates.
  - ImageFolder happy path, nested directories, category labels.
  - Path traversal & sandboxing (.., absolute paths, Windows drive letters, UNC paths, symlink escapes).
  - All supported image formats (PNG, JPEG, WebP, BMP, TIFF).
  - Corrupt images, missing images, unsupported file extensions.
  - Deterministic ordering and reproducible canonical output.
  - Immutability of canonical domain representations.
  - Format detection, ambiguity, empty datasets, duplicate identifiers, Unicode paths.
  - 100% offline air-gapped execution.
"""

import json
import os
import socket
from pathlib import Path
import pytest
import yaml

from aivara.dataset import (
    CanonicalAnnotation,
    CanonicalBBox,
    CanonicalCategory,
    CanonicalDatasetManifest,
    CanonicalSample,
    DatasetFormat,
    DatasetIngester,
    DatasetIngestionError,
    DatasetIngestionResult,
    AmbiguousDatasetFormatError,
    CorruptedImageError,
    InvalidCategoryError,
    InvalidCoordinateError,
    InvalidDatasetConfigError,
    InvalidIdentifierError,
    InvalidImageError,
    MalformedAnnotationError,
    MalformedDatasetError,
    MissingImageError,
    PathTraversalError,
    SymlinkEscapeError,
    UnsupportedDatasetFormatError,
    detect_dataset_format,
    ingest_dataset,
)
from aivara.dataset.image_validator import inspect_image_file

# --- Minimal Valid Image Byte Fixtures ---
TINY_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x0a\x00\x00\x00\x0a\x08\x02\x00\x00\x00\x02\x0d\xb4\x9e"
    b"\x00\x00\x00\x1bIDATx\x9cc\xf8\xcf\xc0\xc0\xc0\x00\x03\x03\x03\x00\x18\xdd\x8d\xb0\x06\x18\x18\x18\x00"
    b"\x00\x00\xff\xff\x03\x00\x0c\xa6\x01\x81\x18\x85\xb0\xec\x00\x00\x00\x00IEND\xaeB`\x82"
)

TINY_JPEG = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05"
    b"\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c"
    b" $.\' \",#\x1c\x1c(7),01444\x1f\'9=82<.342\xff\xc0\x00\x11\x08\x00\x0a\x00\x0a\x03\x01\"\x00\x02\x11\x01"
    b"\x03\x11\x01\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01"
    b"\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00?\x00\xbf\x00\xff\xd9"
)

TINY_WEBP = (
    b"RIFF\x1a\x00\x00\x00WEBPVP8L\x0d\x00\x00\x00/\x09\x40\x02\x00\x07@@\xfe\x07\x00\x00"
)

TINY_BMP = (
    b"BM6\x00\x00\x00\x00\x00\x00\x006\x00\x00\x00(\x00\x00\x00\x0a\x00\x00\x00\x0a\x00\x00\x00\x01\x00\x18\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\x00"
)

TINY_TIFF = (
    b"II*\x00\x08\x00\x00\x00\x04\x00\x00\x01\x03\x00\x01\x00\x00\x00\n\x00\x00\x00\x01\x01\x03\x00\x01\x00\x00\x00"
    b"\n\x00\x00\x00\x06\x01\x03\x00\x01\x00\x00\x00\x02\x00\x00\x00\x15\x01\x03\x00\x01\x00\x00\x00\x03\x00\x00\x00"
    b"\x00\x00\x00\x00"
)


def _create_image_file(path: Path, img_bytes: bytes = TINY_PNG) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(img_bytes)
    return path


# =====================================================================
# 1. Image Header Inspection Tests (All Supported Raster Formats)
# =====================================================================

def test_image_validator_png(tmp_path: Path):
    img = _create_image_file(tmp_path / "test.png", TINY_PNG)
    meta = inspect_image_file(img)
    assert meta.width == 10
    assert meta.height == 10
    assert meta.channels == 3
    assert meta.format_name == "PNG"


def test_image_validator_jpeg(tmp_path: Path):
    img = _create_image_file(tmp_path / "test.jpg", TINY_JPEG)
    meta = inspect_image_file(img)
    assert meta.width == 10
    assert meta.height == 10
    assert meta.channels == 3
    assert meta.format_name == "JPEG"


def test_image_validator_webp(tmp_path: Path):
    img = _create_image_file(tmp_path / "test.webp", TINY_WEBP)
    meta = inspect_image_file(img)
    assert meta.width == 10
    assert meta.height == 10
    assert meta.format_name == "WEBP"


def test_image_validator_bmp(tmp_path: Path):
    img = _create_image_file(tmp_path / "test.bmp", TINY_BMP)
    meta = inspect_image_file(img)
    assert meta.width == 10
    assert meta.height == 10
    assert meta.format_name == "BMP"


def test_image_validator_tiff(tmp_path: Path):
    img = _create_image_file(tmp_path / "test.tiff", TINY_TIFF)
    meta = inspect_image_file(img)
    assert meta.width == 10
    assert meta.height == 10
    assert meta.format_name == "TIFF"


def test_image_validator_corrupt_bytes(tmp_path: Path):
    img = tmp_path / "corrupt.png"
    img.write_bytes(b"\x89PNG\r\n\x1a\nTRUNCATED")
    with pytest.raises(CorruptedImageError):
        inspect_image_file(img)


def test_image_validator_empty_file(tmp_path: Path):
    img = tmp_path / "empty.jpg"
    img.write_bytes(b"")
    with pytest.raises(CorruptedImageError):
        inspect_image_file(img)


def test_image_validator_unsupported_extension(tmp_path: Path):
    f = tmp_path / "test.exe"
    f.write_bytes(b"MZ12345")
    with pytest.raises(InvalidImageError):
        inspect_image_file(f)


# =====================================================================
# 2. Canonical Domain Representation & Immutability Tests
# =====================================================================

def test_canonical_bbox_immutability_and_coords():
    bbox = CanonicalBBox(x_min=10.0, y_min=20.0, width=50.0, height=100.0)
    assert bbox.x_min == 10.0
    assert bbox.y_min == 20.0
    assert bbox.x_max == 60.0
    assert bbox.y_max == 120.0
    assert bbox.area == 5000.0
    assert bbox.center == (35.0, 70.0)

    # Immutability check
    with pytest.raises(Exception):
        bbox.x_min = 15.0  # type: ignore


def test_canonical_annotation_immutability():
    bbox = CanonicalBBox(x_min=0.0, y_min=0.0, width=10.0, height=10.0)
    annot = CanonicalAnnotation(
        annotation_id="ann_1",
        category_id=1,
        category_name="car",
        bbox=bbox,
    )
    assert annot.annotation_id == "ann_1"
    assert annot.category_name == "car"

    with pytest.raises(Exception):
        annot.category_id = 2  # type: ignore


def test_canonical_sample_relative_path_validation():
    sample = CanonicalSample(
        sample_id="s1",
        relative_path="images/train/001.png",
        file_size_bytes=1024,
        width=100,
        height=100,
    )
    assert sample.relative_path == "images/train/001.png"

    # Reject backslash or traversal in relative_path
    with pytest.raises(ValueError):
        CanonicalSample(
            sample_id="s2",
            relative_path="images\\train\\001.png",
            file_size_bytes=1024,
            width=100,
            height=100,
        )

    with pytest.raises(ValueError):
        CanonicalSample(
            sample_id="s3",
            relative_path="../outside.png",
            file_size_bytes=1024,
            width=100,
            height=100,
        )


# =====================================================================
# 3. Path Security & Traversal Rejection Tests
# =====================================================================

def test_path_traversal_detection(tmp_path: Path):
    from aivara.dataset.path_security import normalize_relative_path, resolve_safe_path

    # Normal relative path
    assert normalize_relative_path("images/train/001.jpg") == "images/train/001.jpg"
    assert normalize_relative_path("./images\\train\\001.jpg") == "images/train/001.jpg"

    # Directory traversal attempts
    with pytest.raises(PathTraversalError):
        normalize_relative_path("../secret.txt")

    with pytest.raises(PathTraversalError):
        normalize_relative_path("images/../../secret.txt")

    # Windows drive letter escape
    with pytest.raises(PathTraversalError):
        normalize_relative_path("C:/Windows/system32.dll")

    # UNC network path escape
    with pytest.raises(PathTraversalError):
        normalize_relative_path("//192.168.1.1/share/img.jpg")

    with pytest.raises(PathTraversalError):
        normalize_relative_path("\\\\192.168.1.1\\share\\img.jpg")


# =====================================================================
# 4. COCO Ingestion Tests
# =====================================================================

def test_coco_happy_path(tmp_path: Path):
    img1 = _create_image_file(tmp_path / "images" / "001.png", TINY_PNG)
    img2 = _create_image_file(tmp_path / "images" / "002.png", TINY_PNG)

    coco_data = {
        "info": {"description": "Test COCO Dataset"},
        "categories": [
            {"id": 1, "name": "pedestrian", "supercategory": "person"},
            {"id": 2, "name": "vehicle", "supercategory": "vehicle"},
        ],
        "images": [
            {"id": 101, "file_name": "001.png", "width": 10, "height": 10},
            {"id": 102, "file_name": "002.png", "width": 10, "height": 10},
        ],
        "annotations": [
            {"id": 1, "image_id": 101, "category_id": 1, "bbox": [1.0, 1.0, 4.0, 4.0], "area": 16.0},
            {"id": 2, "image_id": 102, "category_id": 2, "bbox": [2.0, 2.0, 5.0, 5.0], "area": 25.0},
        ],
    }

    manifest_file = tmp_path / "annotations" / "instances_train.json"
    manifest_file.parent.mkdir(parents=True)
    manifest_file.write_text(json.dumps(coco_data), encoding="utf-8")

    res = ingest_dataset(tmp_path)
    assert res.format == DatasetFormat.COCO
    assert res.total_samples == 2
    assert res.total_annotations == 2
    assert len(res.categories) == 2
    assert res.manifest.samples[0].relative_path == "images/001.png"
    assert res.manifest.samples[0].annotations[0].category_name == "pedestrian"


def test_coco_malformed_json(tmp_path: Path):
    manifest = tmp_path / "instances.json"
    manifest.write_text("{ unclosed json: ", encoding="utf-8")
    with pytest.raises(MalformedDatasetError):
        ingest_dataset(tmp_path)


def test_coco_missing_categories(tmp_path: Path):
    _create_image_file(tmp_path / "001.png", TINY_PNG)
    data = {
        "images": [{"id": 1, "file_name": "001.png", "width": 10, "height": 10}],
        "annotations": [],
        # Missing "categories"
    }
    (tmp_path / "instances.json").write_text(json.dumps(data))
    with pytest.raises(MalformedDatasetError):
        ingest_dataset(tmp_path)


def test_coco_invalid_annotation_references(tmp_path: Path):
    _create_image_file(tmp_path / "001.png", TINY_PNG)
    data = {
        "categories": [{"id": 1, "name": "cat"}],
        "images": [{"id": 1, "file_name": "001.png", "width": 10, "height": 10}],
        "annotations": [
            {"id": 1, "image_id": 999, "category_id": 1, "bbox": [0, 0, 5, 5]}  # Non-existent image_id
        ],
    }
    (tmp_path / "instances.json").write_text(json.dumps(data))
    with pytest.raises(MalformedAnnotationError):
        ingest_dataset(tmp_path)


def test_coco_invalid_bbox_coordinates(tmp_path: Path):
    _create_image_file(tmp_path / "001.png", TINY_PNG)
    data = {
        "categories": [{"id": 1, "name": "cat"}],
        "images": [{"id": 1, "file_name": "001.png", "width": 10, "height": 10}],
        "annotations": [
            {"id": 1, "image_id": 1, "category_id": 1, "bbox": [-5.0, 0.0, 10.0, 10.0]}  # Negative x
        ],
    }
    (tmp_path / "instances.json").write_text(json.dumps(data))
    with pytest.raises(InvalidCoordinateError):
        ingest_dataset(tmp_path)


def test_coco_duplicate_image_ids(tmp_path: Path):
    _create_image_file(tmp_path / "001.png", TINY_PNG)
    _create_image_file(tmp_path / "002.png", TINY_PNG)
    data = {
        "categories": [{"id": 1, "name": "cat"}],
        "images": [
            {"id": 1, "file_name": "001.png", "width": 10, "height": 10},
            {"id": 1, "file_name": "002.png", "width": 10, "height": 10},  # Duplicate ID
        ],
        "annotations": [],
    }
    (tmp_path / "instances.json").write_text(json.dumps(data))
    with pytest.raises(InvalidIdentifierError):
        ingest_dataset(tmp_path)


# =====================================================================
# 5. YOLO Ingestion Tests
# =====================================================================

def test_yolo_happy_path(tmp_path: Path):
    img1 = _create_image_file(tmp_path / "images" / "001.jpg", TINY_JPEG)
    img2 = _create_image_file(tmp_path / "images" / "002.jpg", TINY_JPEG)

    # dataset.yaml
    cfg = {
        "names": ["cat", "dog"],
        "nc": 2,
    }
    (tmp_path / "dataset.yaml").write_text(yaml.dump(cfg))

    # label txts (class_id x_center y_center width height)
    labels_dir = tmp_path / "labels"
    labels_dir.mkdir(parents=True)
    (labels_dir / "001.txt").write_text("0 0.5 0.5 0.4 0.4\n")
    (labels_dir / "002.txt").write_text("1 0.3 0.3 0.2 0.2\n")

    res = ingest_dataset(tmp_path)
    assert res.format == DatasetFormat.YOLO
    assert res.total_samples == 2
    assert res.total_annotations == 2
    assert res.manifest.samples[0].relative_path == "images/001.jpg"
    assert res.manifest.samples[0].annotations[0].category_name == "cat"
    # Verify coordinate conversion (width=10, height=10):
    # center (0.5, 0.5) * 10 = (5, 5), width=0.4*10=4, height=0.4*10=4 -> x_min=3, y_min=3
    bbox = res.manifest.samples[0].annotations[0].bbox
    assert bbox is not None
    assert bbox.x_min == 3.0
    assert bbox.y_min == 3.0
    assert bbox.width == 4.0
    assert bbox.height == 4.0


def test_yolo_dict_names_config(tmp_path: Path):
    _create_image_file(tmp_path / "images" / "001.png", TINY_PNG)
    cfg = {
        "names": {0: "stop_sign", 1: "traffic_light"},
    }
    (tmp_path / "data.yaml").write_text(yaml.dump(cfg))
    labels_dir = tmp_path / "labels"
    labels_dir.mkdir()
    (labels_dir / "001.txt").write_text("0 0.5 0.5 0.2 0.2\n1 0.8 0.8 0.1 0.1\n")

    res = ingest_dataset(tmp_path)
    assert res.format == DatasetFormat.YOLO
    assert res.total_annotations == 2
    assert res.manifest.samples[0].annotations[0].category_name == "stop_sign"
    assert res.manifest.samples[0].annotations[1].category_name == "traffic_light"


def test_yolo_malformed_annotation_token_count(tmp_path: Path):
    _create_image_file(tmp_path / "images" / "001.png", TINY_PNG)
    (tmp_path / "dataset.yaml").write_text("names: [cat]\n")
    labels_dir = tmp_path / "labels"
    labels_dir.mkdir()
    (labels_dir / "001.txt").write_text("0 0.5 0.5 0.2\n")  # Only 4 tokens
    with pytest.raises(MalformedAnnotationError):
        ingest_dataset(tmp_path)


def test_yolo_invalid_out_of_bounds_coordinates(tmp_path: Path):
    _create_image_file(tmp_path / "images" / "001.png", TINY_PNG)
    (tmp_path / "dataset.yaml").write_text("names: [cat]\n")
    labels_dir = tmp_path / "labels"
    labels_dir.mkdir()
    (labels_dir / "001.txt").write_text("0 1.5 0.5 0.2 0.2\n")  # x_center > 1.0
    with pytest.raises(InvalidCoordinateError):
        ingest_dataset(tmp_path)


def test_yolo_negative_class_id(tmp_path: Path):
    _create_image_file(tmp_path / "images" / "001.png", TINY_PNG)
    (tmp_path / "dataset.yaml").write_text("names: [cat]\n")
    labels_dir = tmp_path / "labels"
    labels_dir.mkdir()
    (labels_dir / "001.txt").write_text("-1 0.5 0.5 0.2 0.2\n")
    with pytest.raises(InvalidCategoryError):
        ingest_dataset(tmp_path)


# =====================================================================
# 6. ImageFolder Ingestion Tests
# =====================================================================

def test_imagefolder_happy_path(tmp_path: Path):
    _create_image_file(tmp_path / "cats" / "cat1.png", TINY_PNG)
    _create_image_file(tmp_path / "cats" / "cat2.png", TINY_PNG)
    _create_image_file(tmp_path / "dogs" / "dog1.png", TINY_PNG)

    res = ingest_dataset(tmp_path)
    assert res.format == DatasetFormat.IMAGEFOLDER
    assert res.total_samples == 3
    assert len(res.categories) == 2
    cat_names = {c.category_name for c in res.categories}
    assert cat_names == {"cats", "dogs"}
    assert res.manifest.samples[0].annotations[0].category_name == "cats"
    assert res.manifest.samples[0].annotations[0].bbox is None  # Classification only


def test_imagefolder_nested_subdirectories(tmp_path: Path):
    _create_image_file(tmp_path / "vehicles" / "cars" / "car1.jpg", TINY_JPEG)
    _create_image_file(tmp_path / "vehicles" / "trucks" / "truck1.jpg", TINY_JPEG)

    res = ingest_dataset(tmp_path)
    assert res.format == DatasetFormat.IMAGEFOLDER
    assert res.total_samples == 2
    assert res.categories[0].category_name == "vehicles"


def test_imagefolder_empty_class_directory(tmp_path: Path):
    (tmp_path / "empty_class").mkdir()
    _create_image_file(tmp_path / "valid_class" / "img.png", TINY_PNG)
    with pytest.raises(MalformedDatasetError):
        ingest_dataset(tmp_path)


# =====================================================================
# 7. Detection Ambiguity, Empty & Unsupported Datasets
# =====================================================================

def test_empty_dataset_directory(tmp_path: Path):
    with pytest.raises(MalformedDatasetError):
        ingest_dataset(tmp_path)


def test_unsupported_dataset_layout(tmp_path: Path):
    (tmp_path / "random_file.txt").write_text("hello world")
    with pytest.raises(UnsupportedDatasetFormatError):
        ingest_dataset(tmp_path)


def test_ambiguous_dataset_format(tmp_path: Path):
    # Has both valid COCO JSON and YOLO yaml
    _create_image_file(tmp_path / "001.png", TINY_PNG)
    coco_data = {
        "categories": [{"id": 1, "name": "cat"}],
        "images": [{"id": 1, "file_name": "001.png", "width": 10, "height": 10}],
        "annotations": [],
    }
    (tmp_path / "instances.json").write_text(json.dumps(coco_data))
    (tmp_path / "dataset.yaml").write_text("names: [cat]\n")

    with pytest.raises(AmbiguousDatasetFormatError):
        ingest_dataset(tmp_path)


# =====================================================================
# 8. Deterministic Ordering & Reproducibility Tests
# =====================================================================

def test_deterministic_ordering_and_reproducibility(tmp_path: Path):
    # Create images in non-alphabetical order
    _create_image_file(tmp_path / "images" / "z_image.png", TINY_PNG)
    _create_image_file(tmp_path / "images" / "a_image.png", TINY_PNG)
    _create_image_file(tmp_path / "images" / "m_image.png", TINY_PNG)

    coco_data = {
        "categories": [
            {"id": 2, "name": "zebra"},
            {"id": 1, "name": "antelope"},
        ],
        "images": [
            {"id": 3, "file_name": "z_image.png", "width": 10, "height": 10},
            {"id": 1, "file_name": "a_image.png", "width": 10, "height": 10},
            {"id": 2, "file_name": "m_image.png", "width": 10, "height": 10},
        ],
        "annotations": [
            {"id": 3, "image_id": 3, "category_id": 2, "bbox": [0, 0, 5, 5]},
            {"id": 1, "image_id": 1, "category_id": 1, "bbox": [0, 0, 5, 5]},
            {"id": 2, "image_id": 2, "category_id": 1, "bbox": [0, 0, 5, 5]},
        ],
    }
    (tmp_path / "instances.json").write_text(json.dumps(coco_data))

    # Ingest twice
    res1 = ingest_dataset(tmp_path)
    res2 = ingest_dataset(tmp_path)

    # Verify deterministic lexical ordering
    paths = [s.relative_path for s in res1.manifest.samples]
    assert paths == ["images/a_image.png", "images/m_image.png", "images/z_image.png"]

    # Verify categories sorted by ID
    cat_ids = [c.category_id for c in res1.manifest.categories]
    assert cat_ids == [1, 2]

    # Verify exact JSON-level reproducibility
    assert res1.manifest.model_dump() == res2.manifest.model_dump()


# =====================================================================
# 9. Unicode Paths and Filenames
# =====================================================================

def test_unicode_paths_and_class_names(tmp_path: Path):
    img = _create_image_file(tmp_path / "車両" / "写真_001.png", TINY_PNG)
    res = ingest_dataset(tmp_path)
    assert res.format == DatasetFormat.IMAGEFOLDER
    assert res.total_samples == 1
    assert res.manifest.samples[0].relative_path == "車両/写真_001.png"
    assert res.manifest.categories[0].category_name == "車両"


# =====================================================================
# 10. Offline Air-Gapped Network Isolation Test
# =====================================================================

def test_offline_execution_guarantee(tmp_path: Path, monkeypatch):
    """Ensure dataset ingestion makes zero network socket connections."""
    def _forbidden_connect(*args, **kwargs):
        raise RuntimeError("Network socket connection attempted during offline dataset ingestion!")

    monkeypatch.setattr(socket.socket, "connect", _forbidden_connect)
    _create_image_file(tmp_path / "class1" / "img1.png", TINY_PNG)
    res = ingest_dataset(tmp_path)
    assert res.total_samples == 1

# =====================================================================
# 11. Additional Adversarial & Structural Edge Cases
# =====================================================================

def test_coco_file_name_path_traversal_attempt(tmp_path: Path):
    """Ensure path traversal inside COCO file_name is blocked."""
    outside_img = tmp_path.parent / "outside.png"
    outside_img.write_bytes(TINY_PNG)

    coco_data = {
        "categories": [{"id": 1, "name": "cat"}],
        "images": [{"id": 1, "file_name": "../outside.png", "width": 10, "height": 10}],
        "annotations": [],
    }
    (tmp_path / "instances.json").write_text(json.dumps(coco_data))

    with pytest.raises(PathTraversalError):
        ingest_dataset(tmp_path)


def test_coco_duplicate_category_and_annotation_ids(tmp_path: Path):
    _create_image_file(tmp_path / "001.png", TINY_PNG)
    # Duplicate category ID
    data_dup_cat = {
        "categories": [{"id": 1, "name": "cat"}, {"id": 1, "name": "dog"}],
        "images": [{"id": 1, "file_name": "001.png", "width": 10, "height": 10}],
        "annotations": [],
    }
    (tmp_path / "instances.json").write_text(json.dumps(data_dup_cat))
    with pytest.raises(InvalidIdentifierError):
        ingest_dataset(tmp_path)

    # Duplicate annotation ID
    data_dup_ann = {
        "categories": [{"id": 1, "name": "cat"}],
        "images": [{"id": 1, "file_name": "001.png", "width": 10, "height": 10}],
        "annotations": [
            {"id": 100, "image_id": 1, "category_id": 1, "bbox": [0, 0, 2, 2]},
            {"id": 100, "image_id": 1, "category_id": 1, "bbox": [1, 1, 3, 3]},
        ],
    }
    (tmp_path / "instances.json").write_text(json.dumps(data_dup_ann))
    with pytest.raises(InvalidIdentifierError):
        ingest_dataset(tmp_path)


def test_coco_segmentation_polygon_parsing(tmp_path: Path):
    _create_image_file(tmp_path / "001.png", TINY_PNG)
    coco_data = {
        "categories": [{"id": 1, "name": "cat"}],
        "images": [{"id": 1, "file_name": "001.png", "width": 10, "height": 10}],
        "annotations": [
            {
                "id": 1,
                "image_id": 1,
                "category_id": 1,
                "bbox": [1.0, 1.0, 5.0, 5.0],
                "segmentation": [[1.0, 1.0, 6.0, 1.0, 6.0, 6.0, 1.0, 6.0]],
                "area": 25.0,
                "iscrowd": 0,
            }
        ],
    }
    (tmp_path / "instances.json").write_text(json.dumps(coco_data))
    res = ingest_dataset(tmp_path)
    annot = res.manifest.samples[0].annotations[0]
    assert annot.segmentation is not None
    assert len(annot.segmentation) == 1
    assert annot.segmentation[0] == (1.0, 1.0, 6.0, 1.0, 6.0, 6.0, 1.0, 6.0)
    assert annot.area == 25.0
    assert not annot.is_crowd


def test_yolo_malformed_yaml_syntax(tmp_path: Path):
    _create_image_file(tmp_path / "images" / "001.png", TINY_PNG)
    (tmp_path / "dataset.yaml").write_text("names: [unclosed list")
    with pytest.raises(InvalidDatasetConfigError):
        ingest_dataset(tmp_path)


def test_yolo_zero_width_or_height(tmp_path: Path):
    _create_image_file(tmp_path / "images" / "001.png", TINY_PNG)
    (tmp_path / "dataset.yaml").write_text("names: [cat]\n")
    labels_dir = tmp_path / "labels"
    labels_dir.mkdir()
    (labels_dir / "001.txt").write_text("0 0.5 0.5 0.0 0.2\n")  # width = 0.0
    with pytest.raises(InvalidCoordinateError):
        ingest_dataset(tmp_path)


def test_symlink_escape_rejection(tmp_path: Path):
    """Test symlink escape rejection."""
    dataset_dir = tmp_path / "dataset"
    dataset_dir.mkdir()
    outside_dir = tmp_path / "outside_secret"
    outside_dir.mkdir()
    _create_image_file(outside_dir / "secret.png", TINY_PNG)

    # Attempt to symlink outside image into dataset
    link_path = dataset_dir / "escaped.png"
    symlink_created = False
    try:
        link_path.symlink_to(outside_dir / "secret.png")
        symlink_created = True
    except (OSError, NotImplementedError):
        pass

    if symlink_created:
        coco_data = {
            "categories": [{"id": 1, "name": "cat"}],
            "images": [{"id": 1, "file_name": "escaped.png", "width": 10, "height": 10}],
            "annotations": [],
        }
        (dataset_dir / "instances.json").write_text(json.dumps(coco_data))

        with pytest.raises(SymlinkEscapeError):
            ingest_dataset(dataset_dir)


def test_resolve_safe_path_relative_escape_check(tmp_path: Path):
    """Directly test resolve_safe_path rejecting path resolution outside root."""
    from aivara.dataset.path_security import resolve_safe_path

    root = tmp_path / "root"
    root.mkdir()

    with pytest.raises(PathTraversalError):
        resolve_safe_path(root, "../outside.txt")

