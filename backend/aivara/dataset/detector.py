"""Deterministic dataset format detection and structural sniffing."""

import json
from pathlib import Path
from typing import List, Optional, Tuple
import yaml

from aivara.dataset.exceptions import (
    AmbiguousDatasetFormatError,
    MalformedDatasetError,
    UnsupportedDatasetFormatError,
)
from aivara.dataset.image_validator import SUPPORTED_IMAGE_EXTENSIONS
from aivara.dataset.schemas import DatasetFormat


def _find_coco_candidate_files(dataset_root: Path) -> List[Path]:
    """Find JSON files that indicate a COCO manifest."""
    candidates: List[Path] = []

    # Check annotations/ directory
    annot_dir = dataset_root / "annotations"
    if annot_dir.is_dir():
        for p in annot_dir.glob("*.json"):
            if p.is_file() and not p.name.startswith("."):
                candidates.append(p)

    # Check root directory
    for p in dataset_root.glob("*.json"):
        if p.is_file() and not p.name.startswith("."):
            candidates.append(p)

    return candidates


def _is_yolo_candidate(dataset_root: Path) -> bool:
    """Check for presence of YOLO config or paired images/labels layout."""
    for yaml_name in ("dataset.yaml", "data.yaml", "dataset.yml", "data.yml"):
        if (dataset_root / yaml_name).is_file():
            return True

    images_dir = dataset_root / "images"
    labels_dir = dataset_root / "labels"
    if images_dir.is_dir() and labels_dir.is_dir():
        return True

    return False


def _is_imagefolder_candidate(dataset_root: Path) -> Tuple[bool, int]:
    """Check if root has subdirectories containing images (excluding reserved YOLO/COCO dirs)."""
    reserved_names = {"images", "labels", "annotations", ".git", ".pytest_cache"}
    subdirs = [
        p for p in dataset_root.iterdir()
        if p.is_dir() and not p.name.startswith(".") and p.name.lower() not in reserved_names
    ]
    if not subdirs:
        return False, 0

    total_images = 0
    dirs_with_images = 0

    for sub in subdirs:
        img_count = sum(
            1 for f in sub.rglob("*")
            if f.is_file() and not f.name.startswith(".") and f.suffix.lower() in SUPPORTED_IMAGE_EXTENSIONS
        )
        if img_count > 0:
            dirs_with_images += 1
            total_images += img_count

    # If all or most subdirectories are class directories
    return (dirs_with_images > 0 or len(subdirs) > 0), total_images


def detect_dataset_format(dataset_root: Path) -> DatasetFormat:
    """Deterministically detect the dataset format for a given root directory.

    Returns:
      DatasetFormat enum (COCO, YOLO, or IMAGEFOLDER).

    Raises:
      MalformedDatasetError: Root does not exist, is not a directory, or is empty.
      AmbiguousDatasetFormatError: Multiple conflicting format indicators found.
      UnsupportedDatasetFormatError: No supported dataset format structure identified.
    """
    if not dataset_root.exists():
        raise MalformedDatasetError(
            f"Dataset directory '{dataset_root}' does not exist.",
            details={"path": str(dataset_root)},
        )

    if not dataset_root.is_dir():
        raise MalformedDatasetError(
            f"Dataset path '{dataset_root}' is not a directory.",
            details={"path": str(dataset_root)},
        )

    # Check for empty directory
    entries = [p for p in dataset_root.iterdir() if not p.name.startswith(".")]
    if not entries:
        raise MalformedDatasetError(
            f"Dataset directory '{dataset_root}' is empty.",
            details={"path": str(dataset_root)},
        )

    detected_formats: List[DatasetFormat] = []

    # 1. Check for COCO
    coco_candidates = _find_coco_candidate_files(dataset_root)
    if coco_candidates:
        detected_formats.append(DatasetFormat.COCO)

    # 2. Check for YOLO
    if _is_yolo_candidate(dataset_root):
        detected_formats.append(DatasetFormat.YOLO)

    # 3. Check for ImageFolder (only if no COCO or YOLO candidate present)
    is_imgfolder, img_count = _is_imagefolder_candidate(dataset_root)
    if is_imgfolder and not coco_candidates and not _is_yolo_candidate(dataset_root):
        detected_formats.append(DatasetFormat.IMAGEFOLDER)

    if len(detected_formats) > 1:
        raise AmbiguousDatasetFormatError(
            f"Conflicting dataset format indicators found: {[f.value for f in detected_formats]}",
            details={"detected_formats": [f.value for f in detected_formats]},
        )

    if len(detected_formats) == 1:
        return detected_formats[0]

    # If it has subdirectories without COCO/YOLO indicators, treat as ImageFolder candidate
    if is_imgfolder:
        return DatasetFormat.IMAGEFOLDER

    raise UnsupportedDatasetFormatError(
        f"Unable to identify a supported dataset format (COCO, YOLO, ImageFolder) in '{dataset_root.name}'.",
        details={"path": str(dataset_root.name)},
    )
