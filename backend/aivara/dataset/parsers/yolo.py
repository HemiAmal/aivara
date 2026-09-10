"""YOLO object detection format parser."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import yaml

from aivara.dataset.exceptions import (
    InvalidCategoryError,
    InvalidCoordinateError,
    InvalidDatasetConfigError,
    MalformedAnnotationError,
    MalformedDatasetError,
    MissingImageError,
)
from aivara.dataset.image_validator import SUPPORTED_IMAGE_EXTENSIONS, inspect_image_file
from aivara.dataset.parsers.base import DatasetParserBase
from aivara.dataset.path_security import normalize_relative_path, resolve_safe_path
from aivara.dataset.schemas import (
    CanonicalAnnotation,
    CanonicalBBox,
    CanonicalCategory,
    CanonicalDatasetManifest,
    CanonicalSample,
    DatasetFormat,
)


class YoloDatasetParser(DatasetParserBase):
    """Parser for YOLO Object Detection datasets with dataset.yaml and txt annotations."""

    @property
    def format(self) -> DatasetFormat:
        return DatasetFormat.YOLO

    def _load_yolo_config(self, dataset_root: Path) -> Tuple[Optional[Path], Dict[str, Any]]:
        """Find and parse dataset.yaml or data.yaml if present."""
        for cfg_name in ("dataset.yaml", "data.yaml", "dataset.yml", "data.yml"):
            cfg_path = dataset_root / cfg_name
            if cfg_path.is_file():
                try:
                    with open(cfg_path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                        if isinstance(data, dict):
                            return cfg_path, data
                except Exception as e:
                    raise InvalidDatasetConfigError(
                        f"Failed to parse YOLO config '{cfg_name}': {e}",
                        details={"file": cfg_name, "error": str(e)},
                    )
        return None, {}

    def _resolve_categories(
        self, config_data: Dict[str, Any], dataset_root: Path
    ) -> Dict[int, CanonicalCategory]:
        """Extract category ID to CanonicalCategory mapping from YOLO config or infer from labels."""
        raw_names = config_data.get("names")
        category_map: Dict[int, CanonicalCategory] = {}

        if raw_names is not None:
            if isinstance(raw_names, list):
                for idx, name in enumerate(raw_names):
                    if not isinstance(name, str):
                        raise InvalidCategoryError(f"YOLO class name at index {idx} must be a string.")
                    category_map[idx] = CanonicalCategory(
                        category_id=idx,
                        category_name=name.strip(),
                    )
            elif isinstance(raw_names, dict):
                for k, v in raw_names.items():
                    try:
                        cid = int(k)
                    except (ValueError, TypeError):
                        raise InvalidCategoryError(f"YOLO category key '{k}' must be an integer.")
                    if cid < 0:
                        raise InvalidCategoryError(f"Negative category ID '{cid}' is forbidden.")
                    category_map[cid] = CanonicalCategory(
                        category_id=cid,
                        category_name=str(v).strip(),
                    )
            else:
                raise InvalidDatasetConfigError("YOLO 'names' configuration must be a list or dict.")

        return category_map

    def _find_image_files(self, dataset_root: Path) -> List[Path]:
        """Discover all valid image files in YOLO directory structure."""
        images_dir = dataset_root / "images"
        search_roots = [images_dir] if images_dir.is_dir() else [dataset_root]

        found_images: List[Path] = []
        for s_root in search_roots:
            for p in s_root.rglob("*"):
                if (
                    p.is_file()
                    and not p.name.startswith(".")
                    and p.suffix.lower() in SUPPORTED_IMAGE_EXTENSIONS
                ):
                    found_images.append(p)

        return sorted(found_images, key=lambda x: x.as_posix())

    def _locate_label_file(self, img_path: Path, dataset_root: Path) -> Optional[Path]:
        """Find corresponding .txt annotation file for an image."""
        # 1. Standard YOLO layout: images/split/xxx.jpg -> labels/split/xxx.txt
        img_rel = img_path.relative_to(dataset_root)
        parts = list(img_rel.parts)

        if parts and parts[0] == "images":
            label_parts = ["labels"] + parts[1:]
            cand = dataset_root.joinpath(*label_parts).with_suffix(".txt")
            if cand.is_file():
                return cand

        # 2. Sibling labels directory: labels/xxx.txt
        sibling_cand = dataset_root / "labels" / f"{img_path.stem}.txt"
        if sibling_cand.is_file():
            return sibling_cand

        # 3. Same directory: xxx.txt
        same_dir_cand = img_path.with_suffix(".txt")
        if same_dir_cand.is_file():
            return same_dir_cand

        return None

    def parse(self, dataset_root: Path) -> CanonicalDatasetManifest:
        """Parse YOLO dataset into CanonicalDatasetManifest."""
        cfg_path, cfg_data = self._load_yolo_config(dataset_root)
        category_map = self._resolve_categories(cfg_data, dataset_root)

        image_files = self._find_image_files(dataset_root)
        if not image_files:
            raise MalformedDatasetError(
                f"No valid image files found in YOLO dataset at '{dataset_root.name}'.",
                details={"path": str(dataset_root)},
            )

        canonical_samples: List[CanonicalSample] = []
        annot_counter = 0

        for img_file in image_files:
            rel_path = normalize_relative_path(img_file.relative_to(dataset_root.resolve()))
            img_meta = inspect_image_file(img_file)

            label_file = self._locate_label_file(img_file, dataset_root)
            sample_annotations: List[CanonicalAnnotation] = []

            if label_file and label_file.is_file():
                try:
                    with open(label_file, "r", encoding="utf-8") as f:
                        lines = [line.strip() for line in f if line.strip()]
                except OSError as e:
                    raise MalformedAnnotationError(
                        f"Failed to read YOLO label file '{label_file.name}': {e}",
                        details={"file": label_file.name},
                    )

                for line_idx, line in enumerate(lines, start=1):
                    tokens = line.split()
                    if len(tokens) != 5:
                        raise MalformedAnnotationError(
                            f"YOLO annotation in '{label_file.name}' line {line_idx} must have exactly 5 values (got {len(tokens)}).",
                            details={"file": label_file.name, "line": line_idx, "content": line},
                        )

                    try:
                        class_id = int(tokens[0])
                        x_center = float(tokens[1])
                        y_center = float(tokens[2])
                        width_norm = float(tokens[3])
                        height_norm = float(tokens[4])
                    except ValueError:
                        raise InvalidCoordinateError(
                            f"Non-numeric values in YOLO annotation '{label_file.name}' line {line_idx}.",
                            details={"line": line_idx, "content": line},
                        )

                    if class_id < 0:
                        raise InvalidCategoryError(
                            f"Negative class ID '{class_id}' in '{label_file.name}' line {line_idx}.",
                            details={"class_id": class_id, "line": line_idx},
                        )

                    # Validate normalized coordinates [0.0, 1.0]
                    for name, val in [
                        ("x_center", x_center),
                        ("y_center", y_center),
                        ("width", width_norm),
                        ("height", height_norm),
                    ]:
                        if val < 0.0 or val > 1.0:
                            raise InvalidCoordinateError(
                                f"YOLO coordinate '{name}'={val} out of normalized bounds [0.0, 1.0] in '{label_file.name}' line {line_idx}.",
                                details={"coordinate": name, "value": val, "line": line_idx},
                            )

                    if width_norm <= 0.0 or height_norm <= 0.0:
                        raise InvalidCoordinateError(
                            f"YOLO bounding box width/height must be strictly positive in '{label_file.name}' line {line_idx}.",
                            details={"width": width_norm, "height": height_norm, "line": line_idx},
                        )

                    # Resolve category name
                    if class_id not in category_map:
                        # Auto-register if not defined in YAML
                        category_map[class_id] = CanonicalCategory(
                            category_id=class_id,
                            category_name=f"class_{class_id}",
                        )

                    cat_name = category_map[class_id].category_name

                    # Convert normalized center coordinates to absolute pixel bbox
                    abs_w = width_norm * img_meta.width
                    abs_h = height_norm * img_meta.height
                    abs_x = (x_center - width_norm / 2.0) * img_meta.width
                    abs_y = (y_center - height_norm / 2.0) * img_meta.height

                    # Clamp precision boundaries
                    abs_x = max(0.0, abs_x)
                    abs_y = max(0.0, abs_y)

                    bbox_obj = CanonicalBBox(
                        x_min=abs_x,
                        y_min=abs_y,
                        width=abs_w,
                        height=abs_h,
                        confidence=1.0,
                    )

                    annot_counter += 1
                    sample_annotations.append(
                        CanonicalAnnotation(
                            annotation_id=f"yolo_annot_{annot_counter}",
                            category_id=class_id,
                            category_name=cat_name,
                            bbox=bbox_obj,
                            attributes={"yolo_raw": line},
                        )
                    )

            # Sort annotations deterministically
            sorted_annots = sorted(
                sample_annotations,
                key=lambda a: (
                    a.category_id,
                    a.bbox.x_min if a.bbox else 0.0,
                    a.bbox.y_min if a.bbox else 0.0,
                    a.bbox.width if a.bbox else 0.0,
                    a.bbox.height if a.bbox else 0.0,
                    a.annotation_id,
                ),
            )

            sample_id = f"sample_{rel_path.replace('/', '_')}"
            canonical_samples.append(
                CanonicalSample(
                    sample_id=sample_id,
                    relative_path=rel_path,
                    file_size_bytes=img_meta.file_size_bytes,
                    width=img_meta.width,
                    height=img_meta.height,
                    channels=img_meta.channels,
                    color_space=img_meta.color_space,
                    annotations=tuple(sorted_annots),
                    metadata={
                        "yolo_label_file": label_file.name if label_file else None,
                    },
                )
            )

        # Sort samples strictly lexicographically by relative_path
        canonical_samples.sort(key=lambda s: s.relative_path)
        sorted_categories = sorted(category_map.values(), key=lambda c: c.category_id)
        total_annots = sum(len(s.annotations) for s in canonical_samples)

        return CanonicalDatasetManifest(
            schema_version="1.0",
            format=DatasetFormat.YOLO,
            dataset_name=dataset_root.name,
            sample_count=len(canonical_samples),
            annotation_count=total_annots,
            categories=tuple(sorted_categories),
            samples=tuple(canonical_samples),
            metadata={
                "yolo_config_file": cfg_path.name if cfg_path else None,
            },
        )
