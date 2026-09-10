"""COCO object detection format parser."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from aivara.dataset.exceptions import (
    InvalidCategoryError,
    InvalidCoordinateError,
    InvalidIdentifierError,
    MalformedAnnotationError,
    MalformedDatasetError,
    MissingImageError,
)
from aivara.dataset.image_validator import inspect_image_file
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


class CocoDatasetParser(DatasetParserBase):
    """Parser for standard COCO Object Detection / Segmentation datasets."""

    @property
    def format(self) -> DatasetFormat:
        return DatasetFormat.COCO

    def _find_coco_json(self, dataset_root: Path) -> Path:
        """Locate primary COCO JSON manifest."""
        annot_dir = dataset_root / "annotations"
        candidates: List[Path] = []

        if annot_dir.is_dir():
            for p in sorted(annot_dir.glob("*.json"), key=lambda x: x.name):
                if p.is_file() and not p.name.startswith("."):
                    candidates.append(p)

        for p in sorted(dataset_root.glob("*.json"), key=lambda x: x.name):
            if p.is_file() and not p.name.startswith("."):
                candidates.append(p)

        for candidate in candidates:
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if (
                        isinstance(data, dict)
                        and "images" in data
                        and "annotations" in data
                        and "categories" in data
                    ):
                        return candidate
            except Exception:
                continue

        raise MalformedDatasetError(
            f"No valid COCO JSON manifest found in '{dataset_root}'.",
            details={"path": str(dataset_root)},
        )

    def parse(self, dataset_root: Path) -> CanonicalDatasetManifest:
        """Parse COCO dataset into CanonicalDatasetManifest."""
        json_path = self._find_coco_json(dataset_root)

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise MalformedDatasetError(
                f"Malformed COCO JSON in '{json_path.name}': {e}",
                details={"file": json_path.name, "error": str(e)},
            )
        except OSError as e:
            raise MalformedDatasetError(
                f"Failed to read COCO manifest '{json_path.name}': {e}",
                details={"file": json_path.name, "error": str(e)},
            )

        if not isinstance(data, dict):
            raise MalformedDatasetError(
                "COCO JSON root must be a JSON object/dict.",
                details={"file": json_path.name},
            )

        # 1. Parse Categories
        raw_categories = data.get("categories")
        if not isinstance(raw_categories, list):
            raise MalformedDatasetError(
                "COCO 'categories' field must be a list.",
                details={"file": json_path.name},
            )

        category_map: Dict[int, CanonicalCategory] = {}
        seen_cat_ids: Set[int] = set()

        for cat_dict in raw_categories:
            if not isinstance(cat_dict, dict):
                raise MalformedDatasetError("COCO category entry must be a dictionary.")

            cat_id = cat_dict.get("id")
            cat_name = cat_dict.get("name")

            if cat_id is None or not isinstance(cat_id, int) or cat_id < 0:
                raise InvalidCategoryError(
                    f"Invalid category ID '{cat_id}'; must be non-negative integer.",
                    details={"category": cat_dict},
                )
            if not cat_name or not isinstance(cat_name, str):
                raise InvalidCategoryError(
                    f"Invalid category name for ID {cat_id}.",
                    details={"category": cat_dict},
                )

            if cat_id in seen_cat_ids:
                raise InvalidIdentifierError(
                    f"Duplicate category ID {cat_id} detected in COCO manifest.",
                    details={"category_id": cat_id},
                )
            seen_cat_ids.add(cat_id)

            category_map[cat_id] = CanonicalCategory(
                category_id=cat_id,
                category_name=cat_name.strip(),
                supercategory=cat_dict.get("supercategory"),
            )

        # 2. Parse Images
        raw_images = data.get("images")
        if not isinstance(raw_images, list):
            raise MalformedDatasetError(
                "COCO 'images' field must be a list.",
                details={"file": json_path.name},
            )

        image_map: Dict[Any, Dict[str, Any]] = {}
        seen_image_ids: Set[Any] = set()
        seen_rel_paths: Set[str] = set()

        for img_dict in raw_images:
            if not isinstance(img_dict, dict):
                raise MalformedDatasetError("COCO image entry must be a dictionary.")

            img_id = img_dict.get("id")
            file_name = img_dict.get("file_name")

            if img_id is None:
                raise InvalidIdentifierError(
                    "COCO image entry missing required 'id' field.",
                    details={"image": img_dict},
                )
            if not file_name or not isinstance(file_name, str):
                raise MalformedDatasetError(
                    f"COCO image ID {img_id} has invalid 'file_name'.",
                    details={"image_id": img_id},
                )

            if img_id in seen_image_ids:
                raise InvalidIdentifierError(
                    f"Duplicate image ID '{img_id}' in COCO manifest.",
                    details={"image_id": str(img_id)},
                )
            seen_image_ids.add(img_id)

            # Resolve image file location safely
            norm_name = normalize_relative_path(file_name)

            # Check candidate locations: direct relative, images/ prefix, or dataset_root / norm_name
            candidate_paths = [
                norm_name,
                f"images/{norm_name}",
            ]
            found_path: Optional[Path] = None
            resolved_rel_path: Optional[str] = None

            for c_rel in candidate_paths:
                try:
                    p = resolve_safe_path(dataset_root, c_rel, require_exists=True)
                    found_path = p
                    resolved_rel_path = normalize_relative_path(p.relative_to(dataset_root.resolve()))
                    break
                except (MissingImageError, Exception):
                    continue

            if found_path is None or resolved_rel_path is None:
                raise MissingImageError(
                    f"Image file '{file_name}' referenced by COCO image ID {img_id} not found.",
                    details={"image_id": str(img_id), "file_name": file_name},
                )

            if resolved_rel_path in seen_rel_paths:
                raise InvalidIdentifierError(
                    f"Duplicate relative path '{resolved_rel_path}' mapped to multiple images.",
                    details={"relative_path": resolved_rel_path},
                )
            seen_rel_paths.add(resolved_rel_path)

            # Inspect actual image on disk
            img_meta = inspect_image_file(found_path)

            image_map[img_id] = {
                "relative_path": resolved_rel_path,
                "file_size": img_meta.file_size_bytes,
                "width": img_meta.width,
                "height": img_meta.height,
                "channels": img_meta.channels,
                "color_space": img_meta.color_space,
                "metadata": {
                    "coco_image_id": img_id,
                    "original_file_name": file_name,
                    **{k: v for k, v in img_dict.items() if k not in ("id", "file_name", "width", "height")},
                },
                "annotations": [],
            }

        # 3. Parse Annotations
        raw_annotations = data.get("annotations")
        if not isinstance(raw_annotations, list):
            raise MalformedDatasetError(
                "COCO 'annotations' field must be a list.",
                details={"file": json_path.name},
            )

        seen_annot_ids: Set[Any] = set()

        for annot_dict in raw_annotations:
            if not isinstance(annot_dict, dict):
                raise MalformedAnnotationError("COCO annotation entry must be a dictionary.")

            annot_id = annot_dict.get("id")
            if annot_id is None:
                raise InvalidIdentifierError(
                    "COCO annotation missing required 'id' field.",
                    details={"annotation": annot_dict},
                )
            if annot_id in seen_annot_ids:
                raise InvalidIdentifierError(
                    f"Duplicate annotation ID '{annot_id}' in COCO manifest.",
                    details={"annotation_id": str(annot_id)},
                )
            seen_annot_ids.add(annot_id)

            img_id = annot_dict.get("image_id")
            if img_id not in image_map:
                raise MalformedAnnotationError(
                    f"Annotation ID {annot_id} references non-existent image_id '{img_id}'.",
                    details={"annotation_id": str(annot_id), "image_id": str(img_id)},
                )

            cat_id = annot_dict.get("category_id")
            if cat_id not in category_map:
                raise InvalidCategoryError(
                    f"Annotation ID {annot_id} references undefined category_id '{cat_id}'.",
                    details={"annotation_id": str(annot_id), "category_id": str(cat_id)},
                )

            # Parse bounding box: [x, y, width, height]
            raw_bbox = annot_dict.get("bbox")
            bbox_obj: Optional[CanonicalBBox] = None

            if raw_bbox is not None:
                if not isinstance(raw_bbox, (list, tuple)) or len(raw_bbox) != 4:
                    raise InvalidCoordinateError(
                        f"COCO bbox for annotation {annot_id} must be a 4-element list [x, y, w, h].",
                        details={"bbox": raw_bbox},
                    )

                x, y, w, h = raw_bbox
                if not all(isinstance(v, (int, float)) for v in (x, y, w, h)):
                    raise InvalidCoordinateError(
                        f"Non-numeric coordinates in bbox for annotation {annot_id}.",
                        details={"bbox": raw_bbox},
                    )

                x, y, w, h = float(x), float(y), float(w), float(h)
                if x < 0.0 or y < 0.0 or w <= 0.0 or h <= 0.0:
                    raise InvalidCoordinateError(
                        f"Invalid bbox dimensions [x={x}, y={y}, w={w}, h={h}] for annotation {annot_id}.",
                        details={"bbox": raw_bbox},
                    )

                bbox_obj = CanonicalBBox(
                    x_min=x,
                    y_min=y,
                    width=w,
                    height=h,
                    confidence=1.0,
                )

            # Segmentation parsing
            raw_seg = annot_dict.get("segmentation")
            seg_tuples: Optional[Tuple[Tuple[float, ...], ...]] = None
            if isinstance(raw_seg, list):
                polys = []
                for p in raw_seg:
                    if isinstance(p, (list, tuple)) and len(p) >= 6:
                        polys.append(tuple(float(coord) for coord in p))
                if polys:
                    seg_tuples = tuple(polys)

            area = annot_dict.get("area")
            if area is not None:
                try:
                    area = float(area)
                    if area < 0.0:
                        raise InvalidCoordinateError(f"Negative area for annotation {annot_id}.")
                except (ValueError, TypeError):
                    raise InvalidCoordinateError(f"Invalid area value for annotation {annot_id}.")

            is_crowd = bool(annot_dict.get("iscrowd") or annot_dict.get("is_crowd", False))

            extra_attrs = {
                k: v for k, v in annot_dict.items()
                if k not in ("id", "image_id", "category_id", "bbox", "segmentation", "area", "iscrowd", "is_crowd")
            }

            canonical_annot = CanonicalAnnotation(
                annotation_id=str(annot_id),
                category_id=cat_id,
                category_name=category_map[cat_id].category_name,
                bbox=bbox_obj,
                segmentation=seg_tuples,
                area=area,
                is_crowd=is_crowd,
                attributes=extra_attrs,
            )
            image_map[img_id]["annotations"].append(canonical_annot)

        # 4. Construct Sorted Canonical Samples
        canonical_samples: List[CanonicalSample] = []
        for img_id, img_data in image_map.items():
            # Sort annotations deterministically
            sorted_annots = sorted(
                img_data["annotations"],
                key=lambda a: (
                    a.category_id,
                    a.bbox.x_min if a.bbox else 0.0,
                    a.bbox.y_min if a.bbox else 0.0,
                    a.bbox.width if a.bbox else 0.0,
                    a.bbox.height if a.bbox else 0.0,
                    a.annotation_id,
                ),
            )

            sample_id = f"sample_{img_data['relative_path'].replace('/', '_')}"
            canonical_samples.append(
                CanonicalSample(
                    sample_id=sample_id,
                    relative_path=img_data["relative_path"],
                    file_size_bytes=img_data["file_size"],
                    width=img_data["width"],
                    height=img_data["height"],
                    channels=img_data["channels"],
                    color_space=img_data["color_space"],
                    annotations=tuple(sorted_annots),
                    metadata=img_data["metadata"],
                )
            )

        # Sort samples strictly lexicographically by relative_path
        canonical_samples.sort(key=lambda s: s.relative_path)
        sorted_categories = sorted(category_map.values(), key=lambda c: c.category_id)

        total_annots = sum(len(s.annotations) for s in canonical_samples)

        return CanonicalDatasetManifest(
            schema_version="1.0",
            format=DatasetFormat.COCO,
            dataset_name=dataset_root.name,
            sample_count=len(canonical_samples),
            annotation_count=total_annots,
            categories=tuple(sorted_categories),
            samples=tuple(canonical_samples),
            metadata={
                "coco_manifest_file": json_path.name,
                "coco_info": data.get("info", {}),
                "coco_licenses": data.get("licenses", []),
            },
        )
