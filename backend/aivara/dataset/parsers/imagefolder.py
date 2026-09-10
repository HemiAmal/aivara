"""ImageFolder classification format parser."""

from pathlib import Path
from typing import Dict, List, Set, Tuple

from aivara.dataset.exceptions import (
    MalformedDatasetError,
)
from aivara.dataset.image_validator import SUPPORTED_IMAGE_EXTENSIONS, inspect_image_file
from aivara.dataset.parsers.base import DatasetParserBase
from aivara.dataset.path_security import normalize_relative_path
from aivara.dataset.schemas import (
    CanonicalAnnotation,
    CanonicalCategory,
    CanonicalDatasetManifest,
    CanonicalSample,
    DatasetFormat,
)


class ImageFolderDatasetParser(DatasetParserBase):
    """Parser for ImageFolder classification datasets (class_name/image.ext)."""

    @property
    def format(self) -> DatasetFormat:
        return DatasetFormat.IMAGEFOLDER

    def parse(self, dataset_root: Path) -> CanonicalDatasetManifest:
        """Parse ImageFolder dataset into CanonicalDatasetManifest."""
        if not dataset_root.is_dir():
            raise MalformedDatasetError(
                f"ImageFolder dataset root '{dataset_root}' is not a directory.",
                details={"path": str(dataset_root)},
            )

        # Discover class directories (exclude hidden directories like .git, .DS_Store)
        class_dirs = sorted(
            [p for p in dataset_root.iterdir() if p.is_dir() and not p.name.startswith(".")],
            key=lambda p: p.name,
        )

        if not class_dirs:
            raise MalformedDatasetError(
                f"No class subdirectories found in ImageFolder dataset '{dataset_root.name}'.",
                details={"path": str(dataset_root)},
            )

        category_map: Dict[str, CanonicalCategory] = {}
        canonical_categories: List[CanonicalCategory] = []

        for cat_id, cdir in enumerate(class_dirs):
            cat_name = cdir.name.strip()
            cat_obj = CanonicalCategory(
                category_id=cat_id,
                category_name=cat_name,
            )
            category_map[cat_name] = cat_obj
            canonical_categories.append(cat_obj)

        canonical_samples: List[CanonicalSample] = []
        annot_counter = 0

        for cdir in class_dirs:
            cat_name = cdir.name.strip()
            cat_obj = category_map[cat_name]

            # Discover all valid images under this class directory (handling nested subdirectories)
            class_images = sorted(
                [
                    p for p in cdir.rglob("*")
                    if p.is_file() and not p.name.startswith(".") and p.suffix.lower() in SUPPORTED_IMAGE_EXTENSIONS
                ],
                key=lambda p: p.as_posix(),
            )

            if not class_images:
                # Warning or rejection if a class folder is empty
                raise MalformedDatasetError(
                    f"Class directory '{cdir.name}' contains no valid image files.",
                    details={"class_dir": cdir.name},
                )

            for img_path in class_images:
                rel_path = normalize_relative_path(img_path.relative_to(dataset_root.resolve()))
                img_meta = inspect_image_file(img_path)

                annot_counter += 1
                classification_annot = CanonicalAnnotation(
                    annotation_id=f"cls_annot_{annot_counter}",
                    category_id=cat_obj.category_id,
                    category_name=cat_obj.category_name,
                    bbox=None,  # Classification has no bounding box
                    attributes={"source_class_directory": cat_name},
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
                        annotations=(classification_annot,),
                        metadata={"class_name": cat_name},
                    )
                )

        # Sort samples strictly lexicographically by relative_path
        canonical_samples.sort(key=lambda s: s.relative_path)
        total_annots = sum(len(s.annotations) for s in canonical_samples)

        return CanonicalDatasetManifest(
            schema_version="1.0",
            format=DatasetFormat.IMAGEFOLDER,
            dataset_name=dataset_root.name,
            sample_count=len(canonical_samples),
            annotation_count=total_annots,
            categories=tuple(canonical_categories),
            samples=tuple(canonical_samples),
            metadata={
                "class_count": len(canonical_categories),
            },
        )
