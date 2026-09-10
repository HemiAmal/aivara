"""Main orchestrator for dataset ingestion and canonical normalization."""

from pathlib import Path
from typing import Dict, Optional, Type, Union

from aivara.dataset.detector import detect_dataset_format
from aivara.dataset.exceptions import UnsupportedDatasetFormatError
from aivara.dataset.parsers.base import DatasetParserBase
from aivara.dataset.parsers.coco import CocoDatasetParser
from aivara.dataset.parsers.imagefolder import ImageFolderDatasetParser
from aivara.dataset.parsers.yolo import YoloDatasetParser
from aivara.dataset.schemas import (
    CanonicalDatasetManifest,
    DatasetFormat,
    DatasetIngestionResult,
)


class DatasetIngester:
    """Orchestrator for ingesting, validating, and normalizing computer vision datasets."""

    def __init__(self):
        self._parsers: Dict[DatasetFormat, Type[DatasetParserBase]] = {
            DatasetFormat.COCO: CocoDatasetParser,
            DatasetFormat.YOLO: YoloDatasetParser,
            DatasetFormat.IMAGEFOLDER: ImageFolderDatasetParser,
        }

    def ingest(
        self,
        dataset_path: Union[str, Path],
        expected_format: Optional[DatasetFormat] = None,
    ) -> DatasetIngestionResult:
        """Ingest a dataset from disk and return an immutable DatasetIngestionResult.

        Args:
            dataset_path: Path to dataset root directory.
            expected_format: Optional explicit format override. If None, format is auto-detected.

        Returns:
            DatasetIngestionResult containing the canonical manifest and ingestion summary.
        """
        root_path = Path(dataset_path).resolve()

        # Detect or validate format
        if expected_format is None:
            detected_format = detect_dataset_format(root_path)
        else:
            detected_format = expected_format

        parser_cls = self._parsers.get(detected_format)
        if not parser_cls:
            raise UnsupportedDatasetFormatError(
                f"No parser available for dataset format '{detected_format.value}'.",
                details={"format": detected_format.value},
            )

        parser = parser_cls()
        manifest: CanonicalDatasetManifest = parser.parse(root_path)

        warnings = []
        if manifest.sample_count == 0:
            warnings.append("Dataset contains zero samples.")
        if manifest.annotation_count == 0 and detected_format != DatasetFormat.IMAGEFOLDER:
            warnings.append("Object detection dataset contains zero annotations.")

        capability_info = {
            "offline_mode": True,
            "supported_formats": [f.value for f in self._parsers.keys()],
            "image_formats": ["PNG", "JPEG", "WebP", "BMP", "TIFF"],
            "bbox_convention": "absolute_pixel_top_left_origin",
        }

        return DatasetIngestionResult(
            format=detected_format,
            dataset_root=str(root_path).replace("\\", "/"),
            manifest=manifest,
            total_samples=manifest.sample_count,
            valid_samples=manifest.sample_count,
            invalid_samples=0,
            total_annotations=manifest.annotation_count,
            categories=list(manifest.categories),
            warnings=warnings,
            capability_info=capability_info,
        )


def ingest_dataset(
    dataset_path: Union[str, Path],
    expected_format: Optional[DatasetFormat] = None,
) -> DatasetIngestionResult:
    """Convenience helper to ingest and normalize a dataset."""
    ingester = DatasetIngester()
    return ingester.ingest(dataset_path=dataset_path, expected_format=expected_format)
