"""Structured domain exceptions for dataset ingestion, parsing, and validation."""

from typing import Any, Dict, Optional
from aivara.core.exceptions import AivaraException


class DatasetIngestionError(AivaraException):
    """Base exception for all dataset ingestion and validation errors."""

    def __init__(
        self,
        message: str,
        code: str = "DATASET_INGESTION_ERROR",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message=message, code=code, details=details or {})


class UnsupportedDatasetFormatError(DatasetIngestionError):
    """Raised when the dataset format is not recognized or unsupported."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code="UNSUPPORTED_DATASET_FORMAT",
            details=details,
        )


class AmbiguousDatasetFormatError(DatasetIngestionError):
    """Raised when a dataset contains conflicting format indicators (e.g. both COCO and YOLO)."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code="AMBIGUOUS_DATASET_FORMAT",
            details=details,
        )


class MalformedDatasetError(DatasetIngestionError):
    """Raised when a dataset structure, manifest, or directory layout is malformed."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code="MALFORMED_DATASET",
            details=details,
        )


class MalformedAnnotationError(DatasetIngestionError):
    """Raised when an individual annotation or label record is invalid or unparseable."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code="MALFORMED_ANNOTATION",
            details=details,
        )


class InvalidImageError(DatasetIngestionError):
    """Raised when an image file cannot be read, decoded, or validated."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code="INVALID_IMAGE",
            details=details,
        )


class CorruptedImageError(DatasetIngestionError):
    """Raised when an image has a corrupted header, truncated data, or invalid magic bytes."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code="CORRUPTED_IMAGE",
            details=details,
        )


class MissingImageError(DatasetIngestionError):
    """Raised when an annotation or manifest references an image file that does not exist."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code="MISSING_IMAGE",
            details=details,
        )


class InvalidCategoryError(DatasetIngestionError):
    """Raised when a category/class definition is invalid, negative, or undefined."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code="INVALID_CATEGORY",
            details=details,
        )


class InvalidIdentifierError(DatasetIngestionError):
    """Raised when a dataset identifier (image ID, annotation ID) is duplicated or invalid."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code="INVALID_IDENTIFIER",
            details=details,
        )


class PathTraversalError(DatasetIngestionError):
    """Raised when a manifest or path attempts directory traversal escaping the dataset root."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code="PATH_TRAVERSAL_DETECTED",
            details=details,
        )


class SymlinkEscapeError(DatasetIngestionError):
    """Raised when a symlink points outside the dataset root directory."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code="SYMLINK_ESCAPE_DETECTED",
            details=details,
        )


class InvalidCoordinateError(DatasetIngestionError):
    """Raised when bounding box or segmentation coordinates are non-numeric, negative, or invalid."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code="INVALID_COORDINATES",
            details=details,
        )


class InvalidDatasetConfigError(DatasetIngestionError):
    """Raised when dataset configuration (e.g. YOLO dataset.yaml) is invalid."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code="INVALID_DATASET_CONFIG",
            details=details,
        )
