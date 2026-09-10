"""Domain exceptions for Phase 5.7 OOD and Image Quality Engine."""

from typing import Any, Dict, Optional


class OODQualityError(Exception):
    """Base domain exception for Phase 5.7 OOD & Image Quality Engine."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class InsufficientReferenceSupportError(OODQualityError):
    """Raised when reference distribution has fewer samples than required guardrail."""
    pass


class FeatureExtractionError(OODQualityError):
    """Raised when visual feature extraction fails or encounters fatal incompatibility."""
    pass


class ImageQualityError(OODQualityError):
    """Raised when image quality metric computation encounters unrecoverable errors."""
    pass


class InvalidReferenceDistributionError(OODQualityError):
    """Raised when reference distribution definition or dimensionality is invalid."""
    pass
