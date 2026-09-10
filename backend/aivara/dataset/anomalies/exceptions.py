"""Domain exceptions for Label Anomaly & Confident Learning Engine (Phase 5.5)."""

from typing import Any, Optional
from aivara.core.exceptions import AivaraException


class LabelAnomalyError(AivaraException, ValueError):
    """Base exception for label anomaly detection errors."""

    def __init__(
        self,
        message: str,
        code: str = "LABEL_ANOMALY_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class ModelUnavailableError(LabelAnomalyError):
    """Raised when an inference model or feature extractor is missing in the offline environment."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="MODEL_UNAVAILABLE", details=details)


class ModelIncompatibleError(LabelAnomalyError):
    """Raised when a model is incompatible with the target dataset ontology or input shape."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="MODEL_INCOMPATIBLE", details=details)


class ModelLoadFailedError(LabelAnomalyError):
    """Raised when an offline model fails to deserialize or initialize."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="MODEL_LOAD_FAILED", details=details)


class InsufficientDataError(LabelAnomalyError):
    """Raised when dataset size or class distribution is statistically insufficient for estimation."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INSUFFICIENT_DATA", details=details)


class InvalidFoldSplitError(LabelAnomalyError):
    """Raised when cross-validation fold splitting fails due to invalid parameters or class imbalance."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_FOLD_SPLIT", details=details)


class UnsupportedModalityError(LabelAnomalyError):
    """Raised when an unsupported annotation modality (e.g. continuous regression, dense masks) is supplied."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="UNSUPPORTED_MODALITY", details=details)
