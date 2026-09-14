"""Exceptions for Cross-Subsystem Evidence Ingestion (Phase 12.4)."""

from aivara.universal.ingestion.enums import IngestionErrorType


class UniversalIngestionError(Exception):
    """Base exception for all Phase 12.4 ingestion engine errors."""
    def __init__(self, message: str, error_type: IngestionErrorType = IngestionErrorType.INVALID_PAYLOAD) -> None:
        super().__init__(message)
        self.error_type = error_type


class IngestionValidationError(UniversalIngestionError):
    """Raised when incoming upstream payload fails schema or structural validation."""
    def __init__(self, message: str) -> None:
        super().__init__(message, IngestionErrorType.INVALID_SCHEMA)


class DomainMismatchIngestionError(UniversalIngestionError):
    """Raised when an evidence item's domain does not match the ingestion handler."""
    def __init__(self, message: str) -> None:
        super().__init__(message, IngestionErrorType.DOMAIN_MISMATCH)


class ProjectBoundaryIngestionError(UniversalIngestionError):
    """Raised when an evidence item belongs to a mismatched project or tenant."""
    def __init__(self, message: str) -> None:
        super().__init__(message, IngestionErrorType.PROJECT_BOUNDARY_VIOLATION)


class SourceHashMismatchIngestionError(UniversalIngestionError):
    """Raised when supplied source payload hash does not match computed source hash."""
    def __init__(self, message: str) -> None:
        super().__init__(message, IngestionErrorType.SOURCE_HASH_MISMATCH)


class AncestryConflictIngestionError(UniversalIngestionError):
    """Raised when conflicting ancestry keys are supplied."""
    def __init__(self, message: str) -> None:
        super().__init__(message, IngestionErrorType.ANCESTRY_CONFLICT)


class IngestionResourceLimitError(UniversalIngestionError):
    """Raised when an ingestion batch or payload exceeds safety ceilings."""
    def __init__(self, message: str) -> None:
        super().__init__(message, IngestionErrorType.RESOURCE_LIMIT)
