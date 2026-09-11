"""Domain exceptions for Contributor Risk Engine (Phase 6)."""

from __future__ import annotations

from aivara.core.exceptions import AivaraException


class ContributorRiskError(AivaraException, ValueError):
    """Base exception for all Contributor Risk domain errors."""

    def __init__(self, message: str, code: str = "CONTRIBUTOR_RISK_ERROR") -> None:
        super().__init__(message, code=code)


class InsufficientEvidenceError(ContributorRiskError):
    """Raised when an analytical operation lacks minimum required statistical evidence."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="INSUFFICIENT_EVIDENCE")


class SupportStateError(ContributorRiskError):
    """Raised when an operation is invalid for the contributor's support state tier."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="INVALID_SUPPORT_STATE")


class InvalidBaselineError(ContributorRiskError):
    """Raised when an invalid or malformed baseline is supplied."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="INVALID_BASELINE")


class CrossProjectContaminationError(ContributorRiskError):
    """Raised when contributor or evidence references span across different project contexts."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="CROSS_PROJECT_CONTAMINATION")


class SemanticSafetyViolationError(ContributorRiskError):
    """Raised when prohibited accusatory or human-intent language is detected."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="SEMANTIC_SAFETY_VIOLATION")
