"""Exception types for Phase 8.6 Behavioral Anomaly Detection."""

from __future__ import annotations


class BehavioralAnomalyError(Exception):
    """Base exception for behavioral anomaly analysis errors."""


class CrossProjectAnalysisError(BehavioralAnomalyError):
    """Raised when an analysis attempts to evaluate across different project_ids."""


class IncompatibleAnalysisContextError(BehavioralAnomalyError):
    """Raised when observations cannot be compared due to mismatched execution/model context."""


class InsufficientSupportError(BehavioralAnomalyError):
    """Raised when statistical support is insufficient to perform requested assessment."""


class InvalidMetricDataError(BehavioralAnomalyError):
    """Raised when input metric values or distributions contain unrecoverable non-finite data."""
