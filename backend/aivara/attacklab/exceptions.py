"""Exceptions for the AIVARA Attack Simulation Lab (Phase 13)."""

from __future__ import annotations


class AttackLabError(Exception):
    """Base exception for all Attack Simulation Lab errors."""
    pass


class InvalidScenarioError(AttackLabError):
    """Raised when a scenario definition is malformed or invalid."""
    pass


class FixtureGenerationError(AttackLabError):
    """Raised when synthetic fixture generation fails."""
    pass


class MutationError(AttackLabError):
    """Raised when a mutation operator cannot be applied safely."""
    pass


class OracleEvaluationError(AttackLabError):
    """Raised when oracle evaluation encounters an unexpected state."""
    pass


class ResourceBudgetExceededError(AttackLabError):
    """Raised when simulation limits (scenarios, mutations, payload size) are breached."""
    pass


class SecurityBoundaryViolationError(AttackLabError):
    """Raised when an operation attempts to breach offline or tenancy boundaries."""
    pass
