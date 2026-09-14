"""Tests for Phase 12.7 Input Mutation and Fail-Closed Validation (REQ-12-POL-009, 010)."""

import pytest

from aivara.universal.policy.engine import UniversalPolicyEngine
from aivara.universal.policy.exceptions import (
    InvalidPolicyError,
    InvalidRiskInputError,
)
from aivara.universal.policy.schemas import UniversalPolicy
from aivara.universal.risk.enums import RiskLevel
from aivara.universal.risk.exceptions import NonFiniteRiskError, RiskOutOfRangeError
from aivara.universal.risk.schemas import UniversalRiskAssessment


@pytest.fixture
def policy_engine():
    return UniversalPolicyEngine()


@pytest.fixture
def valid_policy():
    return UniversalPolicy.get_default_policy()


def test_none_risk_assessment_rejected(policy_engine, valid_policy):
    """Passing None as risk assessment raises InvalidRiskInputError."""
    with pytest.raises(InvalidRiskInputError):
        policy_engine.evaluate(valid_policy, None)  # type: ignore


def test_invalid_type_risk_assessment_rejected(policy_engine, valid_policy):
    """Passing a non-UniversalRiskAssessment instance raises InvalidRiskInputError."""
    with pytest.raises(InvalidRiskInputError):
        policy_engine.evaluate(valid_policy, {"risk_score": 0.5})  # type: ignore


def test_tampered_risk_hash_rejected(policy_engine, valid_policy):
    """UniversalRiskAssessment with a falsified risk_hash is rejected (tamper detection)."""
    # Create valid assessment
    assessment = UniversalRiskAssessment(
        project_id="proj_tamper",
        asset_id="asset_tamper",
        risk_score=0.25,
        risk_level=RiskLevel.LOW,
    )
    # Manually alter risk_hash in private attribute
    object.__setattr__(assessment, "risk_hash", "0" * 64)

    with pytest.raises(InvalidRiskInputError, match="Risk assessment hash mismatch"):
        policy_engine.evaluate(valid_policy, assessment)


def test_risk_score_out_of_range_rejected():
    """Risk scores outside [0.0, 1.0] are rejected at assessment creation."""
    from pydantic import ValidationError
    with pytest.raises((ValidationError, RiskOutOfRangeError)):
        UniversalRiskAssessment(
            project_id="proj_invalid",
            asset_id="asset_invalid",
            risk_score=-0.05,
            risk_level=RiskLevel.LOW,
        )

    with pytest.raises((ValidationError, RiskOutOfRangeError)):
        UniversalRiskAssessment(
            project_id="proj_invalid",
            asset_id="asset_invalid",
            risk_score=1.05,
            risk_level=RiskLevel.CRITICAL,
        )


def test_non_finite_risk_rejected():
    """Non-finite risk scores (NaN, +Inf, -Inf) are rejected."""
    from pydantic import ValidationError
    with pytest.raises((ValidationError, NonFiniteRiskError)):
        UniversalRiskAssessment(
            project_id="proj_nan",
            asset_id="asset_nan",
            risk_score=float("nan"),
            risk_level=RiskLevel.LOW,
        )

    with pytest.raises((ValidationError, NonFiniteRiskError)):
        UniversalRiskAssessment(
            project_id="proj_inf",
            asset_id="asset_inf",
            risk_score=float("inf"),
            risk_level=RiskLevel.CRITICAL,
        )


def test_disabled_policy_rejected(policy_engine):
    """Evaluating against a disabled policy raises InvalidPolicyError."""
    policy = UniversalPolicy(
        policy_id="disabled_policy",
        enabled=False,
        thresholds=UniversalPolicy.get_default_policy().thresholds,
    )
    assessment = UniversalRiskAssessment(
        project_id="p1",
        asset_id="a1",
        risk_score=0.10,
        risk_level=RiskLevel.LOW,
    )

    with pytest.raises(InvalidPolicyError, match="is disabled"):
        policy_engine.evaluate(policy, assessment)


def test_none_policy_rejected(policy_engine):
    """Passing None as policy raises InvalidPolicyError."""
    assessment = UniversalRiskAssessment(
        project_id="p1",
        asset_id="a1",
        risk_score=0.10,
        risk_level=RiskLevel.LOW,
    )
    with pytest.raises(InvalidPolicyError):
        policy_engine.evaluate(None, assessment)  # type: ignore
