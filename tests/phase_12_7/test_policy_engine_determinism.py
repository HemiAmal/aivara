"""Tests for Phase 12.7 Engine Determinism, Monotonicity, and Hash Integrity (REQ-12-POL-012, 013, 014)."""

import pytest

from aivara.universal.policy.engine import UniversalPolicyEngine
from aivara.universal.policy.enums import UniversalDecision
from aivara.universal.policy.schemas import UniversalPolicy
from aivara.universal.risk.enums import RiskLevel
from aivara.universal.risk.schemas import UniversalRiskAssessment


@pytest.fixture
def policy_engine():
    return UniversalPolicyEngine()


def make_assessment(risk_score: float) -> UniversalRiskAssessment:
    level = (
        RiskLevel.CRITICAL if risk_score >= 0.85
        else (RiskLevel.HIGH if risk_score >= 0.65
              else (RiskLevel.MEDIUM if risk_score >= 0.30
                    else (RiskLevel.LOW if risk_score > 0.0 else RiskLevel.NONE)))
    )
    return UniversalRiskAssessment(
        project_id="proj_determinism",
        asset_id="asset_determinism",
        risk_score=risk_score,
        risk_level=level,
        finding_count=1,
        evidence_count=1,
        cluster_count=1,
    )


def test_repeated_evaluation_determinism(policy_engine):
    """100 repeated evaluations of same policy and assessment produce bit-for-bit identical hashes and decisions."""
    policy = UniversalPolicy.get_default_policy()
    assessment = make_assessment(risk_score=0.42)

    first_decision = policy_engine.evaluate(policy, assessment)

    for _ in range(100):
        d = policy_engine.evaluate(policy, assessment)
        assert d.decision == first_decision.decision
        assert d.decision_hash == first_decision.decision_hash
        assert d.policy_hash == first_decision.policy_hash
        assert d.reason.to_canonical_dict() == first_decision.reason.to_canonical_dict()
        assert d.trace.to_canonical_dict() == first_decision.trace.to_canonical_dict()


def test_monotonic_risk_escalation(policy_engine):
    """Monotonically increasing risk scores strictly produce non-decreasing decision severity ranks."""
    policy = UniversalPolicy.get_default_policy()
    risk_scores = [0.0, 0.10, 0.20, 0.29, 0.30, 0.40, 0.64, 0.65, 0.70, 0.84, 0.85, 0.90, 1.00]

    decisions = [policy_engine.evaluate(policy, make_assessment(r)).decision for r in risk_scores]

    # Verify that decision severity rank is monotonically non-decreasing
    for i in range(len(decisions) - 1):
        d_curr = decisions[i]
        d_next = decisions[i + 1]
        assert d_curr.severity_rank <= d_next.severity_rank, (
            f"Monotonicity violated at index {i}: risk {risk_scores[i]} ({d_curr.value}) > "
            f"risk {risk_scores[i+1]} ({d_next.value})"
        )


def test_decision_hash_sensitivity(policy_engine):
    """Mutating any security-relevant parameter changes the computed decision_hash."""
    policy_a = UniversalPolicy.get_default_policy(policy_id="policy_A")
    policy_b = UniversalPolicy.get_default_policy(policy_id="policy_B")

    assess_1 = make_assessment(risk_score=0.25)
    assess_2 = make_assessment(risk_score=0.26)

    d_base = policy_engine.evaluate(policy_a, assess_1)
    d_diff_policy = policy_engine.evaluate(policy_b, assess_1)
    d_diff_risk = policy_engine.evaluate(policy_a, assess_2)

    assert d_base.decision_hash != d_diff_policy.decision_hash
    assert d_base.decision_hash != d_diff_risk.decision_hash
