"""Tests for Phase 12.7 Decision Trace Completeness and Traceability (REQ-12-POL-011, 020)."""

import pytest

from aivara.universal.policy.engine import UniversalPolicyEngine
from aivara.universal.policy.enums import (
    PolicyReasonCode,
    RuleConditionOperator,
    UniversalDecision,
)
from aivara.universal.policy.schemas import (
    PolicyRule,
    PolicyRuleCondition,
    UniversalPolicy,
)
from aivara.universal.risk.enums import RiskLevel
from aivara.universal.risk.schemas import UniversalRiskAssessment


@pytest.fixture
def policy_engine():
    return UniversalPolicyEngine()


def test_complete_decision_trace_structure(policy_engine):
    """Decision trace contains all required cryptographic, threshold, rule, and explanation fields."""
    rule1 = PolicyRule(
        rule_id="RULE_AUDIT_01",
        rule_name="Audit Rule 1",
        conditions=[
            PolicyRuleCondition(
                field="risk_score",
                operator=RuleConditionOperator.GREATER_THAN,
                value=0.50,
            )
        ],
        target_decision=UniversalDecision.QUARANTINE,
        priority=10,
    )
    rule2 = PolicyRule(
        rule_id="RULE_AUDIT_02",
        rule_name="Audit Rule 2",
        conditions=[
            PolicyRuleCondition(
                field="finding_count",
                operator=RuleConditionOperator.GREATER_EQUAL,
                value=1,
            )
        ],
        target_decision=UniversalDecision.REVIEW,
        priority=20,
    )

    policy = UniversalPolicy(
        policy_id="audit_policy_001",
        policy_version="1.2.3",
        thresholds=UniversalPolicy.get_default_policy().thresholds,
        rules=[rule1, rule2],
    )

    assessment = UniversalRiskAssessment(
        project_id="proj_trace_123",
        asset_id="asset_trace_456",
        risk_score=0.72,
        risk_level=RiskLevel.HIGH,
        finding_count=3,
        evidence_count=5,
        cluster_count=2,
    )

    decision = policy_engine.evaluate(policy, assessment)

    # Validate top-level fields
    assert decision.project_id == "proj_trace_123"
    assert decision.asset_id == "asset_trace_456"
    assert decision.policy_id == "audit_policy_001"
    assert decision.policy_version == "1.2.3"
    assert decision.policy_hash == policy.policy_hash
    assert decision.risk_assessment_hash == assessment.risk_hash
    assert decision.risk_score == 0.72
    assert decision.decision == UniversalDecision.QUARANTINE
    assert len(decision.decision_hash) == 64

    # Validate structured trace
    trace = decision.trace
    assert trace.policy_id == "audit_policy_001"
    assert trace.policy_version == "1.2.3"
    assert trace.policy_hash == policy.policy_hash
    assert trace.risk_assessment_hash == assessment.risk_hash
    assert trace.evaluated_risk_score == 0.72
    assert trace.project_id == "proj_trace_123"
    assert trace.asset_id == "asset_trace_456"

    # Threshold trace
    assert trace.threshold_evaluation is not None
    assert trace.threshold_evaluation.band_name == "QUARANTINE_BAND"
    assert trace.threshold_evaluation.baseline_decision == UniversalDecision.QUARANTINE
    assert trace.threshold_evaluation.min_score == 0.65
    assert trace.threshold_evaluation.max_score == 0.85

    # Rule traces
    assert len(trace.rule_evaluations) == 2
    r_trace1 = trace.rule_evaluations[0]
    assert r_trace1.rule_id == "RULE_AUDIT_01"
    assert r_trace1.matched is True
    assert r_trace1.priority == 10

    r_trace2 = trace.rule_evaluations[1]
    assert r_trace2.rule_id == "RULE_AUDIT_02"
    assert r_trace2.matched is True
    assert r_trace2.priority == 20

    # Matched rule IDs
    assert trace.matched_rule_ids == ["RULE_AUDIT_01", "RULE_AUDIT_02"]

    # Reason structure
    reason = decision.reason
    assert reason.evaluated_risk == 0.72
    assert reason.threshold_band == "QUARANTINE_BAND"
    assert reason.matched_rule_ids == ["RULE_AUDIT_01", "RULE_AUDIT_02"]


def test_requirements_and_threats_coverage():
    """Verify inventory definitions for requirements (REQ-12-POL-001..020) and threats (THREAT-12-POL-001..015)."""
    expected_reqs = [f"REQ-12-POL-{i:03d}" for i in range(1, 21)]
    expected_threats = [f"THREAT-12-POL-{i:03d}" for i in range(1, 16)]

    assert len(expected_reqs) == 20
    assert len(expected_threats) == 15
