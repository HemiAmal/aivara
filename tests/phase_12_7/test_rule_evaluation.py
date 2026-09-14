"""Tests for Phase 12.7 Rule Conditions, Precedence, and Escalation (REQ-12-POL-007, 008, 014)."""

import pytest

from aivara.domain.schemas import Severity
from aivara.universal.enums import SubsystemDomain
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
from aivara.universal.risk.enums import EvidenceSufficiencyStatus, RiskLevel
from aivara.universal.risk.schemas import RiskContribution, UniversalRiskAssessment


@pytest.fixture
def policy_engine():
    return UniversalPolicyEngine()


def make_assessment(
    risk_score: float = 0.15,
    evidence_sufficiency: EvidenceSufficiencyStatus = EvidenceSufficiencyStatus.SUFFICIENT,
    contributions: list = None,
) -> UniversalRiskAssessment:
    level = RiskLevel.LOW if risk_score < 0.30 else (RiskLevel.MEDIUM if risk_score < 0.65 else RiskLevel.HIGH)
    return UniversalRiskAssessment(
        project_id="proj_alpha",
        asset_id="asset_beta",
        risk_score=risk_score,
        risk_level=level,
        evidence_sufficiency=evidence_sufficiency,
        finding_count=len(contributions) if contributions else 1,
        evidence_count=len(contributions) if contributions else 1,
        cluster_count=1,
        contributions=contributions or [],
    )


def test_baseline_decision_no_rules(policy_engine):
    """Low risk score (0.15) with no rules results in baseline ACCEPT."""
    policy = UniversalPolicy.get_default_policy()
    assessment = make_assessment(risk_score=0.15)
    decision = policy_engine.evaluate(policy, assessment)

    assert decision.decision == UniversalDecision.ACCEPT
    assert decision.reason.reason_code == PolicyReasonCode.RISK_BELOW_REVIEW_THRESHOLD
    assert decision.reason.escalation_applied is False
    assert decision.reason.triggering_rule_id is None
    assert decision.trace.threshold_evaluation.baseline_decision == UniversalDecision.ACCEPT


def test_single_rule_escalation(policy_engine):
    """Rule matching insufficient ancestry escalates baseline ACCEPT to REVIEW."""
    rule = PolicyRule(
        rule_id="RULE_ANCESTRY_ESCALATION",
        rule_name="Insufficient Ancestry Guard",
        conditions=[
            PolicyRuleCondition(
                field="evidence_sufficiency",
                operator=RuleConditionOperator.EQUALS,
                value="INSUFFICIENT_ANCESTRY",
            )
        ],
        target_decision=UniversalDecision.REVIEW,
        reason_code=PolicyReasonCode.INSUFFICIENT_ANCESTRY_ESCALATION,
        reason_summary="Escalated due to incomplete cryptographic ancestry trace.",
        priority=10,
    )
    policy = UniversalPolicy(
        policy_id="ancestry_policy",
        thresholds=UniversalPolicy.get_default_policy().thresholds,
        rules=[rule],
    )

    assessment = make_assessment(
        risk_score=0.10,  # Baseline is ACCEPT
        evidence_sufficiency=EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY,
    )

    decision = policy_engine.evaluate(policy, assessment)
    assert decision.decision == UniversalDecision.REVIEW
    assert decision.reason.escalation_applied is True
    assert decision.reason.triggering_rule_id == "RULE_ANCESTRY_ESCALATION"
    assert decision.reason.reason_code == PolicyReasonCode.INSUFFICIENT_ANCESTRY_ESCALATION
    assert "RULE_ANCESTRY_ESCALATION" in decision.reason.matched_rule_ids


def test_multiple_conflicting_rules_most_restrictive_wins(policy_engine):
    """When multiple rules match proposing different decisions, the most restrictive decision wins."""
    # Rule 1 proposes REVIEW
    r1 = PolicyRule(
        rule_id="RULE_01_REVIEW",
        rule_name="Propose Review",
        conditions=[
            PolicyRuleCondition(
                field="risk_score",
                operator=RuleConditionOperator.GREATER_EQUAL,
                value=0.10,
            )
        ],
        target_decision=UniversalDecision.REVIEW,
        priority=10,
    )
    # Rule 2 proposes QUARANTINE
    r2 = PolicyRule(
        rule_id="RULE_02_QUARANTINE",
        rule_name="Propose Quarantine",
        conditions=[
            PolicyRuleCondition(
                field="has_critical_severity",
                operator=RuleConditionOperator.EQUALS,
                value=True,
            )
        ],
        target_decision=UniversalDecision.QUARANTINE,
        priority=20,
    )
    # Rule 3 proposes REJECT
    r3 = PolicyRule(
        rule_id="RULE_03_REJECT",
        rule_name="Propose Reject",
        conditions=[
            PolicyRuleCondition(
                field="critical_finding_count",
                operator=RuleConditionOperator.GREATER_EQUAL,
                value=2,
            )
        ],
        target_decision=UniversalDecision.REJECT,
        priority=30,
    )

    policy = UniversalPolicy(
        policy_id="multi_rule_policy",
        thresholds=UniversalPolicy.get_default_policy().thresholds,
        rules=[r1, r2, r3],
    )

    # Assessment with 2 critical findings -> r1, r2, r3 all match
    c1 = RiskContribution(
        contribution_id="c1",
        source_id="s1",
        target_id="asset_beta",
        severity=Severity.CRITICAL,
        raw_score=0.90,
        effective_score=0.90,
    )
    c2 = RiskContribution(
        contribution_id="c2",
        source_id="s2",
        target_id="asset_beta",
        severity=Severity.CRITICAL,
        raw_score=0.85,
        effective_score=0.85,
    )

    assessment = make_assessment(
        risk_score=0.20,  # Baseline is ACCEPT
        contributions=[c1, c2],
    )

    decision = policy_engine.evaluate(policy, assessment)
    # Most restrictive (REJECT) wins over REVIEW and QUARANTINE
    assert decision.decision == UniversalDecision.REJECT
    assert decision.reason.escalation_applied is True
    assert decision.reason.triggering_rule_id == "RULE_03_REJECT"
    assert len(decision.reason.matched_rule_ids) == 3


def test_disabled_rules_ignored(policy_engine):
    """Disabled rules are not evaluated and cannot trigger escalation."""
    rule = PolicyRule(
        rule_id="DISABLED_RULE",
        rule_name="Disabled Rule",
        conditions=[
            PolicyRuleCondition(
                field="risk_score",
                operator=RuleConditionOperator.GREATER_EQUAL,
                value=0.0,
            )
        ],
        target_decision=UniversalDecision.REJECT,
        enabled=False,  # Disabled!
    )
    policy = UniversalPolicy(
        policy_id="disabled_rule_policy",
        thresholds=UniversalPolicy.get_default_policy().thresholds,
        rules=[rule],
    )

    assessment = make_assessment(risk_score=0.10)
    decision = policy_engine.evaluate(policy, assessment)

    assert decision.decision == UniversalDecision.ACCEPT
    assert decision.reason.escalation_applied is False
    assert len(decision.trace.rule_evaluations) == 0


def test_monotonic_rule_cannot_downgrade(policy_engine):
    """A rule targeting ACCEPT cannot downgrade a baseline REJECT (monotonicity invariant)."""
    rule = PolicyRule(
        rule_id="RULE_DOWNGRADE_ATTEMPT",
        rule_name="Attempt Downgrade",
        conditions=[
            PolicyRuleCondition(
                field="risk_score",
                operator=RuleConditionOperator.GREATER_EQUAL,
                value=0.0,
            )
        ],
        target_decision=UniversalDecision.ACCEPT,  # Permissive target
    )
    policy = UniversalPolicy(
        policy_id="downgrade_attempt_policy",
        thresholds=UniversalPolicy.get_default_policy().thresholds,
        rules=[rule],
    )

    # Risk score 0.90 is baseline REJECT
    assessment = make_assessment(risk_score=0.90)
    decision = policy_engine.evaluate(policy, assessment)

    assert decision.decision == UniversalDecision.REJECT
    assert decision.reason.escalation_applied is False


def test_all_condition_operators(policy_engine):
    """Test NOT_EQUALS, LESS_THAN, LESS_EQUAL, IN, CONTAINS operators."""
    r_not_eq = PolicyRule(
        rule_id="R_NOT_EQ",
        rule_name="Not Equals",
        conditions=[
            PolicyRuleCondition(field="evidence_sufficiency", operator=RuleConditionOperator.NOT_EQUALS, value="SUFFICIENT")
        ],
        target_decision=UniversalDecision.REVIEW,
    )
    r_less_than = PolicyRule(
        rule_id="R_LT",
        rule_name="Less Than",
        conditions=[
            PolicyRuleCondition(field="finding_count", operator=RuleConditionOperator.LESS_THAN, value=5)
        ],
        target_decision=UniversalDecision.REVIEW,
    )
    r_less_eq = PolicyRule(
        rule_id="R_LE",
        rule_name="Less Equal",
        conditions=[
            PolicyRuleCondition(field="cluster_count", operator=RuleConditionOperator.LESS_EQUAL, value=1)
        ],
        target_decision=UniversalDecision.REVIEW,
    )
    r_in = PolicyRule(
        rule_id="R_IN",
        rule_name="In",
        conditions=[
            PolicyRuleCondition(field="risk_level", operator=RuleConditionOperator.IN, value=["LOW", "MEDIUM"])
        ],
        target_decision=UniversalDecision.REVIEW,
    )

    policy = UniversalPolicy(
        policy_id="op_policy",
        thresholds=UniversalPolicy.get_default_policy().thresholds,
        rules=[r_not_eq, r_less_than, r_less_eq, r_in],
    )

    assess = make_assessment(
        risk_score=0.10,
        evidence_sufficiency=EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY,
    )

    d = policy_engine.evaluate(policy, assess)
    assert d.decision == UniversalDecision.REVIEW
    assert set(d.reason.matched_rule_ids) == {"R_NOT_EQ", "R_LT", "R_LE", "R_IN"}


def test_domain_specific_rule_evaluation(policy_engine):
    """Test domain count and max score property evaluations in policy rules."""
    c_backdoor = RiskContribution(
        contribution_id="c_bd",
        source_id="s_bd",
        target_id="asset_beta",
        domain=SubsystemDomain.BACKDOOR_TRIGGER,
        severity=Severity.HIGH,
        raw_score=0.75,
        effective_score=0.75,
    )
    r_bd = PolicyRule(
        rule_id="RULE_BACKDOOR_GUARD",
        rule_name="Backdoor Trigger High Risk Guard",
        conditions=[
            PolicyRuleCondition(
                field="domain_max_score.BACKDOOR_TRIGGER",
                operator=RuleConditionOperator.GREATER_EQUAL,
                value=0.70,
            )
        ],
        target_decision=UniversalDecision.QUARANTINE,
        reason_code=PolicyReasonCode.DOMAIN_THRESHOLD_ESCALATION,
    )
    policy = UniversalPolicy(
        policy_id="bd_policy",
        thresholds=UniversalPolicy.get_default_policy().thresholds,
        rules=[r_bd],
    )

    assess = make_assessment(
        risk_score=0.15,
        contributions=[c_backdoor],
    )

    d = policy_engine.evaluate(policy, assess)
    assert d.decision == UniversalDecision.QUARANTINE
    assert d.reason.reason_code == PolicyReasonCode.DOMAIN_THRESHOLD_ESCALATION
    assert d.reason.triggering_rule_id == "RULE_BACKDOOR_GUARD"
