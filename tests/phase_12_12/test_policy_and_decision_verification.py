"""Test 12.12.7: Policy Governance & Universal Decision Verification."""

import pytest
from aivara.universal.policy.engine import UniversalPolicyEngine
from aivara.universal.policy.enums import UniversalDecision
from aivara.universal.policy.schemas import UniversalPolicy
from aivara.universal.risk.enums import EvidenceSufficiencyStatus, RiskLevel
from aivara.universal.risk.schemas import UniversalRiskAssessment


def test_decision_thresholds_mapping():
    """Verify decision thresholds: [0, 0.30)->ACCEPT, [0.30, 0.65)->REVIEW, [0.65, 0.85)->QUARANTINE, [0.85, 1.0]->REJECT."""
    eng = UniversalPolicyEngine()
    policy = UniversalPolicy.get_default_policy()

    def make_mock_risk(score: float):
        return UniversalRiskAssessment(
            project_id="proj-p",
            asset_id="a1",
            asset_type="model",
            risk_score=score,
            risk_level=RiskLevel.HIGH if score >= 0.7 else RiskLevel.LOW,
            evidence_sufficiency=EvidenceSufficiencyStatus.SUFFICIENT,
            finding_count=1,
            evidence_count=1,
            cluster_count=1,
            contributions=[],
        )

    assert eng.evaluate(policy, make_mock_risk(0.15)).decision == UniversalDecision.ACCEPT
    assert eng.evaluate(policy, make_mock_risk(0.45)).decision == UniversalDecision.REVIEW
    assert eng.evaluate(policy, make_mock_risk(0.75)).decision == UniversalDecision.QUARANTINE
    assert eng.evaluate(policy, make_mock_risk(0.90)).decision == UniversalDecision.REJECT

