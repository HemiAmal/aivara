"""Test expected-result oracle outcome classifications."""

from aivara.attacklab.enums import (
    AttackClass,
    AttackDomain,
    ExpectedDecisionClass,
    OracleOutcome,
)
from aivara.attacklab.oracle import SimulationOracle
from aivara.attacklab.schemas import (
    ExpectedBehavior,
    PipelineExecutionTrace,
    ScenarioDefinition,
)


def test_oracle_expected_detection():
    """Verify oracle correctly classifies successful detection."""
    scenario = ScenarioDefinition(
        scenario_id="TEST_ORACLE_01",
        name="Oracle Detection Test",
        target_domain=AttackDomain.DATASET_INTEGRITY,
        attack_class=AttackClass.SAMPLE_POISONING,
        description="Oracle test",
        project_id="proj_orc",
        fixture_type="dataset_integrity",
        expected=ExpectedBehavior(
            expected_outcome=OracleOutcome.EXPECTED_DETECTION,
            expect_finding_types=["DATASET_LABEL_ANOMALY"],
            min_risk=0.30,
            expected_decision=ExpectedDecisionClass.ANY_ELEVATED,
        ),
    )

    clean_trace = PipelineExecutionTrace(
        executed_at="2026-09-14T00:00:00Z",
        success=True,
        finding_types=[],
        risk_score=0.0,
        decision="ACCEPT",
    )
    attack_trace = PipelineExecutionTrace(
        executed_at="2026-09-14T00:00:00Z",
        success=True,
        finding_types=["DATASET_LABEL_ANOMALY"],
        risk_score=0.55,
        decision="REVIEW",
    )

    outcome = SimulationOracle.evaluate(
        scenario=scenario,
        clean_trace=clean_trace,
        attack_trace=attack_trace,
        risk_delta=0.55,
        new_findings=["DATASET_LABEL_ANOMALY"],
    )

    assert outcome.oracle_outcome == OracleOutcome.EXPECTED_DETECTION
    assert outcome.is_pass is True


def test_oracle_false_negative():
    """Verify oracle flags FALSE_NEGATIVE when expected detection did not occur."""
    scenario = ScenarioDefinition(
        scenario_id="TEST_ORACLE_02",
        name="Oracle False Negative Test",
        target_domain=AttackDomain.DATASET_INTEGRITY,
        attack_class=AttackClass.SAMPLE_POISONING,
        description="Oracle FN test",
        project_id="proj_orc",
        fixture_type="dataset_integrity",
        expected=ExpectedBehavior(
            expected_outcome=OracleOutcome.EXPECTED_DETECTION,
            expect_finding_types=["DATASET_LABEL_ANOMALY"],
            min_risk=0.40,
        ),
    )

    clean_trace = PipelineExecutionTrace(
        executed_at="2026-09-14T00:00:00Z",
        success=True,
        finding_types=[],
        risk_score=0.0,
        decision="ACCEPT",
    )
    # Attack produced no findings
    attack_trace = PipelineExecutionTrace(
        executed_at="2026-09-14T00:00:00Z",
        success=True,
        finding_types=[],
        risk_score=0.0,
        decision="ACCEPT",
    )

    outcome = SimulationOracle.evaluate(
        scenario=scenario,
        clean_trace=clean_trace,
        attack_trace=attack_trace,
        risk_delta=0.0,
        new_findings=[],
    )

    assert outcome.oracle_outcome == OracleOutcome.FALSE_NEGATIVE
    assert outcome.is_pass is False


def test_oracle_false_positive():
    """Verify oracle flags FALSE_POSITIVE when clean baseline produces unexpected findings."""
    scenario = ScenarioDefinition(
        scenario_id="TEST_ORACLE_03",
        name="Oracle False Positive Test",
        target_domain=AttackDomain.DATASET_INTEGRITY,
        attack_class=AttackClass.SAMPLE_POISONING,
        description="Oracle FP test",
        project_id="proj_orc",
        fixture_type="dataset_integrity",
        expected=ExpectedBehavior(
            expected_outcome=OracleOutcome.EXPECTED_NO_DETECTION,
        ),
    )

    clean_trace = PipelineExecutionTrace(
        executed_at="2026-09-14T00:00:00Z",
        success=True,
        finding_types=["UNEXPECTED_FINDING"],
        risk_score=0.50,
        decision="REVIEW",
    )
    attack_trace = clean_trace

    outcome = SimulationOracle.evaluate(
        scenario=scenario,
        clean_trace=clean_trace,
        attack_trace=attack_trace,
        risk_delta=0.0,
        new_findings=[],
    )

    assert outcome.oracle_outcome == OracleOutcome.FALSE_POSITIVE
    assert outcome.is_pass is False
