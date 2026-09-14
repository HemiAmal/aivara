"""Comprehensive execution and verification of all 20 Golden Attack Scenarios (G01 to G20)."""

import pytest

from aivara.attacklab.runner import AttackLabRunner
from aivara.attacklab.scenarios import get_all_golden_scenarios, get_scenario_by_id


@pytest.fixture(scope="module")
def runner():
    return AttackLabRunner()


@pytest.mark.parametrize("scenario_id", [f"G{i:02d}" for i in range(1, 21)])
def test_golden_scenario_execution(runner: AttackLabRunner, scenario_id: str):
    """Verify that every Golden Attack Scenario (G01 to G20) executes and passes its oracle criteria."""
    scenario = get_scenario_by_id(scenario_id, project_id="proj_golden_test")
    assert scenario is not None, f"Scenario {scenario_id} not found."

    outcome = runner.run_scenario(scenario)

    assert outcome.is_pass is True, (
        f"Scenario {scenario_id} failed oracle verification: "
        f"Outcome={outcome.oracle_outcome.value}, Reasons={outcome.oracle_reasons}"
    )


def test_golden_suite_batch_execution(runner: AttackLabRunner):
    """Verify batch execution of all 20 Golden Scenarios produces a 100% detection rate report."""
    scenarios = get_all_golden_scenarios(project_id="proj_batch_test")
    report = runner.run_suite(scenarios, project_id="proj_batch_test")

    assert report.total_scenarios == 20
    assert report.passed_scenarios == 20
    assert report.failed_scenarios == 0
    assert report.detection_rate == 1.0
    assert report.false_negative_rate == 0.0
    assert report.false_positive_rate == 0.0
    assert len(report.report_hash) == 64
