"""Test cryptographic sealing, JSON/Markdown export, and reporting integrity."""

import json

from aivara.attacklab.reporting import SimulationReportGenerator
from aivara.attacklab.runner import AttackLabRunner
from aivara.attacklab.scenarios import get_scenario_by_id


def test_simulation_report_export_and_integrity():
    """Verify simulation report generation and formatting."""
    scenario = get_scenario_by_id("G01", project_id="proj_rep_test")
    assert scenario is not None

    runner = AttackLabRunner()
    report = runner.run_suite([scenario], project_id="proj_rep_test")

    # JSON export test
    json_str = SimulationReportGenerator.to_json(report)
    parsed = json.loads(json_str)
    assert parsed["report_id"] == report.report_id
    assert parsed["total_scenarios"] == 1
    assert parsed["passed_scenarios"] == 1

    # Markdown export test
    md_str = SimulationReportGenerator.to_markdown(report)
    assert "# AIVARA Attack Simulation Lab — Execution Report" in md_str
    assert report.report_hash in md_str
    assert "`G01`" in md_str
    assert "**PASS**" in md_str
