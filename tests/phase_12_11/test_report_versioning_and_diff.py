"""Test Report Versioning and Semantic Diff Engine (Phase 12.11)."""

import pytest
from aivara.universal.audit.diff import compare_audit_reports
from aivara.universal.audit.generator import UniversalAuditReportGenerator
from aivara.universal.exceptions import ProjectMismatchError


def test_report_semantic_diff_detection():
    """Verify semantic diff correctly detects risk score and asset changes between versions."""
    gen = UniversalAuditReportGenerator()

    rep1 = gen.generate_report(
        project_id="proj-diff-1",
        asset_ids=["asset-1"],
        evidence_items=[],
        risk_assessments={"asset-1": {"risk_score": 0.20}},
        instance_version=1,
        report_id="rep-v1",
    )

    rep2 = gen.generate_report(
        project_id="proj-diff-1",
        asset_ids=["asset-1", "asset-2"],
        evidence_items=[],
        risk_assessments={"asset-1": {"risk_score": 0.20}, "asset-2": {"risk_score": 0.80}},
        instance_version=2,
        report_id="rep-v2",
    )

    diff = compare_audit_reports(rep1, rep2)
    assert diff.has_changes is True
    assert diff.base_instance_version == 1
    assert diff.target_instance_version == 2
    assert "asset-2" in diff.added_assets
    assert diff.risk_score_delta > 0.0


def test_cross_project_diff_fails_closed():
    """Verify comparing reports from different projects raises ScopeMismatchError."""
    gen = UniversalAuditReportGenerator()

    rep1 = gen.generate_report(
        project_id="proj-diff-A",
        asset_ids=["asset-1"],
        evidence_items=[],
        report_id="rep-A",
    )
    rep2 = gen.generate_report(
        project_id="proj-diff-B",
        asset_ids=["asset-1"],
        evidence_items=[],
        report_id="rep-B",
    )

    with pytest.raises(ProjectMismatchError):
        compare_audit_reports(rep1, rep2)
