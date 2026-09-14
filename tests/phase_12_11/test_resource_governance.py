"""Test Resource Governance and Ceiling Enforcement (Phase 12.11)."""

import pytest
from aivara.universal.audit.generator import UniversalAuditReportGenerator


def test_large_evidence_and_asset_report_generation():
    """Verify report generator handles large bounded scopes deterministically without recursion depth errors."""
    gen = UniversalAuditReportGenerator()

    # Generate 50 assets and 200 evidence items
    assets = [f"asset-scale-{i}" for i in range(50)]
    evidence = [
        {
            "evidence_id": f"ev-scale-{i}",
            "domain": "drift",
            "evidence_layer": "detection",
            "primary_asset_id": f"asset-scale-{i % 50}",
        }
        for i in range(200)
    ]

    report = gen.generate_report(
        project_id="proj-scale-1",
        asset_ids=assets,
        evidence_items=evidence,
        report_id="rep-scale-1",
    )

    assert len(report.scope.asset_ids) == 50
    assert report.evidence_summary.total_evidence_count == 200
    assert len(report.report_hash) == 64
