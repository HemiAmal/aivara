"""Test Deterministic Audit Report Generation (Phase 12.11)."""

import pytest
from aivara.universal.audit.generator import UniversalAuditReportGenerator
from aivara.universal.audit.integrity import compute_canonical_report_hash
from aivara.domain.schemas import EvidenceLayer
from aivara.universal.enums import SubsystemDomain


def test_identical_inputs_produce_identical_canonical_hash():
    """Verify identical assurance inputs produce identical canonical content hash across multiple runs."""
    gen = UniversalAuditReportGenerator()

    evidence = [
        {
            "evidence_id": "ev-1",
            "domain": SubsystemDomain.MODEL_INTEGRITY,
            "evidence_layer": EvidenceLayer.PROOF,
            "primary_asset_id": "asset-1",
        },
        {
            "evidence_id": "ev-2",
            "domain": SubsystemDomain.BACKDOOR_TRIGGER,
            "evidence_layer": EvidenceLayer.DETECTION,
            "primary_asset_id": "asset-1",
        },
    ]

    risks = {"asset-1": {"risk_score": 0.20, "risk_level": "LOW", "assessment_hash": "a" * 64}}

    rep1 = gen.generate_report(
        project_id="proj-det-1",
        asset_ids=["asset-1"],
        evidence_items=evidence,
        risk_assessments=risks,
        report_id="rep-fixed-id-1",
    )

    rep2 = gen.generate_report(
        project_id="proj-det-1",
        asset_ids=["asset-1"],
        evidence_items=evidence,
        risk_assessments=risks,
        report_id="rep-fixed-id-1",
    )

    assert rep1.report_hash == rep2.report_hash
    assert compute_canonical_report_hash(rep1) == compute_canonical_report_hash(rep2)
