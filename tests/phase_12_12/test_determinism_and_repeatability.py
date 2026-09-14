"""Test 12.12.13: Determinism & Repeatability Verification."""

import pytest
from aivara.universal.audit.generator import UniversalAuditReportGenerator
from aivara.universal.audit.integrity import compute_canonical_report_hash
from aivara.universal.enums import SubsystemDomain
from aivara.domain.schemas import EvidenceLayer


def test_repeated_report_generation_determinism():
    """Verify multiple independent runs produce bit-for-bit identical canonical hashes."""
    gen = UniversalAuditReportGenerator()

    evidence = [
        {"evidence_id": "ev-1", "domain": SubsystemDomain.MODEL_INTEGRITY, "evidence_layer": EvidenceLayer.PROOF, "primary_asset_id": "a1"},
        {"evidence_id": "ev-2", "domain": SubsystemDomain.BACKDOOR_TRIGGER, "evidence_layer": EvidenceLayer.DETECTION, "primary_asset_id": "a1"},
    ]
    risks = {"a1": {"risk_score": 0.25, "assessment_hash": "a" * 64}}

    rep1 = gen.generate_report(project_id="p-det", asset_ids=["a1"], evidence_items=evidence, risk_assessments=risks, report_id="r1")
    rep2 = gen.generate_report(project_id="p-det", asset_ids=["a1"], evidence_items=evidence, risk_assessments=risks, report_id="r1")

    assert rep1.report_hash == rep2.report_hash
    assert compute_canonical_report_hash(rep1) == compute_canonical_report_hash(rep2)
