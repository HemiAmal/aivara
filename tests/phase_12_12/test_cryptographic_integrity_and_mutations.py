"""Test 12.12.12: Cryptographic Boundary & Avalanche Mutation Campaign Verification."""

import pytest
from aivara.universal.audit.generator import UniversalAuditReportGenerator
from aivara.universal.audit.integrity import compute_canonical_report_hash, verify_report_integrity
from aivara.universal.audit.enums import ReportIntegrityStatus
from aivara.universal.policy.enums import UniversalDecision


def test_audit_report_avalanche_mutations():
    """Verify single-field mutations invalidate cryptographic hash and trigger TAMPERED integrity status."""
    gen = UniversalAuditReportGenerator()
    rep = gen.generate_report(
        project_id="proj-mut",
        asset_ids=["a1"],
        evidence_items=[],
        report_id="rep-mut-1",
    )
    orig_hash = rep.report_hash

    # 1. Mutate Policy Decision
    mut1 = rep.model_copy(update={"policy_summary": rep.policy_summary.model_copy(update={"overall_decision": UniversalDecision.REJECT})})
    assert compute_canonical_report_hash(mut1) != orig_hash
    assert verify_report_integrity(mut1).status == ReportIntegrityStatus.TAMPERED

    # 2. Mutate Risk Score
    mut2 = rep.model_copy(update={"risk_summary": rep.risk_summary.model_copy(update={"project_risk_score": 0.99})})
    assert compute_canonical_report_hash(mut2) != orig_hash
    assert verify_report_integrity(mut2).status == ReportIntegrityStatus.TAMPERED

    # 3. Mutate Asset Scope
    mut3 = rep.model_copy(update={"scope": rep.scope.model_copy(update={"asset_ids": ["a1", "injected_asset"]})})
    assert compute_canonical_report_hash(mut3) != orig_hash
    assert verify_report_integrity(mut3).status == ReportIntegrityStatus.TAMPERED
