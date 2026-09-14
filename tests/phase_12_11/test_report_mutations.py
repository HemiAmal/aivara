"""Test Mutation Sensitivity across all Report Sections (Phase 12.11)."""

import pytest
from aivara.universal.audit.enums import ReportIntegrityStatus
from aivara.universal.policy.enums import UniversalDecision
from aivara.universal.audit.generator import UniversalAuditReportGenerator
from aivara.universal.audit.integrity import compute_canonical_report_hash, verify_report_integrity


@pytest.fixture
def base_report():
    gen = UniversalAuditReportGenerator()
    return gen.generate_report(
        project_id="proj-mut-1",
        asset_ids=["asset-1"],
        evidence_items=[{"evidence_id": "ev-1", "domain": "drift", "evidence_layer": "detection", "primary_asset_id": "asset-1"}],
        report_id="rep-mut-base",
    )


def test_decision_mutation_changes_hash(base_report):
    """Mutating overall policy decision changes report content hash."""
    mutated_pol = base_report.policy_summary.model_copy(update={"overall_decision": UniversalDecision.REJECT})
    mutated_rep = base_report.model_copy(update={"policy_summary": mutated_pol})
    assert compute_canonical_report_hash(mutated_rep) != base_report.report_hash
    assert verify_report_integrity(mutated_rep).status == ReportIntegrityStatus.TAMPERED


def test_asset_scope_mutation_changes_hash(base_report):
    """Mutating asset scope list changes report content hash."""
    mutated_scope = base_report.scope.model_copy(update={"asset_ids": ["asset-1", "asset-injected-2"]})
    mutated_rep = base_report.model_copy(update={"scope": mutated_scope})
    assert compute_canonical_report_hash(mutated_rep) != base_report.report_hash
    assert verify_report_integrity(mutated_rep).status == ReportIntegrityStatus.TAMPERED


def test_evidence_count_mutation_changes_hash(base_report):
    """Mutating evidence summary counts changes report content hash."""
    mutated_ev = base_report.evidence_summary.model_copy(update={"total_evidence_count": 999})
    mutated_rep = base_report.model_copy(update={"evidence_summary": mutated_ev})
    assert compute_canonical_report_hash(mutated_rep) != base_report.report_hash
    assert verify_report_integrity(mutated_rep).status == ReportIntegrityStatus.TAMPERED
