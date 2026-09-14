"""Tests for Proof-Aware Aggregation & Escalation (REQ-12-AGG-010, 011, 012)."""

from aivara.universal.aggregation.engine import UniversalProjectAggregator
from aivara.universal.aggregation.enums import AssetRole
from aivara.universal.policy.enums import UniversalDecision
from aivara.universal.proof.enums import ProofVerificationStatus
from aivara.universal.proof.schemas import UniversalProofAssessment
from aivara.universal.risk.enums import EvidenceSufficiencyStatus, RiskLevel
from aivara.universal.risk.schemas import AssetRiskAssessment, ProjectRiskAssessment


def test_core_deployed_proof_failure_forces_project_reject():
    """Proof failure on a CORE_DEPLOYED asset forces final Project disposition to REJECT."""
    aggregator = UniversalProjectAggregator()

    # Asset A: Core model with low detection risk (0.10), but fatal proof failure
    ass_a = AssetRiskAssessment(
        project_id="proj_proof_esc",
        asset_id="core_model_v1",
        asset_type="model",
        risk_score=0.10,
        risk_level=RiskLevel.LOW,
        evidence_sufficiency=EvidenceSufficiencyStatus.SUFFICIENT,
        finding_count=1,
        evidence_count=1,
        cluster_count=1,
        contributions=[],
    )

    proof_ass_a = UniversalProofAssessment(
        project_id="proj_proof_esc",
        asset_id="core_model_v1",
        overall_proof_status=ProofVerificationStatus.TAMPERED,
        total_evidence_evaluated=1,
        tampered_count=1,
        proof_override_required=True,
        override_decision=UniversalDecision.REJECT,
        evidence_results=[],
    )

    proj_ass = ProjectRiskAssessment(
        project_id="proj_proof_esc",
        project_risk_score=0.10,
        risk_level=RiskLevel.LOW,
        peak_asset_risk=0.10,
        peak_asset_id="core_model_v1",
        asset_count=1,
        chain_count=0,
    )

    disp = aggregator.synthesize_project_disposition(
        project_assessment=proj_ass,
        asset_assessments=[ass_a],
        proof_assessments_map={"core_model_v1": proof_ass_a},
        asset_roles={"core_model_v1": AssetRole.CORE_DEPLOYED},
    )

    assert disp.decision == UniversalDecision.REJECT
    assert disp.proof_override_triggered is True
    assert "Core deployed asset 'core_model_v1' suffered fatal cryptographic proof failure" in (disp.escalation_reason or "")


def test_peripheral_sample_proof_failure_escalates_to_quarantine():
    """Proof failure on a PERIPHERAL_SAMPLE asset escalates Project disposition to at least QUARANTINE."""
    aggregator = UniversalProjectAggregator()

    # Asset B: Peripheral sample with proof failure
    ass_b = AssetRiskAssessment(
        project_id="proj_proof_esc_2",
        asset_id="sample_test_batch",
        asset_type="sample",
        risk_score=0.15,
        risk_level=RiskLevel.LOW,
        evidence_sufficiency=EvidenceSufficiencyStatus.SUFFICIENT,
        finding_count=1,
        evidence_count=1,
        cluster_count=1,
        contributions=[],
    )

    proof_ass_b = UniversalProofAssessment(
        project_id="proj_proof_esc_2",
        asset_id="sample_test_batch",
        overall_proof_status=ProofVerificationStatus.INVALID,
        total_evidence_evaluated=1,
        invalid_count=1,
        proof_override_required=True,
        override_decision=UniversalDecision.REJECT,
        evidence_results=[],
    )

    proj_ass = ProjectRiskAssessment(
        project_id="proj_proof_esc_2",
        project_risk_score=0.15,
        risk_level=RiskLevel.LOW,
        peak_asset_risk=0.15,
        peak_asset_id="sample_test_batch",
        asset_count=1,
        chain_count=0,
    )

    disp = aggregator.synthesize_project_disposition(
        project_assessment=proj_ass,
        asset_assessments=[ass_b],
        proof_assessments_map={"sample_test_batch": proof_ass_b},
        asset_roles={"sample_test_batch": AssetRole.PERIPHERAL_SAMPLE},
    )

    assert disp.decision == UniversalDecision.QUARANTINE
    assert disp.proof_override_triggered is True
    assert "Peripheral sample asset 'sample_test_batch' suffered cryptographic proof failure" in (disp.escalation_reason or "")
