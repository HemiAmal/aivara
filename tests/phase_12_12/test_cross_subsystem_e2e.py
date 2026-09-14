"""Test 12.12.3: Cross-Subsystem End-to-End Pipeline Verification across all 7 Domains."""

import pytest
from aivara.universal.api.service import UniversalAssuranceService
from aivara.universal.api.schemas import UniversalAssuranceTaskCreateRequest
from aivara.universal.enums import SubsystemDomain
from aivara.domain.schemas import EvidenceLayer
from aivara.universal.audit.generator import UniversalAuditReportGenerator


def test_full_7_domain_assurance_pipeline():
    """Execute all 7 canonical assurance domains through the complete Phase 12 pipeline."""
    project_id = "proj-e2e-7dom"
    service = UniversalAssuranceService()

    raw_evidence = [
        # Domain 0: DATASET_INTEGRITY
        {
            "evidence_id": "ev-0-ds",
            "project_id": project_id,
            "source_subsystem": SubsystemDomain.DATASET_INTEGRITY.value,
            "evidence_layer": EvidenceLayer.DETECTION.value,
            "evidence_type": "LABEL_ANOMALY",
            "severity": "low",
            "confidence": 0.90,
            "primary_asset_type": "dataset",
            "primary_asset_id": "dataset-1",
            "ancestry_keys": {"sample_id": "s1"},
            "data_json": {"score": 0.2},
        },
        # Domain 1: CONTRIBUTOR_RISK
        {
            "evidence_id": "ev-1-cr",
            "project_id": project_id,
            "source_subsystem": SubsystemDomain.CONTRIBUTOR_RISK.value,
            "evidence_layer": EvidenceLayer.DETECTION.value,
            "evidence_type": "CONTRIBUTOR_BURST",
            "severity": "medium",
            "confidence": 0.85,
            "primary_asset_type": "contributor",
            "primary_asset_id": "dataset-1",
            "ancestry_keys": {"source_id": "c1"},
            "data_json": {"score": 0.4},
        },
        # Domain 2: MODEL_INTEGRITY
        {
            "evidence_id": "ev-2-mi",
            "project_id": project_id,
            "source_subsystem": SubsystemDomain.MODEL_INTEGRITY.value,
            "evidence_layer": EvidenceLayer.PROOF.value,
            "evidence_type": "WEIGHT_HASH",
            "severity": "info",
            "confidence": 1.0,
            "primary_asset_type": "model",
            "primary_asset_id": "model-1",
            "ancestry_keys": {"model_fingerprint": "fp_m1"},
            "data_json": {"verified": True},
        },
        # Domain 3: BEHAVIORAL_ANALYSIS
        {
            "evidence_id": "ev-3-ba",
            "project_id": project_id,
            "source_subsystem": SubsystemDomain.BEHAVIORAL_ANALYSIS.value,
            "evidence_layer": EvidenceLayer.DETECTION.value,
            "evidence_type": "OUTPUT_DRIFT",
            "severity": "low",
            "confidence": 0.80,
            "primary_asset_type": "model",
            "primary_asset_id": "model-1",
            "ancestry_keys": {"window_id": "w1"},
            "data_json": {"drift": 0.15},
        },
        # Domain 4: BACKDOOR_TRIGGER
        {
            "evidence_id": "ev-4-bt",
            "project_id": project_id,
            "source_subsystem": SubsystemDomain.BACKDOOR_TRIGGER.value,
            "evidence_layer": EvidenceLayer.DETECTION.value,
            "evidence_type": "TRIGGER_MATCH",
            "severity": "low",
            "confidence": 0.75,
            "primary_asset_type": "model",
            "primary_asset_id": "model-1",
            "ancestry_keys": {"sample_id": "s1"},
            "data_json": {"match": 0.1},
        },
        # Domain 5: INFERENCE_INTEGRITY
        {
            "evidence_id": "ev-5-ii",
            "project_id": project_id,
            "source_subsystem": SubsystemDomain.INFERENCE_INTEGRITY.value,
            "evidence_layer": EvidenceLayer.DETECTION.value,
            "evidence_type": "SCHEMA_MISMATCH",
            "severity": "info",
            "confidence": 0.95,
            "primary_asset_type": "inference",
            "primary_asset_id": "model-1",
            "ancestry_keys": {"window_id": "w1"},
            "data_json": {"status": "ok"},
        },
        # Domain 6: DISTRIBUTION_SHIFT
        {
            "evidence_id": "ev-6-ds",
            "project_id": project_id,
            "source_subsystem": SubsystemDomain.DISTRIBUTION_SHIFT.value,
            "evidence_layer": EvidenceLayer.DETECTION.value,
            "evidence_type": "COVARIATE_SHIFT",
            "severity": "low",
            "confidence": 0.85,
            "primary_asset_type": "dataset",
            "primary_asset_id": "dataset-1",
            "ancestry_keys": {"sample_id": "s1"},
            "data_json": {"shift": 0.12},
        },
    ]

    edges = [
        {
            "project_id": project_id,
            "source_asset_id": "dataset-1",
            "target_asset_id": "model-1",
            "edge_type": "FEEDS",
            "propagation_weight": 0.8,
        }
    ]

    req = UniversalAssuranceTaskCreateRequest(
        project_id=project_id,
        asset_ids=["dataset-1", "model-1"],
        evidence_items=raw_evidence,
        dependency_edges=edges,
        asset_roles={"model-1": "CORE_DEPLOYED", "dataset-1": "SUPPORTING_INPUT"},
    )

    task_resp, _ = service.initiate_assurance_task(project_id, req)
    task_id = task_resp.task_id

    # Execute synchronous task step
    task = service.task_manager.get_task(task_id)
    service._execute_pipeline(task)

    assert task.status.value == "COMPLETED"
    assert "dataset-1" in task.risk_assessments
    assert "model-1" in task.risk_assessments
    assert task.hierarchical_assessment is not None

    # Audit generation from task
    audit_gen = UniversalAuditReportGenerator()
    report = audit_gen.generate_report(
        project_id=project_id,
        asset_ids=["dataset-1", "model-1"],
        evidence_items=raw_evidence,
        risk_assessments=task.risk_assessments,
        policy_decisions=task.decision_assessments,
        proof_assessments=task.proof_assessments,
        hierarchical_assessment=task.hierarchical_assessment,
        instance_version=1,
    )
    assert report.report_hash != ""
    assert len(report.compliance_results) > 0
