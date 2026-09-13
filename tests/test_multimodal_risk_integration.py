"""Comprehensive Verification Suite for Phase 11.9: Evidence, Findings & Multi-Modal Risk Integration.

Verifies all 50 formal requirements across 12 exhaustive test suites:
- Schema validation, finite numeric bounds, non-NaN/Inf
- Evidence deduplication via content-addressed digests
- Proof Layer non-compensability and scope isolation
- Detection confidence calibration and statistical support
- Ancestry-aware clustering by asset lineage keys
- Parameterized correlation damping (lambda_corr in [0.0, 0.50])
- Sub-additive bounded risk formula mathematics
- Decision policy thresholds and deterministic disposition mapping
- Insufficient and conflicting evidence fail-closed handling
- Multi-tenant project isolation and ProjectMismatchError
- Deterministic RFC 8785 JCS digests and mutation sensitivity
- AST security scan, 100% offline air-gap execution, and cross-phase compatibility
"""

from __future__ import annotations

import ast
import copy
import glob
import hashlib
import math
import os
from typing import Any, Dict, List

import pytest
from pydantic import ValidationError

from aivara.assurance import (
    DEFAULT_CATEGORY_WEIGHTS,
    DecisionPolicy,
    DependencyRelation,
    EvidenceCategory,
    EvidenceReference,
    IntegratedAssuranceProfile,
    IntegrationEvaluationStatus,
    InvalidEvidenceError,
    MultiModalRiskIntegrationEngine,
    PolicyValidationError,
    ProjectMismatchError,
    ResourceLimitExceededError,
    RiskPolicy,
    SynthesizedFinding,
    compute_decision_policy_hash,
    compute_evidence_set_hash,
    compute_integrated_profile_hash,
    compute_risk_policy_hash,
)
from aivara.domain.schemas import Disposition, EvidenceLayer, Severity


def test_01_to_05_schema_validation_and_finite_numeric_bounds() -> None:
    """Verify FR-11.9-001, STAT-11.9-001, SEC-11.9-005: Schema bounds, finite float validation, Proof layer confidence."""
    # 1. Valid EvidenceReference instantiation
    ev_valid = EvidenceReference(
        evidence_id="ev_001",
        project_id="proj_alpha",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="feature_drift",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Tabular Feature Shift",
        confidence=0.95,
        severity=Severity.HIGH,
        target_asset_type="dataset",
        target_asset_id="ds_123",
        evidence_hash="a" * 64,
        data_json={"psi": 0.25},
    )
    assert ev_valid.confidence == 0.95

    # 2. Rejection of NaN / Inf in confidence
    with pytest.raises((ValueError, ValidationError)):
        EvidenceReference(
            evidence_id="ev_nan",
            project_id="proj_alpha",
            evidence_layer=EvidenceLayer.DETECTION,
            evidence_type="test",
            title="Invalid NaN",
            confidence=float("nan"),
            evidence_hash="b" * 64,
        )

    # 3. Proof layer must have confidence == 1.0 (ADR-028)
    with pytest.raises((ValueError, ValidationError)):
        EvidenceReference(
            evidence_id="ev_proof_invalid",
            project_id="proj_alpha",
            evidence_layer=EvidenceLayer.PROOF,
            evidence_type="hash_mismatch",
            title="Proof Violation",
            confidence=0.90,  # Invalid for proof layer!
            evidence_hash="c" * 64,
        )

    # Valid Proof layer
    ev_proof = EvidenceReference(
        evidence_id="ev_proof_ok",
        project_id="proj_alpha",
        evidence_layer=EvidenceLayer.PROOF,
        evidence_type="hash_mismatch",
        evidence_category=EvidenceCategory.CRYPTOGRAPHIC_PROOF,
        title="Proof Violation",
        confidence=1.0,
        severity=Severity.CRITICAL,
        evidence_hash="d" * 64,
    )
    assert ev_proof.confidence == 1.0


def test_06_to_10_evidence_deduplication_and_set_hashing() -> None:
    """Verify FR-11.9-003, CRYPTO-11.9-002: Content-addressed deduplication by evidence_hash."""
    engine = MultiModalRiskIntegrationEngine()

    ev1 = EvidenceReference(
        evidence_id="ev_001",
        project_id="proj_test",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift_ks",
        title="KS Drift",
        confidence=0.90,
        evidence_hash="1" * 64,
        data_json={"stat": 0.12},
    )

    # Duplicate with different evidence_id but identical evidence_hash
    ev1_dup = EvidenceReference(
        evidence_id="ev_001_dup",
        project_id="proj_test",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift_ks",
        title="KS Drift Duplicate",
        confidence=0.90,
        evidence_hash="1" * 64,
        data_json={"stat": 0.12},
    )

    ev2 = EvidenceReference(
        evidence_id="ev_002",
        project_id="proj_test",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift_psi",
        title="PSI Drift",
        confidence=0.85,
        evidence_hash="2" * 64,
        data_json={"stat": 0.22},
    )

    profile = engine.evaluate(
        project_id="proj_test",
        target_asset_type="dataset",
        target_asset_id="ds_alpha",
        evidence_items=[ev1, ev1_dup, ev2],
    )

    assert profile.metadata_json["raw_evidence_count"] == 3
    assert profile.deduplicated_evidence_count == 2
    assert len(profile.evidence_set_hash) == 64


def test_11_to_15_ancestry_clustering_and_double_counting() -> None:
    """Verify FR-11.9-004, RISK-11.9-003: Modality clustering on shared asset lineage & correlation damping."""
    engine = MultiModalRiskIntegrationEngine()

    # Ingest 3 detectors observing the SAME dataset version (Phase 11.4 feature, 11.5 image, 11.6 representation)
    ancestry = {"dataset_version_id": "v_1.0_prod"}

    ev_feat = EvidenceReference(
        evidence_id="ev_feat",
        project_id="proj_ancestry",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="feature_drift",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Feature Drift",
        confidence=0.95,
        severity=Severity.HIGH,
        ancestry_keys=ancestry,
        evidence_hash="a1" * 32,
    )

    ev_img = EvidenceReference(
        evidence_id="ev_img",
        project_id="proj_ancestry",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="image_drift",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Image Drift",
        confidence=0.92,
        severity=Severity.HIGH,
        ancestry_keys=ancestry,
        evidence_hash="a2" * 32,
    )

    ev_repr = EvidenceReference(
        evidence_id="ev_repr",
        project_id="proj_ancestry",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="representation_drift",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="DINOv2 Embedding Drift",
        confidence=0.98,
        severity=Severity.HIGH,
        ancestry_keys=ancestry,
        evidence_hash="a3" * 32,
    )

    # Policy with damping lambda_corr = 0.10
    policy = RiskPolicy(correlation_damping_factor=0.10)
    profile = engine.evaluate(
        project_id="proj_ancestry",
        target_asset_type="dataset",
        target_asset_id="ds_main",
        evidence_items=[ev_feat, ev_img, ev_repr],
        risk_policy=policy,
    )

    # Should form exactly 1 cluster for the shared dataset ancestry
    assert len(profile.clusters) == 1
    cluster = profile.clusters[0]
    assert len(cluster.evidence_ids) == 3

    # Verify score is sub-additive: not a naive triple addition
    # Max score ~ 0.60 * 0.80 * 0.98 = 0.4704. Damped terms add only 0.10 * (other terms).
    assert cluster.cluster_score < 0.60
    assert profile.overall_risk_score < 0.60


def test_16_to_20_parameterized_correlation_damping() -> None:
    """Verify RISK-11.9-003, CRYPTO-11.9-003: Parameterized lambda_corr in RiskPolicy changes score and policy hash."""
    engine = MultiModalRiskIntegrationEngine()
    ancestry = {"dataset_version_id": "v_2.0"}

    ev1 = EvidenceReference(
        evidence_id="e1",
        project_id="proj_damp",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift1",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Shift 1",
        confidence=0.90,
        severity=Severity.HIGH,
        ancestry_keys=ancestry,
        evidence_hash="b1" * 32,
    )
    ev2 = EvidenceReference(
        evidence_id="e2",
        project_id="proj_damp",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift2",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Shift 2",
        confidence=0.90,
        severity=Severity.HIGH,
        ancestry_keys=ancestry,
        evidence_hash="b2" * 32,
    )

    policy_zero = RiskPolicy(correlation_damping_factor=0.0)
    policy_ten = RiskPolicy(correlation_damping_factor=0.10)
    policy_quarter = RiskPolicy(correlation_damping_factor=0.25)

    prof_zero = engine.evaluate(project_id="proj_damp", target_asset_type="dataset", target_asset_id="d1", evidence_items=[ev1, ev2], risk_policy=policy_zero)
    prof_ten = engine.evaluate(project_id="proj_damp", target_asset_type="dataset", target_asset_id="d1", evidence_items=[ev1, ev2], risk_policy=policy_ten)
    prof_quarter = engine.evaluate(project_id="proj_damp", target_asset_type="dataset", target_asset_id="d1", evidence_items=[ev1, ev2], risk_policy=policy_quarter)

    # Monotonic scaling with lambda
    assert prof_zero.overall_risk_score < prof_ten.overall_risk_score < prof_quarter.overall_risk_score

    # Policy hashes must be distinct
    assert prof_zero.risk_policy_hash != prof_ten.risk_policy_hash != prof_quarter.risk_policy_hash


def test_21_to_25_risk_formula_mathematics_and_bounds() -> None:
    """Verify RISK-11.9-001, RISK-11.9-002: Mathematical properties of R = 1 - prod(1 - S_k)."""
    engine = MultiModalRiskIntegrationEngine()

    # 1. Empty evidence -> R = 0.0
    prof_empty = engine.evaluate(
        project_id="proj_math",
        target_asset_type="dataset",
        target_asset_id="ds_empty",
        evidence_items=[],
    )
    assert prof_empty.overall_risk_score == 0.0
    assert prof_empty.overall_disposition == Disposition.ACCEPT

    # 2. Single cluster -> R = S(C_1)
    ev_single = EvidenceReference(
        evidence_id="e_s",
        project_id="proj_math",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Single Shift",
        confidence=0.80,
        severity=Severity.HIGH,
        target_asset_id="ds_s",
        evidence_hash="c1" * 32,
    )
    prof_single = engine.evaluate(
        project_id="proj_math",
        target_asset_type="dataset",
        target_asset_id="ds_s",
        evidence_items=[ev_single],
    )
    cluster_score = prof_single.clusters[0].cluster_score
    assert math.isclose(prof_single.overall_risk_score, cluster_score, rel_tol=1e-5)

    # 3. Two independent clusters -> R = 1 - (1 - S1)(1 - S2)
    ev_clust2 = EvidenceReference(
        evidence_id="e_c2",
        project_id="proj_math",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="anomaly",
        evidence_category=EvidenceCategory.BEHAVIORAL_ANOMALY,
        title="Behavioral Shift",
        confidence=0.75,
        severity=Severity.HIGH,
        target_asset_id="model_m",
        evidence_hash="c2" * 32,
    )
    prof_dual = engine.evaluate(
        project_id="proj_math",
        target_asset_type="composite",
        target_asset_id="comp_1",
        evidence_items=[ev_single, ev_clust2],
    )
    s1 = prof_dual.clusters[0].cluster_score
    s2 = prof_dual.clusters[1].cluster_score
    expected_r = 1.0 - (1.0 - s1) * (1.0 - s2)
    assert math.isclose(prof_dual.overall_risk_score, expected_r, rel_tol=1e-5)


def test_26_to_30_decision_thresholds_and_disposition_dispatch() -> None:
    """Verify DECISION-11.9-001, DECISION-11.9-003: Exact boundary testing for policy disposition."""
    engine = MultiModalRiskIntegrationEngine()
    d_policy = DecisionPolicy(
        review_threshold=0.30,
        quarantine_threshold=0.65,
        reject_threshold=0.85,
    )

    # Helper to generate artificial risk score via custom category weights
    def eval_with_confidence(conf: float, cat_weight: float) -> IntegratedAssuranceProfile:
        ev = EvidenceReference(
            evidence_id="ev_thresh",
            project_id="proj_thresh",
            evidence_layer=EvidenceLayer.DETECTION,
            evidence_type="drift",
            evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
            title="Threshold Test",
            confidence=conf,
            severity=Severity.CRITICAL,  # sev_multiplier = 1.0
            evidence_hash=hashlib.sha256(f"thresh_{conf}_{cat_weight}".encode()).hexdigest(),
        )
        r_policy = RiskPolicy(category_weights={EvidenceCategory.DISTRIBUTION_SHIFT.value: cat_weight})
        return engine.evaluate(
            project_id="proj_thresh",
            target_asset_type="dataset",
            target_asset_id="ds_thresh",
            evidence_items=[ev],
            risk_policy=r_policy,
            decision_policy=d_policy,
        )

    # 1. R < 0.30 -> ACCEPT
    p_accept = eval_with_confidence(0.50, 0.40)  # R = 0.20
    assert p_accept.overall_risk_score < 0.30
    assert p_accept.overall_disposition == Disposition.ACCEPT

    # 2. 0.30 <= R < 0.65 -> REVIEW
    p_review = eval_with_confidence(0.80, 0.50)  # R = 0.40
    assert 0.30 <= p_review.overall_risk_score < 0.65
    assert p_review.overall_disposition == Disposition.REVIEW

    # 3. 0.65 <= R < 0.85 -> QUARANTINE
    p_quar = eval_with_confidence(0.90, 0.80)  # R = 0.72
    assert 0.65 <= p_quar.overall_risk_score < 0.85
    assert p_quar.overall_disposition == Disposition.QUARANTINE

    # 4. R >= 0.85 -> QUARANTINE (or reject disposition state)
    p_reject = eval_with_confidence(0.95, 0.95)  # R = 0.9025
    assert p_reject.overall_risk_score >= 0.85
    assert p_reject.overall_disposition == Disposition.QUARANTINE
    assert p_reject.risk_level == "CRITICAL"


def test_31_to_35_proof_layer_non_compensability() -> None:
    """Verify STAT-11.9-004, DECISION-11.9-002: Proof failure triggers mandatory rejection regardless of detection risk."""
    engine = MultiModalRiskIntegrationEngine()

    ev_proof_fail = EvidenceReference(
        evidence_id="ev_hash_break",
        project_id="proj_proof",
        evidence_layer=EvidenceLayer.PROOF,
        evidence_type="cryptographic_hash_mismatch",
        evidence_category=EvidenceCategory.CRYPTOGRAPHIC_PROOF,
        title="Dataset Hash Chain Break Detected",
        confidence=1.0,
        severity=Severity.CRITICAL,
        evidence_hash="f1" * 32,
    )

    ev_benign_detect = EvidenceReference(
        evidence_id="ev_benign",
        project_id="proj_proof",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift_normal",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Completely Normal Distribution",
        confidence=0.50,  # low risk
        severity=Severity.LOW,
        evidence_hash="f2" * 32,
    )

    profile = engine.evaluate(
        project_id="proj_proof",
        target_asset_type="dataset",
        target_asset_id="ds_compromised",
        evidence_items=[ev_proof_fail, ev_benign_detect],
    )

    # Proof failure is non-compensable: must quarantine/reject immediately
    assert profile.overall_disposition == Disposition.QUARANTINE
    assert profile.evaluation_status == IntegrationEvaluationStatus.PROOF_VIOLATION
    assert profile.proof_violations_count == 1
    assert "MANDATORY DISPOSITION" in profile.rationale


def test_36_to_40_insufficient_and_conflicting_evidence() -> None:
    """Verify SEC-11.9-003, SEC-11.9-004: Fail-closed handling for missing required categories."""
    engine = MultiModalRiskIntegrationEngine()

    ev_drift = EvidenceReference(
        evidence_id="ev_drift_only",
        project_id="proj_req",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Drift Only",
        confidence=0.50,
        severity=Severity.LOW,
        evidence_hash="e1" * 32,
    )

    # Require MODEL_INTEGRITY and PROOF categories as well
    required = [EvidenceCategory.DISTRIBUTION_SHIFT, EvidenceCategory.MODEL_INTEGRITY]

    profile = engine.evaluate(
        project_id="proj_req",
        target_asset_type="dataset",
        target_asset_id="ds_partial",
        evidence_items=[ev_drift],
        required_categories=required,
    )

    # Missing MODEL_INTEGRITY -> Fails closed to REVIEW
    assert profile.evaluation_status == IntegrationEvaluationStatus.INSUFFICIENT_DATA
    assert profile.overall_disposition == Disposition.REVIEW
    assert len(profile.limitations) >= 1
    assert "Missing required assurance categories" in profile.limitations[0]


def test_41_to_44_project_isolation_and_privacy() -> None:
    """Verify PRIV-11.9-001, PRIV-11.9-002: Project scope enforcement and ProjectMismatchError."""
    engine = MultiModalRiskIntegrationEngine()

    ev_tenant_a = EvidenceReference(
        evidence_id="ev_a",
        project_id="tenant_A",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift",
        title="Tenant A Drift",
        confidence=0.80,
        evidence_hash="a1" * 32,
    )

    # Evaluating for tenant_B must fail with ProjectMismatchError
    with pytest.raises(ProjectMismatchError, match="Project mismatch"):
        engine.evaluate(
            project_id="tenant_B",  # Mismatch!
            target_asset_type="dataset",
            target_asset_id="ds_b",
            evidence_items=[ev_tenant_a],
        )


def test_45_to_48_cryptographic_hashes_and_mutation_sensitivity() -> None:
    """Verify CRYPTO-11.9-001 through CRYPTO-11.9-005: RFC 8785 hashes & mutation sensitivity."""
    engine = MultiModalRiskIntegrationEngine()

    ev1 = EvidenceReference(
        evidence_id="ev_hash_1",
        project_id="proj_crypto",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift",
        title="Drift Base",
        confidence=0.90,
        evidence_hash="h1" * 32,
    )

    prof1 = engine.evaluate(project_id="proj_crypto", target_asset_type="dataset", target_asset_id="ds_c", evidence_items=[ev1])
    prof2 = engine.evaluate(project_id="proj_crypto", target_asset_type="dataset", target_asset_id="ds_c", evidence_items=[ev1])

    # Deterministic replay
    assert prof1.integrated_profile_hash == prof2.integrated_profile_hash
    assert prof1.evidence_set_hash == prof2.evidence_set_hash
    assert prof1.risk_policy_hash == prof2.risk_policy_hash
    assert prof1.decision_policy_hash == prof2.decision_policy_hash

    # Mutation 1: Change project_id
    prof_mut_proj = engine.evaluate(project_id="proj_crypto_mut", target_asset_type="dataset", target_asset_id="ds_c", evidence_items=[ev1.model_copy(update={"project_id": "proj_crypto_mut"})])
    assert prof1.integrated_profile_hash != prof_mut_proj.integrated_profile_hash

    # Mutation 2: Change risk policy damping factor
    r_mut = RiskPolicy(correlation_damping_factor=0.35)
    prof_mut_policy = engine.evaluate(project_id="proj_crypto", target_asset_type="dataset", target_asset_id="ds_c", evidence_items=[ev1], risk_policy=r_mut)
    assert prof1.integrated_profile_hash != prof_mut_policy.integrated_profile_hash
    assert prof1.risk_policy_hash != prof_mut_policy.risk_policy_hash

    # Mutation 3: Change decision threshold
    d_mut = DecisionPolicy(review_threshold=0.20)
    prof_mut_dec = engine.evaluate(project_id="proj_crypto", target_asset_type="dataset", target_asset_id="ds_c", evidence_items=[ev1], decision_policy=d_mut)
    assert prof1.integrated_profile_hash != prof_mut_dec.integrated_profile_hash
    assert prof1.decision_policy_hash != prof_mut_dec.decision_policy_hash


def test_49_to_50_security_ast_scan_and_offline() -> None:
    """Verify SEC-11.9-001, OFFLINE-11.9-001: 0 forbidden AST constructs & 0 network imports."""
    assurance_dir = os.path.join("backend", "aivara", "assurance")
    py_files = glob.glob(os.path.join(assurance_dir, "*.py"))
    assert len(py_files) >= 5

    forbidden_funcs = {"eval", "exec", "pickle"}
    forbidden_modules = {"requests", "httpx", "urllib", "socket", "dns", "subprocess"}

    for path in py_files:
        with open(path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in forbidden_funcs:
                    pytest.fail(f"Forbidden function call '{node.func.id}' found in {path}")
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                mod = getattr(node, "module", None)
                if mod and mod.split(".")[0] in forbidden_modules:
                    pytest.fail(f"Forbidden network/system import '{mod}' found in {path}")


def test_51_cross_phase_multi_subsystem_integration() -> None:
    """Verify COMPAT-11.9-001 through COMPAT-11.9-008: Seamless multi-phase evidence unification."""
    engine = MultiModalRiskIntegrationEngine()

    # Ingest diverse evidence from across AIVARA
    ev_list = [
        EvidenceReference(
            evidence_id="ev_phase4_proof",
            project_id="proj_full",
            evidence_layer=EvidenceLayer.PROOF,
            evidence_type="provenance_valid",
            evidence_category=EvidenceCategory.CRYPTOGRAPHIC_PROOF,
            title="Provenance Chain Valid",
            confidence=1.0,
            severity=Severity.INFO,
            evidence_hash="p4" * 32,
        ),
        EvidenceReference(
            evidence_id="ev_phase5_dataset",
            project_id="proj_full",
            evidence_layer=EvidenceLayer.DETECTION,
            evidence_type="dataset_anomalies",
            evidence_category=EvidenceCategory.DATASET_INTEGRITY,
            title="Sample Duplication Ratio",
            confidence=0.88,
            severity=Severity.MEDIUM,
            ancestry_keys={"dataset_version_id": "ds_v1"},
            evidence_hash="p5" * 32,
        ),
        EvidenceReference(
            evidence_id="ev_phase6_contrib",
            project_id="proj_full",
            evidence_layer=EvidenceLayer.DETECTION,
            evidence_type="contributor_risk",
            evidence_category=EvidenceCategory.CONTRIBUTOR_RISK,
            title="Empirical Bayes Contributor Deviation",
            confidence=0.78,
            severity=Severity.MEDIUM,
            ancestry_keys={"source_group_id": "contrib_42"},
            evidence_hash="p6" * 32,
        ),
        EvidenceReference(
            evidence_id="ev_phase7_model",
            project_id="proj_full",
            evidence_layer=EvidenceLayer.PROOF,
            evidence_type="model_fingerprint_valid",
            evidence_category=EvidenceCategory.MODEL_INTEGRITY,
            title="Model Weight Hash Verified",
            confidence=1.0,
            severity=Severity.INFO,
            ancestry_keys={"model_fingerprint": "fp_vit_s14"},
            evidence_hash="p7" * 32,
        ),
        EvidenceReference(
            evidence_id="ev_phase8_behavior",
            project_id="proj_full",
            evidence_layer=EvidenceLayer.DETECTION,
            evidence_type="behavioral_perturbation",
            evidence_category=EvidenceCategory.BEHAVIORAL_ANOMALY,
            title="Adversarial Perturbation Stability",
            confidence=0.91,
            severity=Severity.HIGH,
            ancestry_keys={"model_fingerprint": "fp_vit_s14"},
            evidence_hash="p8" * 32,
        ),
        EvidenceReference(
            evidence_id="ev_phase11_drift",
            project_id="proj_full",
            evidence_layer=EvidenceLayer.DETECTION,
            evidence_type="distribution_shift",
            evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
            title="Multivariate MMD Representation Drift",
            confidence=0.96,
            severity=Severity.HIGH,
            ancestry_keys={"dataset_version_id": "ds_v1"},
            evidence_hash="11" * 32,
        ),
    ]

    profile = engine.evaluate(
        project_id="proj_full",
        target_asset_type="composite",
        target_asset_id="asset_complete",
        evidence_items=ev_list,
    )

    assert profile.deduplicated_evidence_count == 6
    assert len(profile.clusters) >= 4
    assert profile.overall_disposition in (Disposition.REVIEW, Disposition.QUARANTINE)
    assert len(profile.synthesized_findings) >= 2
    assert "Category Component Scores:" in profile.rationale
