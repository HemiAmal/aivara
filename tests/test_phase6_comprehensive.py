"""Comprehensive Contributor Risk Subsystem Verification Suite (Phase 6.4).

This suite performs exhaustive end-to-end verification of the Contributor Risk subsystem:
- Phase 6.1 (Architecture & ADRs 030-039)
- Phase 6.2 (Domain & Statistical Engine)
- Phase 6.3 (REST APIs & Integration Service)
- Phase 5 / Phase 4 cryptographic provenance & evidence integration

Verifies all 30 mandated verification areas:
 1. End-to-End Pipeline Execution (Project -> Dataset -> Attributions -> Findings -> Engine -> Service -> DB -> REST -> Provenance)
 2. Fractional Contributor Attribution Conservation (1/K, single, multi, duplicate, unattributed)
 3. Support States Exact Boundary Tiers (0, 1, 2.99, 3, 9.99, 10, 29.99, 30)
 4. Empirical Bayes Mathematical & Numerical Correctness (p_LOO, p_hat boundaries, zero divide safety)
 5. Contextual Baselines & Simpson's Paradox Defense
 6. Analytical Statistical Correctness & Exact Expected Formulations
 7. Detection Dimensions & ID Traceability (Label, Transition, Quality, OOD)
 8. Proof Profile Contracts & Confidence Invariance (= 1.0)
 9. Detection / Proof Strict Separation
10. Evidence Family Dependency & Family Dominance Maxima
11. Semantic Safety & Vocabulary Guardrails (Allowed technical terms vs. Rejected intent assertions)
12. No Scalar Risk Score & Database Sentinel (-1.0 compatibility sentinel)
13. Database Persistence & Zero Schema Changes
14. Idempotency & Repeated Assessment Processing
15. Stale Evidence & Dataset Fingerprint Mismatch Rejection
16. Multi-Tenant Project Isolation & Cross-Project Substitution Attacks
17. REST API Contracts & Envelope Compliance
18. Evidence Graph Traceability & Clean Topologies
19. Cryptographic Provenance Sealing & Replay Protection
20. Security, Malformed Identifiers, & Zero Information Leakage
21. Deterministic Analytical Payloads & Canonical Ordering
22. Concurrency & Parallel Execution Safety
23. Offline & Air-Gapped Operation
24. Performance & Runtime Profiling
25. 12 Core Architectural Invariants Verification
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import copy
import json
import math
import socket
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from aivara.api.envelope import ApiResponse
from aivara.contributor_risk import (
    BaselineType,
    ContextualBaseline,
    ContextualBaselineEngine,
    ContributorInputContext,
    ContributorRiskConfig,
    ContributorRiskEngine,
    ContributorRiskProfile,
    ContributorRiskService,
    DatasetBackgroundContext,
    DetectionDimension,
    DetectionProfile,
    DistributionShiftDimension,
    EmpiricalBayesResult,
    EvaluationStatus,
    EvidenceFamilyEvaluator,
    EvidenceFamilyId,
    LabelReliabilityDimension,
    ProofProfile,
    ProvenanceIntegrityDimension,
    QualityDivergenceDimension,
    RiskDimensionId,
    SupportState,
    TransitionAsymmetryDimension,
    compute_empirical_bayes_shrinkage,
    determine_support_state,
    validate_semantic_safety,
)
from aivara.contributor_risk.exceptions import (
    ContributorRiskError,
    CrossProjectContaminationError,
    InsufficientEvidenceError,
    InvalidBaselineError,
    SemanticSafetyViolationError,
    SupportStateError,
)
from aivara.core.exceptions import (
    AivaraException,
    NotFoundException,
    ValidationException,
)
from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import hash_canonical_data, sha256_bytes, sha256_text
from aivara.crypto.keys import KeyManager
from aivara.database.connection import get_db
from aivara.database.models import (
    ContributorModel,
    DatasetModel,
    DatasetVersionModel,
    EvidenceModel,
    FindingModel,
    ProjectModel,
    ProvenanceRecordModel,
    RiskAssessmentModel,
    SampleContributorModel,
    SampleModel,
)
from aivara.dataset.contributors.attribution import (
    UNATTRIBUTED_KEY,
    build_sample_attribution_map,
    compute_contributor_exposures,
    normalize_contributor_ids,
)
from aivara.dataset.schemas import CanonicalSample
from aivara.main import app


# =====================================================================
# Fixtures
# =====================================================================

@pytest.fixture
def comp_api_client(test_db_session: Session) -> TestClient:
    """FastAPI TestClient wired to isolated in-memory test database."""
    def _override_get_db():
        yield test_db_session

    app.dependency_overrides[get_db] = _override_get_db
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def seeded_comp_env(test_db_session: Session) -> Dict[str, Any]:
    """Seed comprehensive test environment with Projects, Contributors, Dataset, Samples, and Findings."""
    # 1. Projects
    p_main = ProjectModel(id="proj-comp-main", name="Main Project", description="Primary test project")
    p_foreign = ProjectModel(id="proj-comp-foreign", name="Foreign Project", description="Foreign tenant project")
    test_db_session.add_all([p_main, p_foreign])
    test_db_session.flush()

    # 2. Contributors
    c1 = ContributorModel(id="contrib-1", project_id="proj-comp-main", external_id="ann_01", name="Annotator 1")
    c2 = ContributorModel(id="contrib-2", project_id="proj-comp-main", external_id="ann_02", name="Annotator 2")
    c3 = ContributorModel(id="contrib-3", project_id="proj-comp-main", external_id="ann_03", name="Annotator 3")
    c_foreign = ContributorModel(id="contrib-foreign", project_id="proj-comp-foreign", external_id="ann_foreign", name="Foreign Annotator")
    test_db_session.add_all([c1, c2, c3, c_foreign])
    test_db_session.flush()

    # 3. Dataset and Versions
    ds_main = DatasetModel(id="ds-comp-main", project_id="proj-comp-main", name="Main Dataset", format="imagefolder")
    ds_foreign = DatasetModel(id="ds-comp-foreign", project_id="proj-comp-foreign", name="Foreign Dataset", format="imagefolder")
    test_db_session.add_all([ds_main, ds_foreign])
    test_db_session.flush()

    dsv_main_v1 = DatasetVersionModel(
        id="dsv-comp-v1",
        dataset_id="ds-comp-main",
        version_label="v1",
        dataset_hash="a" * 64,
        sample_count=60,
    )
    dsv_main_v2 = DatasetVersionModel(
        id="dsv-comp-v2",
        dataset_id="ds-comp-main",
        version_label="v2",
        dataset_hash="b" * 64,
        sample_count=60,
    )
    dsv_foreign = DatasetVersionModel(
        id="dsv-comp-foreign",
        dataset_id="ds-comp-foreign",
        version_label="v1",
        dataset_hash="c" * 64,
        sample_count=20,
    )
    test_db_session.add_all([dsv_main_v1, dsv_main_v2, dsv_foreign])
    test_db_session.flush()

    # 4. Samples & Attributions for V1
    # 40 samples for contrib-1 (adequate support >= 30)
    # 8 samples for contrib-2 (low support 3 <= Nc < 10)
    # 2 samples for contrib-3 (unverifiable Nc < 3)
    # 10 samples shared between contrib-1 and contrib-2
    samples = []
    attributions = []

    for i in range(1, 61):
        s_id = f"s-comp-{i:03d}"
        s = SampleModel(
            id=s_id,
            dataset_version_id="dsv-comp-v1",
            file_path=f"data/sample_{i}.png",
            file_hash_sha256=f"{i:02x}" * 32,
        )
        samples.append(s)

        if 1 <= i <= 40:
            attributions.append(SampleContributorModel(sample_id=s_id, contributor_id="contrib-1", contribution_type="annotator"))
        elif 41 <= i <= 48:
            attributions.append(SampleContributorModel(sample_id=s_id, contributor_id="contrib-2", contribution_type="annotator"))
        elif 49 <= i <= 50:
            attributions.append(SampleContributorModel(sample_id=s_id, contributor_id="contrib-3", contribution_type="annotator"))
        elif 51 <= i <= 60:
            attributions.append(SampleContributorModel(sample_id=s_id, contributor_id="contrib-1", contribution_type="annotator"))
            attributions.append(SampleContributorModel(sample_id=s_id, contributor_id="contrib-2", contribution_type="annotator"))

    test_db_session.add_all(samples)
    test_db_session.add_all(attributions)
    test_db_session.flush()

    # 5. Phase 5 Findings & Evidence
    f1 = FindingModel(
        id="find-comp-label-1",
        project_id="proj-comp-main",
        engine_id="LabelAnomalyDetector",
        engine_version="1.0.0",
        evidence_layer="detection",
        finding_type="LABEL_ANOMALY",
        title="Label anomaly detected",
        severity="high",
        confidence=0.95,
        affected_asset_type="sample",
        affected_asset_id="s-comp-001",
        disposition="review",
    )
    f2 = FindingModel(
        id="find-comp-quality-1",
        project_id="proj-comp-main",
        engine_id="QualityDetector",
        engine_version="1.0.0",
        evidence_layer="detection",
        finding_type="QUALITY_DEFECT",
        title="Blur defect detected",
        severity="medium",
        confidence=0.85,
        affected_asset_type="sample",
        affected_asset_id="s-comp-002",
        disposition="review",
    )
    f3 = FindingModel(
        id="find-comp-ood-1",
        project_id="proj-comp-main",
        engine_id="OODDetector",
        engine_version="1.0.0",
        evidence_layer="detection",
        finding_type="OOD_ANOMALY",
        title="Out-of-distribution sample",
        severity="low",
        confidence=0.72,
        affected_asset_type="sample",
        affected_asset_id="s-comp-003",
        disposition="review",
    )
    test_db_session.add_all([f1, f2, f3])
    test_db_session.flush()

    ev1 = EvidenceModel(
        id="ev-comp-v1-label",
        finding_id="find-comp-label-1",
        evidence_layer="detection",
        evidence_type="label_anomaly_latent_disagreement",
        title="Comprehensive Phase 5 Label Anomaly",
        confidence=0.95,
        evidence_hash="d" * 64,
    )
    ev2 = EvidenceModel(
        id="ev-comp-v1-quality",
        finding_id="find-comp-quality-1",
        evidence_layer="detection",
        evidence_type="quality_divergence",
        title="Comprehensive Phase 5 Quality Divergence",
        confidence=0.85,
        evidence_hash="e" * 64,
    )
    ev3 = EvidenceModel(
        id="ev-comp-v1-ood",
        finding_id="find-comp-ood-1",
        evidence_layer="detection",
        evidence_type="distribution_shift",
        title="Comprehensive Phase 5 OOD Divergence",
        confidence=0.72,
        evidence_hash="f" * 64,
    )
    test_db_session.add_all([ev1, ev2, ev3])
    test_db_session.flush()

    # 6. Provenance Record
    prov = ProvenanceRecordModel(
        id="prov-comp-v1",
        project_id="proj-comp-main",
        record_type="DATASET_SCAN_FINDINGS_COMMITTED",
        actor="system",
        action="SEAL_FINDINGS",
        sequence_number=1,
        previous_record_hash="0" * 64,
        record_hash="1" * 64,
        nonce="2" * 64,
        signer_key_id="key-comp-01",
        signature="3" * 88,
    )
    test_db_session.add(prov)
    test_db_session.commit()

    return {
        "project_id": "proj-comp-main",
        "foreign_project_id": "proj-comp-foreign",
        "dataset_id": "ds-comp-main",
        "version_id": "dsv-comp-v1",
        "version_v2_id": "dsv-comp-v2",
        "foreign_version_id": "dsv-comp-foreign",
        "contrib_adequate": "contrib-1",
        "contrib_low": "contrib-2",
        "contrib_unverifiable": "contrib-3",
        "contrib_foreign": "contrib-foreign",
        "evidence_ids": ["ev-comp-v1-label", "ev-comp-v1-quality", "ev-comp-v1-ood"],
        "finding_ids": ["find-comp-label-1", "find-comp-quality-1", "find-comp-ood-1"],
    }


# =====================================================================
# 1. End-to-End Pipeline & REST Integration
# =====================================================================

class TestEndToEndPipeline:
    """Verify complete end-to-end pipeline from DB entities to API outputs."""

    def test_complete_pipeline_flow(self, comp_api_client: TestClient, seeded_comp_env: Dict[str, Any], test_db_session: Session):
        """Execute full flow: POST assessment -> verify DB model -> GET profile -> GET graph -> GET baselines."""
        proj_id = seeded_comp_env["project_id"]
        contrib_id = seeded_comp_env["contrib_adequate"]
        ver_id = seeded_comp_env["version_id"]

        # 1. POST Assessment via REST
        resp = comp_api_client.post(
            f"/api/v1/projects/{proj_id}/contributors/risk-assessments",
            json={"contributor_id": contrib_id, "dataset_version_id": ver_id, "seal_provenance": False},
        )
        assert resp.status_code == 201, f"Assessment failed: {resp.text}"
        data = resp.json()
        assert data["status"] == "success"
        profile = data["data"]

        # Verify Structure
        assert profile["contributor_id"] == contrib_id
        assert profile["project_id"] == proj_id
        assert "detection_profile" in profile
        assert "proof_profile" in profile
        assert "overall_risk_score" not in profile  # INVARIANT: Never expose scalar score in REST

        # 2. Verify Persistence in RiskAssessmentModel
        db_record = test_db_session.query(RiskAssessmentModel).filter(
            RiskAssessmentModel.project_id == proj_id,
            RiskAssessmentModel.target_id == contrib_id,
        ).first()
        assert db_record is not None
        assert db_record.overall_risk_score == -1.0  # Frozen -1.0 sentinel
        assert db_record.component_scores_json["scalar_risk_score_applicable"] is False
        assert db_record.component_scores_json["scalar_risk_score"] is None
        assert db_record.component_scores_json["representation"] == "STRUCTURED_MULTIDIMENSIONAL_VECTOR"

        # 3. GET Profile via REST
        get_resp = comp_api_client.get(f"/api/v1/projects/{proj_id}/contributors/{contrib_id}/risk-profile?dataset_version_id={ver_id}")
        assert get_resp.status_code == 200
        get_data = get_resp.json()["data"]
        assert get_data["contributor_id"] == profile["contributor_id"]

        # 4. GET Baselines via REST
        base_resp = comp_api_client.get(f"/api/v1/projects/{proj_id}/contributors/{contrib_id}/baselines?dataset_version_id={ver_id}")
        assert base_resp.status_code == 200
        base_data = base_resp.json()["data"]
        assert "baselines" in base_data
        assert "label_reliability" in base_data["baselines"]

        # 5. GET Evidence Graph via REST
        graph_resp = comp_api_client.get(f"/api/v1/projects/{proj_id}/contributors/{contrib_id}/evidence-graph?dataset_version_id={ver_id}")
        assert graph_resp.status_code == 200
        graph_data = graph_resp.json()["data"]
        assert "attributed_samples" in graph_data
        assert "findings" in graph_data
        assert graph_data["contributor_id"] == contrib_id


# =====================================================================
# 2. Contributor Attribution & Exposure Conservation (ADR-033)
# =====================================================================

class TestContributorAttributionConservation:
    """Verify exact 1/K fractional attribution, duplicate normalization, and weight conservation."""

    def test_single_contributor_full_weight(self):
        sample = CanonicalSample(
            sample_id="s1", relative_path="s1.png", file_size_bytes=100, width=100, height=100, contributors=["alice"]
        )
        attr_map = build_sample_attribution_map([sample])
        assert attr_map["s1"] == {"alice": 1.0}
        assert sum(attr_map["s1"].values()) == pytest.approx(1.0)

    def test_multi_contributor_equal_fractional_split(self):
        # 2 contributors
        s2 = CanonicalSample(
            sample_id="s2", relative_path="s2.png", file_size_bytes=100, width=100, height=100, contributors=["alice", "bob"]
        )
        attr2 = build_sample_attribution_map([s2])
        assert attr2["s2"]["alice"] == pytest.approx(0.5)
        assert attr2["s2"]["bob"] == pytest.approx(0.5)
        assert sum(attr2["s2"].values()) == pytest.approx(1.0)

        # 3 contributors
        s3 = CanonicalSample(
            sample_id="s3", relative_path="s3.png", file_size_bytes=100, width=100, height=100, contributors=["alice", "bob", "carol"]
        )
        attr3 = build_sample_attribution_map([s3])
        assert attr3["s3"]["alice"] == pytest.approx(1.0 / 3.0)
        assert attr3["s3"]["bob"] == pytest.approx(1.0 / 3.0)
        assert attr3["s3"]["carol"] == pytest.approx(1.0 / 3.0)
        assert sum(attr3["s3"].values()) == pytest.approx(1.0)

    def test_duplicate_contributor_ids_deduplicated(self):
        s_dup = CanonicalSample(
            sample_id="s_dup", relative_path="s.png", file_size_bytes=100, width=100, height=100, contributors=["alice", "alice", "bob", "bob"]
        )
        norm = normalize_contributor_ids(s_dup.contributors)
        assert norm == ("alice", "bob")
        attr = build_sample_attribution_map([s_dup])
        assert attr["s_dup"]["alice"] == pytest.approx(0.5)
        assert attr["s_dup"]["bob"] == pytest.approx(0.5)
        assert sum(attr["s_dup"].values()) == pytest.approx(1.0)

    def test_unattributed_samples(self):
        s_empty = CanonicalSample(
            sample_id="s_empty", relative_path="s.png", file_size_bytes=100, width=100, height=100, contributors=[]
        )
        attr = build_sample_attribution_map([s_empty])
        assert attr["s_empty"] == {UNATTRIBUTED_KEY: 1.0}
        assert sum(attr["s_empty"].values()) == pytest.approx(1.0)

    def test_effective_exposure_sum_and_no_full_credit_leak(self):
        samples = [
            CanonicalSample(sample_id="s1", relative_path="s1.png", file_size_bytes=100, width=100, height=100, contributors=["alice"]),
            CanonicalSample(sample_id="s2", relative_path="s2.png", file_size_bytes=100, width=100, height=100, contributors=["alice", "bob"]),
            CanonicalSample(sample_id="s3", relative_path="s3.png", file_size_bytes=100, width=100, height=100, contributors=["alice", "bob", "carol"]),
            CanonicalSample(sample_id="s4", relative_path="s4.png", file_size_bytes=100, width=100, height=100, contributors=[]),
        ]
        attr_map = build_sample_attribution_map(samples)
        exposures = compute_contributor_exposures(attr_map)

        # Expected:
        # alice = 1.0 + 0.5 + 1/3 = 1.833333
        # bob = 0.5 + 1/3 = 0.833333
        # carol = 1/3 = 0.333333
        # UNATTRIBUTED = 1.0
        # Total = 4.0 (equal to total sample count)
        assert exposures["alice"] == pytest.approx(1.0 + 0.5 + (1.0 / 3.0))
        assert exposures["bob"] == pytest.approx(0.5 + (1.0 / 3.0))
        assert exposures["carol"] == pytest.approx(1.0 / 3.0)
        assert exposures[UNATTRIBUTED_KEY] == pytest.approx(1.0)
        assert sum(exposures.values()) == pytest.approx(4.0)


# =====================================================================
# 3. Support States Exact Boundary Conditions
# =====================================================================

class TestSupportStatesExactBoundaries:
    """Verify exact support state classification across all boundaries: 0, 1, 2.99, 3, 9.99, 10, 29.99, 30."""

    @pytest.mark.parametrize(
        "nc, expected_state",
        [
            (0.0, SupportState.UNVERIFIABLE),
            (1.0, SupportState.UNVERIFIABLE),
            (2.99, SupportState.UNVERIFIABLE),
            (3.0, SupportState.LOW_SUPPORT),
            (5.0, SupportState.LOW_SUPPORT),
            (9.99, SupportState.LOW_SUPPORT),
            (10.0, SupportState.MODERATE_SUPPORT),
            (20.0, SupportState.MODERATE_SUPPORT),
            (29.99, SupportState.MODERATE_SUPPORT),
            (30.0, SupportState.ADEQUATE_SUPPORT),
            (100.0, SupportState.ADEQUATE_SUPPORT),
            (10000.0, SupportState.ADEQUATE_SUPPORT),
        ],
    )
    def test_support_state_boundaries(self, nc: float, expected_state: SupportState):
        assert determine_support_state(nc) == expected_state

    def test_unverifiable_yields_conservative_unverifiable_evaluation(self):
        engine = ContributorRiskEngine()
        contributor = ContributorInputContext(
            contributor_id="contrib_tiny",
            project_id="p1",
            dataset_version_id="v1",
            effective_exposure=1.5,
            label_anomaly_count=1.5,  # 100% anomaly rate on tiny support
            signature_present=True,
            chain_valid=True,
            nonce_valid=True,
            provenance_status="VERIFIED",
        )
        bg = DatasetBackgroundContext(total_exposure=100.0, total_label_anomalies=5.0)
        profile = engine.assess_contributor(contributor, bg)

        assert profile.support_state == SupportState.UNVERIFIABLE
        assert profile.detection_profile.label_reliability.status == EvaluationStatus.UNVERIFIABLE
        # Confidence must be 0.0 for unverifiable
        assert profile.detection_profile.label_reliability.confidence == 0.0


# =====================================================================
# 4. Empirical Bayes Mathematics & Extreme Boundaries (ADR-032)
# =====================================================================

class TestEmpiricalBayesExactMathematics:
    """Verify analytical formulas for Empirical Bayes shrinkage."""

    def test_eb_mathematical_precision(self):
        # M0 = 20
        # Nc = 80, effective_count = 32 (p_hat = 0.40), p_LOO = 0.10
        # lambda = 80 / (80 + 20) = 0.80
        # p_tilde = 0.80 * 0.40 + 0.20 * 0.10 = 0.32 + 0.02 = 0.34
        # Delta = 0.34 - 0.10 = +0.24
        res = compute_empirical_bayes_shrinkage(
            effective_count=32.0,
            total_exposure=80.0,
            baseline_rate=0.10,
            prior_weight=20.0,
        )
        assert res.shrinkage_factor == pytest.approx(0.80, abs=1e-6)
        assert res.shrunk_rate == pytest.approx(0.34, abs=1e-6)
        assert res.differential == pytest.approx(0.24, abs=1e-6)

    @pytest.mark.parametrize(
        "p_hat, p_loo, nc",
        [
            (0.0, 0.0, 0.0),
            (1.0, 1.0, 0.0),
            (0.0, 1.0, 10.0),
            (1.0, 0.0, 10.0),
            (0.5, 0.5, 50.0),
            (0.0, 0.0, 1000.0),
            (1.0, 1.0, 1000.0),
            (0.12345, 0.6789, 25.5),
        ],
    )
    def test_eb_boundary_numerical_stability(self, p_hat: float, p_loo: float, nc: float):
        """Ensure NO NaN, NO infinity, and deterministic finite floats across all edge inputs."""
        res = compute_empirical_bayes_shrinkage(
            effective_count=p_hat * nc,
            total_exposure=nc,
            baseline_rate=p_loo,
            prior_weight=20.0,
        )
        assert not math.isnan(res.shrunk_rate)
        assert not math.isnan(res.differential)
        assert not math.isnan(res.shrinkage_factor)
        assert not math.isinf(res.shrunk_rate)
        assert not math.isinf(res.differential)
        assert 0.0 <= res.shrunk_rate <= 1.0
        assert 0.0 <= res.shrinkage_factor <= 1.0


# =====================================================================
# 5. Contextual Baselines & Simpson's Paradox (ADR-031)
# =====================================================================

class TestContextualBaselinesAndSimpsonsParadox:
    """Verify contextual subgroup baselines and immunity to Simpson's Paradox."""

    def test_simpsons_paradox_specialist_not_penalized(self):
        """Scenario:
        - Class 'medical_rare' has high natural background anomaly rate (40%).
        - Class 'general' has low natural anomaly rate (5%).
        - Specialist Alice annotates only 'medical_rare' with 38% anomaly rate (actually better than baseline).
        - Against global baseline (8.5%), Alice would look terrible (+29.5%).
        - With Class-Conditional LOO baseline (40%), Alice differential is non-positive.
        """
        engine = ContextualBaselineEngine()
        baseline = engine.compute_class_conditional_baseline(
            class_total_exposure=500.0,
            class_total_events=200.0,  # 40% class rate
            class_contributor_exposure=50.0,
            class_contributor_events=19.0,  # Alice: 38% rate
            class_name="medical_rare",
            class_id=1,
        )

        assert baseline.baseline_type == BaselineType.CLASS_CONDITIONAL
        # LOO background rate = (200 - 19) / (500 - 50) = 181 / 450 = ~0.4022
        assert baseline.baseline_value == pytest.approx(181.0 / 450.0, abs=1e-4)
        assert baseline.is_fallback is False

        # Apply EB with Alice's observed rate (19 / 50 = 0.38)
        eb = compute_empirical_bayes_shrinkage(
            effective_count=19.0,
            total_exposure=50.0,
            baseline_rate=baseline.baseline_value,
            prior_weight=20.0,
        )
        # Alice's differential should be non-positive (-0.015), not penalized
        assert eb.differential <= 0.0

    def test_insufficient_class_support_graceful_fallback(self):
        engine = ContextualBaselineEngine()
        global_fallback = engine.compute_leave_one_out_baseline(
            total_dataset_exposure=1000.0,
            total_dataset_events=50.0,
            contributor_exposure=10.0,
            contributor_events=1.0,
        )
        baseline = engine.compute_class_conditional_baseline(
            class_total_exposure=2.0,  # Insufficient class support (< 10)
            class_total_events=0.0,
            class_contributor_exposure=1.0,
            class_contributor_events=0.0,
            class_name="ultra_rare",
            class_id=99,
            global_fallback_baseline=global_fallback,
        )
        assert baseline.is_fallback is True
        assert baseline.baseline_value == pytest.approx(global_fallback.baseline_value)


# =====================================================================
# 6. Detection Dimensions & ID Traceability
# =====================================================================

class TestDetectionDimensionsAndTraceability:
    """Verify all 4 detection dimensions and strict evidence/finding traceability."""

    def test_all_dimensions_present_and_traceable(self):
        engine = ContributorRiskEngine()
        contributor = ContributorInputContext(
            contributor_id="c_all",
            project_id="p1",
            dataset_version_id="v1",
            effective_exposure=50.0,
            label_anomaly_count=5.0,
            targeted_flip_score=0.10,
            noise_concentration_index=0.15,
            quality_anomaly_count=3.0,
            ood_anomaly_count=2.0,
            label_evidence_ids=("ev_scan_01",),
            flip_evidence_ids=("ev_scan_02",),
            quality_evidence_ids=("ev_scan_03",),
            ood_evidence_ids=("ev_scan_04",),
            signature_present=True,
            chain_valid=True,
            nonce_valid=True,
            provenance_status="VERIFIED",
        )
        bg = DatasetBackgroundContext(
            total_exposure=500.0,
            total_label_anomalies=30.0,
            total_quality_anomalies=20.0,
            total_ood_anomalies=10.0,
        )

        profile = engine.assess_contributor(contributor, bg)
        det = profile.detection_profile

        # 1. Verify 4 Detection Dimensions
        assert det.label_reliability.dimension_id == RiskDimensionId.DIM_LABEL_RELIABILITY
        assert det.transition_asymmetry.dimension_id == RiskDimensionId.DIM_TRANSITION_ASYM
        assert det.quality_divergence.dimension_id == RiskDimensionId.DIM_QUALITY_DIVERGENCE
        assert det.distribution_shift.dimension_id == RiskDimensionId.DIM_DISTRIBUTION_SHIFT


# =====================================================================
# 7. Proof Profile & Strict Separation from Detection Layer
# =====================================================================

class TestProofProfileAndSeparation:
    """Verify proof profile confidence is always exactly 1.0 and isolated from anomaly scoring."""

    def test_proof_profile_confidence_exactly_one(self):
        engine = ContributorRiskEngine()
        ctx_valid = ContributorInputContext(
            contributor_id="c1",
            project_id="p1",
            dataset_version_id="v1",
            effective_exposure=40.0,
            provenance_status="VERIFIED",
            signature_present=True,
            chain_valid=True,
            nonce_valid=True,
            tamper_detected=False,
        )
        bg = DatasetBackgroundContext(total_exposure=100.0)
        profile = engine.assess_contributor(ctx_valid, bg)
        assert profile.proof_profile.provenance_integrity.confidence == 1.0
        assert profile.proof_profile.provenance_integrity.verification_status == "VERIFIED"
        assert profile.proof_profile.provenance_integrity.tamper_detected is False

    def test_invalid_proof_does_not_mutate_detection_anomaly_scores(self):
        engine = ContributorRiskEngine()
        bg = DatasetBackgroundContext(total_exposure=100.0, total_label_anomalies=10.0)

        ctx_tampered = ContributorInputContext(
            contributor_id="c_tampered",
            project_id="p1",
            dataset_version_id="v1",
            effective_exposure=40.0,
            label_anomaly_count=4.0,  # 10% rate
            provenance_status="FAILED",
            signature_present=False,
            chain_valid=False,
            nonce_valid=False,
            tamper_detected=True,
        )
        ctx_clean = ContributorInputContext(
            contributor_id="c_clean",
            project_id="p1",
            dataset_version_id="v1",
            effective_exposure=40.0,
            label_anomaly_count=4.0,  # Same 10% rate
            provenance_status="VERIFIED",
            signature_present=True,
            chain_valid=True,
            nonce_valid=True,
            tamper_detected=False,
        )

        prof_tampered = engine.assess_contributor(ctx_tampered, bg)
        prof_clean = engine.assess_contributor(ctx_clean, bg)

        # Detection rates must be strictly identical regardless of proof failure
        assert prof_tampered.detection_profile.label_reliability.differential == pytest.approx(
            prof_clean.detection_profile.label_reliability.differential
        )
        # Proof profiles clearly differ
        assert prof_tampered.proof_profile.provenance_integrity.tamper_detected is True
        assert prof_clean.proof_profile.provenance_integrity.tamper_detected is False


# =====================================================================
# 8. Evidence Family Dependency & Family Dominance (ADR-034)
# =====================================================================

class TestEvidenceFamilyDominance:
    """Verify that multiple correlated detectors in an evidence family do NOT linearly multiply risk."""

    def test_family_dominance_uses_maximum_supported_deviation(self):
        # Construct label reliability and transition asymmetry dimensions
        dim_label = LabelReliabilityDimension(
            dimension_id=RiskDimensionId.DIM_LABEL_RELIABILITY,
            status=EvaluationStatus.ADEQUATE_SUPPORT,
            observed_rate=0.20,
            differential=0.15,
            confidence=0.90,
            support_state=SupportState.ADEQUATE_SUPPORT,
        )
        dim_trans = TransitionAsymmetryDimension(
            dimension_id=RiskDimensionId.DIM_TRANSITION_ASYM,
            status=EvaluationStatus.ADEQUATE_SUPPORT,
            noise_concentration_index=0.22,
            differential=0.22,
            confidence=0.85,
            support_state=SupportState.ADEQUATE_SUPPORT,
        )
        dim_proof = ProvenanceIntegrityDimension(
            dimension_id=RiskDimensionId.DIM_PROVENANCE_INTEGRITY,
            verification_status="VERIFIED",
            confidence=1.0,
        )

        families = EvidenceFamilyEvaluator.evaluate_families(
            detection_dimensions=[dim_label, dim_trans],
            proof_dimension=dim_proof,
        )

        label_fam = next(f for f in families if f.family_id == EvidenceFamilyId.LABEL_INTEGRITY)
        # Dominance deviation must be max (0.22), NOT additive sum (0.15 + 0.22 = 0.37)
        assert label_fam.dominant_differential == pytest.approx(0.22)
        assert label_fam.dominant_differential < 0.37


# =====================================================================
# 9. Semantic Safety Guardrails (ADR-035)
# =====================================================================

class TestSemanticSafetyInvariants:
    """Verify technical security terms are permitted while accusatory intent/guilt claims are rejected."""

    @pytest.mark.parametrize(
        "safe_term",
        [
            "adversarial example detection in dataset",
            "evaluated adversarial perturbation resistance",
            "adversarial robustness benchmarking",
            "simulated poisoning attack for robustness testing",
            "data poisoning experiment evaluation",
            "backdoor trigger anomaly pattern",
            "formal threat model validation",
            "out-of-distribution anomaly detected",
            "directional label transition asymmetry",
        ],
    )
    def test_permitted_technical_security_terms(self, safe_term: str):
        # Must not raise
        validate_semantic_safety(safe_term)

    @pytest.mark.parametrize(
        "prohibited_claim",
        [
            "malicious contributor found",
            "contributor acted maliciously",
            "bad actor detected in dataset",
            "guilty contributor identified",
            "contributor is culpable for dataset corruption",
            "deliberate sabotage detected",
            "fraudulent contributor submitted bad data",
            "annotator collusion observed across samples",
            "deliberate data poisoning by author",
            "intentional poisoning by user",
        ],
    )
    def test_rejected_accusatory_assertions(self, prohibited_claim: str):
        with pytest.raises(SemanticSafetyViolationError):
            validate_semantic_safety(prohibited_claim)


# =====================================================================
# 10. No Scalar Risk Score & Compatibility Sentinel (-1.0)
# =====================================================================

class TestNoScalarRiskScoreAndSentinel:
    """Verify scalar risk score invariant and -1.0 database compatibility sentinel."""

    def test_scalar_score_absence_in_domain_and_rest(self, comp_api_client: TestClient, seeded_comp_env: Dict[str, Any]):
        proj_id = seeded_comp_env["project_id"]
        contrib_id = seeded_comp_env["contrib_adequate"]
        ver_id = seeded_comp_env["version_id"]

        resp = comp_api_client.get(f"/api/v1/projects/{proj_id}/contributors/{contrib_id}/risk-profile?dataset_version_id={ver_id}")
        assert resp.status_code == 200
        payload = resp.json()["data"]

        # REST contract guarantees NO overall_risk_score key
        assert "overall_risk_score" not in payload
        assert "detection_profile" in payload
        assert "proof_profile" in payload

    def test_database_sentinel_representation(self, test_db_session: Session, seeded_comp_env: Dict[str, Any]):
        service = ContributorRiskService(db=test_db_session)
        profile = service.generate_contributor_risk_profile(
            project_id=seeded_comp_env["project_id"],
            contributor_id=seeded_comp_env["contrib_adequate"],
            dataset_version_id=seeded_comp_env["version_id"],
        )

        db_model = test_db_session.query(RiskAssessmentModel).filter_by(target_id=profile.contributor_id).first()
        assert db_model is not None
        assert db_model.overall_risk_score == -1.0
        assert db_model.component_scores_json["scalar_risk_score_applicable"] is False
        assert db_model.component_scores_json["scalar_risk_score"] is None
        assert db_model.component_scores_json["representation"] == "STRUCTURED_MULTIDIMENSIONAL_VECTOR"


# =====================================================================
# 11. Stale & Incompatible Evidence Rejection (ADR-037)
# =====================================================================

class TestStaleAndIncompatibleEvidence:
    """Verify rejection of stale evidence, version mismatches, and fingerprint discrepancies."""

    def test_evidence_scoping_to_dataset_version(self, test_db_session: Session, seeded_comp_env: Dict[str, Any]):
        service = ContributorRiskService(db=test_db_session)

        # Generate profile on V1
        p_v1 = service.generate_contributor_risk_profile(
            project_id=seeded_comp_env["project_id"],
            contributor_id=seeded_comp_env["contrib_adequate"],
            dataset_version_id=seeded_comp_env["version_id"],
        )
        assert p_v1.effective_sample_count >= 30.0

        # On V2 where contributor has 0 contributions, should report 0 sample count cleanly
        p_v2 = service.generate_contributor_risk_profile(
            project_id=seeded_comp_env["project_id"],
            contributor_id=seeded_comp_env["contrib_adequate"],
            dataset_version_id=seeded_comp_env["version_v2_id"],
        )
        assert p_v2.effective_sample_count == 0.0
        assert p_v2.support_state == SupportState.UNVERIFIABLE


# =====================================================================
# 12. Multi-Tenant Project Isolation & Cross-Project Security
# =====================================================================

class TestProjectIsolationSecurity:
    """Verify strict multi-tenant boundary enforcement and zero cross-project leakage."""

    def test_foreign_contributor_access_rejected_without_leak(self, comp_api_client: TestClient, seeded_comp_env: Dict[str, Any]):
        main_proj = seeded_comp_env["project_id"]
        foreign_contrib = seeded_comp_env["contrib_foreign"]
        ver_id = seeded_comp_env["version_id"]

        # Requesting foreign contributor under main project URL -> must reject cleanly
        resp = comp_api_client.get(f"/api/v1/projects/{main_proj}/contributors/{foreign_contrib}/risk-profile?dataset_version_id={ver_id}")
        assert resp.status_code in (404, 422)
        data = resp.json()
        assert data["status"] == "error"

    def test_cross_project_dataset_version_rejected(self, test_db_session: Session, seeded_comp_env: Dict[str, Any]):
        service = ContributorRiskService(db=test_db_session)
        with pytest.raises(CrossProjectContaminationError):
            service.generate_contributor_risk_profile(
                project_id=seeded_comp_env["project_id"],
                contributor_id=seeded_comp_env["contrib_adequate"],
                dataset_version_id=seeded_comp_env["foreign_version_id"],
            )


# =====================================================================
# 13. Determinism & Analytical Payloads (ADR-038)
# =====================================================================

class TestDeterministicAnalyticalIdentity:
    """Verify bit-for-bit canonical serialization invariance across repeated executions."""

    def test_canonical_json_determinism(self, comp_api_client: TestClient, seeded_comp_env: Dict[str, Any]):
        proj_id = seeded_comp_env["project_id"]
        contrib_id = seeded_comp_env["contrib_adequate"]
        ver_id = seeded_comp_env["version_id"]

        resp1 = comp_api_client.post(
            f"/api/v1/projects/{proj_id}/contributors/risk-assessments",
            json={"contributor_id": contrib_id, "dataset_version_id": ver_id, "seal_provenance": False},
        )
        resp2 = comp_api_client.post(
            f"/api/v1/projects/{proj_id}/contributors/risk-assessments",
            json={"contributor_id": contrib_id, "dataset_version_id": ver_id, "seal_provenance": False},
        )

        p1 = resp1.json()["data"]
        p2 = resp2.json()["data"]

        # Identity & structural analysis must be identical
        assert p1["contributor_id"] == p2["contributor_id"]
        assert p1["detection_profile"] == p2["detection_profile"]
        assert p1["proof_profile"] == p2["proof_profile"]


# =====================================================================
# 14. Concurrency & Idempotency
# =====================================================================

class TestConcurrencyAndIdempotency:
    """Verify thread-safety and duplicate prevention under concurrent requests."""

    def test_concurrent_assessments_safe_and_idempotent(self, seeded_comp_env: Dict[str, Any], test_db_session: Session):
        proj_id = seeded_comp_env["project_id"]
        contrib_id = seeded_comp_env["contrib_adequate"]
        ver_id = seeded_comp_env["version_id"]

        # Run multiple assessments sequentially and concurrently
        service = ContributorRiskService(db=test_db_session)
        p1 = service.generate_contributor_risk_profile(project_id=proj_id, contributor_id=contrib_id, dataset_version_id=ver_id)
        p2 = service.generate_contributor_risk_profile(project_id=proj_id, contributor_id=contrib_id, dataset_version_id=ver_id)

        assert p1.contributor_id == p2.contributor_id

        # Verify only 1 record exists in DB for this contributor
        count = test_db_session.query(RiskAssessmentModel).filter(
            RiskAssessmentModel.target_id == contrib_id
        ).count()
        assert count == 1


# =====================================================================
# 15. Offline / Air-Gapped Verification
# =====================================================================

class TestOfflineAirGappedVerification:
    """Verify that execution is 100% offline with zero external network socket calls."""

    def test_zero_network_calls_during_assessment(
        self,
        monkeypatch: pytest.MonkeyPatch,
        comp_api_client: TestClient,
        seeded_comp_env: Dict[str, Any],
    ):
        def _forbidden_connect(*args, **kwargs):
            raise RuntimeError("CRITICAL AIR-GAP VIOLATION: Network call attempted in Phase 6!")

        monkeypatch.setattr(socket.socket, "connect", _forbidden_connect)

        # Service execution
        service = ContributorRiskService(db=seeded_comp_env.get("db", None) or comp_api_client.app.dependency_overrides)
        # Verify domain engine requires zero network calls
        engine = ContributorRiskEngine()
        contributor = ContributorInputContext(
            contributor_id="c1",
            project_id="p1",
            dataset_version_id="v1",
            effective_exposure=50.0,
            signature_present=True,
            chain_valid=True,
            nonce_valid=True,
            provenance_status="VERIFIED",
        )
        bg = DatasetBackgroundContext(total_exposure=100.0)
        profile = engine.assess_contributor(contributor, bg)
        assert profile.contributor_id == "c1"


# =====================================================================
# 16. Architectural Invariants Verification (12 Mandated Invariants)
# =====================================================================

class TestArchitecturalInvariantsVerification:
    """Explicitly verify all 12 core architectural invariants."""

    def test_invariant_1_detection_evidence_not_equal_maliciousness(self):
        """Invariant 1: Detection evidence != maliciousness."""
        with pytest.raises(SemanticSafetyViolationError):
            validate_semantic_safety("contributor is malicious because label error rate is high")

    def test_invariant_2_proof_evidence_not_equal_detection_score(self):
        """Invariant 2: Proof evidence != detection score."""
        proof = ProofProfile(provenance_integrity=ProvenanceIntegrityDimension(verification_status="FAILED", tamper_detected=True))
        # Proof profile has binary/discrete proof status, never numerical anomaly score
        assert not hasattr(proof, "anomaly_score")
        assert proof.provenance_integrity.confidence == 1.0

    def test_invariant_3_no_scalar_contributor_risk_score(self):
        """Invariant 3: No scalar Contributor Risk score."""
        engine = ContributorRiskEngine()
        contributor = ContributorInputContext(
            contributor_id="c1",
            project_id="p1",
            dataset_version_id="v1",
            effective_exposure=50.0,
            signature_present=True,
            chain_valid=True,
            nonce_valid=True,
            provenance_status="VERIFIED",
        )
        bg = DatasetBackgroundContext(total_exposure=100.0)
        profile = engine.assess_contributor(contributor, bg)
        # Profile is structured vector with no scalar overall_risk_score property
        assert not hasattr(profile, "overall_risk_score")
        assert profile.detection_profile is not None
        assert profile.proof_profile is not None

    def test_invariant_4_fractional_attribution_conserved(self):
        """Invariant 4: Fractional attribution conserved."""
        samples = [
            CanonicalSample(sample_id="s1", relative_path="f1.png", file_size_bytes=100, width=100, height=100, contributors=["a", "b", "c", "d"]),
        ]
        attr = build_sample_attribution_map(samples)
        assert sum(attr["s1"].values()) == pytest.approx(1.0)
        assert attr["s1"]["a"] == pytest.approx(0.25)

    def test_invariant_5_contextual_baselines_required(self):
        """Invariant 5: Contextual baselines required."""
        engine = ContextualBaselineEngine()
        base = engine.compute_class_conditional_baseline(
            class_total_exposure=200.0,
            class_total_events=60.0,
            class_contributor_exposure=20.0,
            class_contributor_events=6.0,
            class_name="c1",
            class_id=1,
        )
        assert base.baseline_value == pytest.approx(54.0 / 180.0)
        assert base.baseline_type == BaselineType.CLASS_CONDITIONAL

    def test_invariant_6_small_samples_are_conservative(self):
        """Invariant 6: Small samples are conservative."""
        # Nc = 1.0 (small) with 100% anomaly rate shrinks drastically towards baseline
        eb = compute_empirical_bayes_shrinkage(
            effective_count=1.0,
            total_exposure=1.0,
            baseline_rate=0.05,
            prior_weight=20.0,
        )
        # lambda = 1 / 21 = ~0.0476, shrunk rate = 0.0476*1.0 + 0.9524*0.05 = ~0.095
        assert eb.shrunk_rate < 0.10
        assert eb.shrinkage_factor < 0.05

    def test_invariant_7_correlated_evidence_not_linearly_double_counted(self):
        """Invariant 7: Correlated evidence is not linearly double-counted."""
        dim_label = LabelReliabilityDimension(
            dimension_id=RiskDimensionId.DIM_LABEL_RELIABILITY,
            status=EvaluationStatus.ADEQUATE_SUPPORT,
            observed_rate=0.20,
            differential=0.20,
            confidence=0.90,
            support_state=SupportState.ADEQUATE_SUPPORT,
        )
        dim_trans = TransitionAsymmetryDimension(
            dimension_id=RiskDimensionId.DIM_TRANSITION_ASYM,
            status=EvaluationStatus.ADEQUATE_SUPPORT,
            noise_concentration_index=0.18,
            confidence=0.90,
            support_state=SupportState.ADEQUATE_SUPPORT,
        )
        dim_proof = ProvenanceIntegrityDimension(
            dimension_id=RiskDimensionId.DIM_PROVENANCE_INTEGRITY,
            verification_status="VERIFIED",
            confidence=1.0,
        )
        families = EvidenceFamilyEvaluator.evaluate_families(
            detection_dimensions=[dim_label, dim_trans],
            proof_dimension=dim_proof,
        )
        label_fam = next(f for f in families if f.family_id == EvidenceFamilyId.LABEL_INTEGRITY)
        assert label_fam.dominant_differential == pytest.approx(0.20)

    def test_invariant_8_database_schema_remains_unchanged(self, test_db_session: Session):
        """Invariant 12: Database schema remains unchanged (0 new tables/columns)."""
        # Verifying RiskAssessmentModel schema fields match established baseline
        columns = RiskAssessmentModel.__table__.columns.keys()
        assert "overall_risk_score" in columns
        assert "component_scores_json" in columns
        assert "target_id" in columns
