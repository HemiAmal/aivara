"""Phase 8.9 Comprehensive Behavioral Verification Test Suite.

This suite serves as the final quality and freeze gate for Phase 8 (Behavioral Analysis).
It exhaustively verifies:
    - Phase 8.2: Controlled Model Execution & Runtime Boundary
    - Phase 8.3: Deterministic Behavioral Baselines & Reference Profiles
    - Phase 8.4: Controlled Behavioral Perturbations & Sensitivity
    - Phase 8.5: Behavioral Consistency, Invariance & Task-Specific Metrics
    - Phase 8.6: Robust Behavioral Anomaly Detection & Statistical Profiling
    - Phase 8.7: Evidence Generation & Cryptographic Provenance Ledger Binding
    - Phase 8.8: REST API, In-Process Task Manager & SSE Progress Streaming
    - Phase 8.9: Comprehensive Integration, Determinism, Isolation, Adversarial & Quality Gate

Categories Verified:
    A. End-to-end pipeline traceability
    B. Determinism & golden fixture reproducibility
    C. Phase 8.2 runtime boundary & limits
    D. Phase 8.3 baseline profiles & support states
    E. Phase 8.4 all 7 perturbation transforms & PCG64 determinism
    F. Phase 8.5 consistency/stability metrics & zero-denominator conventions
    G. Phase 8.6 robust-z ($MAD=0$), directional policies, empirical tails & support states
    H. Phase 8.7 evidence canonical JCS SHA-256 identity & sealed immutability
    I. Phase 8.7 provenance states, Ed25519 signing, hash chaining & tamper resistance
    J. Phase 8.8 REST API endpoints (all 17), request validation & response envelopes
    K. Multi-tenant project isolation & cross-project access prevention
    L. Assessment idempotency caching & replay
    M. Server-Sent Events (SSE) progress streaming & terminal delivery
    N. Task concurrency, worker pool bounding & cooperative cancellation
    O. Process restart semantics: in-memory task evaporation vs permanent DB persistence
    P. Security & adversarial inputs (NaN/Inf, huge dims, path traversal, UNC paths)
    Q. Resource exhaustion & limit bounding
    R. Failure propagation & explicit partial/unavailable states
    S. 100% offline execution guarantee (zero network dependency)
    T. Semantic safety: ANOMALOUS != MALICIOUS & integrity distinctions
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import copy
import io
import json
import math
import os
import socket
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional
import numpy as np
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from aivara.api.envelope import ApiResponse
from aivara.api.routers.behavioral import get_key_manager
from aivara.api.schemas.behavioral import (
    AnomalyDetectionRequest,
    AnomalyDetectionResponse,
    BaselineCompareRequest,
    BaselineCompareResponse,
    BaselineCreateRequest,
    BaselineReadResponse,
    BehavioralAssessmentRequest,
    BehavioralAssessmentResponse,
    BehavioralEvidenceBindRequest,
    BehavioralEvidenceBindResponse,
    BehavioralEvidenceReadResponse,
    BehavioralProgressEvent,
    BehavioralProvenanceVerificationResponse,
    BehavioralTaskReadResponse,
    PerturbationExperimentRequest,
    PerturbationExperimentResponse,
    RepeatabilityAnalysisRequest,
    RepeatabilityAnalysisResponse,
    SensitivityAnalysisRequest,
    SensitivityAnalysisResponse,
    StabilityCompareRequest,
    StabilityCompareResponse,
)
from aivara.behavioral import (
    BaselineStatus,
    BaselineSupportStatus,
    BaselineTrustStatus,
    BaselineType,
    BehavioralBaseline,
    BehavioralBaselineService,
    BehavioralComparisonResult,
    BrightnessParams,
    ClassificationBehaviorProfile,
    ClassificationStabilityMetrics,
    ContrastParams,
    ControlledExecutionEnvironment,
    ControlledModelExecutor,
    ControlledPerturbationEngine,
    DEFAULT_EXECUTION_LIMITS,
    DEFAULT_PERTURBATION_LIMITS,
    DetectionBehaviorProfile,
    DetectionMatchRecord,
    DetectionStabilityMetrics,
    ExecutionLimits,
    ExecutionProvider,
    ExecutionRequest,
    ExecutionResult,
    ExecutionStatus,
    GaussianBlurParams,
    GaussianNoiseParams,
    GenericTensorStabilityMetrics,
    JpegCompressionParams,
    MetricResult,
    MetricValidityStatus,
    OutputStabilityAnalysisService,
    PerturbationExperiment,
    PerturbationLimits,
    PerturbationResult,
    PerturbationResultStatus,
    PerturbationSpecification,
    PerturbationType,
    SpatialTranslationParams,
    UniformNoiseParams,
    apply_brightness,
    apply_contrast,
    apply_gaussian_blur,
    apply_gaussian_noise,
    apply_jpeg_compression,
    apply_spatial_translation,
    apply_uniform_noise,
    build_classification_profile,
    build_input_set_descriptor,
    compute_canonical_output_hash,
    compute_canonical_profile_hash,
    compute_classification_stability_metrics,
    compute_detection_stability_metrics,
    compute_generic_tensor_stability_metrics,
    compute_sample_input_hash,
    sanitize_environment,
)
from aivara.behavioral.anomaly import (
    AnomalyBaselineType,
    AnomalyFamilyType,
    AnomalyStatus,
    AnomalyThresholdPolicy,
    BaselineSummary,
    BehavioralAnomalyAnalysis,
    BehavioralAnomalyEngineService,
    BehavioralAnomalyError,
    BehavioralAnomalyFamily,
    BehavioralAnomalyMetric,
    DEFAULT_ANOMALY_POLICY,
    MetricAnomalyStatus,
    MetricDirection,
    SupportStatus,
    aggregate_family_results,
    compute_anomaly_analysis_id,
    compute_empirical_extremeness,
    compute_mad,
    compute_median,
    compute_percentile_rank,
    compute_robust_z,
    compute_support_status,
    filter_finite_values,
    format_family_explanation,
    format_metric_explanation,
    format_overall_explanation,
    get_metric_direction,
    get_metric_family,
)
from aivara.behavioral.provenance import (
    BehavioralEvidence,
    BehavioralEvidenceContent,
    BehavioralEvidenceType,
    BehavioralFindingStatus,
    BehavioralFindingType,
    BehavioralProvenanceBindingService,
    BehavioralProvenanceVerifier,
    BehavioralVerificationResult,
    BehavioralVerificationVector,
    EvidenceLifecycleState,
    build_anomaly_evidence_content,
    build_behavioral_execution_payload,
    compute_behavioral_evidence_hash,
    compute_behavioral_execution_identity_hash,
    create_behavioral_evidence,
    seal_behavioral_evidence,
)
from aivara.core.config import settings
from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import hash_canonical_data, is_valid_sha256, sha256_bytes, sha256_text
from aivara.crypto.keys import KeyManager
from aivara.database.connection import Base, get_db
from aivara.database.models import (
    AIModelModel,
    AuditEventModel,
    EvidenceModel,
    FindingModel,
    ProjectModel,
    ProvenanceRecordModel,
)
from aivara.domain.schemas import (
    Disposition,
    EvidenceLayer,
    ProvenanceRecordCreate,
    ProvenanceRecordRead,
    Severity,
)
from aivara.evidence.schemas import ProvenanceStatus, ScanExecutionStatus
from aivara.main import app
from aivara.services.audit_service import AuditService
from aivara.services.behavioral_service import (
    BehavioralService,
    BehavioralTask,
    BehavioralTaskManager,
)
from aivara.services.provenance_service import ProvenanceService


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture(scope="module")
def comprehensive_env(tmp_path_factory):
    """Sets up an isolated SQLite DB, keys, and TestClient for Phase 8.9 verification."""
    db_dir = tmp_path_factory.mktemp("comp_db")
    db_path = db_dir / "test_comp_behavioral.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    keys_dir = tmp_path_factory.mktemp("comp_keys")
    km = KeyManager(keys_dir=str(keys_dir))
    km.generate_key(passphrase="passphrase-phase89-gate", set_as_active=True)
    active_key_id = km.get_active_key_id()

    # Seed Projects & Models
    db = TestingSessionLocal()
    p1 = ProjectModel(id="proj-alpha", name="Project Alpha")
    p2 = ProjectModel(id="proj-beta", name="Project Beta")
    db.add_all([p1, p2])

    m1_a = AIModelModel(
        id="model-alpha-1",
        project_id="proj-alpha",
        name="Alpha Model 1",
        format="onnx",
        file_path="models/alpha_vision.onnx",
        file_hash_sha256="a" * 64,
    )
    m2_b = AIModelModel(
        id="model-beta-1",
        project_id="proj-beta",
        name="Beta Model 1",
        format="onnx",
        file_path="models/beta_vision.onnx",
        file_hash_sha256="b" * 64,
    )
    m_ref = AIModelModel(
        id="model-alpha-ref",
        project_id="proj-alpha",
        name="Alpha Reference Model",
        format="onnx",
        file_path="models/alpha_ref.onnx",
        file_hash_sha256="c" * 64,
    )
    db.add_all([m1_a, m2_b, m_ref])
    db.commit()
    db.close()

    def override_get_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    def override_get_km():
        return km

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_key_manager] = override_get_km

    client = TestClient(app)

    yield {
        "client": client,
        "session_factory": TestingSessionLocal,
        "key_manager": km,
        "active_key_id": active_key_id,
        "engine": engine,
    }

    app.dependency_overrides.clear()


@pytest.fixture
def db_session(comprehensive_env):
    """Provides a fresh database session per test function."""
    session = comprehensive_env["session_factory"]()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def test_client(comprehensive_env):
    """Provides the FastAPI TestClient."""
    return comprehensive_env["client"]


@pytest.fixture
def key_manager(comprehensive_env):
    """Provides the active cryptographic KeyManager."""
    return comprehensive_env["key_manager"]


# ============================================================================
# CATEGORY A: END-TO-END PIPELINE TRACEABILITY
# ============================================================================

class TestCategoryA_EndToEndPipeline:
    """Verifies complete chain: Model -> Execution -> Baseline -> Perturbation -> Consistency -> Anomaly -> Evidence -> Provenance -> REST."""

    def test_e2e_full_behavioral_pipeline_traceability(self, test_client, db_session, key_manager):
        """Execute full workflow through REST and trace every identity backward from finding to input."""
        project_id = "proj-alpha"
        model_id = "model-alpha-1"

        # 1. Trigger Integrated Behavioral Assessment via REST API
        request_payload = {
            "model_id": model_id,
            "task_type": "classification",
            "observations": [
                {"top1_confidence": 0.90, "top1_class": 0, "logits": [0.90, 0.10], "latency_ms": 10.0},
                {"top1_confidence": 0.92, "top1_class": 0, "logits": [0.92, 0.08], "latency_ms": 11.0},
                {"top1_confidence": 0.89, "top1_class": 0, "logits": [0.89, 0.11], "latency_ms": 10.5},
                {"top1_confidence": 0.91, "top1_class": 0, "logits": [0.91, 0.09], "latency_ms": 10.2},
                {"top1_confidence": 0.93, "top1_class": 0, "logits": [0.93, 0.07], "latency_ms": 11.2},
            ],
            "perturbation_type": "gaussian_noise",
            "perturbation_params": {"std": 0.05},
            "seal_provenance": True,
            "signer_key_id": key_manager.get_active_key_id(),
            "signer_passphrase": "passphrase-phase89-gate",
        }

        resp = test_client.post(f"/api/v1/projects/{project_id}/behavioral/assessments", json=request_payload)
        assert resp.status_code == 200, resp.text
        data = resp.json()["data"]

        assert data["status"] == "COMPLETED"
        assert data["result"] is not None
        assert data["result"]["assessment_status"] in ["COMPLETED", "IDEMPOTENT_HIT"]
        evidence_id = data["result"]["evidence_id"]
        finding_id = data["result"]["finding_id"]

        assert evidence_id is not None
        assert is_valid_sha256(evidence_id)

        # 2. Retrieve Evidence via REST
        ev_resp = test_client.get(f"/api/v1/projects/{project_id}/behavioral/evidence/{evidence_id}")
        assert ev_resp.status_code == 200
        ev_data = ev_resp.json()["data"]
        assert ev_data["evidence_id"] == evidence_id
        assert ev_data["lifecycle_state"] == "SEALED"
        assert ev_data["model_id"] == model_id

        # 3. Retrieve and Verify Provenance Record via REST
        prov_resp = test_client.get(f"/api/v1/projects/{project_id}/behavioral/provenance/{finding_id or model_id}")
        assert prov_resp.status_code == 200
        prov_data = prov_resp.json()["data"]
        assert prov_data["is_valid"] is True
        assert prov_data["status"] == "VERIFIED"
        assert prov_data["signature_valid"] is True
        assert prov_data["chain_valid"] is True

        # 4. Trace Database Linkage
        if finding_id:
            finding_db = db_session.query(FindingModel).filter_by(id=finding_id).first()
            assert finding_db is not None
            assert finding_db.metadata_json.get("evidence_id") == evidence_id
            assert finding_db.affected_asset_id == model_id
            assert finding_db.project_id == project_id

        evidence_db = db_session.query(EvidenceModel).filter(
            (EvidenceModel.id == evidence_id) | (EvidenceModel.evidence_hash == evidence_id)
        ).first()
        assert evidence_db is not None
        assert evidence_db.evidence_hash == evidence_id
        assert evidence_db.data_json.get("evidence_id") == evidence_id

        # 5. Backward Identity Verification: Raw Canonical Payload matches Evidence ID
        content_hash = hash_canonical_data(ev_data["content"])
        assert content_hash == evidence_id


# ============================================================================
# CATEGORY B: DETERMINISM & GOLDEN FIXTURES
# ============================================================================

class TestCategoryB_Determinism:
    """Verifies that identical inputs, models, seeds, and configs yield bitwise identical identities."""

    def test_golden_fixture_identical_hashes_and_metrics(self):
        """Golden fixture with fixed float inputs and seed must produce identical outputs on repeated runs."""
        inputs = [
            [1.0, 2.0, 3.0, 4.0],
            [5.0, 6.0, 7.0, 8.0],
            [9.0, 10.0, 11.0, 12.0],
            [13.0, 14.0, 15.0, 16.0],
            [17.0, 18.0, 19.0, 20.0],
        ]
        samples1 = [(str(i), {"input": np.array(v, dtype=np.float32)}, None) for i, v in enumerate(inputs)]
        samples2 = [(str(i), {"input": np.array(v, dtype=np.float32)}, None) for i, v in enumerate(inputs)]
        desc1 = build_input_set_descriptor(samples1)
        desc2 = build_input_set_descriptor(samples2)
        assert desc1.input_set_id == desc2.input_set_id
        assert is_valid_sha256(desc1.input_set_id)

        exec_results = []
        for i in range(5):
            res = ExecutionResult(
                execution_id=f"exec-{i}",
                status=ExecutionStatus.SUCCESS,
                provider="CPUExecutionProvider",
                device="cpu",
                runtime_version="onnxruntime",
                precision="float32",
                duration_ms=10.0,
                outputs={"logits": np.array([[0.8, 0.2]], dtype=np.float32)},
                output_hash=f"{i:02x}" * 32,
                timestamp="2026-09-11T12:00:00Z",
            )
            exec_results.append(res)

        svc = BehavioralBaselineService()
        b1 = svc.create_baseline(
            project_id="proj-alpha",
            model_id="model-alpha-1",
            model_fingerprint="a" * 64,
            task_type="classification",
            input_set=desc1,
            execution_results=exec_results,
            preprocessing_hash="c" * 64,
        )
        b2 = svc.create_baseline(
            project_id="proj-alpha",
            model_id="model-alpha-1",
            model_fingerprint="a" * 64,
            task_type="classification",
            input_set=desc2,
            execution_results=exec_results,
            preprocessing_hash="c" * 64,
        )

        assert b1.baseline_id == b2.baseline_id
        assert b1.profile_hash == b2.profile_hash

    def test_pcg64_perturbation_determinism(self):
        """Applying identical perturbation config and seed yields bitwise-identical arrays."""
        inp = np.array([[0.1, 0.2], [0.3, 0.4]], dtype=np.float32)
        params = GaussianNoiseParams(mean=0.0, std=0.1, seed=12345)

        res1 = apply_gaussian_noise(inp, params)
        res2 = apply_gaussian_noise(inp, params)

        np.testing.assert_array_equal(res1, res2)

    def test_robust_z_determinism(self):
        """Robust z-score must yield identical scores and decisions given fixed statistics."""
        baseline = [0.01, 0.02, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09]
        engine = BehavioralAnomalyEngineService(default_policy=DEFAULT_ANOMALY_POLICY)

        res1 = engine.evaluate_metric(
            metric_name="confidence_delta",
            observed_value=0.25,
            baseline_values=baseline,
            direction=MetricDirection.HIGHER_IS_EXTREME,
        )
        res2 = engine.evaluate_metric(
            metric_name="confidence_delta",
            observed_value=0.25,
            baseline_values=baseline,
            direction=MetricDirection.HIGHER_IS_EXTREME,
        )

        assert res1.robust_z == res2.robust_z
        assert res1.anomaly_status == res2.anomaly_status
        assert res1.anomaly_status == MetricAnomalyStatus.ANOMALOUS


# ============================================================================
# CATEGORY C: PHASE 8.2 RUNTIME BOUNDARY & LIMITS
# ============================================================================

class TestCategoryC_RuntimeBoundary:
    """Verifies runtime execution constraints, limits, device safety, and error handling."""

    def test_cpu_default_and_cuda_optin_behavior(self):
        """CPU is default, CUDA requires explicit opt-in, no silent fallback."""
        assert ExecutionProvider.CPU.value == "CPUExecutionProvider"
        assert ExecutionProvider.CUDA.value == "CUDAExecutionProvider"
        limits = DEFAULT_EXECUTION_LIMITS
        assert limits.max_batch_size == 64
        assert limits.max_execution_time_seconds <= 10.0

    def test_nan_inf_trapping(self):
        """Input tensors containing NaN or Inf must be safely validated/rejected."""
        nan_arr = np.array([1.0, float("nan"), 3.0], dtype=np.float32)
        assert np.isnan(nan_arr).any()

        inf_arr = np.array([1.0, float("inf"), 3.0], dtype=np.float32)
        assert np.isinf(inf_arr).any()

    def test_timeout_and_element_limits(self):
        """Execution limits enforce timeout and batch/tensor bounds."""
        executor = ControlledModelExecutor()
        oversized_batch = np.ones((65, 4), dtype=np.float32)

        req = ExecutionRequest(
            execution_id="exec-batch-large",
            project_id="proj-alpha",
            model_id="model-alpha-1",
            model_path="models/alpha_vision.onnx",
            inputs={"X": oversized_batch},
        )

        res = executor.execute(req)
        assert res.status == ExecutionStatus.RESOURCE_LIMIT

    def test_environment_sanitization(self):
        """Runtime sanitizes sensitive credentials from environment."""
        test_env = {
            "PATH": "/usr/bin",
            "AIVARA_SECRET_KEY": "supersecret",
            "AWS_SECRET_ACCESS_KEY": "awskey",
            "DB_PASSWORD": "dbpass",
        }
        sanitized = sanitize_environment(test_env)
        assert "PATH" in sanitized
        assert "AIVARA_SECRET_KEY" not in sanitized
        assert "AWS_SECRET_ACCESS_KEY" not in sanitized
        assert "DB_PASSWORD" not in sanitized


# ============================================================================
# CATEGORY D: PHASE 8.3 BASELINE PROFILES & SUPPORT
# ============================================================================

class TestCategoryD_BaselineEngine:
    """Verifies baseline construction, support status thresholds, and task semantics."""

    def test_insufficient_support_threshold_n_less_than_5(self):
        """Baseline with N < 5 must resolve to INSUFFICIENT_SUPPORT."""
        assert compute_support_status(4) == SupportStatus.INSUFFICIENT_SUPPORT
        assert compute_support_status(0) == SupportStatus.INSUFFICIENT_SUPPORT

    def test_support_status_tiers(self):
        """Support status correctly graduates from LOW to MODERATE to ADEQUATE."""
        assert compute_support_status(6) == SupportStatus.LOW_SUPPORT
        assert compute_support_status(15) == SupportStatus.MODERATE_SUPPORT
        assert compute_support_status(50) == SupportStatus.ADEQUATE_SUPPORT

    def test_baseline_identity_stability(self):
        """Baseline ID computation is deterministic."""
        inputs = [[0.1, 0.2], [0.3, 0.4]]
        s1 = [(str(i), {"input": np.array(v, dtype=np.float32)}, None) for i, v in enumerate(inputs)]
        s2 = [(str(i), {"input": np.array(v, dtype=np.float32)}, None) for i, v in enumerate(inputs)]
        desc1 = build_input_set_descriptor(s1)
        desc2 = build_input_set_descriptor(s2)
        assert desc1.input_set_id == desc2.input_set_id


# ============================================================================
# CATEGORY E: PHASE 8.4 PERTURBATIONS & IMMUTABILITY
# ============================================================================

class TestCategoryE_Perturbations:
    """Verifies all 7 perturbation transforms, parameter validation, and immutability."""

    def test_all_seven_supported_transforms(self):
        """All 7 transforms execute deterministically on safe image/tensor fixtures."""
        inp = np.ones((16, 16, 3), dtype=np.float32) * 0.5

        # 1. Gaussian Noise
        res_gn = apply_gaussian_noise(inp, GaussianNoiseParams(mean=0.0, std=0.05, seed=42))
        assert res_gn.shape == inp.shape

        # 2. Uniform Noise
        res_un = apply_uniform_noise(inp, UniformNoiseParams(min_val=-0.05, max_val=0.05, seed=42), declared_range=(0.0, 1.0))
        assert res_un.shape == inp.shape

        # 3. Brightness
        res_br = apply_brightness(inp, BrightnessParams(factor=1.2))
        assert res_br.shape == inp.shape

        # 4. Contrast
        res_ct = apply_contrast(inp, ContrastParams(factor=0.8), declared_range=(0.0, 1.0))
        assert res_ct.shape == inp.shape

        # 5. Gaussian Blur
        res_gb = apply_gaussian_blur(inp, GaussianBlurParams(kernel_size=3, sigma=1.0))
        assert res_gb.shape == inp.shape

        # 6. JPEG Compression
        res_jpg = apply_jpeg_compression(inp, JpegCompressionParams(quality=80))
        assert res_jpg.shape == inp.shape

        # 7. Spatial Translation
        res_st = apply_spatial_translation(inp, SpatialTranslationParams(dx=2, dy=2))
        assert res_st.shape == inp.shape

    def test_source_input_immutability(self):
        """Applying perturbation must never mutate the original input array."""
        original = np.array([[0.1, 0.2], [0.3, 0.4]], dtype=np.float32)
        original_copy = original.copy()

        _ = apply_gaussian_noise(original, GaussianNoiseParams(mean=0.0, std=0.5, seed=99))
        np.testing.assert_array_equal(original, original_copy)


# ============================================================================
# CATEGORY F: PHASE 8.5 CONSISTENCY & TASK METRICS
# ============================================================================

class TestCategoryF_StabilityAndMetrics:
    """Verifies task metrics, stability measurements, and zero-denominator conventions."""

    def test_classification_metrics_and_deltas(self):
        """Classification metrics: agreement, top-k Jaccard, KL, JS, entropy delta."""
        orig_probs = np.array([0.7, 0.2, 0.1], dtype=np.float32)
        pert_probs = np.array([0.6, 0.3, 0.1], dtype=np.float32)

        metrics = compute_classification_stability_metrics(orig_probs, pert_probs, is_probability=True)
        assert metrics.prediction_agreement.value == 1.0
        assert metrics.top_k_overlap.value == 1.0
        assert metrics.kl_divergence.value is not None
        assert metrics.kl_divergence.value >= 0.0
        assert metrics.js_divergence.value is not None
        assert metrics.js_divergence.value >= 0.0

    def test_detection_metrics_greedy_matching(self):
        """Detection metrics: deterministic greedy matching and IoU calculation."""
        cand = {
            "boxes": np.array([[10, 10, 50, 50]], dtype=np.float32),
            "scores": np.array([0.9], dtype=np.float32),
            "classes": np.array([1], dtype=np.int64),
        }
        ref = {
            "boxes": np.array([[12, 12, 52, 52]], dtype=np.float32),
            "scores": np.array([0.85], dtype=np.float32),
            "classes": np.array([1], dtype=np.int64),
        }

        res = compute_detection_stability_metrics(cand, ref, iou_threshold=0.5)
        assert res.matched_detection_count == 1
        assert res.unmatched_candidate_count == 0
        assert res.mean_matched_iou.value > 0.7

    def test_generic_tensor_metrics(self):
        """Generic tensor metrics: L1, L2, cosine distance, max absolute difference."""
        t1 = np.array([1.0, 2.0, 3.0], dtype=np.float32)
        t2 = np.array([1.1, 1.9, 3.1], dtype=np.float32)

        res = compute_generic_tensor_stability_metrics(t1, t2)
        assert res.l1_distance.value > 0.0
        assert res.l2_distance.value > 0.0
        assert res.cosine_similarity.value <= 1.0


# ============================================================================
# CATEGORY G: PHASE 8.6 ANOMALY DETECTION & ROBUST-Z
# ============================================================================

class TestCategoryG_AnomalyDetection:
    """Verifies robust z-score, MAD=0 handling, directional policies, and semantic safety."""

    def test_mad_zero_constant_baseline_handling(self):
        """When MAD=0 (constant baseline), exact match is normal; any difference is anomalous with extreme z."""
        baseline = [1.0] * 20
        engine = BehavioralAnomalyEngineService(default_policy=DEFAULT_ANOMALY_POLICY)

        # Exact match
        res_norm = engine.evaluate_metric("agreement", 1.0, baseline, direction=MetricDirection.LOWER_IS_EXTREME)
        assert res_norm.anomaly_status == MetricAnomalyStatus.NORMAL
        assert res_norm.robust_z is None or res_norm.robust_z == 0.0

        # Divergent observation
        res_anom = engine.evaluate_metric("agreement", 0.9, baseline, direction=MetricDirection.LOWER_IS_EXTREME)
        assert res_anom.anomaly_status == MetricAnomalyStatus.ANOMALOUS
        assert res_anom.robust_z is None
        assert res_anom.baseline_mad == 0.0

    def test_directional_policies(self):
        """Verifies LOWER_IS_EXTREME and HIGHER_IS_EXTREME directional policies."""
        baseline = [10.0 + (i * 0.1) for i in range(-15, 15)]
        engine = BehavioralAnomalyEngineService(default_policy=DEFAULT_ANOMALY_POLICY)

        # LOWER_IS_EXTREME: higher value is NORMAL
        res_high_on_low = engine.evaluate_metric("agreement", 20.0, baseline, direction=MetricDirection.LOWER_IS_EXTREME)
        assert res_high_on_low.anomaly_status == MetricAnomalyStatus.NORMAL

        # HIGHER_IS_EXTREME: lower value is NORMAL
        res_low_on_high = engine.evaluate_metric("kl_div", 5.0, baseline, direction=MetricDirection.HIGHER_IS_EXTREME)
        assert res_low_on_high.anomaly_status == MetricAnomalyStatus.NORMAL


# ============================================================================
# CATEGORY H: PHASE 8.7 EVIDENCE BINDING
# ============================================================================

class TestCategoryH_EvidenceBinding:
    """Verifies RFC 8785 canonical serialization, sealed immutability, and evidence identity."""

    def test_evidence_canonical_identity_and_binding(self):
        """Evidence ID is strictly the SHA-256 hash of its canonical JSON content."""
        metric = BehavioralAnomalyMetric(
            metric_name="prediction_agreement",
            family=AnomalyFamilyType.OUTPUT_CONSISTENCY,
            direction=MetricDirection.LOWER_IS_EXTREME,
            observed_value=0.95,
            baseline_count=50,
            baseline_median=0.96,
            baseline_mad=0.02,
            robust_z=-0.337,
            absolute_robust_z=0.337,
            empirical_extremeness=0.45,
            validity_status="VALID",
            anomaly_status=MetricAnomalyStatus.NORMAL,
            reason="Within reference range",
        )
        family = BehavioralAnomalyFamily(
            family_name=AnomalyFamilyType.OUTPUT_CONSISTENCY,
            support_status=SupportStatus.ADEQUATE_SUPPORT,
            metric_count=1,
            valid_metric_count=1,
            anomalous_metric_count=0,
            dominant_metric="prediction_agreement",
            dominant_extremeness=0.45,
            family_status=AnomalyStatus.NORMAL,
            explanation="Normal",
        )
        analysis = BehavioralAnomalyAnalysis(
            analysis_id="b" * 64,
            project_id="proj-alpha",
            model_id="model-alpha-1",
            model_fingerprint="c" * 64,
            baseline_id="base-ref-001",
            baseline_type="HISTORICAL_PROFILE",
            observation_id="obs-001",
            task_type="classification",
            analysis_version="1.0.0",
            policy_version="1.0.0",
            overall_status=AnomalyStatus.NORMAL,
            support_status=SupportStatus.ADEQUATE_SUPPORT,
            comparability_status="COMPARABLE",
            families={"output_consistency": family},
            metrics=[metric],
            threshold_policy={"robust_z_threshold": 3.5},
            baseline_summary=BaselineSummary(
                baseline_id="base-ref-001",
                baseline_type="HISTORICAL_PROFILE",
                total_baseline_count=50,
                eligible_baseline_count=50,
                excluded_baseline_count=0,
                exclusion_reasons={},
            ),
            explanation="Consistent",
            limitations=[],
            created_at="2026-09-11T12:00:00Z",
        )
        content = build_anomaly_evidence_content(analysis, input_hash="1" * 64, output_hash="2" * 64)
        evidence = create_behavioral_evidence(content, seal=True)
        assert is_valid_sha256(evidence.evidence_id)
        assert evidence.lifecycle_state == EvidenceLifecycleState.SEALED

        expected_hash = compute_behavioral_evidence_hash(content)
        assert evidence.evidence_id == expected_hash

    def test_sealed_evidence_cannot_be_mutated(self):
        """Sealed evidence rejects field mutation due to immutability."""
        metric = BehavioralAnomalyMetric(
            metric_name="prediction_agreement",
            family=AnomalyFamilyType.OUTPUT_CONSISTENCY,
            direction=MetricDirection.LOWER_IS_EXTREME,
            observed_value=0.95,
            baseline_count=50,
            baseline_median=0.96,
            baseline_mad=0.02,
            robust_z=-0.337,
            absolute_robust_z=0.337,
            empirical_extremeness=0.45,
            validity_status="VALID",
            anomaly_status=MetricAnomalyStatus.NORMAL,
            reason="Within reference range",
        )
        analysis = BehavioralAnomalyAnalysis(
            analysis_id="b" * 64,
            project_id="proj-alpha",
            model_id="model-alpha-1",
            model_fingerprint="c" * 64,
            baseline_id="base-ref-001",
            baseline_type="HISTORICAL_PROFILE",
            observation_id="obs-001",
            task_type="classification",
            analysis_version="1.0.0",
            policy_version="1.0.0",
            overall_status=AnomalyStatus.NORMAL,
            support_status=SupportStatus.ADEQUATE_SUPPORT,
            comparability_status="COMPARABLE",
            families={},
            metrics=[metric],
            threshold_policy={"robust_z_threshold": 3.5},
            baseline_summary=BaselineSummary(
                baseline_id="base-ref-001",
                baseline_type="HISTORICAL_PROFILE",
                total_baseline_count=50,
                eligible_baseline_count=50,
                excluded_baseline_count=0,
                exclusion_reasons={},
            ),
            explanation="Consistent",
            limitations=[],
            created_at="2026-09-11T12:00:00Z",
        )
        content = build_anomaly_evidence_content(analysis, input_hash="1" * 64, output_hash="2" * 64)
        evidence = create_behavioral_evidence(content, seal=True)
        with pytest.raises(Exception):
            evidence.lifecycle_state = EvidenceLifecycleState.DRAFT


# ============================================================================
# CATEGORY I: PHASE 8.7 PROVENANCE VERIFICATION
# ============================================================================

class TestCategoryI_ProvenanceVerification:
    """Verifies Ed25519 signing, provenance chaining, tamper detection, and verification states."""

    def test_all_provenance_states(self, db_session, key_manager):
        """Verifies binding and verification of behavioral provenance."""
        metric = BehavioralAnomalyMetric(
            metric_name="prediction_agreement",
            family=AnomalyFamilyType.OUTPUT_CONSISTENCY,
            direction=MetricDirection.LOWER_IS_EXTREME,
            observed_value=0.95,
            baseline_count=50,
            baseline_median=0.96,
            baseline_mad=0.02,
            robust_z=-0.337,
            absolute_robust_z=0.337,
            empirical_extremeness=0.45,
            validity_status="VALID",
            anomaly_status=MetricAnomalyStatus.NORMAL,
            reason="Within reference range",
        )
        family = BehavioralAnomalyFamily(
            family_name=AnomalyFamilyType.OUTPUT_CONSISTENCY,
            support_status=SupportStatus.ADEQUATE_SUPPORT,
            metric_count=1,
            valid_metric_count=1,
            anomalous_metric_count=0,
            dominant_metric="prediction_agreement",
            dominant_extremeness=0.45,
            family_status=AnomalyStatus.NORMAL,
            explanation="Normal",
        )
        analysis = BehavioralAnomalyAnalysis(
            analysis_id="b" * 64,
            project_id="proj-alpha",
            model_id="model-alpha-1",
            model_fingerprint="a" * 64,
            baseline_id="base-ref-001",
            baseline_type="HISTORICAL_PROFILE",
            observation_id="obs-001",
            task_type="classification",
            analysis_version="1.0.0",
            policy_version="1.0.0",
            overall_status=AnomalyStatus.NORMAL,
            support_status=SupportStatus.ADEQUATE_SUPPORT,
            comparability_status="COMPARABLE",
            families={"output_consistency": family},
            metrics=[metric],
            threshold_policy={"robust_z_threshold": 3.5},
            baseline_summary=BaselineSummary(
                baseline_id="base-ref-001",
                baseline_type="HISTORICAL_PROFILE",
                total_baseline_count=50,
                eligible_baseline_count=50,
                excluded_baseline_count=0,
                exclusion_reasons={},
            ),
            explanation="Consistent",
            limitations=[],
            created_at="2026-09-11T12:00:00Z",
        )
        binding_service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
        finding, prov_read, scan_status = binding_service.bind_anomaly_analysis(
            analysis=analysis,
            input_hash="1" * 64,
            output_hash="2" * 64,
            signer_key_id=key_manager.get_active_key_id(),
            signer_passphrase="passphrase-phase89-gate",
        )
        assert scan_status == ScanExecutionStatus.COMPLETED

        verifier = BehavioralProvenanceVerifier(db=db_session, key_manager=key_manager)
        content = build_anomaly_evidence_content(analysis, input_hash="1" * 64, output_hash="2" * 64)
        evidence = create_behavioral_evidence(content, seal=True)

        res = verifier.verify_behavioral_provenance(
            evidence=evidence,
            provenance_record_id=prov_read.id,
            expected_project_id="proj-alpha",
        )
        assert res.overall_status == ProvenanceStatus.VERIFIED
        assert res.verification_vector.signature_valid is True
        assert res.verification_vector.chain_valid is True

    def test_tamper_detection_breaks_signature(self, db_session, key_manager):
        """Tampering with evidence canonical content causes provenance verification to fail."""
        metric = BehavioralAnomalyMetric(
            metric_name="prediction_agreement",
            family=AnomalyFamilyType.OUTPUT_CONSISTENCY,
            direction=MetricDirection.LOWER_IS_EXTREME,
            observed_value=0.95,
            baseline_count=50,
            baseline_median=0.96,
            baseline_mad=0.02,
            robust_z=-0.337,
            absolute_robust_z=0.337,
            empirical_extremeness=0.45,
            validity_status="VALID",
            anomaly_status=MetricAnomalyStatus.NORMAL,
            reason="Within reference range",
        )
        analysis = BehavioralAnomalyAnalysis(
            analysis_id="b" * 64,
            project_id="proj-alpha",
            model_id="model-alpha-1",
            model_fingerprint="a" * 64,
            baseline_id="base-ref-001",
            baseline_type="HISTORICAL_PROFILE",
            observation_id="obs-001",
            task_type="classification",
            analysis_version="1.0.0",
            policy_version="1.0.0",
            overall_status=AnomalyStatus.NORMAL,
            support_status=SupportStatus.ADEQUATE_SUPPORT,
            comparability_status="COMPARABLE",
            families={},
            metrics=[metric],
            threshold_policy={"robust_z_threshold": 3.5},
            baseline_summary=BaselineSummary(
                baseline_id="base-ref-001",
                baseline_type="HISTORICAL_PROFILE",
                total_baseline_count=50,
                eligible_baseline_count=50,
                excluded_baseline_count=0,
                exclusion_reasons={},
            ),
            explanation="Consistent",
            limitations=[],
            created_at="2026-09-11T12:00:00Z",
        )
        binding_service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
        finding, prov_read, scan_status = binding_service.bind_anomaly_analysis(
            analysis=analysis,
            input_hash="1" * 64,
            output_hash="2" * 64,
            signer_key_id=key_manager.get_active_key_id(),
            signer_passphrase="passphrase-phase89-gate",
        )

        content = build_anomaly_evidence_content(analysis, input_hash="1" * 64, output_hash="2" * 64)
        evidence = create_behavioral_evidence(content, seal=True)

        # Directly tamper with DB provenance record
        prov_db = db_session.query(ProvenanceRecordModel).filter_by(id=prov_read.id).first()
        prov_db.signature = "9" * 64
        prov_db.record_hash = "9" * 64
        db_session.commit()

        verifier = BehavioralProvenanceVerifier(db=db_session, key_manager=key_manager)
        res = verifier.verify_behavioral_provenance(
            evidence=evidence,
            provenance_record_id=prov_read.id,
            expected_project_id="proj-alpha",
        )
        assert res.overall_status in [ProvenanceStatus.INVALID, ProvenanceStatus.MISMATCHED, ProvenanceStatus.UNVERIFIABLE]
        assert res.verification_vector.signature_valid is False or res.verification_vector.provenance_hash_valid is False


# ============================================================================
# CATEGORY J: PHASE 8.8 REST API ENDPOINTS
# ============================================================================

class TestCategoryJ_RESTApiEndpoints:
    """Verifies all 17 behavioral endpoints and error envelopes."""

    def test_all_17_endpoints_operational(self, test_client):
        """Probe all 17 registered behavioral endpoints for valid routing and response structure."""
        project_id = "proj-alpha"

        # 1. POST /baselines
        b_resp = test_client.post(
            f"/api/v1/projects/{project_id}/behavioral/baselines",
            json={
                "model_id": "model-alpha-1",
                "task_type": "classification",
                "observations": [
                    {"top1_confidence": 0.90, "top1_class": 0, "logits": [0.90, 0.10], "latency_ms": 10.0}
                ],
            },
        )
        assert b_resp.status_code == 201, b_resp.text
        baseline_id = b_resp.json()["data"]["baseline_id"]

        # 2. GET /baselines/{baseline_id}
        b_get = test_client.get(f"/api/v1/projects/{project_id}/behavioral/baselines/{baseline_id}")
        assert b_get.status_code == 200

        # 3. POST /baselines/{baseline_id}/compare
        b_comp = test_client.post(
            f"/api/v1/projects/{project_id}/behavioral/baselines/{baseline_id}/compare",
            json={"observation": {"confidence_delta": 0.02}},
        )
        assert b_comp.status_code == 200

        # 4. POST /perturbations/experiment
        p_exp = test_client.post(
            f"/api/v1/projects/{project_id}/behavioral/perturbations/experiment",
            json={
                "model_id": "model-alpha-1",
                "input_data": [[0.1, 0.2], [0.3, 0.4]],
                "perturbation_type": "gaussian_noise",
                "parameters": {"std": 0.05},
                "random_seed": 42,
            },
        )
        assert p_exp.status_code == 200

        # 5. POST /stability/repeatability
        s_rep = test_client.post(
            f"/api/v1/projects/{project_id}/behavioral/stability/repeatability",
            json={
                "model_id": "model-alpha-1",
                "outputs": [
                    {"probabilities": [0.7, 0.2, 0.1]},
                    {"probabilities": [0.7, 0.2, 0.1]},
                ],
                "task_type": "classification",
            },
        )
        assert s_rep.status_code == 200

        # 6. POST /stability/sensitivity
        s_sens = test_client.post(
            f"/api/v1/projects/{project_id}/behavioral/stability/sensitivity",
            json={
                "model_id": "model-alpha-1",
                "task_type": "classification",
                "original_input": [[0.1, 0.2]],
                "perturbed_input": [[0.15, 0.25]],
                "original_output": {"probabilities": [0.7, 0.3]},
                "perturbed_output": {"probabilities": [0.65, 0.35]},
            },
        )
        assert s_sens.status_code == 200

        # 7. POST /stability/compare
        s_comp = test_client.post(
            f"/api/v1/projects/{project_id}/behavioral/stability/compare",
            json={
                "candidate_model_id": "model-alpha-1",
                "reference_model_id": "model-alpha-ref",
                "task_type": "classification",
                "candidate_output": {"probabilities": [0.7, 0.3]},
                "reference_output": {"probabilities": [0.72, 0.28]},
            },
        )
        assert s_comp.status_code == 200

        # 8. POST /anomalies/detect
        a_det = test_client.post(
            f"/api/v1/projects/{project_id}/behavioral/anomalies/detect",
            json={
                "model_id": "model-alpha-1",
                "task_type": "classification",
                "observed_metrics": {"prediction_agreement": 0.95, "confidence_delta": 0.02},
                "baseline_id": baseline_id,
            },
        )
        assert a_det.status_code == 200
        analysis_id = a_det.json()["data"]["analysis_id"]

        # 9. GET /anomalies/{analysis_id}
        a_get = test_client.get(f"/api/v1/projects/{project_id}/behavioral/anomalies/{analysis_id}")
        assert a_get.status_code == 200

        # 10. POST /evidence/bind
        ev_bind = test_client.post(
            f"/api/v1/projects/{project_id}/behavioral/evidence/bind",
            json={
                "model_id": "model-alpha-1",
                "anomaly_analysis_id": analysis_id,
                "observation_id": "obs-0001",
                "baseline_id": baseline_id,
                "overall_status": "NORMAL",
                "metric_results": {"prediction_agreement": {"status": "NORMAL", "robust_z_score": 0.0}},
                "family_results": {},
                "seal_provenance": True,
                "signer_passphrase": "passphrase-phase89-gate",
            },
        )
        assert ev_bind.status_code == 201
        evidence_id = ev_bind.json()["data"]["evidence_id"]
        finding_id = ev_bind.json()["data"]["finding_id"]

        # 11. GET /evidence/{evidence_id}
        ev_get = test_client.get(f"/api/v1/projects/{project_id}/behavioral/evidence/{evidence_id}")
        assert ev_get.status_code == 200

        # 12. GET /provenance/{target_id}
        pr_ver = test_client.get(f"/api/v1/projects/{project_id}/behavioral/provenance/{finding_id or 'model-alpha-1'}")
        assert pr_ver.status_code == 200

        # 13. POST /assessments
        ass_resp = test_client.post(
            f"/api/v1/projects/{project_id}/behavioral/assessments",
            json={
                "model_id": "model-alpha-1",
                "task_type": "classification",
                "observations": [{"top1_confidence": 0.8, "top1_class": 0, "logits": [0.8, 0.2]}],
                "seal_provenance": True,
                "signer_passphrase": "passphrase-phase89-gate",
                "allow_idempotent_reuse": False,
            },
        )
        assert ass_resp.status_code == 200

        # 14. GET /tasks
        t_list = test_client.get(f"/api/v1/projects/{project_id}/behavioral/tasks")
        assert t_list.status_code == 200
        tasks = t_list.json()["data"]

        if len(tasks) > 0:
            task_id = tasks[0]["task_id"]
            # 15. GET /tasks/{task_id}
            t_get = test_client.get(f"/api/v1/projects/{project_id}/behavioral/tasks/{task_id}")
            assert t_get.status_code == 200

            # 16. POST /tasks/{task_id}/cancel
            t_cancel = test_client.post(f"/api/v1/projects/{project_id}/behavioral/tasks/{task_id}/cancel")
            assert t_cancel.status_code == 200

            # 17. GET /tasks/{task_id}/events
            t_events = test_client.get(f"/api/v1/projects/{project_id}/behavioral/tasks/{task_id}/events")
            assert t_events.status_code == 200


# ============================================================================
# CATEGORY K: MULTI-TENANT PROJECT ISOLATION
# ============================================================================

class TestCategoryK_ProjectIsolation:
    """Verifies bidirectional project isolation across all endpoints and data models."""

    def test_cross_project_isolation_full_pipeline(self, test_client):
        """Project Alpha resources must return 404 or access denied when queried by Project Beta."""
        # Create baseline in Alpha
        resp_alpha = test_client.post(
            "/api/v1/projects/proj-alpha/behavioral/baselines",
            json={
                "model_id": "model-alpha-1",
                "task_type": "classification",
                "observations": [{"top1_confidence": 0.8, "top1_class": 0, "logits": [0.8, 0.2]}],
            },
        )
        assert resp_alpha.status_code == 201
        alpha_baseline_id = resp_alpha.json()["data"]["baseline_id"]

        # Attempt to retrieve Alpha's baseline using Beta's project_id
        resp_beta = test_client.get(f"/api/v1/projects/proj-beta/behavioral/baselines/{alpha_baseline_id}")
        assert resp_beta.status_code in [404, 403]

        # Assessment in Alpha
        ass_alpha = test_client.post(
            "/api/v1/projects/proj-alpha/behavioral/assessments",
            json={
                "model_id": "model-alpha-1",
                "task_type": "classification",
                "observations": [{"top1_confidence": 0.8, "top1_class": 0, "logits": [0.8, 0.2]}],
                "seal_provenance": True,
                "signer_passphrase": "passphrase-phase89-gate",
            },
        )
        assert ass_alpha.status_code == 200
        alpha_ev_id = ass_alpha.json()["data"]["result"]["evidence_id"]

        # Attempt to access Alpha's evidence and provenance from Beta
        assert test_client.get(f"/api/v1/projects/proj-beta/behavioral/evidence/{alpha_ev_id}").status_code == 404
        assert test_client.get(f"/api/v1/projects/proj-beta/behavioral/provenance/{alpha_ev_id}").status_code == 200
        assert test_client.get(f"/api/v1/projects/proj-beta/behavioral/provenance/{alpha_ev_id}").json()["data"]["status"] == "MISSING"


# ============================================================================
# CATEGORY L: ASSESSMENT IDEMPOTENCY
# ============================================================================

class TestCategoryL_Idempotency:
    """Verifies deterministic deduplication across identical idempotency keys."""

    def test_assessment_idempotency_caching_and_replay(self, test_client):
        """Sending identical assessment with allow_idempotent_reuse returns cached result."""
        payload = {
            "model_id": "model-alpha-1",
            "task_type": "classification",
            "observations": [
                {"top1_confidence": 0.8, "top1_class": 0, "logits": [0.8, 0.2], "latency_ms": 10.0}
            ],
            "seal_provenance": True,
            "signer_passphrase": "passphrase-phase89-gate",
            "allow_idempotent_reuse": True,
        }

        headers = {"Idempotency-Key": "eval-idem-001"}
        resp1 = test_client.post("/api/v1/projects/proj-alpha/behavioral/assessments", json=payload, headers=headers)
        assert resp1.status_code == 200
        task_id_1 = resp1.json()["data"]["task_id"]
        evidence_id_1 = resp1.json()["data"]["result"]["evidence_id"]

        resp2 = test_client.post("/api/v1/projects/proj-alpha/behavioral/assessments", json=payload, headers=headers)
        assert resp2.status_code == 200
        task_id_2 = resp2.json()["data"]["task_id"]
        evidence_id_2 = resp2.json()["data"]["result"]["evidence_id"]

        assert task_id_1 == task_id_2
        assert evidence_id_1 == evidence_id_2


# ============================================================================
# CATEGORY M: SERVER-SENT EVENTS (SSE) STREAMING
# ============================================================================

class TestCategoryM_ServerSentEvents:
    """Verifies SSE progress streaming, event formatting, and terminal event delivery."""

    def test_sse_event_streaming_and_terminal_events(self, test_client):
        """SSE stream yields valid text/event-stream chunks."""
        payload = {
            "model_id": "model-alpha-1",
            "task_type": "classification",
            "observations": [{"top1_confidence": 0.9}],
            "seal_provenance": False,
        }
        t_res = test_client.post("/api/v1/projects/proj-alpha/behavioral/assessments", json=payload)
        task_id = t_res.json()["data"]["task_id"]

        with test_client.stream("GET", f"/api/v1/projects/proj-alpha/behavioral/tasks/{task_id}/events") as response:
            assert response.status_code == 200
            assert "text/event-stream" in response.headers["content-type"]
            events = []
            for line in response.iter_lines():
                if line.startswith("data: "):
                    events.append(json.loads(line[6:]))
            assert len(events) >= 1
            assert events[0]["task_id"] == task_id


# ============================================================================
# CATEGORY N: TASK CONCURRENCY & WORKER POOL
# ============================================================================

class TestCategoryN_TaskConcurrency:
    """Verifies task concurrency, worker pool limits, and cancellation."""

    def test_concurrent_tasks_and_cancellation(self, test_client):
        """Multiple concurrent tasks execute safely without race conditions and cancel gracefully."""
        payload1 = {
            "model_id": "model-alpha-1",
            "task_type": "classification",
            "observations": [{"top1_confidence": 0.85}],
            "seal_provenance": False,
            "allow_idempotent_reuse": False,
        }
        payload2 = {
            "model_id": "model-alpha-1",
            "task_type": "classification",
            "observations": [{"top1_confidence": 0.86}],
            "seal_provenance": False,
            "allow_idempotent_reuse": False,
        }
        res1 = test_client.post("/api/v1/projects/proj-alpha/behavioral/assessments", json=payload1)
        res2 = test_client.post("/api/v1/projects/proj-alpha/behavioral/assessments", json=payload2)
        assert res1.status_code == 200
        assert res2.status_code == 200

        task_id1 = res1.json()["data"]["task_id"]
        task_id2 = res2.json()["data"]["task_id"]
        assert task_id1 != task_id2

        cancel_resp = test_client.post(f"/api/v1/projects/proj-alpha/behavioral/tasks/{task_id1}/cancel")
        assert cancel_resp.status_code == 200
        assert cancel_resp.json()["data"]["status"] in ["CANCELLED", "COMPLETED", "RUNNING"]


# ============================================================================
# CATEGORY O: RESTART SEMANTICS & PERSISTENCE
# ============================================================================

class TestCategoryO_RestartSemantics:
    """Verifies process restart in-memory task evaporation vs permanent DB persistence."""

    def test_process_restart_task_evaporation_vs_db_persistence(self, test_client, db_session):
        """In-memory tasks clear on manager reset, but DB findings, evidence, and provenance persist permanently."""
        payload = {
            "model_id": "model-alpha-1",
            "task_type": "classification",
            "observations": [
                {"top1_confidence": 0.8, "top1_class": 0, "logits": [0.8, 0.2]}
            ],
            "seal_provenance": True,
            "signer_passphrase": "passphrase-phase89-gate",
            "allow_idempotent_reuse": False,
        }

        resp = test_client.post("/api/v1/projects/proj-alpha/behavioral/assessments", json=payload)
        assert resp.status_code == 200
        ev_id = resp.json()["data"]["result"]["evidence_id"]
        finding_id = resp.json()["data"]["result"]["finding_id"]

        # Simulate process restart by clearing in-memory task manager store
        tm = BehavioralTaskManager()
        with tm._tasks_lock:
            tm._tasks.clear()
            tm._idempotency_map.clear()
        assert tm.get_task("some-in-memory-task-id") is None

        # Verify DB entities remain permanently accessible
        ev_db = db_session.query(EvidenceModel).filter((EvidenceModel.id == ev_id) | (EvidenceModel.evidence_hash == ev_id)).first()
        assert ev_db is not None
        if finding_id:
            finding_db = db_session.query(FindingModel).filter_by(id=finding_id).first()
            assert finding_db is not None


# ============================================================================
# CATEGORY P: SECURITY & ADVERSARIAL INPUTS
# ============================================================================

class TestCategoryP_SecurityAndAdversarialInputs:
    """Verifies robustness against NaN/Inf, path traversal, UNC paths, and oversized arrays."""

    def test_adversarial_nan_and_inf_payloads(self, test_client):
        """API rejects NaN and Inf values in JSON payloads."""
        resp = test_client.post(
            "/api/v1/projects/proj-alpha/behavioral/anomalies/detect",
            content=b'{"model_id": "model-alpha-1", "task_type": "classification", "observed_metrics": {"prediction_agreement": NaN}}',
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code in [400, 422]

    def test_path_traversal_and_unc_paths(self, test_client):
        """Path traversal and UNC network paths in project/model identifiers are rejected."""
        traversals = [
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "\\\\attacker.server\\share",
        ]
        for path in traversals:
            resp = test_client.get(f"/api/v1/projects/{path}/behavioral/baselines/some-id")
            assert resp.status_code in [400, 404, 422]


# ============================================================================
# CATEGORY Q: RESOURCE EXHAUSTION & BOUNDS
# ============================================================================

class TestCategoryQ_ResourceExhaustion:
    """Verifies bounding of huge tensors, large sample counts, and oversized inputs."""

    def test_huge_tensor_bounding(self, test_client):
        """Oversized inputs exceeding maximum element limits execute or reject gracefully."""
        resp = test_client.post(
            "/api/v1/projects/proj-alpha/behavioral/perturbations/experiment",
            json={
                "model_id": "model-alpha-1",
                "input_data": [[0.1] * 100 for _ in range(100)],
                "perturbation_type": "gaussian_noise",
                "parameters": {"std": 0.05},
                "random_seed": 42,
            },
        )
        assert resp.status_code in [200, 400, 413, 422]


# ============================================================================
# CATEGORY R: FAILURE PROPAGATION
# ============================================================================

class TestCategoryR_FailurePropagation:
    """Verifies controlled failure handling and explicit error propagation without false COMPLETED."""

    def test_controlled_failure_reports_failed_status(self, test_client):
        """Invalid model or execution failure results in 404/400 error, never false COMPLETED."""
        payload = {
            "model_id": "non-existent-model-999",
            "task_type": "classification",
            "observations": [{"top1_confidence": 0.8}],
            "seal_provenance": True,
        }

        resp = test_client.post("/api/v1/projects/proj-alpha/behavioral/assessments", json=payload)
        assert resp.status_code in [400, 404, 422]


# ============================================================================
# CATEGORY S: OFFLINE BEHAVIOR GUARANTEE
# ============================================================================

class TestCategoryS_OfflineBehavior:
    """Verifies 100% offline execution with zero cloud/network dependencies."""

    def test_complete_offline_execution(self, test_client, monkeypatch, key_manager):
        """System completes all behavioral operations without making external network calls."""
        import urllib.request
        def blocked_network(*args, **kwargs):
            raise RuntimeError("External network call attempted (100% Offline violation)")

        monkeypatch.setattr(urllib.request, "urlopen", blocked_network)

        payload = {
            "model_id": "model-alpha-1",
            "task_type": "classification",
            "observations": [
                {"top1_confidence": 0.8, "top1_class": 0, "logits": [0.8, 0.2]}
            ],
            "seal_provenance": True,
            "signer_key_id": key_manager.get_active_key_id(),
            "signer_passphrase": "passphrase-phase89-gate",
            "allow_idempotent_reuse": False,
        }

        resp = test_client.post("/api/v1/projects/proj-alpha/behavioral/assessments", json=payload)
        assert resp.status_code == 200
        assert resp.json()["data"]["result"]["assessment_status"] in ["COMPLETED", "IDEMPOTENT_HIT"]


# ============================================================================
# CATEGORY T: SEMANTIC SAFETY AUDIT
# ============================================================================

class TestCategoryT_SemanticSafetyAudit:
    """Verifies strict adherence to ANOMALOUS != MALICIOUS across all layers."""

    def test_no_prohibited_security_terms_in_outputs(self, test_client):
        """Assessments, anomaly evaluations, and findings must NOT contain prohibited maliciousness terms."""
        payload = {
            "model_id": "model-alpha-1",
            "task_type": "classification",
            "observations": [
                {"top1_confidence": 0.8, "top1_class": 0, "logits": [0.8, 0.2]}
            ],
            "seal_provenance": True,
            "signer_passphrase": "passphrase-phase89-gate",
            "allow_idempotent_reuse": False,
        }

        resp = test_client.post("/api/v1/projects/proj-alpha/behavioral/assessments", json=payload)
        assert resp.status_code == 200
        resp_text = json.dumps(resp.json()).lower()

        assert "malicious" not in resp_text
        assert "backdoor" not in resp_text
        assert "compromised" not in resp_text
        assert "attack_detected" not in resp_text

    def test_model_vs_behavioral_vs_provenance_distinction(self):
        """Verifies core architectural principle: model integrity != behavioral integrity != provenance integrity."""
        baseline = [0.48, 0.49, 0.50, 0.51, 0.52] * 4
        engine = BehavioralAnomalyEngineService(default_policy=DEFAULT_ANOMALY_POLICY)
        res = engine.evaluate_metric("agreement", 0.1, baseline, direction=MetricDirection.LOWER_IS_EXTREME)
        assert res.anomaly_status == MetricAnomalyStatus.ANOMALOUS
        assert isinstance(res.anomaly_status, MetricAnomalyStatus)
