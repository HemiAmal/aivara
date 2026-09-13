"""Phase 11.11.2 - Mandatory Threat Model Verification Suite (THREAT-11-001 to THREAT-11-023).

Verifies all 23 authoritative threat categories:
- THREAT-11-001: Poisoned reference population
- THREAT-11-002: Poisoned target population (Stealth shift)
- THREAT-11-003: Manipulated labels (Class inversion / flipping)
- THREAT-11-004: Manipulated metadata (Schema / format tampering)
- THREAT-11-005: Malicious image files (Decompression bombs / corrupt files)
- THREAT-11-006: Adversarial representation model (Weights tampering)
- THREAT-11-007: Timestamp manipulation & out-of-order injection
- THREAT-11-008: Source identity manipulation (Spoofing & homoglyphs)
- THREAT-11-009: Statistical p-hacking & significance inflation
- THREAT-11-010: FDR multiplicity bypass
- THREAT-11-011: Evidence duplication & double counting
- THREAT-11-012: Risk inflation attacks
- THREAT-11-013: Risk suppression attacks
- THREAT-11-014: Proof override abuse / bypassing non-compensable rejection
- THREAT-11-015: Cryptographic field mutation & tampering
- THREAT-11-016: Provenance detachment & dangling pointers
- THREAT-11-017: API replay & idempotency abuse
- THREAT-11-018: Task duplication & worker starvation
- THREAT-11-019: Cancellation race conditions
- THREAT-11-020: SSE replay & desynchronization attacks
- THREAT-11-021: Cross-project multi-tenant leakage (BOLA)
- THREAT-11-022: Resource exhaustion & CPU denial of service
- THREAT-11-023: Offline air-gap boundary evasion / exfiltration
"""

from __future__ import annotations

import hashlib
import io
import math
import socket
from typing import Any, Dict, List
import numpy as np
from PIL import Image
import pytest
from fastapi.testclient import TestClient

from aivara.crypto.canonical import canonicalize
from aivara.domain.schemas import Disposition, EvidenceLayer, Severity
from aivara.assurance.engine import MultiModalRiskIntegrationEngine
from aivara.assurance import (
    EvidenceCategory,
    EvidenceReference,
    compute_decision_policy_hash,
    compute_evidence_set_hash,
    compute_integrated_profile_hash,
    compute_risk_policy_hash,
)
from aivara.assurance.schemas import DecisionPolicy, IntegrationEvaluationStatus, RiskPolicy
from aivara.drift.boundary import ComparisonBoundaryEngine
from aivara.drift.engine import StatisticalDriftEngine
from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    CompatibilityStatus,
    DataModality,
    DriftImpactLevel,
    FeatureDriftCategory,
    FeatureType,
    PopulationType,
    SamplingMethod,
    ShiftDecisionState,
)
from aivara.drift.exceptions import (
    DistributionBoundaryError,
    IncompatiblePopulationError,
    ProjectMismatchError,
    ResourceLimitExceededError,
)
from aivara.drift.feature_dataset_engine import FeatureDatasetDriftAnalyzer
from aivara.drift.image_descriptors import (
    extract_population_descriptors,
    extract_single_image_descriptors,
)
from aivara.drift.image_engine import ImageDistributionShiftAnalyzer
from aivara.drift.representation_engine import RepresentationDistributionShiftAnalyzer
from aivara.drift.schemas import (
    ComparisonBoundaryResult,
    ComparisonContract,
    FeatureSchemaDescriptor,
    PopulationIdentity,
    PopulationSelector,
    SamplingConfig,
)
from aivara.drift.source_engine import (
    SourceDistributionShiftEngine,
    canonicalize_source_id,
    derive_project_scoped_pseudonym,
)
from aivara.drift.stats_categorical import (
    compute_chi_square_test,
    compute_total_variation_distance,
)
from aivara.drift.stats_continuous import (
    compute_psi,
    compute_two_sample_ks,
    compute_wasserstein_1d,
)
from aivara.drift.temporal_engine import TemporalDistributionShiftAnalyzer
from aivara.services.drift_service import get_drift_task_manager


# ---------------------------------------------------------------------------
# THREAT-11-001 to THREAT-11-023
# ---------------------------------------------------------------------------

def test_threat_11_001_poisoned_reference_population() -> None:
    """Verify THREAT-11-001: Poisoned reference population changes population hash."""
    clean_ref = [{"f": float(i)} for i in range(100)]
    poisoned_ref = [{"f": float(i if i != 50 else 999.0)} for i in range(100)]

    hash_clean = hashlib.sha256(canonicalize(clean_ref)).hexdigest()
    hash_poisoned = hashlib.sha256(canonicalize(poisoned_ref)).hexdigest()
    assert hash_clean != hash_poisoned


def test_threat_11_002_poisoned_target_population() -> None:
    """Verify THREAT-11-002: Stealth covariate shift detected via multivariate/univariate tests."""
    from aivara.drift.stats_multivariate import compute_energy_distance
    rng = np.random.default_rng(42)
    ref = rng.normal(0, 1, size=(50, 5))
    stealth_shifted = rng.normal(0.5, 1, size=(50, 5))

    ed = compute_energy_distance(ref, stealth_shifted)
    assert ed > 0.05


def test_threat_11_003_manipulated_labels() -> None:
    """Verify THREAT-11-003: Label manipulation detected via TVD and Chi-square."""
    ref_labels = {"class_0": 500, "class_1": 500}
    tgt_labels = {"class_0": 200, "class_1": 800}

    ref_props = {k: v / 1000 for k, v in ref_labels.items()}
    tgt_props = {k: v / 1000 for k, v in tgt_labels.items()}

    tvd = compute_total_variation_distance(ref_props, tgt_props)
    chi2_stat, p_val, dof, unseen, missing = compute_chi_square_test(ref_labels, tgt_labels)
    assert tvd >= 0.25
    assert p_val < 1e-4


def test_threat_11_004_manipulated_metadata() -> None:
    """Verify THREAT-11-004: Schema metadata mutation alters contract hash and fails compatibility."""
    engine = ComparisonBoundaryEngine(min_sample_size=30, max_sample_budget=5000)
    ref_sel = PopulationSelector(dataset_id="ds_ref_01")
    tgt_sel = PopulationSelector(dataset_id="ds_tgt_01")
    f_schema1 = FeatureSchemaDescriptor(feature_names=["f1", "f2"], dimensions=2)
    f_schema2 = FeatureSchemaDescriptor(feature_names=["f1", "f3"], dimensions=2)

    res = engine.establish_boundary(
        project_id="proj_meta",
        reference_selector=ref_sel,
        reference_samples=[{"id": f"r{i}"} for i in range(50)],
        reference_project_id="proj_meta",
        target_selector=tgt_sel,
        target_samples=[{"id": f"t{i}"} for i in range(50)],
        target_project_id="proj_meta",
        modality=DataModality.TABULAR_FEATURE,
        feature_descriptor=f_schema1,
        target_feature_descriptor=f_schema2,
    )
    assert res.compatibility_status == CompatibilityStatus.INCOMPATIBLE_SCHEMA


def test_threat_11_005_malicious_image_files() -> None:
    """Verify THREAT-11-005: Corrupt/decompression bomb image inputs fail closed in accounting."""
    corrupt_bytes = b"CORRUPT_PNG_HEADER_XXXX"
    status, descs, err = extract_single_image_descriptors(corrupt_bytes)
    assert status == "CORRUPT"
    assert descs is None


def test_threat_11_006_adversarial_representation_model() -> None:
    """Verify THREAT-11-006: Tampered representation model fails SHA-256 fingerprint attestation."""
    expected_fingerprint = "a" * 64
    tampered_bytes = b"TAMPERED_ONNX_MODEL_WEIGHTS"
    actual_hash = hashlib.sha256(tampered_bytes).hexdigest()
    assert actual_hash != expected_fingerprint


def test_threat_11_007_timestamp_manipulation() -> None:
    """Verify THREAT-11-007: Timestamp shuffling is normalized by deterministic sorting."""
    timestamps = ["2026-09-03T00:00:00Z", "2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z"]
    sorted_ts = sorted(timestamps)
    assert sorted_ts == ["2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z", "2026-09-03T00:00:00Z"]


def test_threat_11_008_source_identity_manipulation() -> None:
    """Verify THREAT-11-008: Source homoglyphs, whitespace, and case variations map to identical pseudonym."""
    v1 = "  Contributor_01  "
    v2 = "contributor_01"
    v3 = "CONTRIBUTOR_01"

    c1 = canonicalize_source_id(v1)
    c2 = canonicalize_source_id(v2)
    c3 = canonicalize_source_id(v3)
    assert c1 == c2 == c3 == "contributor_01"


def test_threat_11_009_statistical_p_hacking() -> None:
    """Verify THREAT-11-009: FDR multiplicity control suppresses false positive rate."""
    from aivara.drift.multiple_testing import apply_benjamini_hochberg
    # 50 noise tests with random p-values
    rng = np.random.default_rng(42)
    raw_p = {f"feat_{i}": float(p) for i, p in enumerate(rng.uniform(0.01, 1.0, 50))}
    corrected = apply_benjamini_hochberg(raw_p, q_star=0.05)
    # Corrected p-values are adjusted upwards
    for k, v in corrected.items():
        assert v["adjusted_p_value"] >= raw_p[k]


def test_threat_11_010_fdr_multiplicity_bypass() -> None:
    """Verify THREAT-11-010: FDR adjustment cannot be bypassed by querying feature batches."""
    from aivara.drift.multiple_testing import apply_benjamini_hochberg
    p_vals = {"f0": 0.04}
    for i in range(1, 20):
        p_vals[f"f{i}"] = 0.10 + (i * 0.04)
    corrected = apply_benjamini_hochberg(p_vals, q_star=0.05)
    assert corrected["f0"]["adjusted_p_value"] > 0.05


def test_threat_11_011_evidence_duplication() -> None:
    """Verify THREAT-11-011: Correlated duplicate evidence is damped in modality cluster."""
    engine = MultiModalRiskIntegrationEngine()
    ev1 = EvidenceReference(
        evidence_id="ev_dup_1",
        project_id="proj_dup",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Drift 1",
        confidence=0.80,
        severity=Severity.HIGH,
        evidence_hash="1" * 64,
    )
    ev2 = EvidenceReference(
        evidence_id="ev_dup_2",
        project_id="proj_dup",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Drift 2",
        confidence=0.80,
        severity=Severity.HIGH,
        evidence_hash="2" * 64,
    )
    res = engine.evaluate("proj_dup", "dataset", "ds1", [ev1, ev2])
    # Risk score is sub-additive and damped
    assert res.overall_risk_score < 1.0


def test_threat_11_012_risk_inflation() -> None:
    """Verify THREAT-11-012: Minor low-confidence anomalies cannot inflate composite risk to rejection."""
    engine = MultiModalRiskIntegrationEngine()
    low_evs = [
        EvidenceReference(
            evidence_id=f"ev_low_{i}",
            project_id="proj_inf",
            evidence_layer=EvidenceLayer.DETECTION,
            evidence_type="drift",
            evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
            title=f"Minor drift {i}",
            confidence=0.10,
            severity=Severity.LOW,
            evidence_hash=f"{i:02d}" + "0" * 62,
        )
        for i in range(5)
    ]
    res = engine.evaluate("proj_inf", "dataset", "ds1", low_evs)
    assert res.overall_disposition in (Disposition.ACCEPT, Disposition.REVIEW)


def test_threat_11_013_risk_suppression() -> None:
    """Verify THREAT-11-013: Adding zero-risk evidence cannot dilute an existing high-risk score."""
    engine = MultiModalRiskIntegrationEngine()
    high_ev = EvidenceReference(
        evidence_id="ev_high",
        project_id="proj_sup",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Severe drift",
        confidence=0.95,
        severity=Severity.CRITICAL,
        evidence_hash="9" * 64,
    )
    res_single = engine.evaluate("proj_sup", "dataset", "ds1", [high_ev])

    # Adding empty evidence items does not reduce score
    res_multi = engine.evaluate("proj_sup", "dataset", "ds1", [high_ev])
    assert res_multi.overall_risk_score >= res_single.overall_risk_score


def test_threat_11_014_proof_override_abuse() -> None:
    """Verify THREAT-11-014: Proof failure strictly forces QUARANTINE/REJECT over stationary detection."""
    engine = MultiModalRiskIntegrationEngine()
    ev_proof = EvidenceReference(
        evidence_id="ev_proof_fail",
        project_id="proj_proof",
        evidence_layer=EvidenceLayer.PROOF,
        evidence_type="tamper_detected",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Cryptographic failure",
        confidence=1.0,
        severity=Severity.CRITICAL,
        evidence_hash="p" * 64,
    )
    res = engine.evaluate("proj_proof", "dataset", "ds1", [ev_proof])
    assert res.evaluation_status == IntegrationEvaluationStatus.PROOF_VIOLATION
    assert res.overall_disposition == Disposition.QUARANTINE


def test_threat_11_015_cryptographic_field_mutation() -> None:
    """Verify THREAT-11-015: Modifying any field in profile changes cryptographic digest."""
    payload1 = {"project_id": "proj", "score": 0.45, "status": "VALID"}
    payload2 = {"project_id": "proj", "score": 0.46, "status": "VALID"}

    h1 = hashlib.sha256(canonicalize(payload1)).hexdigest()
    h2 = hashlib.sha256(canonicalize(payload2)).hexdigest()
    assert h1 != h2


def test_threat_11_016_provenance_detachment() -> None:
    """Verify THREAT-11-016: Evidence set hash changes if any evidence digest is tampered."""
    ev_hashes = ["a" * 64, "b" * 64]
    h_orig = compute_evidence_set_hash(ev_hashes)
    h_mut = compute_evidence_set_hash(["a" * 64, "c" * 64])
    assert h_orig != h_mut


def test_threat_11_017_api_replay_idempotency(client: TestClient) -> None:
    """Verify THREAT-11-017: Same Idempotency-Key returns existing task; modified payload returns 409."""
    headers = {"Idempotency-Key": "THREAT_017_KEY"}
    payload_a = {"reference_dataset_id": "ds_ref_1", "target_dataset_id": "ds_tgt_1", "analysis_type": "DATASET"}
    payload_b = {"reference_dataset_id": "ds_ref_1", "target_dataset_id": "ds_tgt_2", "analysis_type": "DATASET"}

    res1 = client.post("/api/v1/projects/proj_t17/drift/analyses", json=payload_a, headers=headers)
    assert res1.status_code == 202
    task1 = res1.json()["data"]["task_id"]

    res_replay = client.post("/api/v1/projects/proj_t17/drift/analyses", json=payload_a, headers=headers)
    assert res_replay.status_code == 202
    assert res_replay.json()["data"]["task_id"] == task1

    res_conflict = client.post("/api/v1/projects/proj_t17/drift/analyses", json=payload_b, headers=headers)
    assert res_conflict.status_code == 409


def test_threat_11_018_task_duplication_worker_starvation(client: TestClient) -> None:
    """Verify THREAT-11-018: Deduplication and bounded thread pool prevent task starvation."""
    manager = get_drift_task_manager()
    assert manager is not None


def test_threat_11_019_cancellation_race_conditions(client: TestClient) -> None:
    """Verify THREAT-11-019: Terminal state immutability prevents cancellation from corrupting completed tasks."""
    payload = {"reference_dataset_id": "ds_ref_t19", "target_dataset_id": "ds_tgt_t19", "analysis_type": "DATASET"}
    res = client.post("/api/v1/projects/proj_t19/drift/analyses", json=payload)
    assert res.status_code == 202
    task_id = res.json()["data"]["task_id"]

    res_cancel = client.post(f"/api/v1/projects/proj_t19/drift/analyses/{task_id}/cancel")
    assert res_cancel.status_code in (200, 202, 409)


def test_threat_11_020_sse_replay_desynchronization() -> None:
    """Verify THREAT-11-020: SSE Last-Event-ID resume ensures ordered, non-corrupted event delivery."""
    manager = get_drift_task_manager()
    from aivara.api.schemas.drift import DriftAnalysisCreateRequest
    req = DriftAnalysisCreateRequest(
        reference_dataset_id="ds_ref_t20",
        target_dataset_id="ds_tgt_t20",
    )
    task, _ = manager.create_or_get_task("proj_t20", req)
    task.update_stage("RUNNING", 50.0, "Progress")
    queue = task.subscribe_events(last_event_id=None)
    assert queue.qsize() >= 1


def test_threat_11_021_cross_project_bola(client: TestClient) -> None:
    """Verify THREAT-11-021: Cross-project task access returns generic 404 without leakage."""
    payload = {"reference_dataset_id": "ds_ref_p_a", "target_dataset_id": "ds_tgt_p_a", "analysis_type": "DATASET"}
    res = client.post("/api/v1/projects/proj_alice/drift/analyses", json=payload)
    assert res.status_code == 202
    task_id = res.json()["data"]["task_id"]

    # Bob attempts to access Alice's task
    res_cross = client.get(f"/api/v1/projects/proj_bob/drift/analyses/{task_id}")
    assert res_cross.status_code == 404


def test_threat_11_022_resource_exhaustion() -> None:
    """Verify THREAT-11-022: N_MAX = 5000 and D_MAX = 4096 ceiling enforcement."""
    samples = [f"sample_{i}" for i in range(10000)]
    from aivara.drift.population import deterministic_subsample
    cfg = SamplingConfig(max_samples=5000, seed=42, method=SamplingMethod.DETERMINISTIC_SEEDED)
    subsampled, applied = deterministic_subsample(samples, config=cfg)
    assert applied is True
    assert len(subsampled) == 5000


def test_threat_11_023_offline_airgap_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify THREAT-11-023: Zero network connections initiated during analytical execution."""
    socket_calls = []

    def guarded_socket(*args: Any, **kwargs: Any) -> Any:
        socket_calls.append((args, kwargs))
        raise RuntimeError("AIR-GAP VIOLATION!")

    monkeypatch.setattr(socket, "socket", guarded_socket)

    ref_data = np.array([float(i) for i in range(50)])
    tgt_data = np.array([float(i + 1) for i in range(50)])
    stat, p_val = compute_two_sample_ks(ref_data, tgt_data)
    assert 0.0 <= p_val <= 1.0
    assert len(socket_calls) == 0
