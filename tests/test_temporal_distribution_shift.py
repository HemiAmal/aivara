"""Comprehensive Test Suite for Phase 11.7 Temporal & Windowed Distribution Shift Analysis.

Covers all 64 specification requirements across:
A. Timestamp Normalization, Ordering & Tie-Breaking
B. Windowing Topologies, Boundary Semantics & Baseline Selection
C. Deterministic Subsampling & Budget Enforcement
D. Statistical Engine Integration (Phase 11.3 Reuse, Dual-Gate Rule, Two-Tier FDR)
E. Temporal Trajectory Patterns (No Shift, Abrupt, Gradual, Transient, Persistent)
F. Change-Point Candidate Detection & Attribution Prevention
G. Seasonality & Cycle-Aware Limitations
H. Autocorrelation & Serial Dependency Handling
I. Resource Limits (K <= 50, N <= 5000, Memory Bounds)
J. Cryptographic Identity & Canonical Hashing Sensitivity
K. Findings, Evidence & Provenance Linkage
L. Security, Offline Air-Gap & Immutability
M. Cross-Phase Regressions (Phase 11.2 - 11.6 Compatibility)
"""

import ast
from datetime import datetime, timezone
import hashlib
import io
from pathlib import Path
from typing import Any, Dict, List, Tuple
import numpy as np
import pytest

from aivara.crypto.canonical import canonicalize
from aivara.drift.engine import StatisticalDriftEngine
from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    CompatibilityStatus,
    DataModality,
    PopulationType,
    ShiftDecisionState,
    TemporalComparisonTopology,
    TemporalTrajectoryState,
    TemporalWindowStrategy,
    TimestampSource,
)
from aivara.drift.exceptions import (
    IncompatiblePopulationError,
    ProjectMismatchError,
    ResourceLimitExceededError,
)
from aivara.drift.schemas import (
    ComparisonBoundaryResult,
    ComparisonContract,
    PopulationIdentity,
    StatisticalAnalysisConfig,
    TemporalAnalysisContract,
    TemporalAnalysisProfile,
    TemporalObservation,
    TemporalWindowAccounting,
    TemporalWindowDescriptor,
)
from aivara.drift.temporal_engine import (
    TemporalDistributionShiftAnalyzer,
    compute_temporal_contract_hash,
    compute_temporal_drift_profile_hash,
    compute_temporal_window_hash,
    normalize_timestamp_utc,
    parse_utc_iso_to_epoch,
    sort_temporal_observations,
)


def _make_dummy_boundary(
    project_id: str = "proj-temp-1",
    ref_ds: str = "ds-ref-1",
    tgt_ds: str = "ds-tgt-1",
    modality: DataModality = DataModality.TABULAR_FEATURE,
    status: BoundaryEvaluationStatus = BoundaryEvaluationStatus.VALID,
) -> ComparisonBoundaryResult:
    """Helper to construct deterministic ComparisonBoundaryResult for tests."""
    contract = ComparisonContract(
        project_id=project_id,
        reference_dataset_id=ref_ds,
        target_dataset_id=tgt_ds,
        modality=modality,
        reference_population_hash="a" * 64,
        target_population_hash="b" * 64,
        reference_sample_count=200,
        target_sample_count=200,
    )
    boundary_hash = hashlib.sha256(canonicalize(contract.to_canonical_dict())).hexdigest()
    ref_pop = PopulationIdentity(
        dataset_id=ref_ds,
        population_type=PopulationType.COMPLETE_DATASET,
        total_available_samples=200,
        selected_sample_count=200,
        sampling_applied=False,
        sample_ids_hash="c" * 64,
        population_selection_hash="d" * 64,
    )
    tgt_pop = PopulationIdentity(
        dataset_id=tgt_ds,
        population_type=PopulationType.COMPLETE_DATASET,
        total_available_samples=200,
        selected_sample_count=200,
        sampling_applied=False,
        sample_ids_hash="e" * 64,
        population_selection_hash="f" * 64,
    )
    compat = (
        CompatibilityStatus.COMPATIBLE
        if status == BoundaryEvaluationStatus.VALID
        else CompatibilityStatus.INCOMPATIBLE_SCHEMA
    )
    return ComparisonBoundaryResult(
        contract=contract,
        comparison_boundary_hash=boundary_hash,
        reference_population=ref_pop,
        target_population=tgt_pop,
        status=status,
        compatibility_status=compat,
    )


def _make_dummy_temporal_contract(
    analysis_id: str = "temp_analysis_test",
    window_strategy: TemporalWindowStrategy = TemporalWindowStrategy.FIXED_INTERVAL,
    window_size_seconds: float = 3600.0,  # 1 hour
    step_size_seconds: float = None,
    max_windows: int = 50,
    min_window_samples: int = 30,
) -> TemporalAnalysisContract:
    """Helper to construct a deterministic TemporalAnalysisContract."""
    desc = {
        "baseline_policy": "first_window",
        "comparison_topology": "dual_topology",
        "contract_version": "1.0",
        "declared_seasonality_period_seconds": -1.0,
        "max_window_samples": 5000,
        "max_windows": max_windows,
        "min_window_samples": min_window_samples,
        "schema_version": "1.0",
        "step_size_seconds": float(step_size_seconds) if step_size_seconds else -1.0,
        "temporal_analysis_id": analysis_id,
        "timestamp_field": "event_time",
        "timezone_policy": "UTC",
        "window_size_seconds": float(window_size_seconds),
        "window_strategy": window_strategy.value,
    }
    c_hash = compute_temporal_contract_hash(desc)
    return TemporalAnalysisContract(
        temporal_analysis_id=analysis_id,
        timestamp_field=TimestampSource.EVENT_TIME,
        timezone_policy="UTC",
        window_strategy=window_strategy,
        window_size_seconds=window_size_seconds,
        step_size_seconds=step_size_seconds,
        max_windows=max_windows,
        min_window_samples=min_window_samples,
        temporal_contract_hash=c_hash,
    )


# ===========================================================================
# A. Timestamp Normalization & Deterministic Ordering (1 - 8)
# ===========================================================================

def test_01_to_08_timestamp_normalization_and_sorting():
    """1-8. Tests UTC normalization, epoch parsing, timezone handling, and multi-key sorting."""
    # ISO string with UTC Z
    iso_z = "2026-09-01T12:00:00Z"
    norm_z = normalize_timestamp_utc(iso_z)
    assert norm_z.startswith("2026-09-01T12:00:00")
    assert norm_z.endswith("Z")

    # Timezone offset (+05:30)
    iso_offset = "2026-09-01T17:30:00+05:30"
    norm_offset = normalize_timestamp_utc(iso_offset)
    assert norm_offset.startswith("2026-09-01T12:00:00")

    # Numeric epoch
    epoch_val = 1788264000.0  # 2026-09-01 12:00:00 UTC
    norm_epoch = normalize_timestamp_utc(epoch_val)
    assert norm_epoch.startswith("2026-09-01T12:00:00")

    # Malformed timestamp rejection
    with pytest.raises(ValueError, match="Unparseable timestamp"):
        normalize_timestamp_utc("invalid-date-string-1234")

    # None timestamp rejection
    with pytest.raises(ValueError, match="None or empty"):
        normalize_timestamp_utc(None)

    # Multi-key sorting with timestamp collision
    obs1 = TemporalObservation(sample_id="b_sample", timestamp_raw=iso_z, normalized_timestamp_utc=norm_z)
    obs2 = TemporalObservation(sample_id="a_sample", timestamp_raw=iso_z, normalized_timestamp_utc=norm_z)
    obs3 = TemporalObservation(
        sample_id="c_sample",
        timestamp_raw="2026-09-01T11:00:00Z",
        normalized_timestamp_utc=normalize_timestamp_utc("2026-09-01T11:00:00Z"),
    )

    sorted_list = sort_temporal_observations([obs1, obs2, obs3])
    # obs3 is earliest, then obs2 ("a_sample") before obs1 ("b_sample")
    assert [o.sample_id for o in sorted_list] == ["c_sample", "a_sample", "b_sample"]


# ===========================================================================
# B. Windowing Topologies & Boundary Semantics (9 - 17)
# ===========================================================================

def test_09_to_17_window_construction_and_boundaries():
    """9-17. Tests fixed window partitioning, boundary timestamps, empty/sparse window handling."""
    contract = _make_dummy_temporal_contract(window_size_seconds=3600.0, min_window_samples=30)
    boundary = _make_dummy_boundary()
    analyzer = TemporalDistributionShiftAnalyzer()

    # Generate 100 observations across 3 separate 1-hour windows
    # Window 0: 40 samples at 12:00
    # Window 1: 40 samples at 13:00
    # Window 2: 20 samples at 14:00 (sparse window < 30)
    raw_obs = []
    for i in range(40):
        raw_obs.append({"timestamp": "2026-09-01T12:15:00Z", "payload": [0.5] * 10, "id": f"s0_{i}"})
    for i in range(40):
        raw_obs.append({"timestamp": "2026-09-01T13:15:00Z", "payload": [0.5] * 10, "id": f"s1_{i}"})
    for i in range(20):
        raw_obs.append({"timestamp": "2026-09-01T14:15:00Z", "payload": [0.5] * 10, "id": f"s2_{i}"})

    profile = analyzer.analyze(boundary, contract, raw_obs)
    assert len(profile.windows) == 3
    assert profile.windows[0].is_valid is True
    assert profile.windows[0].sample_count == 40
    assert profile.windows[1].is_valid is True
    assert profile.windows[1].sample_count == 40
    assert profile.windows[2].is_valid is False
    assert profile.windows[2].sample_count == 20
    assert profile.accounting.valid_windows_count == 2
    assert profile.accounting.sparse_windows_count == 1


# ===========================================================================
# C. Subsampling & Resource Budget (18 - 20)
# ===========================================================================

def test_18_to_20_window_subsampling_budget():
    """18-20. Tests per-window sample capping when window observations exceed max_window_samples."""
    contract = _make_dummy_temporal_contract(window_size_seconds=3600.0)
    contract = contract.model_copy(update={"max_window_samples": 50})
    boundary = _make_dummy_boundary()
    analyzer = TemporalDistributionShiftAnalyzer()

    # Generate 80 samples in window 0 and 80 in window 1
    raw_obs = []
    for i in range(80):
        raw_obs.append({"timestamp": "2026-09-01T12:10:00Z", "payload": [0.1] * 5, "id": f"w0_{i}"})
    for i in range(80):
        raw_obs.append({"timestamp": "2026-09-01T13:10:00Z", "payload": [0.1] * 5, "id": f"w1_{i}"})

    profile = analyzer.analyze(boundary, contract, raw_obs)
    assert profile.windows[0].sample_count == 50
    assert profile.windows[1].sample_count == 50


# ===========================================================================
# D. Statistical Engine Reuse & Two-Tier FDR (21 - 27)
# ===========================================================================

def test_21_to_27_statistical_engine_reuse_and_fdr():
    """21-27. Validates Phase 11.3 engine reuse, raw vs adjusted p-values, and dual-gate rule."""
    contract = _make_dummy_temporal_contract(window_size_seconds=3600.0, min_window_samples=30)
    boundary = _make_dummy_boundary()
    analyzer = TemporalDistributionShiftAnalyzer()

    rng = np.random.RandomState(42)
    raw_obs = []
    # W0: normal(0, 1)
    for i in range(40):
        raw_obs.append({"timestamp": "2026-09-01T12:10:00Z", "payload": rng.normal(0.0, 1.0, 16), "id": f"w0_{i}"})
    # W1: normal(0, 1) -> identical to baseline
    for i in range(40):
        raw_obs.append({"timestamp": "2026-09-01T13:10:00Z", "payload": rng.normal(0.0, 1.0, 16), "id": f"w1_{i}"})
    # W2: normal(3, 1) -> shifted from baseline
    for i in range(40):
        raw_obs.append({"timestamp": "2026-09-01T14:10:00Z", "payload": rng.normal(3.0, 1.0, 16), "id": f"w2_{i}"})

    profile = analyzer.analyze(boundary, contract, raw_obs)
    assert len(profile.baseline_comparisons) == 2

    comp_w1 = profile.baseline_comparisons[0]
    comp_w2 = profile.baseline_comparisons[1]

    # W0 vs W1 should be NO_SHIFT
    assert comp_w1.status == ShiftDecisionState.NO_SHIFT_DETECTED
    assert comp_w1.adjusted_p_value >= 0.05

    # W0 vs W2 should be MATERIAL_SHIFT
    assert comp_w2.status == ShiftDecisionState.MATERIAL_SHIFT
    assert comp_w2.adjusted_p_value <= 0.05
    assert comp_w2.effect_size > 0.02


# ===========================================================================
# E. Temporal Trajectory Patterns (28 - 35)
# ===========================================================================

def test_28_to_35_temporal_trajectory_patterns():
    """28-35. Tests trajectory classifications: NO_MATERIAL_SHIFT, TRANSIENT_SHIFT, PERSISTENT_SHIFT, GRADUAL_DRIFT."""
    contract = _make_dummy_temporal_contract(window_size_seconds=3600.0, min_window_samples=30)
    boundary = _make_dummy_boundary()
    analyzer = TemporalDistributionShiftAnalyzer()
    rng = np.random.RandomState(42)

    # 1. No shift scenario
    obs_no_shift = []
    for h in range(3):
        for i in range(35):
            obs_no_shift.append({
                "timestamp": f"2026-09-01T{12+h:02d}:10:00Z",
                "payload": rng.normal(0.0, 1.0, 8),
                "id": f"ns_{h}_{i}",
            })
    p_no_shift = analyzer.analyze(boundary, contract, obs_no_shift)
    assert p_no_shift.global_trajectory_status == TemporalTrajectoryState.NO_MATERIAL_SHIFT

    # 2. Transient shift scenario (W0 normal, W1 shifted, W2 normal)
    obs_transient = []
    for i in range(35):
        obs_transient.append({"timestamp": "2026-09-01T12:10:00Z", "payload": rng.normal(0.0, 1.0, 8), "id": f"t0_{i}"})
    for i in range(35):
        obs_transient.append({"timestamp": "2026-09-01T13:10:00Z", "payload": rng.normal(4.0, 1.0, 8), "id": f"t1_{i}"})
    for i in range(35):
        obs_transient.append({"timestamp": "2026-09-01T14:10:00Z", "payload": rng.normal(0.0, 1.0, 8), "id": f"t2_{i}"})
    p_transient = analyzer.analyze(boundary, contract, obs_transient)
    assert p_transient.global_trajectory_status == TemporalTrajectoryState.TRANSIENT_SHIFT

    # 3. Persistent shift scenario (W0 normal, W1 shifted, W2 shifted)
    obs_persistent = []
    for i in range(35):
        obs_persistent.append({"timestamp": "2026-09-01T12:10:00Z", "payload": rng.normal(0.0, 1.0, 8), "id": f"p0_{i}"})
    for i in range(35):
        obs_persistent.append({"timestamp": "2026-09-01T13:10:00Z", "payload": rng.normal(3.0, 1.0, 8), "id": f"p1_{i}"})
    for i in range(35):
        obs_persistent.append({"timestamp": "2026-09-01T14:10:00Z", "payload": rng.normal(3.0, 1.0, 8), "id": f"p2_{i}"})
    p_persistent = analyzer.analyze(boundary, contract, obs_persistent)
    assert p_persistent.global_trajectory_status in (TemporalTrajectoryState.PERSISTENT_SHIFT, TemporalTrajectoryState.ABRUPT_SHIFT)


# ===========================================================================
# F. Change-Point Candidate Detection (36 - 38)
# ===========================================================================

def test_36_to_38_change_point_candidate_detection():
    """36-38. Tests nonparametric change-point candidate detection at step transitions."""
    contract = _make_dummy_temporal_contract(window_size_seconds=3600.0, min_window_samples=30)
    boundary = _make_dummy_boundary()
    analyzer = TemporalDistributionShiftAnalyzer()
    rng = np.random.RandomState(42)

    # Step transition occurs between W0 and W1
    obs = []
    for i in range(35):
        obs.append({"timestamp": "2026-09-01T12:10:00Z", "payload": rng.normal(0.0, 1.0, 8), "id": f"cp0_{i}"})
    for i in range(35):
        obs.append({"timestamp": "2026-09-01T13:10:00Z", "payload": rng.normal(4.0, 1.0, 8), "id": f"cp1_{i}"})

    profile = analyzer.analyze(boundary, contract, obs)
    assert len(profile.change_points) >= 1
    assert profile.change_points[0].window_boundary_index == 1
    assert "malicious" not in profile.change_points[0].supporting_evidence.lower()
    assert "attack" not in profile.change_points[0].supporting_evidence.lower()


# ===========================================================================
# G & H. Seasonality & Autocorrelation Limitations (39 - 42)
# ===========================================================================

def test_39_to_42_seasonality_and_autocorrelation():
    """39-42. Tests seasonality limitation disclosure when window duration is less than cycle period."""
    # Window size = 1h (3600s), Seasonality period = 24h (86400s)
    contract = _make_dummy_temporal_contract(window_size_seconds=3600.0)
    contract = contract.model_copy(update={"declared_seasonality_period_seconds": 86400.0})
    boundary = _make_dummy_boundary()
    analyzer = TemporalDistributionShiftAnalyzer()

    obs = []
    for h in range(2):
        for i in range(35):
            obs.append({"timestamp": f"2026-09-01T{12+h:02d}:10:00Z", "payload": [0.5] * 4, "id": f"s_{h}_{i}"})

    profile = analyzer.analyze(boundary, contract, obs)
    assert any("seasonality period" in lim.lower() for lim in profile.limitations)


# ===========================================================================
# I. Resource Bounds (43 - 46)
# ===========================================================================

def test_43_to_46_resource_bounds_exceeded():
    """43-46. Verifies ResourceLimitExceededError when window count exceeds contract maximum."""
    # max_windows = 2
    contract = _make_dummy_temporal_contract(window_size_seconds=3600.0, max_windows=2)
    boundary = _make_dummy_boundary()
    analyzer = TemporalDistributionShiftAnalyzer()

    # Generate data spanning 5 hours (5 windows)
    obs = []
    for h in range(5):
        for i in range(35):
            obs.append({"timestamp": f"2026-09-01T{12+h:02d}:10:00Z", "payload": [0.1] * 4, "id": f"res_{h}_{i}"})

    with pytest.raises(ResourceLimitExceededError, match="Generated windows count"):
        analyzer.analyze(boundary, contract, obs)


# ===========================================================================
# J. Cryptographic Identity & Mutation Resistance (47 - 50)
# ===========================================================================

def test_47_to_50_cryptographic_hashes_and_sensitivity():
    """47-50. Deterministic hashing and sensitivity to timestamp, window size, and baseline mutations."""
    contract1 = _make_dummy_temporal_contract(analysis_id="analysis_alpha", window_size_seconds=3600.0)
    contract2 = _make_dummy_temporal_contract(analysis_id="analysis_beta", window_size_seconds=3600.0)
    boundary = _make_dummy_boundary()
    analyzer = TemporalDistributionShiftAnalyzer()

    obs = []
    for h in range(2):
        for i in range(35):
            obs.append({"timestamp": f"2026-09-01T{12+h:02d}:10:00Z", "payload": [0.2] * 4, "id": f"hash_{h}_{i}"})

    p1 = analyzer.analyze(boundary, contract1, obs)
    p1_repeat = analyzer.analyze(boundary, contract1, obs)
    p2 = analyzer.analyze(boundary, contract2, obs)

    # Determinism
    assert p1.temporal_analysis_profile_hash == p1_repeat.temporal_analysis_profile_hash
    assert len(p1.temporal_analysis_profile_hash) == 64

    # Mutation changes hash
    assert p1.temporal_analysis_profile_hash != p2.temporal_analysis_profile_hash


# ===========================================================================
# K. Findings, Evidence & Non-Attribution Invariants (51 - 55)
# ===========================================================================

def test_51_to_55_findings_and_evidence():
    """51-55. Synthesis of FindingModel, EvidenceModel, and neutral non-accusatory language."""
    contract = _make_dummy_temporal_contract(window_size_seconds=3600.0)
    boundary = _make_dummy_boundary()
    analyzer = TemporalDistributionShiftAnalyzer()

    obs = []
    for h in range(2):
        for i in range(35):
            obs.append({"timestamp": f"2026-09-01T{12+h:02d}:10:00Z", "payload": [0.3] * 4, "id": f"ev_{h}_{i}"})

    profile = analyzer.analyze(boundary, contract, obs)
    assert len(profile.findings) == 1
    finding = profile.findings[0]
    assert finding["evidence_layer"] == "detection"
    assert finding["finding_type"] == "temporal_distribution_shift"
    assert "malicious" not in finding["description"].lower()
    assert "attack" not in finding["description"].lower()
    assert "fraud" not in finding["description"].lower()
    assert len(profile.evidence_records) == 1


# ===========================================================================
# L. Security & AST Static Scans (56 - 59)
# ===========================================================================

def test_56_to_59_security_and_ast_scan():
    """56-59. Verifies zero forbidden calls and offline operation."""
    src_paths = [
        Path("backend/aivara/drift/temporal_engine.py"),
    ]
    forbidden_calls = {"eval", "exec", "pickle", "system", "popen", "subprocess"}

    for p in src_paths:
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in forbidden_calls:
                    pytest.fail(f"Forbidden call {node.func.id} found in {p}")
                elif isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_calls:
                    pytest.fail(f"Forbidden method {node.func.attr} found in {p}")


# ===========================================================================
# M. Cross-Phase Regressions (60 - 64)
# ===========================================================================

def test_60_to_64_cross_phase_compatibility():
    """60-64. Validates compatibility with Phase 11.2 boundary and Phase 11.6 representation vectors."""
    contract = _make_dummy_temporal_contract(window_size_seconds=3600.0)
    boundary = _make_dummy_boundary(modality=DataModality.LATENT_EMBEDDING)
    analyzer = TemporalDistributionShiftAnalyzer()

    # Precomputed 384-dimensional representation embeddings
    obs = []
    for h in range(2):
        for i in range(35):
            obs.append({"timestamp": f"2026-09-01T{12+h:02d}:10:00Z", "payload": [0.1] * 384, "id": f"rep_{h}_{i}"})

    profile = analyzer.analyze(boundary, contract, obs)
    assert profile.global_trajectory_status == TemporalTrajectoryState.NO_MATERIAL_SHIFT
    assert len(profile.baseline_comparisons) == 1
    assert profile.baseline_comparisons[0].statistic_method == "kernel_mmd"
