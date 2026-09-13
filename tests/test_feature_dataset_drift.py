"""Comprehensive Verification and Test Suite for Phase 11.4 Feature & Dataset Drift Analysis."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Dict, List
import numpy as np
import pytest

from aivara.drift.boundary import ComparisonBoundaryEngine
from aivara.drift.engine import StatisticalDriftEngine
from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    DataModality,
    DriftImpactLevel,
    FeatureDriftCategory,
    FeatureType,
    ShiftDecisionState,
    StatisticalMethod,
)
from aivara.drift.exceptions import (
    DistributionBoundaryError,
    ProjectMismatchError,
)
from aivara.drift.feature_dataset_engine import (
    FeatureDatasetDriftAnalyzer,
    compute_dataset_drift_profile_hash,
)
from aivara.drift.schemas import (
    ComparisonBoundaryResult,
    DatasetDriftProfile,
    FeatureDriftProfile,
    FeatureSchemaDescriptor,
    LabelDriftProfile,
    PopulationSelector,
    StatisticalAnalysisConfig,
    StatisticalAnalysisResult,
)


@pytest.fixture
def setup_boundary_and_engine() -> Tuple[ComparisonBoundaryResult, StatisticalDriftEngine, FeatureDatasetDriftAnalyzer]:
    """Construct a valid ComparisonBoundaryResult, StatisticalDriftEngine, and FeatureDatasetDriftAnalyzer."""
    engine_boundary = ComparisonBoundaryEngine(min_sample_size=30, max_sample_budget=5000)
    ref_selector = PopulationSelector(dataset_id="ds_ref_01")
    target_selector = PopulationSelector(dataset_id="ds_target_01")

    ref_samples = [{"id": f"s_ref_{i:04d}", "split": "train"} for i in range(100)]
    target_samples = [{"id": f"s_tgt_{i:04d}", "split": "val"} for i in range(100)]

    feature_schema = FeatureSchemaDescriptor(
        feature_names=["f1", "f2", "f3"],
        dimensions=3,
    )

    boundary = engine_boundary.establish_boundary(
        project_id="proj_alpha",
        reference_selector=ref_selector,
        reference_samples=ref_samples,
        reference_project_id="proj_alpha",
        target_selector=target_selector,
        target_samples=target_samples,
        target_project_id="proj_alpha",
        modality=DataModality.TABULAR_FEATURE,
        feature_descriptor=feature_schema,
        target_feature_descriptor=feature_schema,
    )

    stat_engine = StatisticalDriftEngine()
    analyzer = FeatureDatasetDriftAnalyzer()
    return boundary, stat_engine, analyzer


# ---------------------------------------------------------------------------
# 1. Numerical Feature Drift Localization & Ranking
# ---------------------------------------------------------------------------

def test_no_numerical_drift_feature_profile(setup_boundary_and_engine):
    """Test identical features produce NO_SHIFT_DETECTED with NEGLIGIBLE impact."""
    boundary, stat_engine, analyzer = setup_boundary_and_engine
    rng = np.random.RandomState(42)
    data = rng.normal(0, 1, 100).tolist()

    stat_res = stat_engine.evaluate_boundary(
        boundary_result=boundary,
        reference_features={"f1": data, "f2": data},
        target_features={"f1": data, "f2": data},
    )

    profile = analyzer.analyze(boundary_result=boundary, statistical_result=stat_res)

    assert profile.global_status == ShiftDecisionState.NO_SHIFT_DETECTED
    assert profile.total_features_evaluated == 2
    assert profile.total_numerical_features == 2
    assert profile.materially_shifted_feature_count == 0
    assert len(profile.affected_numerical_features) == 0

    p_f1 = profile.all_feature_profiles["f1"]
    assert p_f1.feature_name == "f1"
    assert p_f1.feature_type == FeatureType.NUMERICAL
    assert p_f1.category == FeatureDriftCategory.COVARIATE_NUMERICAL
    assert p_f1.shift_status == ShiftDecisionState.NO_SHIFT_DETECTED
    assert p_f1.impact_level == DriftImpactLevel.NEGLIGIBLE


def test_material_numerical_drift_feature_profile(setup_boundary_and_engine):
    """Test shifted features produce MATERIAL_SHIFT with HIGH/MEDIUM impact."""
    boundary, stat_engine, analyzer = setup_boundary_and_engine
    rng = np.random.RandomState(42)
    ref_data = rng.normal(0, 1, 100).tolist()
    target_data = rng.normal(3, 1, 100).tolist()

    stat_res = stat_engine.evaluate_boundary(
        boundary_result=boundary,
        reference_features={"f1": ref_data, "f2": ref_data},
        target_features={"f1": target_data, "f2": ref_data},
    )

    profile = analyzer.analyze(boundary_result=boundary, statistical_result=stat_res)

    assert profile.global_status == ShiftDecisionState.MATERIAL_SHIFT
    assert profile.total_features_evaluated == 2
    assert profile.materially_shifted_feature_count == 1
    assert profile.affected_numerical_features == ["f1"]

    p_f1 = profile.all_feature_profiles["f1"]
    assert p_f1.shift_status == ShiftDecisionState.MATERIAL_SHIFT
    assert p_f1.impact_level in {DriftImpactLevel.HIGH, DriftImpactLevel.MEDIUM}
    assert p_f1.rank == 1

    p_f2 = profile.all_feature_profiles["f2"]
    assert p_f2.shift_status == ShiftDecisionState.NO_SHIFT_DETECTED
    assert p_f2.rank == 2


def test_deterministic_feature_ranking(setup_boundary_and_engine):
    """Test that multiple features are deterministically ranked by severity and effect size."""
    boundary, stat_engine, analyzer = setup_boundary_and_engine
    rng = np.random.RandomState(42)
    ref = rng.normal(0, 1, 100).tolist()
    # f_large has large shift (mean=4), f_med has medium shift (mean=1.5), f_none has no shift (mean=0)
    target_large = rng.normal(4, 1, 100).tolist()
    target_med = rng.normal(1.5, 1, 100).tolist()
    target_none = rng.normal(0, 1, 100).tolist()

    stat_res = stat_engine.evaluate_boundary(
        boundary_result=boundary,
        reference_features={"f_large": ref, "f_med": ref, "f_none": ref},
        target_features={"f_large": target_large, "f_med": target_med, "f_none": target_none},
    )

    profile = analyzer.analyze(boundary_result=boundary, statistical_result=stat_res)

    assert profile.all_feature_profiles["f_large"].rank == 1
    assert profile.all_feature_profiles["f_med"].rank == 2
    assert profile.all_feature_profiles["f_none"].rank == 3


# ---------------------------------------------------------------------------
# 2. Categorical & Label Distribution Localization
# ---------------------------------------------------------------------------

def test_label_drift_profile_with_imbalance(setup_boundary_and_engine):
    """Test label distribution shift localization including class imbalance detection."""
    boundary, stat_engine, analyzer = setup_boundary_and_engine
    ref_labels = ["cat"] * 50 + ["dog"] * 50
    # Imbalanced target: 95 cat vs 5 dog
    target_labels = ["cat"] * 95 + ["dog"] * 5

    stat_res = stat_engine.evaluate_boundary(
        boundary_result=boundary,
        reference_labels=ref_labels,
        target_labels=target_labels,
    )

    profile = analyzer.analyze(boundary_result=boundary, statistical_result=stat_res)

    assert profile.label_drift_profile is not None
    label_prof = profile.label_drift_profile
    assert label_prof.attribute_name == "class_labels"
    assert label_prof.tvd > 0.40
    assert label_prof.shift_status == ShiftDecisionState.MATERIAL_SHIFT
    assert label_prof.is_imbalanced is True
    assert label_prof.imbalance_ratio >= 10.0


def test_label_drift_unseen_and_missing_classes(setup_boundary_and_engine):
    """Test label distribution profile detects unseen and missing classes."""
    boundary, stat_engine, analyzer = setup_boundary_and_engine
    ref_labels = ["cat"] * 50 + ["dog"] * 50
    target_labels = ["dog"] * 50 + ["bird"] * 50

    stat_res = stat_engine.evaluate_boundary(
        boundary_result=boundary,
        reference_labels=ref_labels,
        target_labels=target_labels,
    )

    profile = analyzer.analyze(boundary_result=boundary, statistical_result=stat_res)

    assert profile.label_drift_profile is not None
    label_prof = profile.label_drift_profile
    assert label_prof.unseen_classes == ["bird"]
    assert label_prof.missing_classes == ["cat"]
    assert label_prof.impact_level in {DriftImpactLevel.HIGH, DriftImpactLevel.CRITICAL}


# ---------------------------------------------------------------------------
# 3. Dataset-Level Synthesis & Invariant Reconciliation
# ---------------------------------------------------------------------------

def test_dataset_synthesis_reconciliation(setup_boundary_and_engine):
    """Verify total counts, affected dimensions, and untestable features reconcile consistently."""
    boundary, stat_engine, analyzer = setup_boundary_and_engine
    rng = np.random.RandomState(42)
    ref = rng.normal(0, 1, 100).tolist()
    target = rng.normal(2, 1, 100).tolist()

    stat_res = stat_engine.evaluate_boundary(
        boundary_result=boundary,
        reference_features={"num_f1": ref, "num_f2": ref},
        target_features={"num_f1": target, "num_f2": ref},
        reference_labels=["c1"] * 50 + ["c2"] * 50,
        target_labels=["c1"] * 50 + ["c2"] * 50,
    )

    profile = analyzer.analyze(
        boundary_result=boundary,
        statistical_result=stat_res,
        untestable_features=["untestable_dim_01"],
    )

    assert profile.total_numerical_features == 2
    assert profile.total_categorical_features == 1
    assert profile.total_features_evaluated == 3
    assert profile.untestable_feature_count == 1
    assert profile.untestable_features == ["untestable_dim_01"]
    assert profile.materially_shifted_feature_count == 1
    assert profile.affected_numerical_features == ["num_f1"]


# ---------------------------------------------------------------------------
# 4. Fail-Closed & Integrity Invariants
# ---------------------------------------------------------------------------

def test_boundary_hash_mismatch_raises_error(setup_boundary_and_engine):
    """Test that boundary hash divergence between boundary and stats raises DistributionBoundaryError."""
    boundary, stat_engine, analyzer = setup_boundary_and_engine
    rng = np.random.RandomState(42)
    data = rng.normal(0, 1, 100).tolist()

    stat_res = stat_engine.evaluate_boundary(
        boundary_result=boundary,
        reference_features={"f1": data},
        target_features={"f1": data},
    )

    # Mutate boundary hash on stat_res
    tampered_stat_res = stat_res.model_copy(update={"comparison_boundary_hash": "a" * 64})

    with pytest.raises(DistributionBoundaryError, match="Boundary hash mismatch"):
        analyzer.analyze(boundary_result=boundary, statistical_result=tampered_stat_res)


def test_insufficient_data_returns_fail_closed_profile(setup_boundary_and_engine):
    """Test that INSUFFICIENT_DATA statistical result returns fail-closed DatasetDriftProfile."""
    boundary, stat_engine, analyzer = setup_boundary_and_engine
    
    # Create empty fail-closed stat_res
    stat_res = StatisticalAnalysisResult(
        schema_version="1.0",
        analysis_version="1.0",
        comparison_boundary_hash=boundary.comparison_boundary_hash,
        analysis_result_hash="0" * 64,
        config=StatisticalAnalysisConfig(),
        global_status=ShiftDecisionState.INSUFFICIENT_DATA,
        total_features_tested=0,
        statistically_significant_count=0,
        materially_shifted_count=0,
    )

    profile = analyzer.analyze(boundary_result=boundary, statistical_result=stat_res)
    assert profile.global_status == ShiftDecisionState.INSUFFICIENT_DATA
    assert profile.total_features_evaluated == 0
    assert len(profile.findings) == 0


# ---------------------------------------------------------------------------
# 5. Determinism & Cryptographic Identity
# ---------------------------------------------------------------------------

def test_deterministic_profile_hash_and_sensitivity(setup_boundary_and_engine):
    """Verify that dataset_drift_profile_hash is deterministic and sensitive to mutations."""
    boundary, stat_engine, analyzer = setup_boundary_and_engine
    rng = np.random.RandomState(42)
    ref = rng.normal(0, 1, 100).tolist()
    target = rng.normal(1, 1, 100).tolist()

    stat_res = stat_engine.evaluate_boundary(
        boundary_result=boundary,
        reference_features={"f1": ref},
        target_features={"f1": target},
    )

    prof1 = analyzer.analyze(boundary_result=boundary, statistical_result=stat_res)
    prof2 = analyzer.analyze(boundary_result=boundary, statistical_result=stat_res)

    assert prof1.dataset_drift_profile_hash == prof2.dataset_drift_profile_hash
    assert len(prof1.dataset_drift_profile_hash) == 64

    # Sensitivity test
    desc1 = prof1.to_canonical_dict()
    desc2 = dict(desc1)
    desc2["materially_shifted_feature_count"] = desc1["materially_shifted_feature_count"] + 1
    assert compute_dataset_drift_profile_hash(desc1) != compute_dataset_drift_profile_hash(desc2)


# ---------------------------------------------------------------------------
# 6. Finding & Evidence Synthesis
# ---------------------------------------------------------------------------

def test_finding_and_evidence_integration(setup_boundary_and_engine):
    """Verify FindingModel and EvidenceModel records adhere to detection layer requirements."""
    boundary, stat_engine, analyzer = setup_boundary_and_engine
    rng = np.random.RandomState(42)
    ref = rng.normal(0, 1, 100).tolist()
    target = rng.normal(2, 1, 100).tolist()

    stat_res = stat_engine.evaluate_boundary(
        boundary_result=boundary,
        reference_features={"f1": ref},
        target_features={"f1": target},
    )

    profile = analyzer.analyze(boundary_result=boundary, statistical_result=stat_res)

    assert len(profile.findings) == 1
    finding = profile.findings[0]
    assert finding["evidence_layer"] == "detection"
    assert finding["finding_type"] == "feature_dataset_drift"
    assert finding["severity"] == "high"
    assert finding["disposition"] == "review"
    assert "compromise" in finding["recommendation"].lower()

    assert len(profile.evidence_records) == 1
    evidence = profile.evidence_records[0]
    assert evidence["evidence_layer"] == "detection"
    assert evidence["evidence_type"] == "feature_dataset_drift_evidence"
    assert len(evidence["evidence_hash"]) == 64


# ---------------------------------------------------------------------------
# 7. Immutability & Security AST Scan
# ---------------------------------------------------------------------------

def test_input_immutability(setup_boundary_and_engine):
    """Verify input boundary and statistical results are not mutated."""
    boundary, stat_engine, analyzer = setup_boundary_and_engine
    rng = np.random.RandomState(42)
    ref = rng.normal(0, 1, 100).tolist()
    target = rng.normal(2, 1, 100).tolist()

    stat_res = stat_engine.evaluate_boundary(
        boundary_result=boundary,
        reference_features={"f1": ref},
        target_features={"f1": target},
    )

    boundary_hash_before = boundary.comparison_boundary_hash
    stat_hash_before = stat_res.analysis_result_hash

    profile = analyzer.analyze(boundary_result=boundary, statistical_result=stat_res)

    assert boundary.comparison_boundary_hash == boundary_hash_before
    assert stat_res.analysis_result_hash == stat_hash_before
    assert profile.comparison_boundary_hash == boundary_hash_before
    assert profile.statistical_analysis_hash == stat_hash_before


def test_security_ast_scan_drift_package():
    """Verify drift package contains zero eval, exec, pickle, subprocess, os.system, or shell=True."""
    drift_dir = Path(__file__).resolve().parent.parent / "backend" / "aivara" / "drift"
    py_files = list(drift_dir.glob("*.py"))
    assert len(py_files) >= 8

    for file_path in py_files:
        tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in {"eval", "exec"}, f"Forbidden call {node.func.id} in {file_path}"
                elif isinstance(node.func, ast.Attribute):
                    assert node.func.attr not in {"system", "popen", "spawn"}, f"Forbidden method {node.func.attr} in {file_path}"


# ---------------------------------------------------------------------------
# 8. Additional Edge Cases & Granular Localization
# ---------------------------------------------------------------------------

def test_significant_but_non_material_dataset_shift(setup_boundary_and_engine):
    """Test that significant but practically negligible drift yields SIGNIFICANT_SHIFT with LOW impact."""
    boundary, stat_engine, analyzer = setup_boundary_and_engine
    rng = np.random.RandomState(42)
    # Large N = 4000
    ref_data = rng.normal(0.0, 1.0, 4000).tolist()
    target_data = rng.normal(0.11, 1.0, 4000).tolist()

    engine_boundary = ComparisonBoundaryEngine(min_sample_size=30, max_sample_budget=5000)
    ref_selector = PopulationSelector(dataset_id="ds_ref_large")
    target_selector = PopulationSelector(dataset_id="ds_target_large")
    ref_samples = [{"id": f"s_ref_{i}"} for i in range(4000)]
    target_samples = [{"id": f"s_tgt_{i}"} for i in range(4000)]
    feature_schema = FeatureSchemaDescriptor(feature_names=["f1"], dimensions=1)

    large_boundary = engine_boundary.establish_boundary(
        project_id="proj_alpha",
        reference_selector=ref_selector,
        reference_samples=ref_samples,
        reference_project_id="proj_alpha",
        target_selector=target_selector,
        target_samples=target_samples,
        target_project_id="proj_alpha",
        modality=DataModality.TABULAR_FEATURE,
        feature_descriptor=feature_schema,
        target_feature_descriptor=feature_schema,
    )

    stat_res = stat_engine.evaluate_boundary(
        boundary_result=large_boundary,
        reference_features={"f1": ref_data},
        target_features={"f1": target_data},
    )

    profile = analyzer.analyze(boundary_result=large_boundary, statistical_result=stat_res)

    assert profile.global_status == ShiftDecisionState.SIGNIFICANT_SHIFT
    assert profile.materially_shifted_feature_count == 0
    assert profile.statistically_significant_feature_count == 1
    p_f1 = profile.all_feature_profiles["f1"]
    assert p_f1.shift_status == ShiftDecisionState.SIGNIFICANT_SHIFT
    assert p_f1.impact_level == DriftImpactLevel.LOW


def test_mixed_numerical_and_categorical_drift(setup_boundary_and_engine):
    """Test dataset containing both numerical features and custom categorical features."""
    boundary, stat_engine, analyzer = setup_boundary_and_engine
    rng = np.random.RandomState(42)
    ref_num = rng.normal(0, 1, 100).tolist()
    target_num = rng.normal(3, 1, 100).tolist()

    stat_res = stat_engine.evaluate_boundary(
        boundary_result=boundary,
        reference_features={"f_num": ref_num},
        target_features={"f_num": target_num},
        reference_labels=["cat"] * 50 + ["dog"] * 50,
        target_labels=["cat"] * 20 + ["dog"] * 80,
    )

    profile = analyzer.analyze(boundary_result=boundary, statistical_result=stat_res)

    assert profile.total_numerical_features == 1
    assert profile.total_categorical_features == 1
    assert profile.total_features_evaluated == 2
    assert profile.materially_shifted_feature_count == 2
    assert profile.global_status == ShiftDecisionState.MATERIAL_SHIFT


def test_feature_type_overrides(setup_boundary_and_engine):
    """Test feature type overrides mapping correctly."""
    boundary, stat_engine, analyzer = setup_boundary_and_engine
    rng = np.random.RandomState(42)
    data = rng.normal(0, 1, 100).tolist()

    stat_res = stat_engine.evaluate_boundary(
        boundary_result=boundary,
        reference_features={"f_emb": data},
        target_features={"f_emb": data},
    )

    profile = analyzer.analyze(
        boundary_result=boundary,
        statistical_result=stat_res,
        feature_type_overrides={"f_emb": FeatureType.EMBEDDING},
    )

    assert profile.all_feature_profiles["f_emb"].feature_type == FeatureType.EMBEDDING


def test_dataset_profile_ranks_monotonic(setup_boundary_and_engine):
    """Verify ranks in top_shifted_features and all_feature_profiles are strictly monotonic."""
    boundary, stat_engine, analyzer = setup_boundary_and_engine
    rng = np.random.RandomState(42)
    ref = rng.normal(0, 1, 100).tolist()

    feats_ref = {f"f_{i}": ref for i in range(10)}
    feats_tgt = {f"f_{i}": rng.normal(i * 0.5, 1, 100).tolist() for i in range(10)}

    stat_res = stat_engine.evaluate_boundary(
        boundary_result=boundary,
        reference_features=feats_ref,
        target_features=feats_tgt,
    )

    profile = analyzer.analyze(boundary_result=boundary, statistical_result=stat_res)

    ranks = [p.rank for p in profile.top_shifted_features]
    assert ranks == sorted(ranks)
    assert len(set(ranks)) == len(ranks)

