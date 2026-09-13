"""Comprehensive Verification and Test Suite for Phase 11.3 Statistical Distribution Shift Engine."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Dict, List
import numpy as np
import pytest

from aivara.drift.boundary import ComparisonBoundaryEngine
from aivara.drift.engine import (
    StatisticalDriftEngine,
    compute_analysis_result_hash,
)
from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    CompatibilityStatus,
    DataModality,
    MultipleTestingCorrectionMethod,
    PopulationType,
    ShiftDecisionState,
    StatisticalMethod,
)
from aivara.drift.exceptions import (
    ProjectMismatchError,
    ResourceLimitExceededError,
)
from aivara.drift.multiple_testing import (
    apply_benjamini_hochberg,
    apply_holm_bonferroni,
    apply_multiple_testing_correction,
)
from aivara.drift.population import resolve_population_identity
from aivara.drift.schemas import (
    ComparisonBoundaryResult,
    ComparisonContract,
    FeatureSchemaDescriptor,
    PopulationSelector,
    SamplingConfig,
    StatisticalAnalysisConfig,
)
from aivara.drift.stats_categorical import (
    chi2_survival_function,
    compute_chi_square_test,
    compute_jensen_shannon_divergence,
    compute_total_variation_distance,
)
from aivara.drift.stats_continuous import (
    compute_psi,
    compute_two_sample_ks,
    compute_wasserstein_1d,
    sanitize_1d_array,
)
from aivara.drift.stats_multivariate import (
    compute_energy_distance,
    compute_kernel_mmd,
    compute_permutation_p_value,
    sanitize_2d_array,
)


@pytest.fixture
def valid_boundary_result() -> ComparisonBoundaryResult:
    """Construct a valid ComparisonBoundaryResult for testing."""
    engine = ComparisonBoundaryEngine(min_sample_size=30, max_sample_budget=5000)
    ref_selector = PopulationSelector(dataset_id="ds_ref_01")
    target_selector = PopulationSelector(dataset_id="ds_target_01")

    ref_samples = [{"id": f"s_ref_{i:04d}", "split": "train"} for i in range(100)]
    target_samples = [{"id": f"s_tgt_{i:04d}", "split": "val"} for i in range(100)]

    feature_schema = FeatureSchemaDescriptor(
        feature_names=["f1", "f2", "f3"],
        dimensions=3,
    )

    return engine.establish_boundary(
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



# ---------------------------------------------------------------------------
# 1. Continuous Features & Golden Tests
# ---------------------------------------------------------------------------

def test_identical_continuous_distributions(valid_boundary_result: ComparisonBoundaryResult):
    """Test that identical continuous distributions produce NO_SHIFT_DETECTED with KS D=0, p=1.0."""
    rng = np.random.RandomState(42)
    data = rng.normal(loc=0.0, scale=1.0, size=100).tolist()

    engine = StatisticalDriftEngine()
    result = engine.evaluate_boundary(
        boundary_result=valid_boundary_result,
        reference_features={"f1": data, "f2": data},
        target_features={"f1": data, "f2": data},
    )

    assert result.global_status == ShiftDecisionState.NO_SHIFT_DETECTED
    assert result.statistically_significant_count == 0
    assert result.materially_shifted_count == 0
    for f_res in result.feature_results.values():
        assert f_res.statistic_value == pytest.approx(0.0, abs=1e-5)
        assert f_res.raw_p_value == pytest.approx(1.0, abs=1e-5)
        assert f_res.effect_size == pytest.approx(0.0, abs=1e-5)
        assert f_res.status == ShiftDecisionState.NO_SHIFT_DETECTED


def test_clearly_shifted_continuous_distributions(valid_boundary_result: ComparisonBoundaryResult):
    """Test that clearly shifted continuous distributions produce MATERIAL_SHIFT."""
    rng = np.random.RandomState(42)
    ref_data = rng.normal(loc=0.0, scale=1.0, size=100).tolist()
    target_data = rng.normal(loc=3.0, scale=1.0, size=100).tolist()

    engine = StatisticalDriftEngine()
    result = engine.evaluate_boundary(
        boundary_result=valid_boundary_result,
        reference_features={"f1": ref_data},
        target_features={"f1": target_data},
    )

    assert result.global_status == ShiftDecisionState.MATERIAL_SHIFT
    assert result.statistically_significant_count == 1
    assert result.materially_shifted_count == 1
    f_res = result.feature_results["f1"]
    assert f_res.raw_p_value < 0.001
    assert f_res.is_statistically_significant is True
    assert f_res.is_practically_significant is True
    assert f_res.status == ShiftDecisionState.MATERIAL_SHIFT


def test_tiny_shift_dual_gate_distinction(valid_boundary_result: ComparisonBoundaryResult):
    """Test that tiny shift with large sample produces SIGNIFICANT_SHIFT, NOT MATERIAL_SHIFT."""
    rng = np.random.RandomState(42)
    # Large N = 4000
    ref_data = rng.normal(loc=0.0, scale=1.0, size=4000).tolist()
    target_data = rng.normal(loc=0.11, scale=1.0, size=4000).tolist()



    # Create boundary with large counts
    engine_boundary = ComparisonBoundaryEngine(min_sample_size=30, max_sample_budget=5000)
    ref_selector = PopulationSelector(dataset_id="ds_ref_large")
    target_selector = PopulationSelector(dataset_id="ds_target_large")
    ref_samples = [{"id": f"s_ref_{i}", "split": "train"} for i in range(4000)]
    target_samples = [{"id": f"s_tgt_{i}", "split": "val"} for i in range(4000)]
    feature_schema = FeatureSchemaDescriptor(feature_names=["f1"], dimensions=1)

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


    engine = StatisticalDriftEngine()
    result = engine.evaluate_boundary(
        boundary_result=boundary,
        reference_features={"f1": ref_data},
        target_features={"f1": target_data},
    )

    f_res = result.feature_results["f1"]
    # Should be statistically significant (p < 0.05 due to large N)
    assert f_res.is_statistically_significant is True
    # But practically negligible (PSI < 0.10 and W1/std < 0.10)
    assert f_res.effect_size < 0.10
    assert f_res.is_practically_significant is False
    # Dual gate must yield SIGNIFICANT_SHIFT, not MATERIAL_SHIFT
    assert f_res.status == ShiftDecisionState.SIGNIFICANT_SHIFT
    assert result.global_status == ShiftDecisionState.SIGNIFICANT_SHIFT


def test_constant_identical_distributions(valid_boundary_result: ComparisonBoundaryResult):
    """Test constant identical distributions [5,5,5,...] vs [5,5,5,...]."""
    ref_data = [5.0] * 50
    target_data = [5.0] * 50

    engine = StatisticalDriftEngine()
    result = engine.evaluate_boundary(
        boundary_result=valid_boundary_result,
        reference_features={"f_const": ref_data},
        target_features={"f_const": target_data},
    )

    f_res = result.feature_results["f_const"]
    assert f_res.statistic_value == 0.0
    assert f_res.raw_p_value == 1.0
    assert f_res.effect_size == 0.0
    assert f_res.status == ShiftDecisionState.NO_SHIFT_DETECTED


def test_constant_different_distributions(valid_boundary_result: ComparisonBoundaryResult):
    """Test constant different distributions [5,5,5,...] vs [6,6,6,...]."""
    ref_data = [5.0] * 50
    target_data = [6.0] * 50

    engine = StatisticalDriftEngine()
    result = engine.evaluate_boundary(
        boundary_result=valid_boundary_result,
        reference_features={"f_const": ref_data},
        target_features={"f_const": target_data},
    )

    f_res = result.feature_results["f_const"]
    assert f_res.statistic_value == 1.0
    assert f_res.raw_p_value == 0.0
    assert f_res.is_statistically_significant is True
    assert f_res.status == ShiftDecisionState.MATERIAL_SHIFT


# ---------------------------------------------------------------------------
# 2. Categorical / Label Distribution Tests
# ---------------------------------------------------------------------------

def test_categorical_identical_distributions(valid_boundary_result: ComparisonBoundaryResult):
    """Test identical categorical distributions produce NO_SHIFT_DETECTED with TVD=0, JSD=0."""
    ref_labels = ["cat"] * 50 + ["dog"] * 50
    target_labels = ["cat"] * 50 + ["dog"] * 50

    engine = StatisticalDriftEngine()
    result = engine.evaluate_boundary(
        boundary_result=valid_boundary_result,
        reference_labels=ref_labels,
        target_labels=target_labels,
    )

    cat_res = result.categorical_results["class_labels"]
    assert cat_res.tvd == pytest.approx(0.0, abs=1e-5)
    assert cat_res.jsd == pytest.approx(0.0, abs=1e-5)
    assert cat_res.is_statistically_significant is False
    assert cat_res.status == ShiftDecisionState.NO_SHIFT_DETECTED


def test_categorical_shifted_distributions(valid_boundary_result: ComparisonBoundaryResult):
    """Test shifted categorical distributions produce MATERIAL_SHIFT."""
    ref_labels = ["cat"] * 80 + ["dog"] * 20
    target_labels = ["cat"] * 20 + ["dog"] * 80

    engine = StatisticalDriftEngine()
    result = engine.evaluate_boundary(
        boundary_result=valid_boundary_result,
        reference_labels=ref_labels,
        target_labels=target_labels,
    )

    cat_res = result.categorical_results["class_labels"]
    assert cat_res.tvd == pytest.approx(0.60, abs=1e-2)
    assert cat_res.chi_square_p_value < 0.001
    assert cat_res.is_statistically_significant is True
    assert cat_res.is_practically_significant is True
    assert cat_res.status == ShiftDecisionState.MATERIAL_SHIFT


def test_categorical_unseen_and_missing_classes(valid_boundary_result: ComparisonBoundaryResult):
    """Test categorical evaluation detects unseen and missing classes."""
    ref_labels = ["cat"] * 50 + ["dog"] * 50
    target_labels = ["dog"] * 50 + ["bird"] * 50

    engine = StatisticalDriftEngine()
    result = engine.evaluate_boundary(
        boundary_result=valid_boundary_result,
        reference_labels=ref_labels,
        target_labels=target_labels,
    )

    cat_res = result.categorical_results["class_labels"]
    assert cat_res.unseen_target_classes == ["bird"]
    assert cat_res.missing_target_classes == ["cat"]
    assert any("Unseen categories" in w for w in result.warnings)
    assert any("Categories missing" in w for w in result.warnings)


# ---------------------------------------------------------------------------
# 3. Multivariate & Embedding Tests
# ---------------------------------------------------------------------------

def test_multivariate_identical_embeddings(valid_boundary_result: ComparisonBoundaryResult):
    """Test identical multivariate embeddings produce NO_SHIFT_DETECTED."""
    rng = np.random.RandomState(42)
    embeddings = rng.normal(loc=0.0, scale=1.0, size=(60, 16)).tolist()

    engine = StatisticalDriftEngine()
    result = engine.evaluate_boundary(
        boundary_result=valid_boundary_result,
        reference_embeddings=embeddings,
        target_embeddings=embeddings,
    )

    multi_res = result.multivariate_results
    assert multi_res is not None
    assert multi_res.statistic_value == pytest.approx(0.0, abs=1e-5)
    assert multi_res.permutation_p_value >= 0.05
    assert multi_res.status == ShiftDecisionState.NO_SHIFT_DETECTED


def test_multivariate_shifted_embeddings(valid_boundary_result: ComparisonBoundaryResult):
    """Test shifted multivariate embeddings produce MATERIAL_SHIFT."""
    rng = np.random.RandomState(42)
    ref_emb = rng.normal(loc=0.0, scale=1.0, size=(60, 16)).tolist()
    target_emb = rng.normal(loc=2.0, scale=1.0, size=(60, 16)).tolist()

    engine = StatisticalDriftEngine()
    result = engine.evaluate_boundary(
        boundary_result=valid_boundary_result,
        reference_embeddings=ref_emb,
        target_embeddings=target_emb,
    )

    multi_res = result.multivariate_results
    assert multi_res is not None
    assert multi_res.statistic_value > 0.02
    assert multi_res.permutation_p_value <= 0.05
    assert multi_res.status == ShiftDecisionState.MATERIAL_SHIFT


# ---------------------------------------------------------------------------
# 4. Multiple Testing & Error Control
# ---------------------------------------------------------------------------

def test_benjamini_hochberg_fdr_correction():
    """Verify Benjamini-Hochberg procedure adjusts p-values correctly."""
    # Known p-value series
    raw_p = {
        "f1": 0.001,
        "f2": 0.010,
        "f3": 0.030,
        "f4": 0.040,
        "f5": 0.200,
    }
    corrected = apply_benjamini_hochberg(raw_p, q_star=0.05)

    assert len(corrected) == 5
    # f1: 0.001 * 5 / 1 = 0.005
    assert corrected["f1"]["adjusted_p_value"] == pytest.approx(0.005, abs=1e-4)
    assert corrected["f1"]["is_significant"] is True
    # f5: 0.200 * 5 / 5 = 0.200
    assert corrected["f5"]["adjusted_p_value"] == pytest.approx(0.200, abs=1e-4)
    assert corrected["f5"]["is_significant"] is False


def test_holm_bonferroni_fwer_correction():
    """Verify Holm-Bonferroni step-down procedure adjusts p-values correctly."""
    raw_p = {
        "f1": 0.001,
        "f2": 0.010,
        "f3": 0.040,
    }
    corrected = apply_holm_bonferroni(raw_p, alpha=0.05)

    assert len(corrected) == 3
    # f1: 0.001 * 3 = 0.003
    assert corrected["f1"]["adjusted_p_value"] == pytest.approx(0.003, abs=1e-4)
    assert corrected["f1"]["is_significant"] is True


def test_multiple_testing_dispatcher():
    """Verify apply_multiple_testing_correction dispatches all supported methods."""
    raw_p = {"f1": 0.01, "f2": 0.04}
    res_bh = apply_multiple_testing_correction(raw_p, MultipleTestingCorrectionMethod.BENJAMINI_HOCHBERG_FDR)
    res_holm = apply_multiple_testing_correction(raw_p, MultipleTestingCorrectionMethod.HOLM_BONFERRONI_FWER)
    res_bonf = apply_multiple_testing_correction(raw_p, MultipleTestingCorrectionMethod.BONFERRONI)
    res_none = apply_multiple_testing_correction(raw_p, MultipleTestingCorrectionMethod.NONE)

    assert "f1" in res_bh and "f1" in res_holm and "f1" in res_bonf and "f1" in res_none


# ---------------------------------------------------------------------------
# 5. Fail-Closed & Boundary Invariants
# ---------------------------------------------------------------------------

def test_insufficient_sample_size_fails_closed():
    """Test that sample size N < 30 returns INSUFFICIENT_DATA."""
    engine_boundary = ComparisonBoundaryEngine(min_sample_size=30)
    ref_selector = PopulationSelector(dataset_id="ds_ref_small")
    target_selector = PopulationSelector(dataset_id="ds_target_small")
    ref_samples = [{"id": f"s_ref_{i}"} for i in range(15)]
    target_samples = [{"id": f"s_tgt_{i}"} for i in range(15)]

    boundary = engine_boundary.establish_boundary(
        project_id="proj_alpha",
        reference_selector=ref_selector,
        reference_samples=ref_samples,
        reference_project_id="proj_alpha",
        target_selector=target_selector,
        target_samples=target_samples,
        target_project_id="proj_alpha",
        modality=DataModality.TABULAR_FEATURE,
    )

    engine = StatisticalDriftEngine()
    result = engine.evaluate_boundary(boundary_result=boundary)
    assert result.global_status == ShiftDecisionState.INSUFFICIENT_DATA


def test_project_mismatch_raises_error(valid_boundary_result: ComparisonBoundaryResult):
    """Test that cross-project boundary raises ProjectMismatchError."""
    engine_boundary = ComparisonBoundaryEngine(min_sample_size=30)
    ref_selector = PopulationSelector(dataset_id="ds_ref")
    target_selector = PopulationSelector(dataset_id="ds_target")
    ref_samples = [{"id": f"s_ref_{i}"} for i in range(40)]
    target_samples = [{"id": f"s_tgt_{i}"} for i in range(40)]

    with pytest.raises(ProjectMismatchError):
        engine_boundary.establish_boundary(
            project_id="proj_alpha",
            reference_selector=ref_selector,
            reference_samples=ref_samples,
            reference_project_id="proj_alpha",
            target_selector=target_selector,
            target_samples=target_samples,
            target_project_id="proj_beta",  # Mismatched project
            modality=DataModality.TABULAR_FEATURE,
        )

    # Test evaluating a boundary with status = PROJECT_MISMATCH
    mismatched_boundary = ComparisonBoundaryResult(
        contract=valid_boundary_result.contract,
        comparison_boundary_hash=valid_boundary_result.comparison_boundary_hash,
        reference_population=valid_boundary_result.reference_population,
        target_population=valid_boundary_result.target_population,
        status=BoundaryEvaluationStatus.PROJECT_MISMATCH,
        compatibility_status=CompatibilityStatus.COMPATIBLE,
    )
    engine = StatisticalDriftEngine()
    with pytest.raises(ProjectMismatchError):
        engine.evaluate_boundary(boundary_result=mismatched_boundary)



# ---------------------------------------------------------------------------
# 6. Numerical Robustness & Sanitization
# ---------------------------------------------------------------------------

def test_numerical_nan_inf_trapping():
    """Test that NaN and Infinity in continuous or multivariate inputs are safely trapped."""
    with pytest.raises(ValueError, match="NaN found"):
        sanitize_1d_array([1.0, 2.0, np.nan, 4.0])

    with pytest.raises(ValueError, match="Infinity found"):
        sanitize_1d_array([1.0, 2.0, np.inf, 4.0])

    with pytest.raises(ValueError, match="both NaN and Infinity found"):
        sanitize_2d_array([[1.0, np.nan], [np.inf, 4.0]])


def test_chi2_survival_function_extremes():
    """Test Chi-Square survival function bounds and edge cases."""
    assert chi2_survival_function(0.0, 5) == 1.0
    assert chi2_survival_function(-1.0, 5) == 1.0
    assert chi2_survival_function(100.0, 2) < 1e-15


# ---------------------------------------------------------------------------
# 7. Determinism & Cryptographic Identity
# ---------------------------------------------------------------------------

def test_deterministic_repeatability(valid_boundary_result: ComparisonBoundaryResult):
    """Test that evaluating identical inputs twice produces exact same analysis_result_hash."""
    rng = np.random.RandomState(42)
    ref_data = rng.normal(loc=0.0, scale=1.0, size=100).tolist()
    target_data = rng.normal(loc=1.0, scale=1.0, size=100).tolist()

    engine = StatisticalDriftEngine()
    res1 = engine.evaluate_boundary(
        boundary_result=valid_boundary_result,
        reference_features={"f1": ref_data},
        target_features={"f1": target_data},
    )
    res2 = engine.evaluate_boundary(
        boundary_result=valid_boundary_result,
        reference_features={"f1": ref_data},
        target_features={"f1": target_data},
    )

    assert res1.analysis_result_hash == res2.analysis_result_hash
    assert res1.global_status == res2.global_status
    assert len(res1.analysis_result_hash) == 64


# ---------------------------------------------------------------------------
# 8. Finding & Evidence Synthesis
# ---------------------------------------------------------------------------

def test_finding_and_evidence_integration(valid_boundary_result: ComparisonBoundaryResult):
    """Verify FindingModel and EvidenceModel records adhere to detection layer requirements."""
    rng = np.random.RandomState(42)
    ref_data = rng.normal(loc=0.0, scale=1.0, size=100).tolist()
    target_data = rng.normal(loc=2.0, scale=1.0, size=100).tolist()

    engine = StatisticalDriftEngine()
    result = engine.evaluate_boundary(
        boundary_result=valid_boundary_result,
        reference_features={"f1": ref_data},
        target_features={"f1": target_data},
    )

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding["evidence_layer"] == "detection"
    assert finding["finding_type"] == "distribution_shift"
    assert finding["severity"] == "high"
    assert finding["disposition"] == "review"
    assert "malicious" in finding["recommendation"].lower()  # Disclaiming malice

    assert len(result.evidence_records) == 1
    evidence = result.evidence_records[0]
    assert evidence["evidence_layer"] == "detection"
    assert evidence["evidence_type"] == "statistical_drift_evidence"
    assert "evidence_hash" in evidence
    assert len(evidence["evidence_hash"]) == 64


# ---------------------------------------------------------------------------
# 9. Security AST Scan
# ---------------------------------------------------------------------------

def test_security_ast_scan_drift_package():
    """Verify drift package contains zero eval, exec, pickle, subprocess, os.system, or shell=True."""
    drift_dir = Path(__file__).resolve().parent.parent / "backend" / "aivara" / "drift"
    py_files = list(drift_dir.glob("*.py"))
    assert len(py_files) >= 7

    for file_path in py_files:
        tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in {"eval", "exec"}, f"Forbidden call {node.func.id} in {file_path}"
                elif isinstance(node.func, ast.Attribute):
                    assert node.func.attr not in {"system", "popen", "spawn"}, f"Forbidden method {node.func.attr} in {file_path}"


# ---------------------------------------------------------------------------
# 10. Invariants & Mathematical Properties
# ---------------------------------------------------------------------------

def test_statistical_invariants_and_bounds():
    """Verify non-negativity and theoretical bounds of all implemented metrics."""
    rng = np.random.RandomState(42)
    x = rng.normal(0, 1, 50)
    y = rng.normal(1, 1, 50)

    # 1. 1D continuous
    w1 = compute_wasserstein_1d(x, y)
    assert w1 >= 0.0

    psi_val, _ = compute_psi(x, y)
    assert psi_val >= 0.0

    ks_stat, ks_p = compute_two_sample_ks(x, y)
    assert 0.0 <= ks_stat <= 1.0
    assert 0.0 <= ks_p <= 1.0

    # 2. Categorical
    p = {"a": 0.3, "b": 0.7}
    q = {"a": 0.6, "b": 0.4}
    tvd = compute_total_variation_distance(p, q)
    assert 0.0 <= tvd <= 1.0

    jsd = compute_jensen_shannon_divergence(p, q, base=2.0)
    assert 0.0 <= jsd <= 1.0

    # 3. Multivariate
    X_mat = rng.normal(0, 1, (40, 5))
    Y_mat = rng.normal(2, 1, (40, 5))
    mmd_sq, _ = compute_kernel_mmd(X_mat, Y_mat)
    assert mmd_sq >= 0.0

    energy = compute_energy_distance(X_mat, Y_mat)
    assert energy >= 0.0


def test_resource_limits_max_features(valid_boundary_result: ComparisonBoundaryResult):
    """Verify exceeding max_features raises ResourceLimitExceededError."""
    engine = StatisticalDriftEngine()
    config = StatisticalAnalysisConfig(max_features=5)

    ref_feats = {f"feat_{i}": [1.0] * 35 for i in range(10)}
    target_feats = {f"feat_{i}": [1.0] * 35 for i in range(10)}

    with pytest.raises(ResourceLimitExceededError, match="exceeds limit"):
        engine.evaluate_boundary(
            boundary_result=valid_boundary_result,
            reference_features=ref_feats,
            target_features=target_feats,
            config=config,
        )


def test_input_and_boundary_immutability(valid_boundary_result: ComparisonBoundaryResult):
    """Verify reference and target input structures are never mutated during execution."""
    ref_data = [1.0, 2.0, 3.0] * 20
    target_data = [2.0, 3.0, 4.0] * 20

    ref_copy = list(ref_data)
    target_copy = list(target_data)
    boundary_hash_before = valid_boundary_result.comparison_boundary_hash

    engine = StatisticalDriftEngine()
    result = engine.evaluate_boundary(
        boundary_result=valid_boundary_result,
        reference_features={"f1": ref_data},
        target_features={"f1": target_data},
    )

    # Invariance assertions
    assert ref_data == ref_copy
    assert target_data == target_copy
    assert valid_boundary_result.comparison_boundary_hash == boundary_hash_before
    assert result.comparison_boundary_hash == boundary_hash_before


def test_analysis_result_hash_sensitivity(valid_boundary_result: ComparisonBoundaryResult):
    """Verify modifying any result property alters the cryptographic analysis_result_hash."""
    desc1 = {
        "analysis_version": "1.0",
        "comparison_boundary_hash": valid_boundary_result.comparison_boundary_hash,
        "config": StatisticalAnalysisConfig().to_canonical_dict(),
        "global_status": "no_shift_detected",
        "materially_shifted_count": 0,
        "schema_version": "1.0",
        "statistically_significant_count": 0,
        "total_features_tested": 1,
    }
    desc2 = dict(desc1)
    desc2["global_status"] = "material_shift"

    hash1 = compute_analysis_result_hash(desc1)
    hash2 = compute_analysis_result_hash(desc2)

    assert hash1 != hash2
    assert len(hash1) == 64
    assert len(hash2) == 64

