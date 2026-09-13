"""Layer 1: Unit Statistical & Mathematical Correctness Verification.

Covers:
- REQ-11-VERIF-001: Kolmogorov-Smirnov 2-sample test validity
- REQ-11-VERIF-002: Wasserstein-1 Distance metric accuracy
- REQ-11-VERIF-003: Population Stability Index (PSI) calculation with smoothing
- REQ-11-VERIF-004: Categorical Chi-Square & TVD computation
- REQ-11-VERIF-005: Jensen-Shannon Divergence symmetry and boundedness
- REQ-11-VERIF-006: Kernel Maximum Mean Discrepancy (MMD) & Permutation Testing
- REQ-11-VERIF-007: Energy Distance non-negativity & correctness
- REQ-11-VERIF-008: Benjamini-Hochberg FDR multiplicity adjustment
- REQ-11-VERIF-009: Minimum sample size floor enforcement (N >= 30)
- REQ-11-VERIF-010: Maximum sample size ceiling & deterministic subsampling (N <= 5000)
"""

from __future__ import annotations

import math
import numpy as np
import pytest

from aivara.drift.stats_continuous import (
    compute_two_sample_ks,
    compute_wasserstein_1d,
    compute_psi,
)
from aivara.drift.stats_categorical import (
    compute_chi_square_test,
    compute_total_variation_distance,
    compute_jensen_shannon_divergence,
)
from aivara.drift.stats_multivariate import (
    compute_kernel_mmd,
    compute_energy_distance,
    compute_permutation_p_value,
)
from aivara.drift.multiple_testing import (
    apply_benjamini_hochberg,
    apply_holm_bonferroni,
)
from aivara.drift.population import (
    deterministic_subsample,
)
from aivara.drift.boundary import (
    ComparisonBoundaryEngine,
)
from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    DataModality,
    PopulationType,
    SamplingMethod,
)
from aivara.drift.schemas import (
    PopulationSelector,
    SamplingConfig,
)


def test_req_001_ks_2samp_validity() -> None:
    """Verify REQ-11-VERIF-001: KS 2-sample test statistic and p-value bounds."""
    rng = np.random.default_rng(42)
    ref = rng.normal(0, 1, 100)
    stat, p_val = compute_two_sample_ks(ref, ref)
    assert stat == 0.0
    assert p_val == 1.0

    shifted = rng.normal(5, 1, 100)
    stat_shift, p_val_shift = compute_two_sample_ks(ref, shifted)
    assert 0.0 <= stat_shift <= 1.0
    assert stat_shift > 0.8
    assert p_val_shift < 1e-4


def test_req_002_wasserstein_1d_accuracy() -> None:
    """Verify REQ-11-VERIF-002: Wasserstein-1 metric accuracy matching mean shift."""
    rng = np.random.default_rng(42)
    ref = rng.normal(0, 1, 1000)
    tgt = rng.normal(3.0, 1, 1000)
    w1 = compute_wasserstein_1d(ref, tgt)
    assert 2.8 <= w1 <= 3.2
    assert compute_wasserstein_1d(ref, ref) == 0.0


def test_req_003_psi_quantile_smoothing() -> None:
    """Verify REQ-11-VERIF-003: PSI calculation with Laplace smoothing avoiding NaN/Inf."""
    rng = np.random.default_rng(42)
    ref = rng.normal(0, 1, 200)
    tgt_stat = rng.normal(0, 1, 200)
    psi_stat, info_stat = compute_psi(ref, tgt_stat, num_bins=10)
    assert 0.0 <= psi_stat < 0.10

    tgt_shift = rng.normal(5, 1, 200)
    psi_shift, info_shift = compute_psi(ref, tgt_shift, num_bins=10)
    assert psi_shift > 0.25
    assert not math.isnan(psi_shift)
    assert not math.isinf(psi_shift)


def test_req_004_categorical_chi2_tvd() -> None:
    """Verify REQ-11-VERIF-004: Categorical Chi-Square and TVD computation."""
    ref_probs = {"A": 0.50, "B": 0.50}
    tgt_probs_stat = {"A": 0.48, "B": 0.52}
    tvd_stat = compute_total_variation_distance(ref_probs, tgt_probs_stat)
    assert tvd_stat < 0.05

    tgt_probs_shift = {"A": 0.10, "B": 0.90}
    tvd_shift = compute_total_variation_distance(ref_probs, tgt_probs_shift)
    assert abs(tvd_shift - 0.40) < 1e-6

    ref_counts = {"A": 50, "B": 50}
    tgt_counts_shift = {"A": 10, "B": 90}
    chi2_stat, p_val, dof, unseen, missing = compute_chi_square_test(ref_counts, tgt_counts_shift)
    assert chi2_stat > 20.0
    assert p_val < 1e-4
    assert dof == 1


def test_req_005_jsd_symmetry_and_bounds() -> None:
    """Verify REQ-11-VERIF-005: Jensen-Shannon Divergence symmetry and [0, 1] bounds."""
    p_dist = {"A": 0.7, "B": 0.3}
    q_dist = {"A": 0.2, "B": 0.8}
    jsd_pq = compute_jensen_shannon_divergence(p_dist, q_dist)
    jsd_qp = compute_jensen_shannon_divergence(q_dist, p_dist)
    assert 0.0 <= jsd_pq <= 1.0
    assert abs(jsd_pq - jsd_qp) < 1e-9

    p_disjoint = {"A": 1.0}
    q_disjoint = {"B": 1.0}
    assert abs(compute_jensen_shannon_divergence(p_disjoint, q_disjoint) - 1.0) < 1e-6


def test_req_006_kernel_mmd_permutation() -> None:
    """Verify REQ-11-VERIF-006: Kernel MMD with permutation testing."""
    rng = np.random.default_rng(42)
    x = rng.normal(0, 1, size=(40, 10))
    y_stat = rng.normal(0, 1, size=(40, 10))
    y_shift = rng.normal(3.0, 1, size=(40, 10))

    mmd_stat, _ = compute_kernel_mmd(x, y_stat)
    mmd_shift, _ = compute_kernel_mmd(x, y_shift)
    assert mmd_stat < mmd_shift

    def _stat_fn(a: np.ndarray, b: np.ndarray) -> float:
        val, _ = compute_kernel_mmd(a, b)
        return val

    obs, p_perm, _ = compute_permutation_p_value(x, y_shift, stat_fn=_stat_fn, num_permutations=50, seed=42)
    assert 0.0 <= p_perm <= 0.05


def test_req_007_energy_distance_nonnegativity() -> None:
    """Verify REQ-11-VERIF-007: Energy Distance non-negativity and exact zero on identity."""
    rng = np.random.default_rng(42)
    x = rng.normal(0, 1, size=(50, 5))
    y = rng.normal(2.0, 1, size=(50, 5))
    e_same = compute_energy_distance(x, x)
    e_diff = compute_energy_distance(x, y)
    assert abs(e_same) < 1e-9
    assert e_diff > 0.0


def test_req_008_benjamini_hochberg_fdr() -> None:
    """Verify REQ-11-VERIF-008: Benjamini-Hochberg FDR multiplicity adjustment."""
    raw_p_dict = {
        "feat_1": 0.001,
        "feat_2": 0.01,
        "feat_3": 0.04,
        "feat_4": 0.20,
        "feat_5": 0.80,
    }
    res = apply_benjamini_hochberg(raw_p_dict, q_star=0.05)
    assert len(res) == 5
    for feat, data in res.items():
        assert 0.0 <= data["adjusted_p_value"] <= 1.0


def test_req_009_sample_size_floor_enforcement() -> None:
    """Verify REQ-11-VERIF-009: Boundary engine marks INSUFFICIENT_DATA for N < N_min = 30."""
    engine = ComparisonBoundaryEngine(min_sample_size=30)
    ref_samples = [{"id": f"ref_{i}"} for i in range(15)]
    tgt_samples = [{"id": f"tgt_{i}"} for i in range(15)]

    ref_sel = PopulationSelector(dataset_id="ds_ref", population_type=PopulationType.COMPLETE_DATASET)
    tgt_sel = PopulationSelector(dataset_id="ds_tgt", population_type=PopulationType.COMPLETE_DATASET)

    res = engine.establish_boundary(
        project_id="proj_alpha",
        reference_selector=ref_sel,
        reference_samples=ref_samples,
        reference_project_id="proj_alpha",
        target_selector=tgt_sel,
        target_samples=tgt_samples,
        target_project_id="proj_alpha",
        modality=DataModality.IMAGE,
    )
    assert res.status == BoundaryEvaluationStatus.INSUFFICIENT_DATA
    assert any("below minimum threshold" in w for w in res.warnings)


def test_req_010_sample_size_ceiling_and_deterministic_subsampling() -> None:
    """Verify REQ-11-VERIF-010: Enforcement of N_max = 5000 with seed 42."""
    samples = [f"sample_{i}" for i in range(10000)]
    config = SamplingConfig(max_samples=5000, seed=42, method=SamplingMethod.DETERMINISTIC_SEEDED)
    subsampled, applied = deterministic_subsample(samples, config=config)
    assert applied is True
    assert len(subsampled) == 5000

    subsampled_again, _ = deterministic_subsample(samples, config=config)
    assert subsampled == subsampled_again
