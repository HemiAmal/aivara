"""Deterministic Paired Permutation Testing with NumPy PCG64 (ADR-089).

Implements exact paired permutation hypothesis testing for trigger candidate
success rates against empirical location-shuffled and magnitude-matched noise controls.

Statistical Formulation (Intersection-Union Principle):
- Null Hypothesis: H0: TSR(tau) <= max(TSR(C_shuff), TSR(C_noise))
- Alternative Hypothesis: H1: TSR(tau) > max(TSR(C_shuff), TSR(C_noise))
  which decomposes as H1 = (TSR(tau) > TSR(C_shuff)) AND (TSR(tau) > TSR(C_noise))
- Inferential p-value: p = max(p_shuffled, p_noise)
  where p_shuffled and p_noise are finite-sample exact paired permutation p-values.
- Descriptive Control Baseline: TSR_control = max(TSR(C_shuff), TSR(C_noise))
- Separation: delta_sep = TSR(tau) - TSR_control
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import numpy as np

from aivara.backdoor.statistics.enums import StatisticalSignificanceEnum, StatisticalStatusEnum
from aivara.backdoor.statistics.exceptions import (
    InsufficientSupportError,
    StatisticalComputationError,
)


def evaluate_paired_permutation_test(
    trigger_successes: List[int],
    shuffled_successes: List[int],
    noise_successes: List[int],
    seed: int,
    permutation_count: int = 1000,
    alpha: float = 0.05,
) -> Dict[str, Any]:
    """Execute deterministic paired permutation test against empirical negative controls.
    
    Args:
        trigger_successes: Binary indicators (0/1) for target-matched success under trigger condition.
        shuffled_successes: Binary indicators (0/1) under location-shuffled control.
        noise_successes: Binary indicators (0/1) under magnitude-matched noise control.
        seed: 32-bit unsigned integer derived deterministically from canonical analysis identity.
        permutation_count: Number of permutations B (frozen default = 1000).
        alpha: Significance threshold (frozen default = 0.05).
        
    Returns:
        Dictionary with complete permutation statistics, individual p-values, composite p-value, and control rates.
    """
    n = len(trigger_successes)
    if n != len(shuffled_successes) or n != len(noise_successes):
        raise StatisticalComputationError(
            f"Length mismatch across paired conditions: trigger={n}, shuffled={len(shuffled_successes)}, noise={len(noise_successes)}"
        )
    if permutation_count <= 0 or permutation_count > 100_000:
        raise StatisticalComputationError(f"Permutation count B must be in [1, 100000], got {permutation_count}")
    if alpha <= 0.0 or alpha >= 1.0:
        raise StatisticalComputationError(f"Alpha must be in (0, 1), got {alpha}")

    # Gated support rule: N < 10 returns INSUFFICIENT_SUPPORT
    if n < 10:
        return {
            "status": StatisticalStatusEnum.INSUFFICIENT_SUPPORT,
            "sample_count": n,
            "permutation_count": permutation_count,
            "rng_algorithm": "PCG64",
            "seed": int(seed),
            "raw_tsr_trigger": float(np.mean(trigger_successes)) if n > 0 else None,
            "raw_tsr_shuffled": float(np.mean(shuffled_successes)) if n > 0 else None,
            "raw_tsr_noise": float(np.mean(noise_successes)) if n > 0 else None,
            "control_baseline_tsr": max(float(np.mean(shuffled_successes)), float(np.mean(noise_successes))) if n > 0 else None,
            "sample_envelope_tsr": None,
            "delta_separation": None,
            "t_obs": None,
            "t_obs_shuffled": None,
            "t_obs_noise": None,
            "p_value": None,
            "p_value_shuffled": None,
            "p_value_noise": None,
            "significance": StatisticalSignificanceEnum.NOT_EVALUATED,
        }

    # Convert to strict numpy arrays
    y_trig = np.asarray(trigger_successes, dtype=np.int32)
    y_shuff = np.asarray(shuffled_successes, dtype=np.int32)
    y_noise = np.asarray(noise_successes, dtype=np.int32)

    # Validate binary domain
    for name, arr in [("trigger", y_trig), ("shuffled", y_shuff), ("noise", y_noise)]:
        if not np.all((arr == 0) | (arr == 1)):
            raise StatisticalComputationError(f"Condition '{name}' contains non-binary indicator values.")

    # 1. Descriptive Rates (Candidate-Level)
    tsr_trig = float(np.mean(y_trig))
    tsr_shuff = float(np.mean(y_shuff))
    tsr_noise = float(np.mean(y_noise))
    control_baseline = max(tsr_shuff, tsr_noise)
    delta_sep = tsr_trig - control_baseline

    # Sample-level envelope: c_i = max(shuffled_i, noise_i)
    c_envelope = np.maximum(y_shuff, y_noise)
    sample_envelope_rate = float(np.mean(c_envelope))

    # 2. Paired Differences & Observed Statistics for Each Control
    diff_shuff = y_trig - y_shuff
    t_obs_shuff = float(np.mean(diff_shuff))  # TSR(trigger) - TSR(shuffled)

    diff_noise = y_trig - y_noise
    t_obs_noise = float(np.mean(diff_noise))  # TSR(trigger) - TSR(noise)

    # Descriptive primary observed statistic: delta_sep
    t_obs_primary = delta_sep

    # 3. Synchronized Permutations using Deterministic PCG64
    bit_gen = np.random.PCG64(seed)
    rng = np.random.Generator(bit_gen)

    flips = rng.integers(0, 2, size=(permutation_count, n), dtype=np.int8)
    signs = 1 - 2 * flips  # +1 (unchanged) or -1 (swapped)

    # Permuted statistics under H0_shuff and H0_noise
    t_b_shuff = np.mean(signs * diff_shuff, axis=1)
    t_b_noise = np.mean(signs * diff_noise, axis=1)

    eps = 1e-12
    count_ge_shuff = int(np.sum(t_b_shuff >= (t_obs_shuff - eps)))
    p_val_shuff = float((1 + count_ge_shuff) / (permutation_count + 1))

    count_ge_noise = int(np.sum(t_b_noise >= (t_obs_noise - eps)))
    p_val_noise = float((1 + count_ge_noise) / (permutation_count + 1))

    # 4. Intersection-Union Test (IUT) Combination Rule:
    # H0: TSR(tau) <= max(TSR_shuff, TSR_noise) is rejected at alpha iff
    # BOTH TSR(tau) > TSR_shuff AND TSR(tau) > TSR_noise are rejected at alpha.
    # Therefore, p_composite = max(p_val_shuff, p_val_noise).
    p_composite = max(p_val_shuff, p_val_noise)

    # Significance decision: composite p-value < alpha AND positive separation
    is_sig = (p_composite < alpha) and (delta_sep > 0.0)
    sig_enum = StatisticalSignificanceEnum.SIGNIFICANT if is_sig else StatisticalSignificanceEnum.NOT_SIGNIFICANT

    return {
        "status": StatisticalStatusEnum.COMPLETED,
        "sample_count": n,
        "permutation_count": permutation_count,
        "rng_algorithm": "PCG64",
        "seed": int(seed),
        "raw_tsr_trigger": tsr_trig,
        "raw_tsr_shuffled": tsr_shuff,
        "raw_tsr_noise": tsr_noise,
        "control_baseline_tsr": control_baseline,
        "sample_envelope_tsr": sample_envelope_rate,
        "delta_separation": delta_sep,
        "t_obs": t_obs_primary,
        "t_obs_shuffled": t_obs_shuff,
        "t_obs_noise": t_obs_noise,
        "p_value": p_composite,
        "p_value_shuffled": p_val_shuff,
        "p_value_noise": p_val_noise,
        "significance": sig_enum,
    }
