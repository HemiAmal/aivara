"""Empirical Bayes shrinkage and statistical uncertainty engine for Contributor Risk (Phase 6).

Implements the frozen Phase 6.1 prior-selection policy (ADR-032):
  - Prior sample weight: M_0 = 20.0
  - Prior mean: mu_0 = p_LOO
  - Shrinkage factor: lambda_c = N_c / (N_c + 20.0)
  - Shrunk posterior rate: p_tilde = lambda_c * p_hat + (1 - lambda_c) * p_LOO
  - Differential: Delta = p_tilde - p_LOO
"""

from __future__ import annotations

import math
from typing import NamedTuple, Optional
from pydantic import BaseModel, ConfigDict, Field

from aivara.contributor_risk.schemas import ContributorRiskConfig, SupportState


class EmpiricalBayesResult(BaseModel):
    """Immutable result of an Empirical Bayes rate shrinkage calculation."""

    model_config = ConfigDict(frozen=True)

    raw_rate: float = Field(..., ge=0.0, le=1.0)
    shrunk_rate: float = Field(..., ge=0.0, le=1.0)
    baseline_rate: float = Field(..., ge=0.0, le=1.0)
    differential: float
    standard_error: float = Field(..., ge=0.0)
    shrinkage_factor: float = Field(..., ge=0.0, le=1.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    support_state: SupportState
    effective_exposure: float = Field(..., ge=0.0)
    effective_count: float = Field(..., ge=0.0)


def determine_support_state(
    effective_exposure: float,
    config: Optional[ContributorRiskConfig] = None,
) -> SupportState:
    """Determine statistical sample support tier based on effective fractional exposure (ADR-032).

    Thresholds:
      - Nc < 3.0: UNVERIFIABLE
      - 3.0 <= Nc < 10.0: LOW_SUPPORT
      - 10.0 <= Nc < 30.0: MODERATE_SUPPORT
      - Nc >= 30.0: ADEQUATE_SUPPORT

    Args:
        effective_exposure: Effective sum of fractional weights (N_c).
        config: Optional configuration override.

    Returns:
        SupportState enum value.
    """
    cfg = config or ContributorRiskConfig()
    n = float(effective_exposure)

    if n < cfg.min_support_threshold:
        return SupportState.UNVERIFIABLE
    if n < cfg.moderate_support_threshold:
        return SupportState.LOW_SUPPORT
    if n < cfg.adequate_support_threshold:
        return SupportState.MODERATE_SUPPORT
    return SupportState.ADEQUATE_SUPPORT


def compute_empirical_bayes_shrinkage(
    effective_count: float,
    total_exposure: float,
    baseline_rate: float,
    prior_weight: float = 20.0,
    baseline_support: float = 100.0,
    config: Optional[ContributorRiskConfig] = None,
) -> EmpiricalBayesResult:
    """Compute deterministic Empirical Bayes posterior rate and differential (ADR-032).

    Args:
        effective_count: Weighted anomaly / event count (k_c = sum w_i * y_i).
        total_exposure: Effective sample volume (N_c = sum w_i).
        baseline_rate: Background comparison baseline rate (p_LOO in [0, 1]).
        prior_weight: Frozen pseudo-count weight M_0 (default 20.0).
        baseline_support: Total sample volume in reference population.
        config: Optional ContributorRiskConfig.

    Returns:
        Structured, immutable EmpiricalBayesResult.
    """
    cfg = config or ContributorRiskConfig()
    m0 = float(prior_weight if prior_weight is not None else cfg.prior_sample_weight_m0)
    n_c = max(0.0, float(total_exposure))
    k_c = max(0.0, float(effective_count))

    # Numerical safety for baseline
    mu_0 = max(0.0, min(1.0, float(baseline_rate)))
    support_state = determine_support_state(n_c, cfg)

    # 1. Raw empirical rate
    if n_c > 0.0:
        raw_p = max(0.0, min(1.0, k_c / n_c))
    else:
        raw_p = mu_0

    # 2. Support state handling: Nc < 3 is UNVERIFIABLE
    if support_state == SupportState.UNVERIFIABLE:
        return EmpiricalBayesResult(
            raw_rate=round(raw_p, 6),
            shrunk_rate=round(mu_0, 6),
            baseline_rate=round(mu_0, 6),
            differential=0.0,
            standard_error=0.0,
            shrinkage_factor=0.0,
            confidence=0.0,
            support_state=support_state,
            effective_exposure=round(n_c, 6),
            effective_count=round(k_c, 6),
        )

    # 3. Shrinkage factor lambda_c = N_c / (N_c + M_0)
    lambda_c = n_c / (n_c + m0)
    lambda_c = max(0.0, min(1.0, lambda_c))

    # 4. Posterior shrunk rate p_tilde = lambda_c * p_hat + (1 - lambda_c) * mu_0
    shrunk_p = (lambda_c * raw_p) + ((1.0 - lambda_c) * mu_0)
    shrunk_p = max(0.0, min(1.0, shrunk_p))

    # 5. Differential Delta = p_tilde - mu_0
    differential = shrunk_p - mu_0

    # 6. Standard error
    n_bg = max(1.0, float(baseline_support))
    var_c = (shrunk_p * (1.0 - shrunk_p)) / max(1.0, n_c + m0)
    var_bg = (mu_0 * (1.0 - mu_0)) / n_bg
    se = math.sqrt(max(0.0, var_c + var_bg))

    # 7. Confidence calculation
    if support_state == SupportState.LOW_SUPPORT:
        # Heavily damped confidence for low support
        conf = min(0.50, (n_c / 10.0) * 0.50)
    elif support_state == SupportState.MODERATE_SUPPORT:
        # Calibrated moderate confidence [0.50, 0.85]
        support_factor = 0.50 + 0.35 * ((n_c - 10.0) / 20.0)
        conf = min(0.85, support_factor)
    else:  # ADEQUATE_SUPPORT
        # Asymptotic convergence toward 1.0 (capped at 0.99 for detection layer)
        conf = min(0.99, 0.85 + 0.14 * (1.0 - math.exp(-0.05 * (n_c - 30.0))))

    return EmpiricalBayesResult(
        raw_rate=round(raw_p, 6),
        shrunk_rate=round(shrunk_p, 6),
        baseline_rate=round(mu_0, 6),
        differential=round(differential, 6),
        standard_error=round(se, 6),
        shrinkage_factor=round(lambda_c, 6),
        confidence=round(conf, 6),
        support_state=support_state,
        effective_exposure=round(n_c, 6),
        effective_count=round(k_c, 6),
    )
