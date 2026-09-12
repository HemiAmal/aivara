"""Exact Clopper-Pearson 95% Binomial Confidence Intervals (ADR-090).

Implements exact, numerically stable Clopper-Pearson confidence intervals
using regularized incomplete beta functions with continuous continued fractions
and root-finding. Zero external dependencies beyond standard library math.
"""

from __future__ import annotations

import math
from typing import Optional, Tuple

from aivara.backdoor.statistics.exceptions import StatisticalComputationError


def _log_beta(a: float, b: float) -> float:
    """Compute natural logarithm of the Beta function ln(B(a, b))."""
    return math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)


def _betacf(a: float, b: float, x: float, max_iter: int = 200, eps: float = 1e-14) -> float:
    """Evaluate continued fraction for regularized incomplete beta function (Lentz's method)."""
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < eps:
        d = eps
    d = 1.0 / d
    h = d

    for m in range(1, max_iter + 1):
        m2 = 2 * m
        # Even step
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < eps:
            d = eps
        c = 1.0 + aa / c
        if abs(c) < eps:
            c = eps
        d = 1.0 / d
        h *= d * c

        # Odd step
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < eps:
            d = eps
        c = 1.0 + aa / c
        if abs(c) < eps:
            c = eps
        d = 1.0 / d
        del_val = d * c
        h *= del_val

        if abs(del_val - 1.0) <= eps:
            break

    return h


def regularized_incomplete_beta(a: float, b: float, x: float) -> float:
    """Compute regularized incomplete beta function I_x(a, b)."""
    if x < 0.0 or x > 1.0:
        raise StatisticalComputationError(f"x must be in [0, 1], got {x}")
    if x == 0.0:
        return 0.0
    if x == 1.0:
        return 1.0
    if a <= 0.0 or b <= 0.0:
        raise StatisticalComputationError(f"Parameters a, b must be > 0, got a={a}, b={b}")

    # Use symmetry relation if x is greater than (a+1)/(a+b+2)
    if x > (a + 1.0) / (a + b + 2.0):
        return 1.0 - regularized_incomplete_beta(b, a, 1.0 - x)

    # Factors in front of continued fraction
    log_factor = a * math.log(x) + b * math.log(1.0 - x) - _log_beta(a, b) - math.log(a)
    factor = math.exp(log_factor)
    return factor * _betacf(a, b, x)


def beta_quantile(p: float, a: float, b: float, tol: float = 1e-12, max_iter: int = 100) -> float:
    """Compute quantile (inverse) of Beta distribution: find x such that I_x(a, b) = p."""
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 1.0

    # Initial guess using mean / normal approximation
    mean = a / (a + b)
    var = (a * b) / ((a + b) ** 2 * (a + b + 1.0))
    low = 0.0
    high = 1.0
    x = max(0.001, min(0.999, mean))

    for _ in range(max_iter):
        curr_p = regularized_incomplete_beta(a, b, x)
        err = curr_p - p
        if abs(err) < tol:
            return x

        if err > 0:
            high = x
        else:
            low = x

        # Derivative: PDF of Beta(a, b)
        try:
            log_pdf = (a - 1.0) * math.log(x) + (b - 1.0) * math.log(1.0 - x) - _log_beta(a, b)
            pdf = math.exp(log_pdf)
        except (ValueError, OverflowError):
            pdf = 0.0

        # Newton step if derivative is stable, else bisection
        if pdf > 1e-10:
            x_new = x - err / pdf
            if low < x_new < high:
                x = x_new
            else:
                x = 0.5 * (low + high)
        else:
            x = 0.5 * (low + high)

    return x


def clopper_pearson_confidence_interval(
    k: int,
    n: int,
    confidence_level: float = 0.95,
) -> Tuple[Optional[float], Optional[float]]:
    """Compute exact Clopper-Pearson confidence interval for binomial proportion k / n.
    
    Args:
        k: Number of successes (0 <= k <= n).
        n: Total number of trials.
        confidence_level: Desired two-sided confidence level (default 0.95).
        
    Returns:
        (lower_bound, upper_bound) as floats in [0.0, 1.0], or (None, None) if n < 10.
    """
    if n < 0 or k < 0 or k > n:
        raise StatisticalComputationError(f"Invalid trials/successes: k={k}, n={n}")
    if confidence_level <= 0.0 or confidence_level >= 1.0:
        raise StatisticalComputationError(f"Confidence level must be in (0, 1), got {confidence_level}")

    # Gated support rule: N < 10 returns (None, None)
    if n < 10:
        return (None, None)

    alpha = 1.0 - confidence_level

    # Boundary cases
    if k == 0:
        lower = 0.0
        upper = 1.0 - (alpha / 2.0) ** (1.0 / n)
        return (float(max(0.0, min(1.0, lower))), float(max(0.0, min(1.0, upper))))

    if k == n:
        lower = (alpha / 2.0) ** (1.0 / n)
        upper = 1.0
        return (float(max(0.0, min(1.0, lower))), float(max(0.0, min(1.0, upper))))

    # Exact Beta quantiles
    lower = beta_quantile(alpha / 2.0, float(k), float(n - k + 1))
    upper = beta_quantile(1.0 - alpha / 2.0, float(k + 1), float(n - k))

    return (float(max(0.0, min(1.0, lower))), float(max(0.0, min(1.0, upper))))
