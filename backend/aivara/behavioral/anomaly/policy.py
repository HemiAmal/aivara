"""Centralized, versioned statistical threshold policies for Behavioral Anomaly Detection."""

from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field


class AnomalyThresholdPolicy(BaseModel):
    """Centralized configuration defining statistical behavioral anomaly decision rules."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_version: str = Field("1.0.0", description="Semantic version of the statistical anomaly policy")
    robust_z_threshold: float = Field(
        3.5,
        ge=0.1,
        description="Standardized absolute robust z-score threshold for anomaly classification",
    )
    tail_extremeness_threshold: float = Field(
        0.01,
        ge=0.0,
        le=0.5,
        description="Empirical tail extremeness threshold (values <= threshold are considered extreme)",
    )
    min_support_count: int = Field(
        5,
        ge=1,
        description="Minimum sample count below which results are flagged as INSUFFICIENT_SUPPORT",
    )
    low_support_count: int = Field(
        10,
        ge=1,
        description="Threshold separating LOW_SUPPORT from MODERATE_SUPPORT",
    )
    adequate_support_count: int = Field(
        30,
        ge=1,
        description="Threshold at or above which statistical support is considered ADEQUATE_SUPPORT",
    )
    allow_zero_dispersion_empirical: bool = Field(
        True,
        description="Whether to use empirical comparison when baseline MAD is zero (constant baseline)",
    )
    strict_comparability: bool = Field(
        True,
        description="Whether to enforce strict matching across project, model, provider, and task context",
    )
    custom_metric_thresholds: Dict[str, float] = Field(
        default_factory=dict,
        description="Optional metric-specific robust z-score threshold overrides",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to canonical dictionary format."""
        return {
            "adequate_support_count": self.adequate_support_count,
            "allow_zero_dispersion_empirical": self.allow_zero_dispersion_empirical,
            "custom_metric_thresholds": dict(sorted(self.custom_metric_thresholds.items())),
            "low_support_count": self.low_support_count,
            "min_support_count": self.min_support_count,
            "policy_version": self.policy_version,
            "robust_z_threshold": self.robust_z_threshold,
            "strict_comparability": self.strict_comparability,
            "tail_extremeness_threshold": self.tail_extremeness_threshold,
        }


DEFAULT_ANOMALY_POLICY = AnomalyThresholdPolicy()
