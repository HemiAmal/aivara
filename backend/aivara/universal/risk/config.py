"""Immutable Aggregation Configuration and Parameter Governance (Phase 12.4)."""

from __future__ import annotations

import math
from typing import Any, Dict
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aivara.domain.schemas import Severity
from aivara.universal.hashing import (
    compute_canonical_jcs_bytes,
    compute_sha256_digest,
    validate_finite_numerical_data,
)
from aivara.universal.risk.enums import AggregationSchemaVersion
from aivara.universal.risk.exceptions import InvalidPolicyConfigurationError


class ImmutableAggregationConfig(BaseModel):
    """Immutable parameter configuration governing closed-form hierarchical risk math."""
    model_config = ConfigDict(frozen=True)

    config_version: str = Field(default=AggregationSchemaVersion.V1_0.value)
    intra_cluster_damping: float = Field(default=0.15, ge=0.0, le=1.0)
    lineage_propagation_factor: float = Field(default=0.25, ge=0.0, le=0.50)
    peak_dominance_exponent: float = Field(default=1.0, ge=1.0, le=5.0)
    inter_asset_damping: float = Field(default=0.10, ge=0.0, le=0.50)
    severity_multipliers: Dict[str, float] = Field(
        default_factory=lambda: {
            Severity.CRITICAL.value: 1.0,
            Severity.HIGH.value: 0.8,
            Severity.MEDIUM.value: 0.6,
            Severity.LOW.value: 0.4,
            Severity.INFO.value: 0.2,
        }
    )
    config_hash: str = Field(default="", max_length=64)

    @field_validator(
        "intra_cluster_damping",
        "lineage_propagation_factor",
        "peak_dominance_exponent",
        "inter_asset_damping",
    )
    @classmethod
    def validate_finite_scalars(cls, v: float, info) -> float:
        if math.isnan(v) or math.isinf(v):
            raise InvalidPolicyConfigurationError(f"Configuration parameter '{info.field_name}' must be finite.")
        return float(v)

    @field_validator("severity_multipliers")
    @classmethod
    def validate_multipliers(cls, v: Dict[str, float]) -> Dict[str, float]:
        validate_finite_numerical_data(v)
        for k, val in v.items():
            if val < 0.0 or val > 1.0:
                raise InvalidPolicyConfigurationError(f"Severity multiplier for '{k}' must be in [0.0, 1.0], got {val}")
        return v

    @model_validator(mode="after")
    def compute_config_hash(self) -> ImmutableAggregationConfig:
        if not self.config_hash:
            canonical_dict = self.to_canonical_dict()
            computed = compute_sha256_digest(compute_canonical_jcs_bytes(canonical_dict))
            object.__setattr__(self, "config_hash", computed)
        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Produce deterministic sorted dictionary for RFC 8785 JCS canonical hashing."""
        return {
            "config_version": self.config_version,
            "inter_asset_damping": float(self.inter_asset_damping),
            "intra_cluster_damping": float(self.intra_cluster_damping),
            "lineage_propagation_factor": float(self.lineage_propagation_factor),
            "peak_dominance_exponent": float(self.peak_dominance_exponent),
            "severity_multipliers": {
                k: float(v) for k, v in sorted(self.severity_multipliers.items())
            },
        }
