"""Immutable configuration for Multi-Asset and Project Risk Aggregation (Phase 12.9)."""

from __future__ import annotations

import math
from typing import Any, Dict

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aivara.crypto.hashing import hash_canonical_data
from aivara.universal.aggregation.enums import AggregationSchemaVersion, AssetRole
from aivara.universal.aggregation.exceptions import AggregationError


# Bounded Resource Limits for Phase 12.9
MAX_PROJECT_ASSETS: int = 500
MAX_DEPENDENCY_EDGES: int = 2000
MAX_CHAIN_DEPTH: int = 5
MAX_LINEAGE_CHAINS: int = 500


class ImmutableAggregationPolicyConfig(BaseModel):
    """Frozen, cryptographically hashed policy configuration for hierarchical risk aggregation."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=AggregationSchemaVersion.V1_0.value)
    lineage_propagation_factor: float = Field(default=0.25, ge=0.0, le=0.50, description="Gamma propagation factor")
    peak_dominance_exponent: float = Field(default=1.50, ge=1.0, le=3.0, description="Alpha peak dominance exponent")
    inter_asset_damping: float = Field(default=0.10, ge=0.05, le=0.20, description="Lambda inter-asset damping")
    intra_cluster_damping: float = Field(default=0.15, ge=0.0, le=0.50, description="Lambda intra-cluster damping")
    max_traversal_depth: int = Field(default=MAX_CHAIN_DEPTH, ge=1, le=10)
    
    # Role severity weights for project risk synthesis
    role_weights: Dict[str, float] = Field(
        default_factory=lambda: {
            AssetRole.CORE_DEPLOYED.value: 1.0,
            AssetRole.SUPPORTING_INPUT.value: 0.75,
            AssetRole.PERIPHERAL_SAMPLE.value: 0.50,
        }
    )

    config_hash: str = Field(default="", max_length=64)

    @field_validator(
        "lineage_propagation_factor",
        "peak_dominance_exponent",
        "inter_asset_damping",
        "intra_cluster_damping",
    )
    @classmethod
    def validate_finite_floats(cls, v: float, info) -> float:
        if math.isnan(v) or math.isinf(v):
            raise AggregationError(f"Configuration parameter '{info.field_name}' must be finite, got {v}")
        return round(float(v), 6)

    @model_validator(mode="after")
    def compute_config_hash(self) -> ImmutableAggregationPolicyConfig:
        if not self.config_hash:
            canonical_dict = self.to_canonical_dict()
            computed = hash_canonical_data(canonical_dict)
            object.__setattr__(self, "config_hash", computed)
        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "inter_asset_damping": float(self.inter_asset_damping),
            "intra_cluster_damping": float(self.intra_cluster_damping),
            "lineage_propagation_factor": float(self.lineage_propagation_factor),
            "max_traversal_depth": int(self.max_traversal_depth),
            "peak_dominance_exponent": float(self.peak_dominance_exponent),
            "role_weights": {k: float(v) for k, v in sorted(self.role_weights.items())},
            "schema_version": self.schema_version,
        }
