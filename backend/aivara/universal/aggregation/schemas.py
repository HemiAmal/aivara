"""Pydantic V2 Schemas for Multi-Asset and Project Risk Aggregation (Phase 12.9)."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aivara.crypto.hashing import hash_canonical_data


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
from aivara.universal.aggregation.enums import (
    AggregationSchemaVersion,
    AssetRole,
    DependencyEdgeType,
)
from aivara.universal.aggregation.exceptions import (
    AggregationError,
    DependencyCycleError,
    InvalidAssetRiskError,
    ScopeMismatchError,
)
from aivara.universal.policy.enums import UniversalDecision
from aivara.universal.risk.enums import EvidenceSufficiencyStatus, RiskLevel
from aivara.universal.risk.schemas import (
    AssetRiskAssessment,
    ChainRiskAssessment,
    HierarchicalRiskAssessment,
    ProjectRiskAssessment,
    RiskContribution,
    compute_risk_level,
)


class AssetDependencyEdge(BaseModel):
    """Immutable directed dependency edge between two assets in the project DAG."""

    model_config = ConfigDict(frozen=True)

    project_id: str = Field(..., min_length=1, max_length=128)
    source_asset_id: str = Field(..., min_length=1, max_length=128)
    target_asset_id: str = Field(..., min_length=1, max_length=128)
    edge_type: DependencyEdgeType = Field(default=DependencyEdgeType.LINEAGE)
    propagation_weight: float = Field(default=1.0, ge=0.0, le=1.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    edge_hash: str = Field(default="", max_length=64)

    @field_validator("propagation_weight")
    @classmethod
    def validate_finite_weight(cls, v: float) -> float:
        if math.isnan(v) or math.isinf(v):
            raise AggregationError(f"Propagation weight must be finite, got {v}")
        return round(float(v), 6)

    @model_validator(mode="after")
    def compute_edge_hash(self) -> AssetDependencyEdge:
        if not self.edge_hash:
            canonical_dict = self.to_canonical_dict()
            computed = hash_canonical_data(canonical_dict)
            object.__setattr__(self, "edge_hash", computed)
        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "edge_type": self.edge_type.value,
            "project_id": self.project_id,
            "propagation_weight": float(self.propagation_weight),
            "source_asset_id": self.source_asset_id,
            "target_asset_id": self.target_asset_id,
        }


class ChainPath(BaseModel):
    """Immutable representation of an identified multi-hop asset lineage chain."""

    model_config = ConfigDict(frozen=True)

    project_id: str = Field(..., min_length=1, max_length=128)
    chain_id: str = Field(..., min_length=1, max_length=128)
    asset_ids: List[str] = Field(..., min_length=2)
    chain_risk_score: float = Field(..., ge=0.0, le=1.0)
    hop_count: int = Field(..., ge=1)
    chain_hash: str = Field(default="", max_length=64)

    @field_validator("chain_risk_score")
    @classmethod
    def validate_finite_risk(cls, v: float) -> float:
        if math.isnan(v) or math.isinf(v) or v < 0.0 or v > 1.0:
            raise InvalidAssetRiskError(f"Chain risk score must be finite in [0.0, 1.0], got {v}")
        return round(float(v), 6)

    @model_validator(mode="after")
    def compute_chain_hash(self) -> ChainPath:
        if not self.chain_hash:
            canonical_dict = self.to_canonical_dict()
            computed = hash_canonical_data(canonical_dict)
            object.__setattr__(self, "chain_hash", computed)
        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "asset_ids": list(self.asset_ids),
            "chain_id": self.chain_id,
            "chain_risk_score": float(self.chain_risk_score),
            "hop_count": int(self.hop_count),
            "project_id": self.project_id,
        }


class AssetDependencyGraph(BaseModel):
    """Immutable in-memory DAG of project assets and explicit lineage relationships."""

    model_config = ConfigDict(frozen=True)

    project_id: str = Field(..., min_length=1, max_length=128)
    asset_ids: List[str] = Field(default_factory=list)
    asset_roles: Dict[str, AssetRole] = Field(default_factory=dict)
    edges: List[AssetDependencyEdge] = Field(default_factory=list)
    graph_hash: str = Field(default="", max_length=64)

    @model_validator(mode="after")
    def validate_and_compute_hash(self) -> AssetDependencyGraph:
        # Validate that all edges match project_id
        for e in self.edges:
            if e.project_id != self.project_id:
                raise ScopeMismatchError(
                    f"Edge project '{e.project_id}' does not match graph project '{self.project_id}'"
                )

        # Validate DAG acyclicity
        self.validate_acyclic()

        if not self.graph_hash:
            canonical_dict = self.to_canonical_dict()
            computed = hash_canonical_data(canonical_dict)
            object.__setattr__(self, "graph_hash", computed)
        return self

    def validate_acyclic(self) -> None:
        """Enforce strict DAG acyclicity via DFS cycle detection (fails closed)."""
        adj: Dict[str, List[str]] = {a: [] for a in self.asset_ids}
        for e in self.edges:
            if e.source_asset_id == e.target_asset_id:
                raise DependencyCycleError(
                    f"Self-dependency cycle detected on asset '{e.source_asset_id}'"
                )
            if e.source_asset_id not in adj:
                adj[e.source_asset_id] = []
            adj[e.source_asset_id].append(e.target_asset_id)

        # DFS with 3-color marking (0=unvisited, 1=visiting, 2=visited)
        visited: Dict[str, int] = {a: 0 for a in adj}

        def dfs(node: str, path: List[str]) -> None:
            visited[node] = 1
            for neighbor in adj.get(node, []):
                if visited.get(neighbor) == 1:
                    cycle_str = " -> ".join(path + [neighbor])
                    raise DependencyCycleError(f"Dependency cycle detected: {cycle_str}")
                if visited.get(neighbor) == 0:
                    dfs(neighbor, path + [neighbor])
            visited[node] = 2

        for node in sorted(adj.keys()):
            if visited[node] == 0:
                dfs(node, [node])

    def get_topological_order(self) -> List[str]:
        """Compute deterministic topological ordering of assets."""
        in_degree: Dict[str, int] = {a: 0 for a in self.asset_ids}
        adj: Dict[str, List[str]] = {a: [] for a in self.asset_ids}
        for e in self.edges:
            adj[e.source_asset_id].append(e.target_asset_id)
            in_degree[e.target_asset_id] = in_degree.get(e.target_asset_id, 0) + 1

        # Lexicographical queue for determinism
        queue = [a for a in sorted(in_degree.keys()) if in_degree[a] == 0]
        order: List[str] = []

        while queue:
            curr = queue.pop(0)
            order.append(curr)
            for neighbor in sorted(adj.get(curr, [])):
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
                    queue.sort()

        if len(order) < len(self.asset_ids):
            raise DependencyCycleError("Cycle detected during topological sorting")
        return order

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "asset_ids": sorted(self.asset_ids),
            "asset_roles": {k: self.asset_roles[k].value for k in sorted(self.asset_roles)},
            "edge_hashes": [e.edge_hash for e in sorted(self.edges, key=lambda x: (x.source_asset_id, x.target_asset_id, x.edge_type.value))],
            "project_id": self.project_id,
        }


class ProjectAggregationDisposition(BaseModel):
    """Final project-level disposition synthesizing risk thresholds and proof escalations."""

    model_config = ConfigDict(frozen=True)

    project_id: str = Field(..., min_length=1, max_length=128)
    decision: UniversalDecision
    risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_level: RiskLevel
    escalation_reason: Optional[str] = None
    proof_override_triggered: bool = False
    disposition_hash: str = Field(default="", max_length=64)

    @model_validator(mode="after")
    def compute_disposition_hash(self) -> ProjectAggregationDisposition:
        if not self.disposition_hash:
            canonical_dict = self.to_canonical_dict()
            computed = hash_canonical_data(canonical_dict)
            object.__setattr__(self, "disposition_hash", computed)
        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "escalation_reason": self.escalation_reason,
            "project_id": self.project_id,
            "proof_override_triggered": self.proof_override_triggered,
            "risk_level": self.risk_level.value,
            "risk_score": float(self.risk_score),
        }
