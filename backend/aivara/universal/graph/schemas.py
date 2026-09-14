"""Pydantic schemas and immutable contracts for Universal Evidence Graph (Phase 12.3)."""

from __future__ import annotations

import math
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.enums import SubsystemDomain
from aivara.universal.exceptions import InvalidEvidenceError
from aivara.universal.graph.enums import GraphEdgeType, GraphNodeType, GraphSchemaVersion
from aivara.universal.hashing import (
    compute_canonical_jcs_bytes,
    compute_sha256_digest,
    validate_finite_numerical_data,
)
from aivara.universal.schemas import AncestryPath


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class GraphNode(BaseModel):
    """Immutable node representation within the Universal Evidence Graph."""
    model_config = ConfigDict(frozen=True)

    node_id: str = Field(..., min_length=1, max_length=128)
    project_id: str = Field(..., min_length=1, max_length=128)
    node_type: GraphNodeType
    canonical_identity: str = Field(..., min_length=1, max_length=128)
    canonical_hash: str = Field(..., min_length=64, max_length=64)
    domain: Optional[SubsystemDomain] = None
    evidence_layer: Optional[EvidenceLayer] = None
    severity: Optional[Severity] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    ancestry_path: Optional[AncestryPath] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    schema_version: str = Field(default=GraphSchemaVersion.V1_0.value)

    @field_validator("confidence")
    @classmethod
    def validate_confidence_finite(cls, v: Optional[float]) -> Optional[float]:
        if v is None:
            return None
        if math.isnan(v) or math.isinf(v):
            raise InvalidEvidenceError(f"Confidence must be a finite float, got {v}")
        if v < 0.0 or v > 1.0:
            raise InvalidEvidenceError(f"Confidence must be in [0.0, 1.0], got {v}")
        return float(v)

    @field_validator("metadata")
    @classmethod
    def validate_metadata_floats(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        validate_finite_numerical_data(v)
        return v

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Produce deterministic sorted dictionary for RFC 8785 JCS canonical serialization."""
        return {
            "ancestry_path": self.ancestry_path.to_canonical_dict() if self.ancestry_path else None,
            "canonical_hash": self.canonical_hash,
            "canonical_identity": self.canonical_identity,
            "confidence": float(self.confidence) if self.confidence is not None else None,
            "domain": self.domain.value if self.domain else None,
            "evidence_layer": self.evidence_layer.value if self.evidence_layer else None,
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "project_id": self.project_id,
            "schema_version": self.schema_version,
            "severity": self.severity.value if self.severity else None,
        }


class GraphEdge(BaseModel):
    """Immutable directed edge representation connecting two nodes within the Evidence DAG."""
    model_config = ConfigDict(frozen=True)

    edge_id: str = Field(default="", max_length=128)
    project_id: str = Field(..., min_length=1, max_length=128)
    source_node_id: str = Field(..., min_length=1, max_length=128)
    target_node_id: str = Field(..., min_length=1, max_length=128)
    edge_type: GraphEdgeType
    relationship_version: str = Field(default=GraphSchemaVersion.V1_0.value)
    relevance_weight: float = Field(default=1.0, ge=0.0, le=1.0)
    provenance_hashes: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    canonical_hash: str = Field(default="", max_length=64)

    @field_validator("relevance_weight")
    @classmethod
    def validate_weight_finite(cls, v: float) -> float:
        if math.isnan(v) or math.isinf(v):
            raise InvalidEvidenceError(f"Relevance weight must be a finite float, got {v}")
        return float(v)

    @field_validator("metadata")
    @classmethod
    def validate_metadata_floats(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        validate_finite_numerical_data(v)
        return v

    @model_validator(mode="after")
    def compute_edge_identity_and_hash(self) -> GraphEdge:
        if not self.edge_id:
            # Deterministic UUID5 derived from project, source, target, and edge_type
            seed = f"aivara:graph_edge:{self.project_id}:{self.source_node_id}:{self.target_node_id}:{self.edge_type.value}"
            generated_id = str(uuid.uuid5(uuid.NAMESPACE_URL, seed))
            object.__setattr__(self, "edge_id", generated_id)

        canonical_dict = self.to_canonical_dict()
        computed_hash = compute_sha256_digest(compute_canonical_jcs_bytes(canonical_dict))
        if not self.canonical_hash:
            object.__setattr__(self, "canonical_hash", computed_hash)
        elif self.canonical_hash != computed_hash:
            raise InvalidEvidenceError(
                f"Edge canonical hash mismatch: expected {computed_hash}, got {self.canonical_hash}"
            )
        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Produce deterministic sorted dictionary for RFC 8785 JCS canonical serialization."""
        return {
            "edge_id": self.edge_id,
            "edge_type": self.edge_type.value,
            "project_id": self.project_id,
            "provenance_hashes": sorted(self.provenance_hashes),
            "relationship_version": self.relationship_version,
            "relevance_weight": float(self.relevance_weight),
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
        }


class FindingEvidenceBinding(BaseModel):
    """Authoritative representation of an N:M binding between a Finding and an Evidence item."""
    model_config = ConfigDict(frozen=True)

    binding_id: str = Field(default="", max_length=128)
    project_id: str = Field(..., min_length=1, max_length=128)
    finding_id: str = Field(..., min_length=1, max_length=128)
    evidence_id: str = Field(..., min_length=1, max_length=128)
    relationship_type: GraphEdgeType = Field(default=GraphEdgeType.SUPPORTS)
    relevance_weight: float = Field(default=1.0, ge=0.0, le=1.0)
    binding_hash: str = Field(default="", max_length=64)
    metadata_json: Dict[str, Any] = Field(default_factory=dict)
    created_at_utc: str = Field(default_factory=utcnow_iso)

    @model_validator(mode="after")
    def compute_binding_hash(self) -> FindingEvidenceBinding:
        if not self.binding_id:
            seed = f"aivara:binding:{self.project_id}:{self.finding_id}:{self.evidence_id}:{self.relationship_type.value}"
            generated_id = str(uuid.uuid5(uuid.NAMESPACE_URL, seed))
            object.__setattr__(self, "binding_id", generated_id)

        if not self.binding_hash:
            canonical_dict = {
                "evidence_id": self.evidence_id,
                "finding_id": self.finding_id,
                "project_id": self.project_id,
                "relationship_type": self.relationship_type.value,
                "relevance_weight": float(self.relevance_weight),
            }
            computed = compute_sha256_digest(compute_canonical_jcs_bytes(canonical_dict))
            object.__setattr__(self, "binding_hash", computed)
        return self


class UniversalEvidenceGraphSnapshot(BaseModel):
    """Immutable, content-addressed snapshot of a validated Evidence DAG."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=GraphSchemaVersion.V1_0.value)
    project_id: str = Field(..., min_length=1, max_length=128)
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    node_count: int
    edge_count: int
    max_depth: int = Field(default=0, ge=0, le=5)
    max_branching_factor: int = Field(default=0, ge=0, le=100)
    graph_hash: str = Field(default="", max_length=64)
    merkle_root: str = Field(default="", max_length=64)
    created_at_utc: str = Field(default_factory=utcnow_iso)

    @model_validator(mode="after")
    def compute_snapshot_hashes(self) -> UniversalEvidenceGraphSnapshot:
        if not self.graph_hash:
            node_leaf_digests = [
                compute_sha256_digest(compute_canonical_jcs_bytes(n.to_canonical_dict()))
                for n in self.nodes
            ]
            canonical_summary = {
                "edge_count": self.edge_count,
                "edge_hashes": [e.canonical_hash for e in self.edges],
                "max_branching_factor": self.max_branching_factor,
                "max_depth": self.max_depth,
                "node_count": self.node_count,
                "node_hashes": node_leaf_digests,
                "project_id": self.project_id,
                "schema_version": self.schema_version,
            }
            computed_graph_hash = compute_sha256_digest(compute_canonical_jcs_bytes(canonical_summary))
            object.__setattr__(self, "graph_hash", computed_graph_hash)
        return self
