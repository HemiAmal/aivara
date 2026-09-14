"""Universal Evidence Graph In-Memory Directed Acyclic Graph (DAG) Representation (Phase 12.3)."""

from __future__ import annotations

import collections
from typing import Any, Dict, List, Optional, Sequence, Set

from aivara.universal.exceptions import ProjectMismatchError
from aivara.universal.graph.enums import GraphEdgeType, GraphNodeType
from aivara.universal.graph.schemas import (
    GraphEdge,
    GraphNode,
    UniversalEvidenceGraphSnapshot,
)
from aivara.universal.schemas import AncestryPath


class UniversalEvidenceGraph:
    """Immutable, tenant-isolated in-memory DAG representation of evidence and findings."""

    def __init__(self, snapshot: UniversalEvidenceGraphSnapshot) -> None:
        self._snapshot = snapshot
        self._project_id = snapshot.project_id
        self._nodes: Dict[str, GraphNode] = {n.node_id: n for n in snapshot.nodes}
        self._edges: Dict[str, GraphEdge] = {e.edge_id: e for e in snapshot.edges}
        
        # Build adjacency indices
        self._out_edges: Dict[str, List[GraphEdge]] = collections.defaultdict(list)
        self._in_edges: Dict[str, List[GraphEdge]] = collections.defaultdict(list)
        
        for edge in snapshot.edges:
            self._out_edges[edge.source_node_id].append(edge)
            self._in_edges[edge.target_node_id].append(edge)

    @property
    def project_id(self) -> str:
        return self._project_id

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    @property
    def max_depth(self) -> int:
        return self._snapshot.max_depth

    @property
    def graph_hash(self) -> str:
        return self._snapshot.graph_hash

    @property
    def merkle_root(self) -> str:
        return self._snapshot.merkle_root

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Retrieve a node by its node_id, strictly scoped to this project."""
        return self._nodes.get(node_id)

    def get_nodes(self) -> List[GraphNode]:
        """Return all nodes in canonical order."""
        return list(self._snapshot.nodes)

    def get_edges(self) -> List[GraphEdge]:
        """Return all edges in canonical order."""
        return list(self._snapshot.edges)

    def get_evidence_for_finding(self, finding_id: str) -> List[GraphNode]:
        """Return all evidence nodes supporting a given finding."""
        finding_node_id = finding_id if finding_id.startswith("node_find_") else f"node_find_{finding_id}"
        evidence_nodes: List[GraphNode] = []
        for edge in self._out_edges.get(finding_node_id, []):
            if edge.edge_type == GraphEdgeType.SUPPORTS:
                target_node = self._nodes.get(edge.target_node_id)
                if target_node and target_node.node_type == GraphNodeType.EVIDENCE:
                    evidence_nodes.append(target_node)
        return evidence_nodes

    def get_findings_for_evidence(self, evidence_id: str) -> List[GraphNode]:
        """Return all finding nodes supported by a given evidence item."""
        ev_node_id = evidence_id if evidence_id.startswith("node_ev_") else f"node_ev_{evidence_id}"
        finding_nodes: List[GraphNode] = []
        for edge in self._in_edges.get(ev_node_id, []):
            if edge.edge_type == GraphEdgeType.SUPPORTS:
                source_node = self._nodes.get(edge.source_node_id)
                if source_node and source_node.node_type == GraphNodeType.FINDING:
                    finding_nodes.append(source_node)
        return finding_nodes

    def get_derived_evidence(self, evidence_id: str) -> List[GraphNode]:
        """Return evidence nodes derived from the specified parent evidence item."""
        ev_node_id = evidence_id if evidence_id.startswith("node_ev_") else f"node_ev_{evidence_id}"
        derived_nodes: List[GraphNode] = []
        # In DERIVED_FROM: source is derived, target is parent
        for edge in self._in_edges.get(ev_node_id, []):
            if edge.edge_type == GraphEdgeType.DERIVED_FROM:
                source_node = self._nodes.get(edge.source_node_id)
                if source_node and source_node.node_type == GraphNodeType.EVIDENCE:
                    derived_nodes.append(source_node)
        return derived_nodes

    def get_parent_evidence(self, evidence_id: str) -> List[GraphNode]:
        """Return parent evidence nodes that this evidence was derived from."""
        ev_node_id = evidence_id if evidence_id.startswith("node_ev_") else f"node_ev_{evidence_id}"
        parent_nodes: List[GraphNode] = []
        for edge in self._out_edges.get(ev_node_id, []):
            if edge.edge_type == GraphEdgeType.DERIVED_FROM:
                target_node = self._nodes.get(edge.target_node_id)
                if target_node and target_node.node_type == GraphNodeType.EVIDENCE:
                    parent_nodes.append(target_node)
        return parent_nodes

    def get_ancestry_cluster(self, ancestry_path: AncestryPath) -> List[GraphNode]:
        """Return all evidence nodes matching any non-empty key in the specified ancestry path."""
        if ancestry_path.is_empty():
            return []
        
        matched: List[GraphNode] = []
        for node in self._nodes.values():
            if node.node_type != GraphNodeType.EVIDENCE or not node.ancestry_path:
                continue
            ap = node.ancestry_path
            # Check overlap on any non-empty coordinate
            if (
                (ancestry_path.sample_id and ap.sample_id == ancestry_path.sample_id)
                or (ancestry_path.dataset_version_id and ap.dataset_version_id == ancestry_path.dataset_version_id)
                or (ancestry_path.model_fingerprint and ap.model_fingerprint == ancestry_path.model_fingerprint)
                or (ancestry_path.window_id and ap.window_id == ancestry_path.window_id)
                or (ancestry_path.source_id and ap.source_id == ancestry_path.source_id)
            ):
                matched.append(node)
        return matched

    def to_snapshot(self) -> UniversalEvidenceGraphSnapshot:
        """Return immutable canonical snapshot."""
        return self._snapshot
