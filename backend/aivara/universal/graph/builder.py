"""Deterministic Builder and Validator for Universal Evidence Graph (Phase 12.3)."""

from __future__ import annotations

import collections
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.enums import SubsystemDomain
from aivara.universal.exceptions import (
    InvalidEvidenceError,
    ProjectMismatchError,
    UniversalResourceLimitExceededError,
)
from aivara.universal.graph.enums import GraphEdgeType, GraphNodeType, GraphSchemaVersion
from aivara.universal.graph.exceptions import (
    DanglingEdgeError,
    DuplicateEdgeError,
    DuplicateNodeError,
    GraphBranchingLimitExceededError,
    GraphCycleError,
    GraphDepthLimitExceededError,
)
from aivara.universal.graph.graph import UniversalEvidenceGraph
from aivara.universal.graph.merkle import compute_graph_merkle_root
from aivara.universal.graph.schemas import (
    FindingEvidenceBinding,
    GraphEdge,
    GraphNode,
    UniversalEvidenceGraphSnapshot,
)
from aivara.universal.schemas import UniversalEvidenceEnvelope

# Phase 12.1 frozen hard resource ceilings
MAX_EVIDENCE_NODES: int = 5000
MAX_FINDING_NODES: int = 1000
MAX_ASSET_NODES: int = 250
MAX_DAG_DEPTH: int = 5
MAX_BRANCHING_FACTOR: int = 100


class UniversalEvidenceGraphBuilder:
    """Orchestrates deterministic DAG validation, cycle detection, and snapshot generation."""

    def __init__(self, project_id: str) -> None:
        if not project_id:
            raise ProjectMismatchError("Target project_id must not be empty.")
        self.project_id = project_id
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[str, GraphEdge] = {}
        self._bindings: List[FindingEvidenceBinding] = []
        self._evidence_count: int = 0
        self._finding_count: int = 0
        self._asset_count: int = 0

    def add_node(self, node: GraphNode) -> UniversalEvidenceGraphBuilder:
        """Add a validated GraphNode to the graph builder."""
        if node.project_id != self.project_id:
            raise ProjectMismatchError(
                f"Node project_id '{node.project_id}' does not match graph project_id '{self.project_id}'."
            )
        if node.node_id in self._nodes:
            existing = self._nodes[node.node_id]
            if existing.canonical_hash != node.canonical_hash:
                raise DuplicateNodeError(
                    f"Node '{node.node_id}' already exists with different canonical hash: {existing.canonical_hash} vs {node.canonical_hash}"
                )
            return self

        # Check node type ceilings
        if node.node_type == GraphNodeType.EVIDENCE and self._evidence_count >= MAX_EVIDENCE_NODES:
            raise UniversalResourceLimitExceededError(
                f"Evidence node ceiling ({MAX_EVIDENCE_NODES}) exceeded."
            )
        if node.node_type == GraphNodeType.FINDING and self._finding_count >= MAX_FINDING_NODES:
            raise UniversalResourceLimitExceededError(
                f"Finding node ceiling ({MAX_FINDING_NODES}) exceeded."
            )
        if node.node_type == GraphNodeType.ASSET and self._asset_count >= MAX_ASSET_NODES:
            raise UniversalResourceLimitExceededError(
                f"Asset node ceiling ({MAX_ASSET_NODES}) exceeded."
            )

        if node.node_type == GraphNodeType.EVIDENCE:
            self._evidence_count += 1
        elif node.node_type == GraphNodeType.FINDING:
            self._finding_count += 1
        elif node.node_type == GraphNodeType.ASSET:
            self._asset_count += 1

        self._nodes[node.node_id] = node
        return self

    def add_evidence_envelope(self, envelope: UniversalEvidenceEnvelope) -> UniversalEvidenceGraphBuilder:
        """Convert a Phase 12.2 UniversalEvidenceEnvelope into an Evidence GraphNode and associated edges."""
        if envelope.project_id != self.project_id:
            raise ProjectMismatchError(
                f"Envelope project_id '{envelope.project_id}' does not match graph project_id '{self.project_id}'."
            )

        # Check distinct primary asset ceiling
        distinct_assets = {
            n.metadata.get("primary_asset_id")
            for n in self._nodes.values()
            if n.node_type == GraphNodeType.EVIDENCE and n.metadata.get("primary_asset_id")
        }
        if envelope.primary_asset_id and envelope.primary_asset_id not in distinct_assets:
            if len(distinct_assets) >= MAX_ASSET_NODES:
                raise UniversalResourceLimitExceededError(
                    f"Asset ceiling ({MAX_ASSET_NODES}) exceeded."
                )

        node_id = f"node_ev_{envelope.evidence_id}"
        node = GraphNode(
            node_id=node_id,
            project_id=envelope.project_id,
            node_type=GraphNodeType.EVIDENCE,
            canonical_identity=envelope.evidence_id,
            canonical_hash=envelope.canonical_hash,
            domain=envelope.domain,
            evidence_layer=envelope.evidence_layer,
            severity=envelope.severity,
            confidence=envelope.confidence,
            ancestry_path=envelope.ancestry_path,
            metadata={
                "evidence_type": envelope.evidence_type,
                "primary_asset_type": envelope.primary_asset_type,
                "primary_asset_id": envelope.primary_asset_id,
                "source_payload_hash": envelope.source_payload_hash,
                "normalized_payload_hash": envelope.normalized_payload_hash,
            },
        )
        self.add_node(node)

        # Connect finding linkage if present
        if envelope.finding_id:
            finding_node_id = f"node_find_{envelope.finding_id}"
            # Ensure finding stub node exists if not explicitly provided yet
            if finding_node_id not in self._nodes:
                self.add_node(GraphNode(
                    node_id=finding_node_id,
                    project_id=envelope.project_id,
                    node_type=GraphNodeType.FINDING,
                    canonical_identity=envelope.finding_id,
                    canonical_hash=envelope.canonical_hash,  # Initial reference hash
                    severity=envelope.severity,
                    confidence=envelope.confidence,
                ))
            self.add_finding_evidence_binding(
                finding_id=envelope.finding_id,
                evidence_id=envelope.evidence_id,
                relationship_type=GraphEdgeType.SUPPORTS,
            )

        # Connect parent evidence linkages
        for parent_id in envelope.parent_evidence_ids:
            parent_node_id = f"node_ev_{parent_id}" if not parent_id.startswith("node_ev_") else parent_id
            if parent_node_id in self._nodes:
                self.add_edge(GraphEdge(
                    project_id=self.project_id,
                    source_node_id=node_id,
                    target_node_id=parent_node_id,
                    edge_type=GraphEdgeType.DERIVED_FROM,
                ))

        return self

    def add_finding(self, finding: Union[Any, Dict[str, Any]]) -> UniversalEvidenceGraphBuilder:
        """Convert a Finding record into a Finding GraphNode."""
        raw = finding if isinstance(finding, dict) else (finding.model_dump() if hasattr(finding, "model_dump") else finding.__dict__)
        f_id = str(raw.get("id") or raw.get("finding_id"))
        p_id = str(raw.get("project_id") or self.project_id)

        if p_id != self.project_id:
            raise ProjectMismatchError(
                f"Finding project_id '{p_id}' does not match graph project_id '{self.project_id}'."
            )

        sev_raw = raw.get("severity", Severity.INFO)
        if isinstance(sev_raw, str):
            sev_raw = Severity(sev_raw.lower())

        layer_raw = raw.get("evidence_layer", EvidenceLayer.DETECTION)
        if isinstance(layer_raw, str):
            layer_raw = EvidenceLayer(layer_raw.lower())

        node_id = f"node_find_{f_id}"
        from aivara.universal.hashing import compute_payload_hash
        f_hash = raw.get("finding_hash") or compute_payload_hash({
            "affected_asset_id": raw.get("affected_asset_id", ""),
            "affected_asset_type": raw.get("affected_asset_type", ""),
            "finding_type": raw.get("finding_type", ""),
            "id": f_id,
            "project_id": p_id,
            "severity": sev_raw.value,
        })

        node = GraphNode(
            node_id=node_id,
            project_id=p_id,
            node_type=GraphNodeType.FINDING,
            canonical_identity=f_id,
            canonical_hash=f_hash,
            evidence_layer=layer_raw,
            severity=sev_raw,
            confidence=float(raw.get("confidence", 1.0 if layer_raw == EvidenceLayer.PROOF else 0.90)),
            metadata={
                "finding_type": str(raw.get("finding_type", "general")),
                "affected_asset_type": str(raw.get("affected_asset_type", "dataset")),
                "affected_asset_id": str(raw.get("affected_asset_id", "unknown")),
            },
        )
        self.add_node(node)
        return self

    def add_edge(self, edge: GraphEdge) -> UniversalEvidenceGraphBuilder:
        """Add a directed GraphEdge to the builder."""
        if edge.project_id != self.project_id:
            raise ProjectMismatchError(
                f"Edge project_id '{edge.project_id}' does not match graph project_id '{self.project_id}'."
            )
        if edge.edge_id in self._edges:
            existing = self._edges[edge.edge_id]
            if existing.canonical_hash != edge.canonical_hash:
                raise DuplicateEdgeError(
                    f"Edge '{edge.edge_id}' already exists with different canonical hash."
                )
            return self

        self._edges[edge.edge_id] = edge
        return self

    def add_finding_evidence_binding(
        self,
        finding_id: str,
        evidence_id: str,
        relationship_type: GraphEdgeType = GraphEdgeType.SUPPORTS,
        relevance_weight: float = 1.0,
    ) -> UniversalEvidenceGraphBuilder:
        """Add an N:M finding-evidence junction edge and binding model."""
        binding = FindingEvidenceBinding(
            project_id=self.project_id,
            finding_id=finding_id,
            evidence_id=evidence_id,
            relationship_type=relationship_type,
            relevance_weight=relevance_weight,
        )
        self._bindings.append(binding)

        f_node_id = f"node_find_{finding_id}" if not finding_id.startswith("node_find_") else finding_id
        ev_node_id = f"node_ev_{evidence_id}" if not evidence_id.startswith("node_ev_") else evidence_id

        edge = GraphEdge(
            project_id=self.project_id,
            source_node_id=f_node_id,
            target_node_id=ev_node_id,
            edge_type=relationship_type,
            relevance_weight=relevance_weight,
        )
        self.add_edge(edge)
        return self

    def validate_and_build(self) -> UniversalEvidenceGraph:
        """Validate DAG integrity, cycle freedom, resource bounds, and produce UniversalEvidenceGraph."""
        # 1. Dangling edge check
        for edge in self._edges.values():
            if edge.source_node_id not in self._nodes:
                raise DanglingEdgeError(
                    f"Edge '{edge.edge_id}' references non-existent source node '{edge.source_node_id}'."
                )
            if edge.target_node_id not in self._nodes:
                raise DanglingEdgeError(
                    f"Edge '{edge.edge_id}' references non-existent target node '{edge.target_node_id}'."
                )

        # 2. Build adjacency for validation
        adjacency: Dict[str, List[str]] = collections.defaultdict(list)
        out_degree: Dict[str, int] = collections.defaultdict(int)

        for edge in self._edges.values():
            adjacency[edge.source_node_id].append(edge.target_node_id)
            out_degree[edge.source_node_id] += 1
            if out_degree[edge.source_node_id] > MAX_BRANCHING_FACTOR:
                raise GraphBranchingLimitExceededError(
                    f"Node '{edge.source_node_id}' exceeds maximum branching factor ({MAX_BRANCHING_FACTOR})."
                )

        # 3. Cycle Detection via DFS 3-Coloring (WHITE=0, GREY=1, BLACK=2)
        WHITE, GREY, BLACK = 0, 1, 2
        colors: Dict[str, int] = {node_id: WHITE for node_id in self._nodes}
        parent_map: Dict[str, str] = {}

        def dfs_visit(u: str, path: List[str]) -> None:
            colors[u] = GREY
            path.append(u)
            for v in adjacency.get(u, []):
                if colors[v] == GREY:
                    cycle_start = path.index(v)
                    cycle_path = path[cycle_start:] + [v]
                    raise GraphCycleError(
                        f"Cycle detected in Evidence DAG: {' -> '.join(cycle_path)}",
                        cycle_path=cycle_path,
                    )
                if colors[v] == WHITE:
                    parent_map[v] = u
                    dfs_visit(v, path)
            path.pop()
            colors[u] = BLACK

        for node_id in self._nodes:
            if colors[node_id] == WHITE:
                dfs_visit(node_id, [])

        # 4. Longest Path / Depth Calculation in DAG
        depth_memo: Dict[str, int] = {}

        def compute_depth(u: str) -> int:
            if u in depth_memo:
                return depth_memo[u]
            neighbors = adjacency.get(u, [])
            if not neighbors:
                depth_memo[u] = 0
                return 0
            max_child_depth = max(compute_depth(v) for v in neighbors)
            depth_memo[u] = 1 + max_child_depth
            return depth_memo[u]

        max_graph_depth = 0
        for node_id in self._nodes:
            d = compute_depth(node_id)
            if d > max_graph_depth:
                max_graph_depth = d

        if max_graph_depth > MAX_DAG_DEPTH:
            raise GraphDepthLimitExceededError(
                f"Evidence DAG depth ({max_graph_depth}) exceeds maximum limit ({MAX_DAG_DEPTH})."
            )

        # 5. Canonical Node & Edge Ordering
        sorted_nodes = sorted(
            self._nodes.values(),
            key=lambda n: (n.project_id, n.node_type.value, n.canonical_identity, n.canonical_hash)
        )
        sorted_edges = sorted(
            self._edges.values(),
            key=lambda e: (e.project_id, e.source_node_id, e.target_node_id, e.edge_type.value, e.relationship_version, e.edge_id)
        )

        # 6. Merkle Root Computation
        from aivara.universal.hashing import compute_canonical_jcs_bytes, compute_sha256_digest
        leaf_hashes = [
            compute_sha256_digest(compute_canonical_jcs_bytes(n.to_canonical_dict()))
            for n in sorted_nodes
        ] + [e.canonical_hash for e in sorted_edges]
        merkle_root = compute_graph_merkle_root(leaf_hashes)

        max_branching = max(out_degree.values()) if out_degree else 0

        snapshot = UniversalEvidenceGraphSnapshot(
            schema_version=GraphSchemaVersion.V1_0.value,
            project_id=self.project_id,
            nodes=sorted_nodes,
            edges=sorted_edges,
            node_count=len(sorted_nodes),
            edge_count=len(sorted_edges),
            max_depth=max_graph_depth,
            max_branching_factor=max_branching,
            merkle_root=merkle_root,
        )

        return UniversalEvidenceGraph(snapshot)
