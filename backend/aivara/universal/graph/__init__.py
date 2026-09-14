"""Universal Evidence Graph & Junction Engine (Phase 12.3)."""

from aivara.universal.graph.enums import (
    GraphEdgeType,
    GraphNodeType,
    GraphSchemaVersion,
)
from aivara.universal.graph.exceptions import (
    DanglingEdgeError,
    DuplicateEdgeError,
    DuplicateNodeError,
    GraphBranchingLimitExceededError,
    GraphCycleError,
    GraphDepthLimitExceededError,
    GraphError,
)
from aivara.universal.graph.graph import UniversalEvidenceGraph
from aivara.universal.graph.builder import UniversalEvidenceGraphBuilder
from aivara.universal.graph.merkle import compute_graph_merkle_root
from aivara.universal.graph.models import FindingEvidenceModel, UniversalBase
from aivara.universal.graph.schemas import (
    FindingEvidenceBinding,
    GraphEdge,
    GraphNode,
    UniversalEvidenceGraphSnapshot,
)

__all__ = [
    "DanglingEdgeError",
    "DuplicateEdgeError",
    "DuplicateNodeError",
    "FindingEvidenceBinding",
    "FindingEvidenceModel",
    "GraphBranchingLimitExceededError",
    "GraphCycleError",
    "GraphDepthLimitExceededError",
    "GraphEdge",
    "GraphEdgeType",
    "GraphError",
    "GraphNode",
    "GraphNodeType",
    "GraphSchemaVersion",
    "UniversalBase",
    "UniversalEvidenceGraph",
    "UniversalEvidenceGraphBuilder",
    "UniversalEvidenceGraphSnapshot",
    "compute_graph_merkle_root",
]
