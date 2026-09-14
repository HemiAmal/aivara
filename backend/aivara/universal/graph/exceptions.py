"""Exceptions for Universal Evidence Graph & Junction Engine (Phase 12.3)."""

from typing import Any, Dict, List, Optional
from aivara.universal.exceptions import UniversalEvidenceError


class GraphError(UniversalEvidenceError):
    """Base exception for all Phase 12.3 graph operations."""

    def __init__(
        self,
        message: str,
        code: str = "GRAPH_ERROR",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class GraphCycleError(GraphError):
    """Raised when an insertion would introduce a cycle into the Evidence DAG."""

    def __init__(
        self,
        message: str = "Cycle detected in Evidence DAG.",
        cycle_path: Optional[List[str]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        det = details or {}
        if cycle_path:
            det["cycle_path"] = cycle_path
        super().__init__(message, code="GRAPH_CYCLE_DETECTED", details=det)


class DanglingEdgeError(GraphError):
    """Raised when an edge references non-existent source or target node."""

    def __init__(
        self,
        message: str = "Graph edge references non-existent node.",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="DANGLING_EDGE_ERROR", details=details)


class DuplicateNodeError(GraphError):
    """Raised when attempting to add a node with duplicate identity."""

    def __init__(
        self,
        message: str = "Node with this canonical identity already exists in graph.",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="DUPLICATE_NODE_ERROR", details=details)


class DuplicateEdgeError(GraphError):
    """Raised when attempting to add a duplicate edge."""

    def __init__(
        self,
        message: str = "Edge with this identity already exists in graph.",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="DUPLICATE_EDGE_ERROR", details=details)


class GraphDepthLimitExceededError(GraphError):
    """Raised when graph dependency depth exceeds frozen safety limit (Delta <= 5)."""

    def __init__(
        self,
        message: str = "Evidence DAG depth exceeds maximum ceiling (Delta <= 5).",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="GRAPH_DEPTH_LIMIT_EXCEEDED", details=details)


class GraphBranchingLimitExceededError(GraphError):
    """Raised when a graph node exceeds maximum branching factor (beta <= 100)."""

    def __init__(
        self,
        message: str = "Node branching factor exceeds maximum ceiling (beta <= 100).",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="GRAPH_BRANCHING_LIMIT_EXCEEDED", details=details)
