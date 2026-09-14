"""Enumerations for Universal Evidence Graph & Lineage DAG (Phase 12.3)."""

from enum import Enum


class GraphNodeType(str, Enum):
    """Categorical classification of nodes within the evidence DAG."""
    FINDING = "FINDING"
    EVIDENCE = "EVIDENCE"
    ASSET = "ASSET"


class GraphEdgeType(str, Enum):
    """Authoritative semantic relationship types between graph nodes."""
    SUPPORTS = "SUPPORTS"            # Finding -> Evidence (or Evidence -> Finding)
    DERIVED_FROM = "DERIVED_FROM"    # Derived Evidence -> Parent Evidence
    PARENT_OF = "PARENT_OF"          # Parent Evidence -> Derived Evidence
    LINEAGE = "LINEAGE"              # Asset -> Asset or Version -> Version
    DEPENDS_ON = "DEPENDS_ON"        # Dependency link
    ASSOCIATED_WITH = "ASSOCIATED_WITH"  # Contextual association


class GraphSchemaVersion(str, Enum):
    """SemVer for Universal Evidence Graph contracts."""
    V1_0 = "1.0.0"
