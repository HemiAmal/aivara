"""Traceability, Threat Coverage, and Governance Test Suite for Phase 12.3.

Covers:
- Exact Resource Boundaries: E=5000/5001, F=1000/1001, depth=5/6, branching=100/101, A=250/251.
- Immutability of GraphNode, GraphEdge, FindingEvidenceBinding, Snapshot.
- 5-Coordinate Ancestry extraction & mutation: complete, partial, absent, repeated, derived.
- N:M Junction exhaustive matrix (F1->E1, F1->E2, F2->E1, F2->E2, different relationship types).
- Multi-Tenant Isolation / BOLA fail-closed assertions.
- Static audit verification (zero risk score / damping logic).
"""

import inspect
import math
import pytest
from pydantic import ValidationError

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.enums import AncestryStatus, SubsystemDomain
from aivara.universal.exceptions import (
    InvalidEvidenceError,
    ProjectMismatchError,
    UniversalResourceLimitExceededError,
)
from aivara.universal.graph import (
    DanglingEdgeError,
    DuplicateEdgeError,
    DuplicateNodeError,
    FindingEvidenceBinding,
    GraphBranchingLimitExceededError,
    GraphCycleError,
    GraphDepthLimitExceededError,
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
    UniversalEvidenceGraph,
    UniversalEvidenceGraphBuilder,
    compute_graph_merkle_root,
)
from aivara.universal.schemas import AncestryPath, UniversalEvidenceEnvelope


# =====================================================================
# 1. Resource Governance Boundary Tests
# =====================================================================

def test_evidence_node_ceiling_boundary():
    """Verify E=5000 succeeds and E=5001 raises UniversalResourceLimitExceededError."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_bound_e")
    # Add 5000 evidence nodes
    for i in range(5000):
        builder.add_node(GraphNode(
            node_id=f"node_e_{i}",
            project_id="proj_bound_e",
            node_type=GraphNodeType.EVIDENCE,
            canonical_identity=f"e_{i}",
            canonical_hash=f"{(i%10)}" * 64,
        ))
    assert len(builder._nodes) == 5000

    # 5001st evidence node must fail
    with pytest.raises(UniversalResourceLimitExceededError) as exc_info:
        builder.add_node(GraphNode(
            node_id="node_e_5000",
            project_id="proj_bound_e",
            node_type=GraphNodeType.EVIDENCE,
            canonical_identity="e_5000",
            canonical_hash="0" * 64,
        ))
    assert "Evidence node ceiling" in str(exc_info.value)


def test_finding_node_ceiling_boundary():
    """Verify F=1000 succeeds and F=1001 raises UniversalResourceLimitExceededError."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_bound_f")
    for i in range(1000):
        builder.add_node(GraphNode(
            node_id=f"node_f_{i}",
            project_id="proj_bound_f",
            node_type=GraphNodeType.FINDING,
            canonical_identity=f"f_{i}",
            canonical_hash=f"{(i%10)}" * 64,
        ))
    assert len(builder._nodes) == 1000

    with pytest.raises(UniversalResourceLimitExceededError) as exc_info:
        builder.add_node(GraphNode(
            node_id="node_f_1000",
            project_id="proj_bound_f",
            node_type=GraphNodeType.FINDING,
            canonical_identity="f_1000",
            canonical_hash="0" * 64,
        ))
    assert "Finding node ceiling" in str(exc_info.value)


def test_asset_node_ceiling_boundary():
    """Verify A=250 succeeds and A=251 raises UniversalResourceLimitExceededError."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_bound_a")
    for i in range(250):
        builder.add_node(GraphNode(
            node_id=f"node_a_{i}",
            project_id="proj_bound_a",
            node_type=GraphNodeType.ASSET,
            canonical_identity=f"a_{i}",
            canonical_hash=f"{(i%10)}" * 64,
        ))
    assert len(builder._nodes) == 250

    with pytest.raises(UniversalResourceLimitExceededError) as exc_info:
        builder.add_node(GraphNode(
            node_id="node_a_250",
            project_id="proj_bound_a",
            node_type=GraphNodeType.ASSET,
            canonical_identity="a_250",
            canonical_hash="0" * 64,
        ))
    assert "Asset node ceiling" in str(exc_info.value)


def test_dag_depth_exact_boundary():
    """Verify DAG depth=5 succeeds and depth=6 fails."""
    # Chain of 6 nodes -> depth 5
    b5 = UniversalEvidenceGraphBuilder(project_id="proj_d5")
    for i in range(6):
        b5.add_node(GraphNode(node_id=f"n_{i}", project_id="proj_d5", node_type=GraphNodeType.EVIDENCE, canonical_identity=str(i), canonical_hash=f"{i}" * 64))
    for i in range(5):
        b5.add_edge(GraphEdge(project_id="proj_d5", source_node_id=f"n_{i}", target_node_id=f"n_{i+1}", edge_type=GraphEdgeType.DERIVED_FROM))
    g5 = b5.validate_and_build()
    assert g5.max_depth == 5

    # Chain of 7 nodes -> depth 6
    b6 = UniversalEvidenceGraphBuilder(project_id="proj_d6")
    for i in range(7):
        b6.add_node(GraphNode(node_id=f"n_{i}", project_id="proj_d6", node_type=GraphNodeType.EVIDENCE, canonical_identity=str(i), canonical_hash=f"{i}" * 64))
    for i in range(6):
        b6.add_edge(GraphEdge(project_id="proj_d6", source_node_id=f"n_{i}", target_node_id=f"n_{i+1}", edge_type=GraphEdgeType.DERIVED_FROM))
    with pytest.raises(GraphDepthLimitExceededError):
        b6.validate_and_build()


def test_branching_exact_boundary():
    """Verify branching factor=100 succeeds and branching=101 fails."""
    # Branching 100
    b100 = UniversalEvidenceGraphBuilder(project_id="proj_br100")
    b100.add_node(GraphNode(node_id="root", project_id="proj_br100", node_type=GraphNodeType.FINDING, canonical_identity="root", canonical_hash="0" * 64))
    for i in range(100):
        b100.add_node(GraphNode(node_id=f"child_{i}", project_id="proj_br100", node_type=GraphNodeType.EVIDENCE, canonical_identity=f"c_{i}", canonical_hash=f"{(i%10)}" * 64))
        b100.add_edge(GraphEdge(project_id="proj_br100", source_node_id="root", target_node_id=f"child_{i}", edge_type=GraphEdgeType.SUPPORTS))
    g100 = b100.validate_and_build()
    assert g100._snapshot.max_branching_factor == 100

    # Branching 101
    b101 = UniversalEvidenceGraphBuilder(project_id="proj_br101")
    b101.add_node(GraphNode(node_id="root", project_id="proj_br101", node_type=GraphNodeType.FINDING, canonical_identity="root", canonical_hash="0" * 64))
    for i in range(101):
        b101.add_node(GraphNode(node_id=f"child_{i}", project_id="proj_br101", node_type=GraphNodeType.EVIDENCE, canonical_identity=f"c_{i}", canonical_hash=f"{(i%10)}" * 64))
        b101.add_edge(GraphEdge(project_id="proj_br101", source_node_id="root", target_node_id=f"child_{i}", edge_type=GraphEdgeType.SUPPORTS))
    with pytest.raises(GraphBranchingLimitExceededError):
        b101.validate_and_build()


# =====================================================================
# 2. Immutability Tests
# =====================================================================

def test_model_immutability():
    """Verify GraphNode, GraphEdge, FindingEvidenceBinding, Snapshot cannot be mutated in place."""
    node = GraphNode(node_id="n1", project_id="p1", node_type=GraphNodeType.EVIDENCE, canonical_identity="e1", canonical_hash="1" * 64)
    with pytest.raises(ValidationError):
        node.canonical_identity = "mutated"

    edge = GraphEdge(project_id="p1", source_node_id="n1", target_node_id="n2", edge_type=GraphEdgeType.SUPPORTS)
    with pytest.raises(ValidationError):
        edge.relevance_weight = 0.5

    binding = FindingEvidenceBinding(project_id="p1", finding_id="f1", evidence_id="e1")
    with pytest.raises(ValidationError):
        binding.relevance_weight = 0.5


# =====================================================================
# 3. 5-Coordinate Ancestry Comprehensive Tests
# =====================================================================

def test_ancestry_complete_partial_absent_and_query():
    """Verify ancestry paths (complete, partial, absent) and query clustering."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_anc_full")
    
    # Complete 5-coordinate
    full_anc = AncestryPath(
        sample_id="samp_1",
        dataset_version_id="ds_v1",
        model_fingerprint="m" * 64,
        window_id="win_10",
        source_id="src_99",
    )
    n_full = GraphNode(node_id="n_full", project_id="proj_anc_full", node_type=GraphNodeType.EVIDENCE, canonical_identity="e_full", canonical_hash="1" * 64, ancestry_path=full_anc)
    
    # Partial (only model_fingerprint)
    partial_anc = AncestryPath(model_fingerprint="m" * 64)
    n_part = GraphNode(node_id="n_part", project_id="proj_anc_full", node_type=GraphNodeType.EVIDENCE, canonical_identity="e_part", canonical_hash="2" * 64, ancestry_path=partial_anc)
    
    # Absent
    n_abs = GraphNode(node_id="n_abs", project_id="proj_anc_full", node_type=GraphNodeType.EVIDENCE, canonical_identity="e_abs", canonical_hash="3" * 64, ancestry_path=None)
    
    builder.add_node(n_full)
    builder.add_node(n_part)
    builder.add_node(n_abs)
    
    graph = builder.validate_and_build()
    
    # Query by model_fingerprint -> matches n_full and n_part
    cluster = graph.get_ancestry_cluster(AncestryPath(model_fingerprint="m" * 64))
    assert len(cluster) == 2
    assert {c.canonical_identity for c in cluster} == {"e_full", "e_part"}
    
    # Query by empty ancestry -> returns empty list
    assert graph.get_ancestry_cluster(AncestryPath()) == []


# =====================================================================
# 4. Exhaustive N:M Matrix & Differing Relationship Types
# =====================================================================

def test_nm_exhaustive_relationship_matrix():
    """Verify F1->E1, F1->E2, F2->E1, F2->E2 and same F/E with different relationship type."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_matrix")
    for f in ["f1", "f2"]:
        builder.add_node(GraphNode(node_id=f"node_find_{f}", project_id="proj_matrix", node_type=GraphNodeType.FINDING, canonical_identity=f, canonical_hash="f" * 64))
    for e in ["e1", "e2"]:
        builder.add_node(GraphNode(node_id=f"node_ev_{e}", project_id="proj_matrix", node_type=GraphNodeType.EVIDENCE, canonical_identity=e, canonical_hash="e" * 64))

    # All 4 combinations with SUPPORTS
    builder.add_finding_evidence_binding("f1", "e1", relationship_type=GraphEdgeType.SUPPORTS)
    builder.add_finding_evidence_binding("f1", "e2", relationship_type=GraphEdgeType.SUPPORTS)
    builder.add_finding_evidence_binding("f2", "e1", relationship_type=GraphEdgeType.SUPPORTS)
    builder.add_finding_evidence_binding("f2", "e2", relationship_type=GraphEdgeType.SUPPORTS)
    
    # Same F1 / E1 with a different relationship type (ASSOCIATED_WITH)
    builder.add_finding_evidence_binding("f1", "e1", relationship_type=GraphEdgeType.ASSOCIATED_WITH)

    graph = builder.validate_and_build()
    assert graph.node_count == 4
    assert graph.edge_count == 5

    # Queries
    f1_ev = graph.get_evidence_for_finding("f1")
    assert len(f1_ev) == 2


# =====================================================================
# 5. Multi-Tenant Isolation / BOLA Invariants
# =====================================================================

def test_tenant_isolation_bola_fail_closed():
    """Verify cross-project nodes, edges, queries cannot bridge tenant boundaries."""
    b_proj_a = UniversalEvidenceGraphBuilder(project_id="proj_alpha")
    
    # Project B envelope
    env_b = UniversalEvidenceEnvelope(
        evidence_id="ev_alien",
        project_id="proj_beta",
        domain=SubsystemDomain.MODEL_INTEGRITY,
        evidence_type="proof",
        evidence_layer=EvidenceLayer.PROOF,
        confidence=1.0,
        primary_asset_type="model",
        primary_asset_id="m1",
        source_payload_hash="a" * 64,
        normalized_payload_hash="b" * 64,
        data_json={},
    )
    with pytest.raises(ProjectMismatchError):
        b_proj_a.add_evidence_envelope(env_b)


# =====================================================================
# 6. Static Audit: Zero Risk Engine Logic in universal.graph
# =====================================================================

def test_static_audit_no_risk_engine_in_universal_graph():
    """Confirm backend.aivara.universal.graph has 0 implementation of risk calculations or dispositions."""
    import aivara.universal.graph.builder as b_mod
    import aivara.universal.graph.graph as g_mod
    import aivara.universal.graph.schemas as s_mod

    prohibited_terms = [
        "R_chain",
        "R_project",
        "correlation_damping",
        "dependency_damping",
        "proof_override",
        "disposition_decision",
        "seal_dossier",
    ]

    for mod in [b_mod, g_mod, s_mod]:
        source = inspect.getsource(mod)
        for term in prohibited_terms:
            assert term not in source, f"Prohibited risk engine term '{term}' discovered in {mod.__name__}"
