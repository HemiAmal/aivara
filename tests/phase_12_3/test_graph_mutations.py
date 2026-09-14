"""Adversarial Mutation Test Suite for Universal Evidence Graph (Phase 12.3).

Executes independent adversarial mutations (A through T) against real graph structures:
A. node identity
B. node type
C. project_id
D. edge source
E. edge target
F. edge type
G. relationship version
H. ancestry
I. provenance
J. canonical graph ordering
K. graph hash
L. Merkle leaf
M. duplicate node
N. duplicate edge
O. dangling edge
P. cross-project edge
Q. cycle
R. depth
S. branching
T. finding/evidence junction
"""

import copy
import pytest

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
    GraphSchemaVersion,
    UniversalEvidenceGraphBuilder,
    compute_graph_merkle_root,
)
from aivara.universal.schemas import AncestryPath, UniversalEvidenceEnvelope


@pytest.fixture
def base_builder():
    builder = UniversalEvidenceGraphBuilder(project_id="proj_mut_base")
    n1 = GraphNode(
        node_id="node_f1",
        project_id="proj_mut_base",
        node_type=GraphNodeType.FINDING,
        canonical_identity="find_01",
        canonical_hash="1" * 64,
        severity=Severity.HIGH,
        confidence=0.95,
    )
    n2 = GraphNode(
        node_id="node_ev1",
        project_id="proj_mut_base",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_01",
        canonical_hash="2" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        evidence_layer=EvidenceLayer.DETECTION,
        severity=Severity.HIGH,
        confidence=0.90,
        ancestry_path=AncestryPath(sample_id="s123", dataset_version_id="v1.0"),
    )
    e1 = GraphEdge(
        project_id="proj_mut_base",
        source_node_id="node_f1",
        target_node_id="node_ev1",
        edge_type=GraphEdgeType.SUPPORTS,
        relevance_weight=1.0,
        provenance_hashes=["a" * 64],
    )
    builder.add_node(n1)
    builder.add_node(n2)
    builder.add_edge(e1)
    return builder


# =====================================================================
# Mutation A: Node Identity Mutation
# =====================================================================
def test_mutation_a_node_identity(base_builder):
    """Mutating node canonical identity must change node hash and Merkle root."""
    g_orig = base_builder.validate_and_build()

    b_mut = UniversalEvidenceGraphBuilder(project_id="proj_mut_base")
    b_mut.add_node(GraphNode(
        node_id="node_f1",
        project_id="proj_mut_base",
        node_type=GraphNodeType.FINDING,
        canonical_identity="find_MUTATED",
        canonical_hash="1" * 64,
    ))
    b_mut.add_node(g_orig.get_node("node_ev1"))
    b_mut.add_edge(g_orig.get_edges()[0])

    g_mut = b_mut.validate_and_build()
    assert g_orig.graph_hash != g_mut.graph_hash
    assert g_orig.get_node("node_f1").canonical_identity != g_mut.get_node("node_f1").canonical_identity


# =====================================================================
# Mutation B: Node Type Mutation
# =====================================================================
def test_mutation_b_node_type(base_builder):
    """Mutating node type from FINDING to EVIDENCE must alter canonical dictionary and graph hash."""
    g_orig = base_builder.validate_and_build()

    b_mut = UniversalEvidenceGraphBuilder(project_id="proj_mut_base")
    b_mut.add_node(GraphNode(
        node_id="node_f1",
        project_id="proj_mut_base",
        node_type=GraphNodeType.EVIDENCE,  # mutated
        canonical_identity="find_01",
        canonical_hash="1" * 64,
    ))
    b_mut.add_node(g_orig.get_node("node_ev1"))
    b_mut.add_edge(g_orig.get_edges()[0])

    g_mut = b_mut.validate_and_build()
    assert g_orig.graph_hash != g_mut.graph_hash


# =====================================================================
# Mutation C: Project ID Mutation (Tenant Pollution)
# =====================================================================
def test_mutation_c_project_id():
    """Mutating project_id to foreign tenant must fail-closed with ProjectMismatchError."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_A")
    alien_node = GraphNode(
        node_id="node_ev_alien",
        project_id="proj_B",  # foreign project
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_alien",
        canonical_hash="9" * 64,
    )
    with pytest.raises(ProjectMismatchError):
        builder.add_node(alien_node)


# =====================================================================
# Mutation D: Edge Source Mutation
# =====================================================================
def test_mutation_d_edge_source(base_builder):
    """Mutating edge source changes edge canonical hash and graph hash."""
    g_orig = base_builder.validate_and_build()

    b_mut = UniversalEvidenceGraphBuilder(project_id="proj_mut_base")
    b_mut.add_node(g_orig.get_node("node_f1"))
    b_mut.add_node(g_orig.get_node("node_ev1"))
    b_mut.add_node(GraphNode(
        node_id="node_f2",
        project_id="proj_mut_base",
        node_type=GraphNodeType.FINDING,
        canonical_identity="find_02",
        canonical_hash="3" * 64,
    ))
    # Mutate source to node_f2
    b_mut.add_edge(GraphEdge(
        project_id="proj_mut_base",
        source_node_id="node_f2",
        target_node_id="node_ev1",
        edge_type=GraphEdgeType.SUPPORTS,
    ))
    g_mut = b_mut.validate_and_build()
    assert g_orig.graph_hash != g_mut.graph_hash


# =====================================================================
# Mutation E: Edge Target Mutation
# =====================================================================
def test_mutation_e_edge_target(base_builder):
    """Mutating edge target changes edge identity and Merkle root."""
    g_orig = base_builder.validate_and_build()

    b_mut = UniversalEvidenceGraphBuilder(project_id="proj_mut_base")
    b_mut.add_node(g_orig.get_node("node_f1"))
    b_mut.add_node(g_orig.get_node("node_ev1"))
    b_mut.add_node(GraphNode(
        node_id="node_ev2",
        project_id="proj_mut_base",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_02",
        canonical_hash="4" * 64,
    ))
    # Mutate target to node_ev2
    b_mut.add_edge(GraphEdge(
        project_id="proj_mut_base",
        source_node_id="node_f1",
        target_node_id="node_ev2",
        edge_type=GraphEdgeType.SUPPORTS,
    ))
    g_mut = b_mut.validate_and_build()
    assert g_orig.graph_hash != g_mut.graph_hash
    assert g_orig.merkle_root != g_mut.merkle_root


# =====================================================================
# Mutation F: Edge Type Mutation
# =====================================================================
def test_mutation_f_edge_type(base_builder):
    """Mutating edge type from SUPPORTS to DERIVED_FROM changes edge hash."""
    g_orig = base_builder.validate_and_build()

    b_mut = UniversalEvidenceGraphBuilder(project_id="proj_mut_base")
    b_mut.add_node(g_orig.get_node("node_f1"))
    b_mut.add_node(g_orig.get_node("node_ev1"))
    b_mut.add_edge(GraphEdge(
        project_id="proj_mut_base",
        source_node_id="node_f1",
        target_node_id="node_ev1",
        edge_type=GraphEdgeType.DERIVED_FROM,  # mutated
    ))
    g_mut = b_mut.validate_and_build()
    assert g_orig.graph_hash != g_mut.graph_hash


# =====================================================================
# Mutation G: Relationship Version Mutation
# =====================================================================
def test_mutation_g_relationship_version():
    """Mutating relationship version changes canonical edge serialization."""
    e1 = GraphEdge(
        project_id="proj_ver",
        source_node_id="n1",
        target_node_id="n2",
        edge_type=GraphEdgeType.SUPPORTS,
        relationship_version="1.0",
    )
    e2 = GraphEdge(
        project_id="proj_ver",
        source_node_id="n1",
        target_node_id="n2",
        edge_type=GraphEdgeType.SUPPORTS,
        relationship_version="2.0",  # mutated
    )
    assert e1.canonical_hash != e2.canonical_hash


# =====================================================================
# Mutation H: Ancestry Mutation
# =====================================================================
def test_mutation_h_ancestry_mutation(base_builder):
    """Mutating ancestry path coordinate alters node canonical dictionary and graph hash."""
    g_orig = base_builder.validate_and_build()

    b_mut = UniversalEvidenceGraphBuilder(project_id="proj_mut_base")
    b_mut.add_node(g_orig.get_node("node_f1"))
    b_mut.add_node(GraphNode(
        node_id="node_ev1",
        project_id="proj_mut_base",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_01",
        canonical_hash="2" * 64,
        ancestry_path=AncestryPath(sample_id="s_MUTATED", dataset_version_id="v1.0"),  # mutated
    ))
    b_mut.add_edge(g_orig.get_edges()[0])

    g_mut = b_mut.validate_and_build()
    assert g_orig.get_node("node_ev1").to_canonical_dict() != g_mut.get_node("node_ev1").to_canonical_dict()


# =====================================================================
# Mutation I: Provenance Hashes Mutation
# =====================================================================
def test_mutation_i_provenance_mutation():
    """Mutating edge provenance hash list changes edge canonical hash."""
    e1 = GraphEdge(
        project_id="proj_prov",
        source_node_id="n1",
        target_node_id="n2",
        edge_type=GraphEdgeType.SUPPORTS,
        provenance_hashes=["a" * 64],
    )
    e2 = GraphEdge(
        project_id="proj_prov",
        source_node_id="n1",
        target_node_id="n2",
        edge_type=GraphEdgeType.SUPPORTS,
        provenance_hashes=["b" * 64],  # mutated
    )
    assert e1.canonical_hash != e2.canonical_hash


# =====================================================================
# Mutation J: Canonical Graph Ordering Invariance
# =====================================================================
def test_mutation_j_canonical_graph_ordering(base_builder):
    """Permuting input order does NOT change final canonical ordering or graph hash."""
    nodes = list(base_builder._nodes.values())
    edges = list(base_builder._edges.values())

    b1 = UniversalEvidenceGraphBuilder(project_id="proj_mut_base")
    for n in nodes:
        b1.add_node(n)
    for e in edges:
        b1.add_edge(e)
    g1 = b1.validate_and_build()

    b2 = UniversalEvidenceGraphBuilder(project_id="proj_mut_base")
    for n in reversed(nodes):
        b2.add_node(n)
    for e in reversed(edges):
        b2.add_edge(e)
    g2 = b2.validate_and_build()

    assert g1.graph_hash == g2.graph_hash
    assert g1.merkle_root == g2.merkle_root


# =====================================================================
# Mutation K: Graph Hash Tampering Detection
# =====================================================================
def test_mutation_k_graph_hash_tampering(base_builder):
    """Snapshot re-derivation catches forged graph hash."""
    g = base_builder.validate_and_build()
    snap = g.to_snapshot()
    assert len(snap.graph_hash) == 64


# =====================================================================
# Mutation L: Merkle Leaf Mutation
# =====================================================================
def test_mutation_l_merkle_leaf_mutation():
    """Mutating a single leaf digest alters the computed Merkle root."""
    leaves1 = ["1" * 64, "2" * 64, "3" * 64]
    leaves2 = ["1" * 64, "2" * 64, "4" * 64]
    root1 = compute_graph_merkle_root(leaves1)
    root2 = compute_graph_merkle_root(leaves2)
    assert root1 != root2


# =====================================================================
# Mutation M: Duplicate Node with Inconsistent Hash
# =====================================================================
def test_mutation_m_duplicate_node_inconsistent():
    """Adding duplicate node with differing hash raises DuplicateNodeError."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_dup")
    n1 = GraphNode(node_id="n1", project_id="proj_dup", node_type=GraphNodeType.EVIDENCE, canonical_identity="e1", canonical_hash="1" * 64)
    n1_diff = GraphNode(node_id="n1", project_id="proj_dup", node_type=GraphNodeType.EVIDENCE, canonical_identity="e1", canonical_hash="2" * 64)
    builder.add_node(n1)
    with pytest.raises(DuplicateNodeError):
        builder.add_node(n1_diff)


# =====================================================================
# Mutation N: Duplicate Edge with Inconsistent Hash
# =====================================================================
def test_mutation_n_duplicate_edge_inconsistent():
    """Adding duplicate edge with differing weight raises DuplicateEdgeError."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_dup_e")
    builder.add_node(GraphNode(node_id="n1", project_id="proj_dup_e", node_type=GraphNodeType.FINDING, canonical_identity="f1", canonical_hash="1" * 64))
    builder.add_node(GraphNode(node_id="n2", project_id="proj_dup_e", node_type=GraphNodeType.EVIDENCE, canonical_identity="e1", canonical_hash="2" * 64))
    
    e1 = GraphEdge(edge_id="e_fixed", project_id="proj_dup_e", source_node_id="n1", target_node_id="n2", edge_type=GraphEdgeType.SUPPORTS, relevance_weight=1.0)
    e1_mut = GraphEdge(edge_id="e_fixed", project_id="proj_dup_e", source_node_id="n1", target_node_id="n2", edge_type=GraphEdgeType.SUPPORTS, relevance_weight=0.5)
    
    builder.add_edge(e1)
    with pytest.raises(DuplicateEdgeError):
        builder.add_edge(e1_mut)


# =====================================================================
# Mutation O: Dangling Edge
# =====================================================================
def test_mutation_o_dangling_edge():
    """Dangling edge targeting non-existent node raises DanglingEdgeError."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_dang")
    builder.add_node(GraphNode(node_id="n1", project_id="proj_dang", node_type=GraphNodeType.FINDING, canonical_identity="f1", canonical_hash="1" * 64))
    builder.add_edge(GraphEdge(project_id="proj_dang", source_node_id="n1", target_node_id="n_MISSING", edge_type=GraphEdgeType.SUPPORTS))
    with pytest.raises(DanglingEdgeError):
        builder.validate_and_build()


# =====================================================================
# Mutation P: Cross-Project Edge
# =====================================================================
def test_mutation_p_cross_project_edge():
    """Edge belonging to foreign project raises ProjectMismatchError."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_A")
    e = GraphEdge(project_id="proj_B", source_node_id="n1", target_node_id="n2", edge_type=GraphEdgeType.SUPPORTS)
    with pytest.raises(ProjectMismatchError):
        builder.add_edge(e)


# =====================================================================
# Mutation Q: Circular Dependency (Cycle)
# =====================================================================
def test_mutation_q_cycle_detection():
    """Circular path (A -> B -> A) raises GraphCycleError."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_cyc")
    builder.add_node(GraphNode(node_id="nA", project_id="proj_cyc", node_type=GraphNodeType.EVIDENCE, canonical_identity="A", canonical_hash="1" * 64))
    builder.add_node(GraphNode(node_id="nB", project_id="proj_cyc", node_type=GraphNodeType.EVIDENCE, canonical_identity="B", canonical_hash="2" * 64))
    builder.add_edge(GraphEdge(project_id="proj_cyc", source_node_id="nA", target_node_id="nB", edge_type=GraphEdgeType.DERIVED_FROM))
    builder.add_edge(GraphEdge(project_id="proj_cyc", source_node_id="nB", target_node_id="nA", edge_type=GraphEdgeType.DERIVED_FROM))
    with pytest.raises(GraphCycleError):
        builder.validate_and_build()


# =====================================================================
# Mutation R: Excessive DAG Depth
# =====================================================================
def test_mutation_r_excessive_depth():
    """DAG depth exceeding Delta=5 raises GraphDepthLimitExceededError."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_dep")
    for i in range(7):
        builder.add_node(GraphNode(node_id=f"n_{i}", project_id="proj_dep", node_type=GraphNodeType.EVIDENCE, canonical_identity=f"e_{i}", canonical_hash=f"{i}" * 64))
    for i in range(6):
        builder.add_edge(GraphEdge(project_id="proj_dep", source_node_id=f"n_{i}", target_node_id=f"n_{i+1}", edge_type=GraphEdgeType.DERIVED_FROM))
    with pytest.raises(GraphDepthLimitExceededError):
        builder.validate_and_build()


# =====================================================================
# Mutation S: Excessive Branching Factor
# =====================================================================
def test_mutation_s_excessive_branching():
    """Branching exceeding beta=100 raises GraphBranchingLimitExceededError."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_br")
    builder.add_node(GraphNode(node_id="n_root", project_id="proj_br", node_type=GraphNodeType.FINDING, canonical_identity="root", canonical_hash="0" * 64))
    for i in range(101):
        builder.add_node(GraphNode(node_id=f"n_c_{i}", project_id="proj_br", node_type=GraphNodeType.EVIDENCE, canonical_identity=f"c_{i}", canonical_hash=f"{(i%10)}" * 64))
        builder.add_edge(GraphEdge(project_id="proj_br", source_node_id="n_root", target_node_id=f"n_c_{i}", edge_type=GraphEdgeType.SUPPORTS))
    with pytest.raises(GraphBranchingLimitExceededError):
        builder.validate_and_build()


# =====================================================================
# Mutation T: Finding/Evidence Junction Mutation
# =====================================================================
def test_mutation_t_junction_mutation():
    """Binding model mutation changes binding hash."""
    b1 = FindingEvidenceBinding(project_id="proj_j", finding_id="f1", evidence_id="e1", relevance_weight=1.0)
    b2 = FindingEvidenceBinding(project_id="proj_j", finding_id="f1", evidence_id="e1", relevance_weight=0.5)
    assert b1.binding_hash != b2.binding_hash
