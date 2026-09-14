# PHASE 12.3 — EVIDENCE GRAPH & N:M FINDING-EVIDENCE JUNCTION VERIFICATION PLAN

## 1. Scope of Verification

The Phase 12.3 verification suite exercises:
1. In-memory DAG construction and canonical identity generation.
2. DFS 3-coloring cycle detection ($O(V + E)$).
3. Complex valid topologies (diamond structures, multi-parent evidence, N:M associations).
4. Fail-closed rejection of dangling edges and foreign project identifiers.
5. Resource governance enforcement ($\Delta \le 5$, $\beta \le 100$, $E_{\max} \le 5000$, $F_{\max} \le 1000$).
6. Bit-exact reproducibility of RFC 8785 JCS `graph_hash` and SHA-256 binary `merkle_root` under permutation.
7. Merkle root mutation avalanche effect.
8. Additive SQLite `finding_evidence` junction table persistence and unique constraint handling.
9. 100% offline air-gap enforcement with zero network sockets.
10. Full repository non-regression across Phase 0–11 and Phase 12.2 test suites.

---

## 2. Test Matrix

| Test Case | Module | Description |
| :--- | :--- | :--- |
| `test_graph_builder_basic_construction` | `test_evidence_graph.py` | Validates node and edge construction from normalized envelopes. |
| `test_graph_with_derived_evidence_edges` | `test_evidence_graph.py` | Validates DERIVED_FROM parent-child edge traversal. |
| `test_self_cycle_rejected` | `test_evidence_graph.py` | Asserts self-loop ($A \to A$) raises `GraphCycleError`. |
| `test_multi_node_cycle_rejected` | `test_evidence_graph.py` | Asserts circular loop ($A \to B \to C \to A$) raises `GraphCycleError`. |
| `test_legitimate_nm_diamond_not_rejected_as_cycle` | `test_evidence_graph.py` | Validates diamond pattern ($F_1, F_2 \times E_1, E_2$) builds cleanly. |
| `test_dangling_edge_rejected` | `test_evidence_graph.py` | Asserts non-existent target raises `DanglingEdgeError`. |
| `test_cross_project_node_rejected` | `test_evidence_graph.py` | Asserts foreign project node raises `ProjectMismatchError`. |
| `test_cross_project_edge_rejected` | `test_evidence_graph.py` | Asserts foreign project edge raises `ProjectMismatchError`. |
| `test_deterministic_graph_hashing_and_merkle` | `test_evidence_graph.py` | Asserts permutation invariance of hashes and Merkle root. |
| `test_merkle_root_mutation_sensitivity` | `test_evidence_graph.py` | Asserts single node alteration produces distinct Merkle root. |
| `test_dag_depth_ceiling_enforced` | `test_evidence_graph.py` | Asserts depth $> 5$ raises `GraphDepthLimitExceededError`. |
| `test_branching_factor_ceiling_enforced` | `test_evidence_graph.py` | Asserts branching $> 100$ raises `GraphBranchingLimitExceededError`. |
| `test_ancestry_cluster_query` | `test_evidence_graph.py` | Validates multi-domain ancestry clustering query. |
| `test_graph_100_percent_offline_no_sockets` | `test_evidence_graph.py` | Verifies execution with guarded socket module. |
| `test_finding_evidence_nm_persistence` | `test_finding_evidence_junction.py` | Validates SQLite ORM CRUD operations for N:M bindings. |
| `test_finding_evidence_unique_constraint` | `test_finding_evidence_junction.py` | Validates unique composite key constraint on bindings. |
