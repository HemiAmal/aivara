# PHASE 12.3 — EVIDENCE GRAPH & N:M FINDING-EVIDENCE JUNCTION REQUIREMENTS

## 1. Functional Requirements

- **REQ-12.3-01: In-Memory DAG Representation**: The system MUST construct an immutable, directed acyclic graph representing normalized evidence envelopes and finding nodes.
- **REQ-12.3-02: Strict Cycle Detection**: The system MUST perform cycle detection via DFS 3-color traversal and reject cyclic graphs with `GraphCycleError`.
- **REQ-12.3-03: Diamond & Multi-Parent Acceptance**: The system MUST accept valid DAG topologies including diamond patterns, convergent paths, and multi-parent evidence without false-positive cycle errors.
- **REQ-12.3-04: Dangling Edge Rejection**: Edges referencing non-existent source or target node IDs MUST be rejected fail-closed with `DanglingEdgeError`.
- **REQ-12.3-05: N:M Finding-Evidence Junction Persistence**: The system MUST persist finding-evidence associations in SQLite table `finding_evidence` with a composite unique constraint on `(finding_id, evidence_id, relationship_type)`.
- **REQ-12.3-06: Graph Query Primitives**: The graph MUST expose canonical query methods:
  - `get_evidence_for_finding(finding_id)`
  - `get_findings_for_evidence(evidence_id)`
  - `get_derived_evidence(evidence_id)`
  - `get_parent_evidence(evidence_id)`
  - `get_ancestry_cluster(ancestry_path)`
- **REQ-12.3-07: Deterministic Graph Hashing & Merkle Root**: The graph MUST compute RFC 8785 JCS canonical `graph_hash` and a binary SHA-256 `merkle_root` invariant to node/edge insertion order.

---

## 2. Non-Functional & Governance Requirements

- **REQ-12.3-08: Maximum Graph Depth**: Maximum DAG path length MUST NOT exceed $\Delta_{\max} \le 5$. Graphs exceeding this depth MUST raise `GraphDepthLimitExceededError`.
- **REQ-12.3-09: Maximum Node Branching Factor**: Out-degree branching per node MUST NOT exceed $\beta_{\max} \le 100$. Nodes exceeding this limit MUST raise `GraphBranchingLimitExceededError`.
- **REQ-12.3-10: Evidence and Finding Capacity**: Ingestion limits of $E_{\max} = 5,000$ evidence items and $F_{\max} = 1,000$ findings per graph build MUST be enforced.
- **REQ-12.3-11: Multi-Tenant Isolation**: Nodes and edges MUST belong to the graph's `project_id`. Mismatched foreign identifiers MUST raise `ProjectMismatchError`.
- **REQ-12.3-12: Offline Air-Gapped Operation**: Graph construction and persistence operations MUST run 100% offline with zero outbound network calls.
- **REQ-12.3-13: Frozen Phase 0–11 Invariance**: Phase 0 through Phase 11 production behavior and existing tables MUST remain strictly unmodified and functional.
- **REQ-12.3-14: Risk Computation Prohibition**: Phase 12.3 MUST NOT calculate universal risk scores, dampen cross-domain correlations, or produce project dispositions.
