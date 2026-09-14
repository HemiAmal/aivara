# PHASE 12.3 — EVIDENCE GRAPH & N:M FINDING-EVIDENCE JUNCTION THREAT MODEL

## 1. Threat Identification & Mitigation Matrix

| Threat ID | Threat Name | Attack / Failure Vector | Impact | Mitigation in Phase 12.3 |
| :--- | :--- | :--- | :--- | :--- |
| **THREAT-12.3-01** | Graph Cycle DoS / Infinite Recursion | Adversary injects cyclic parent-child evidence links ($A \to B \to A$) to crash graph traversal. | Service hang, stack overflow, DoS. | DFS 3-color cycle detection runs in $O(\|V\| + \|E\|)$ before graph compilation and raises `GraphCycleError`. |
| **THREAT-12.3-02** | Deep Graph Tree Bomb | Malicious actor constructs a linear chain of hundreds of derived evidence items to exhaust memory/recursion. | Resource exhaustion. | Hard depth ceiling $\Delta \le 5$ enforced via longest-path computation; raises `GraphDepthLimitExceededError`. |
| **THREAT-12.3-03** | Fan-Out Branching Bomb | Adversary binds 10,000 evidence items to a single node. | Memory exhaustion during adjacency queries. | Hard branching ceiling $\beta \le 100$ enforced per node; raises `GraphBranchingLimitExceededError`. |
| **THREAT-12.3-04** | Cross-Tenant Graph Pollution | Attacker injects nodes or edges from Tenant B into Tenant A's graph builder. | Data leak, unauthorized correlation. | Strict `project_id` matching on every node, edge, and binding; raises `ProjectMismatchError`. |
| **THREAT-12.3-05** | Dangling Relationship Manipulation | Edges reference fabricated or deleted node IDs to bypass integrity checks. | Inconsistent state, corrupted proofs. | Fail-closed graph validation checks that all source and target nodes exist in the graph; raises `DanglingEdgeError`. |
| **THREAT-12.3-06** | Graph Hash / Merkle Root Desynchronization | Non-deterministic dict or list ordering leads to divergent graph hashes on different machines. | Unverifiable audit trail, broken reproducibility. | Strict RFC 8785 JCS canonicalization and lexicographical sorting of node and edge hashes before Merkle computation. |
| **THREAT-12.3-07** | Premature Risk Computation Leak | Unverified risk score calculation introduced before formal aggregation design in Phase 12.4. | Architectural divergence, uncertified metrics. | Strict isolation: Phase 12.3 is limited to graph topology and persistence only. |
| **THREAT-12.3-08** | Database Migration Breaking Change | Schema change modifies or drops existing Phase 0–11 columns. | System downtime, broken regressions. | Additive-only `finding_evidence` table creation using standard SQLite ORM metadata. |
