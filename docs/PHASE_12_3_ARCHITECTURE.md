# PHASE 12.3 — EVIDENCE GRAPH & N:M FINDING-EVIDENCE JUNCTION ENGINE ARCHITECTURE

## 1. Executive Summary

Phase 12.3 establishes the authoritative **Universal Evidence Graph** and **N:M Finding-Evidence Junction Engine** for the AIVARA verification workstation.

Building on top of the frozen Phase 12.2 `UniversalEvidenceEnvelope` contracts, Phase 12.3 transforms normalized evidence items, finding linkages, and upstream cross-domain ancestral relationships into a deterministic, tenant-isolated, cycle-free in-memory Directed Acyclic Graph (DAG) with an additive SQLite persistence layer for N:M finding-evidence bindings.

---

## 2. Core Architecture Principles

1. **Strict Directed Acyclic Graph (DAG)**:
   - Cycle detection is performed using depth-first search (DFS) 3-color state tracking (`UNVISITED`, `VISITING`, `VISITED`) in $O(|V| + |E|)$ time.
   - Self-referential edges ($u \to u$) and complex multi-node circular paths are detected and rejected fail-closed with `GraphCycleError`.
   - Diamond structures, convergent paths, and legitimate N:M finding-evidence associations are preserved without false-positive cycle errors.

2. **Hard Resource Ceilings & Structural Governance**:
   - Graph Depth Ceiling: $\Delta_{\max} \le 5$ (`GraphDepthLimitExceededError`).
   - Node Branching Factor: $\beta_{\max} \le 100$ (`GraphBranchingLimitExceededError`).
   - Evidence Envelope Capacity: $E_{\max} = 5,000$.
   - Finding Node Capacity: $F_{\max} = 1,000$.

3. **Multi-Tenant Isolation**:
   - Strict `project_id` scoping across all nodes, edges, bindings, and query primitives.
   - Any attempt to introduce foreign-tenant nodes or edges raises `ProjectMismatchError`.

4. **Cryptographic Content Addressing & Determinism**:
   - Node identity hashes and canonical JSON representations conform to RFC 8785 JSON Canonicalization Scheme (JCS).
   - Graph-level deterministic hash `graph_hash` computed over canonically sorted node and edge hashes.
   - Binary Merkle tree root `merkle_root` computed over canonical leaf hashes with bit-exact reproducibility across arbitrary insertion permutations.

5. **Additive, Non-Breaking N:M Persistence**:
   - SQLite ORM entity `finding_evidence` (`FindingEvidenceModel`) with unique constraint on `(finding_id, evidence_id, relationship_type)`.
   - 100% backward compatibility with Phase 0–11 SQLite schemas.

6. **Strict Subsystem Boundary Separation**:
   - Phase 12.3 is exclusively a **graph topology, relation mapping, and persistence layer**.
   - No universal risk score calculation, hierarchical risk aggregation, correlation damping, or disposition logic is implemented (deferred to Phase 12.4+).

---

## 3. Component Architecture

```
                                  +---------------------------------------+
                                  |    Phase 12.2 Normalized Envelopes    |
                                  +---------------------------------------+
                                                     |
                                                     v
+------------------------+        +---------------------------------------+
|  Authoritative Finding | -----> |     UniversalEvidenceGraphBuilder     |
|   Records & Bindings   |        |  (Tenant checks, DFS Cycle Detection, |
+------------------------+        |    Depth & Branching Governance)      |
                                  +---------------------------------------+
                                                     |
                                                     v
                                  +---------------------------------------+
                                  |        UniversalEvidenceGraph         |
                                  |  - In-Memory Validated DAG            |
                                  |  - Query Primitives & Ancestry Index  |
                                  |  - RFC 8785 JCS Graph Hash            |
                                  |  - Binary Merkle Tree Root            |
                                  +---------------------------------------+
                                                     |
                                                     v
                                  +---------------------------------------+
                                  |   finding_evidence Junction Table     |
                                  |     (Additive SQLite Persistence)     |
                                  +---------------------------------------+
```

---

## 4. Module Layout

- `backend/aivara/universal/graph/enums.py`: Enumerations for node types, edge types, and schema versions.
- `backend/aivara/universal/graph/exceptions.py`: Fail-closed exceptions for cycles, dangling edges, duplicates, and ceiling violations.
- `backend/aivara/universal/graph/schemas.py`: Pydantic V2 immutable contracts for `GraphNode`, `GraphEdge`, `FindingEvidenceBinding`, and `UniversalEvidenceGraphSnapshot`.
- `backend/aivara/universal/graph/merkle.py`: Deterministic binary Merkle tree engine for leaf digestion and root derivation.
- `backend/aivara/universal/graph/graph.py`: Validated in-memory `UniversalEvidenceGraph` class providing adjacency indices and traversal queries.
- `backend/aivara/universal/graph/builder.py`: `UniversalEvidenceGraphBuilder` coordinating envelope ingestion, cycle detection, depth analysis, and snapshot compilation.
- `backend/aivara/database/models.py`: Additive `FindingEvidenceModel` for persistent N:M finding-evidence bindings.
