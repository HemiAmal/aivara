# PHASE 12.9 — REQUIREMENTS SPECIFICATION

**Author:** DeepMind Antigravity Pair Programmer  
**Phase:** 12.9 — Project & Multi-Asset Risk Aggregation  
**Status:** REQUIREMENTS FROZEN  

---

## 1. Functional Requirements

| Requirement ID | Name | Description | Verification Method |
| :--- | :--- | :--- | :--- |
| `REQ-12-AGG-001` | Three-Tier Model | System must evaluate risk at Tier 1 (Asset), Tier 2 (Chain), and Tier 3 (Project). | Unit / Integration Test |
| `REQ-12-AGG-002` | Asset Isolation | Unrelated assets must not contaminate each other's risk evaluations ($R(B)$ unchanged by $R(A)$). | Unit Test |
| `REQ-12-AGG-003` | Explicit Lineage Propagation | Downstream risk increases if and only if an explicit DAG dependency edge connects $A_{\text{src}} \to A_{\text{tgt}}$. | Unit Test |
| `REQ-12-AGG-004` | DAG Strictness & Cycle Rejection | All asset dependency structures must be strictly acyclic; cycles fail closed with `DependencyCycleError`. | Unit Test |
| `REQ-12-AGG-005` | Chain Identification | Chains must be deterministically discovered from explicit graph edges ($A \to B \to C$). | Unit Test |
| `REQ-12-AGG-006` | Bounded Risk Composition | All risk outputs must be bounded in $[0.0, 1.0]$ via sub-additive monotonic formulations. | Property Test |
| `REQ-12-AGG-007` | Monotonicity | Increasing constituent asset risk must monotonically non-decrease chain and project risk scores. | Property Test |
| `REQ-12-AGG-008` | Peak Dominance Preservation | Project risk formula must prioritize the maximum asset risk ($R_{\text{project}} = 1 - (1 - \max R(A))^{\alpha_{\text{peak}}} \cdot \prod (1 - \lambda_{\text{inter}} R(A))$). | Unit Test |
| `REQ-12-AGG-009` | No Double Counting | Identical underlying ancestry paths must be collapsed to prevent duplicate risk multiplication. | Unit Test |
| `REQ-12-AGG-010` | Core Asset Proof Escalation | Proof failure on a `CORE_DEPLOYED` asset must escalate project-level disposition to $\mathbf{REJECT}$. | Integration Test |
| `REQ-12-AGG-011` | Peripheral Asset Proof Escalation | Proof failure on a `PERIPHERAL_SAMPLE` asset must reject the asset and escalate project to at least $\mathbf{QUARANTINE}$. | Integration Test |
| `REQ-12-AGG-012` | Proof Non-Compensability | Cryptographic proof failures cannot be averaged away or compensated by low detection risk. | Unit Test |
| `REQ-12-AGG-013` | Cross-Project Isolation | Assessments for Project P1 must not access or affect assets belonging to Project P2. | Security Test |
| `REQ-12-AGG-014` | Canonical Content-Addressed Hash | All outputs must compute deterministic hashes via RFC 8785 JCS + SHA-256. | Determinism Test |
| `REQ-12-AGG-015` | Hash Mutation Sensitivity | Any mutation to risk scores, edges, roles, or proof states must change the resulting hash. | Mutation Test |
| `REQ-12-AGG-016` | Deterministic Ordering | All iteration, serialization, and aggregation must use canonical lexicographical sorting. | Determinism Test |
| `REQ-12-AGG-017` | Fail-Closed Architecture | Malformed inputs, out-of-bounds risks, or disconnected targets must fail closed. | Error Handling Test |
| `REQ-12-AGG-018` | Bounded Resource Ceilings | Enforce `MAX_PROJECT_ASSETS = 500`, `MAX_CHAIN_DEPTH = 5`, `MAX_DEPENDENCY_EDGES = 2,000`. | Resource Limit Test |
| `REQ-12-AGG-019` | 100% Offline Air-Gapped Operation | Zero network operations, telemetry, or external services. | Static Code Scan |
| `REQ-12-AGG-020` | AST Security & Dynamic Code Prohibition | Zero `eval()`, `exec()`, `os.system()`, or arbitrary dynamic code execution. | AST Security Scan |
