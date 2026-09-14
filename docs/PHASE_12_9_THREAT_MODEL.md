# PHASE 12.9 — THREAT MODEL & SECURITY EVALUATION

**Author:** DeepMind Antigravity Pair Programmer  
**Phase:** 12.9 — Project & Multi-Asset Risk Aggregation  
**Status:** THREAT MODEL FROZEN  

---

## 1. Threat Taxonomy & Mitigations

| Threat ID | Threat Category | Threat Description | Mitigation Strategy |
| :--- | :--- | :--- | :--- |
| `THREAT-12-AGG-001` | Lineage Manipulation | Attacker introduces cyclic or self-referencing dependency edges to cause infinite loops or corrupt risk calculations. | Strict DFS visited-path cycle validation; immediate `DependencyCycleError` fail-closed. |
| `THREAT-12-AGG-002` | Cross-Asset Leakage | Risk from an unrelated, high-risk asset silently contaminates independent healthy assets. | Enforce strict asset isolation; propagation occurs exclusively along explicit directed edges. |
| `THREAT-12-AGG-003` | Cross-Project Contamination | Adversary submits multi-asset graph linking assets across different project IDs to bleed risk or bypass tenant boundaries. | Mandatory `project_id` matching on every asset node and dependency edge; rejects foreign entities. |
| `THREAT-12-AGG-004` | Proof Failure Masking | Attacker bundles multiple low-risk assets to average away or compensate for an authoritative cryptographic proof failure. | Proof non-compensability; core asset proof failure triggers unconditional project $\mathbf{REJECT}$. |
| `THREAT-12-AGG-005` | Double Counting Vulnerability | Multiple findings/evidence derived from a single underlying incident are counted as independent risks. | Ancestry path clustering collapses shared root causes; intra-cluster damping ($\lambda_{\text{intra}}$) applied. |
| `THREAT-12-AGG-006` | Peak Risk Dilution | A catastrophic defect on a core model ($R=1.0$) is diluted by many minor peripheral assets. | Peak dominance formulation: $R_{\text{project}} = 1 - (1 - \max R(A))^{\alpha_{\text{peak}}} \cdot \prod (1 - \lambda_{\text{inter}} R(A))$. |
| `THREAT-12-AGG-007` | Resource Exhaustion (DoS) | Attacker submits a graph with thousands of nodes, deep recursive chains, or dense edges. | Enforce global ceilings: `MAX_PROJECT_ASSETS = 500`, `MAX_CHAIN_DEPTH = 5`, `MAX_DEPENDENCY_EDGES = 2,000`. |
| `THREAT-12-AGG-008` | Non-Deterministic Ordering | Unordered dictionary or set iteration alters the computed canonical hash between identical evaluations. | Strict lexicographical sorting on all IDs, edges, paths, and contributions before hashing. |
| `THREAT-12-AGG-009` | Numerical State Corruption | Internal calculations produce `NaN`, `Inf`, or scores outside $[0.0, 1.0]$. | Pydantic validators and IEEE-754 checks; fail-closed with `NonFiniteRiskError` or `RiskOutOfRangeError`. |
| `THREAT-12-AGG-010` | Role Spoofing | Adversary flags a production core model as a peripheral sample to evade project-level $\mathbf{REJECT}$. | Asset roles are explicitly defined in configuration/metadata and verified during graph ingestion. |
| `THREAT-12-AGG-011` | Phantom Chain Injection | Unlinked assets are erroneously treated as a chain due to shared contributor, timestamp, or domain. | Chains are identified strictly through verified `GraphEdgeType.LINEAGE`/`DEPENDS_ON`/`DERIVED_FROM` edges. |
| `THREAT-12-AGG-012` | Hash Collision / Desync | Assessment results are modified without invalidating the cryptographic hash. | Deterministic content addressing using RFC 8785 JCS + SHA-256 over all security-relevant fields. |
| `THREAT-12-AGG-013` | Attenuation Abuse | Downstream propagation is attenuated to zero, masking serious upstream training set contamination. | Monotonic lower bound on lineage compounding: $R_{\text{chain}} = \gamma_{\text{prop}} \cdot R(A_{\text{src}}) \cdot R(A_{\text{tgt}})$. |
| `THREAT-12-AGG-014` | Fail-Open Fallback | Disconnected or unresolvable asset dependencies produce an empty or passing risk evaluation. | Unresolved targets trigger immediate `AggregationError` fail-closed. |
| `THREAT-12-AGG-015` | External Network Exfiltration | Engine attempts remote lookup or telemetry under load. | 100% offline air-gapped guarantees; static analysis confirms zero network imports. |
| `THREAT-12-AGG-016` | Dynamic Code Execution | Malicious payloads in metadata trigger code execution. | AST scanner verifies complete absence of `eval()`, `exec()`, and `subprocess`. |
