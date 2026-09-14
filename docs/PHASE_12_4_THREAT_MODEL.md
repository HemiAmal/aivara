# PHASE 12.4 — HIERARCHICAL MULTI-ASSET RISK AGGREGATION THREAT MODEL

## 1. Threat Identification & Mitigation Matrix

| Threat ID | Threat Vector | Impact | Mitigation in Phase 12.4 |
| :--- | :--- | :--- | :--- |
| **THREAT-12.4-01** | Risk Score Inflation | False alarm / denial of service. | Sub-additive saturation $R = 1 - \prod(1 - S_k)$ + intra-cluster damping $\lambda_{\text{intra}}$. |
| **THREAT-12.4-02** | Risk Score Suppression | Unsafe model deployed undetected. | Dominance-preserving peak exponent $\alpha_{\text{peak}} \ge 1.0$ guarantees project score reflects worst asset. |
| **THREAT-12.4-03** | Shared Evidence Double-Counting | Artificially inflated risk from multi-detector reports. | Ancestry collapse groups evidence sharing identical ancestry keys into a single cluster. |
| **THREAT-12.4-04** | Non-Finite Value Injection (NaN/Inf) | System crash, undefined behavior. | Pydantic validators + explicit checks reject `NaN`/`Inf` fail-closed with `NonFiniteRiskError`. |
| **THREAT-12.4-05** | Out-of-Range Risk Injection ($R < 0$ or $R > 1$) | Inconsistent policy decisions. | Bounds validation rejects $R \notin [0.0, 1.0]$ with `RiskOutOfRangeError`. |
| **THREAT-12.4-06** | Cross-Project Tenant Contamination | Data leak or tenant pollution. | Graph builder enforce strict `project_id` matching on every envelope and node. |
| **THREAT-12.4-07** | Non-Deterministic Ordering Attack | Inconsistent audit trail across runs. | Lexicographical canonical sorting across nodes, edges, assets, and clusters. |
| **THREAT-12.4-08** | In-Memory Model Mutation | Tampering with in-flight assessment results. | `ConfigDict(frozen=True)` on all Pydantic V2 schemas ensures strict immutability. |
| **THREAT-12.4-09** | Configuration Substitution Attack | Tampered damping factors change scores silently. | `config_hash` computed via RFC 8785 JCS is bound into the final `hierarchical_hash`. |
| **THREAT-12.4-10** | Premature Correlation / Proof Leak | Architectural divergence before certification. | Static source audit confirms 0 correlation matrix or proof override logic in `universal.risk`. |
