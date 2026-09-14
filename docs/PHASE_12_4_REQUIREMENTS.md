# PHASE 12.4 — HIERARCHICAL MULTI-ASSET RISK AGGREGATION REQUIREMENTS

## 1. Functional Requirements

- **REQ-12.4-01: Asset-Level Risk Aggregation**: The engine MUST calculate bounded operational risk $R(A) \in [0.0, 1.0]$ for each target asset using ancestry-aware clustering and sub-additive saturation.
- **REQ-12.4-02: Intra-Cluster Damping**: Evidence sharing primary ancestry coordinates MUST be collapsed into a single modality cluster with intra-cluster damping $\lambda_{\text{intra}} = 0.15$.
- **REQ-12.4-03: Lineage Chain Compounding**: The engine MUST calculate pairwise chain risk $R_{\text{chain}} = \gamma_{\text{prop}} \cdot R(A_1) \cdot R(A_2)$ for all explicit DAG lineage edges ($A_1 \to A_2$).
- **REQ-12.4-04: Project Operational Risk Synthesis**: The engine MUST calculate project risk $R_{\text{project}} = 1.0 - (1.0 - \max_A R(A))^{\alpha_{\text{peak}}} \cdot \prod_A (1.0 - \lambda_{\text{inter}} R(A))$ preserving peak asset dominance.
- **REQ-12.4-05: Explainable Risk Contribution Tracing**: The engine MUST generate deterministic `RiskContribution` records for all active risk drivers.
- **REQ-12.4-06: Cryptographic Content Addressing**: Outputs MUST derive deterministic RFC 8785 JCS + SHA-256 digests (`assessment_hash`, `chain_hash`, `hierarchical_hash`).
- **REQ-12.4-07: Monotonicity Invariant**: Adding positive risk evidence MUST NOT decrease risk; removing positive risk evidence MUST NOT increase risk.
- **REQ-12.4-08: Idempotence Invariant**: Repeated evaluations on identical graph and configuration inputs MUST yield bit-exact identical risk scores and cryptographic hashes.
- **REQ-12.4-15: Analytical Sufficiency Tracking**: Missing or unresolvable ancestry MUST be recorded as an analytical data-quality state (`EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY`) without routing to decisions or assigning dispositions.

---

## 2. Non-Functional & Governance Requirements

- **REQ-12.4-09: Numerical Stability & Bounded Scalars**: All risk calculations MUST produce finite floats strictly within $[0.0, 1.0]$. Non-finite values (`NaN`, `+Inf`, `-Inf`) MUST fail closed.
- **REQ-12.4-10: Immutable Contracts**: All assessment models (`RiskContribution`, `AssetRiskAssessment`, `ChainRiskAssessment`, `ProjectRiskAssessment`, `HierarchicalRiskAssessment`) MUST be immutable Pydantic V2 models.
- **REQ-12.4-11: 100% Offline Air-Gapped Operation**: Aggregation operations MUST execute 100% offline with zero network sockets or external services.
- **REQ-12.4-12: Zero Phase 0–11 Modifications**: Phase 0 through Phase 11 production code and database schemas MUST remain strictly unmodified.
- **REQ-12.4-13: Prohibition of Correlation Damping Matrix**: Phase 12.4 MUST NOT implement the $7 \times 7$ inter-domain correlation matrix (deferred to Phase 12.5).
- **REQ-12.4-14: Prohibition of Decisions & Dispositions**: Phase 12.4 MUST NOT make policy decisions, route to `REVIEW`, or assign dispositions (`ACCEPT`, `REVIEW`, `QUARANTINE`, `REJECT`). Decision mapping belongs exclusively to Phase 12.8.
