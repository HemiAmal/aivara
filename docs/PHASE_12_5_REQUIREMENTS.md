# Phase 12.5 — Requirements Specification

**Phase:** Phase 12.5 Evidence Dependency & Correlation Modeling  
**Status:** Requirements Baseline  

---

## 1. Functional Requirements

- **REQ-12.5-01 (Canonical 7x7 Matrix):** The correlation matrix must be strictly $7 \times 7$ indexed by the frozen canonical domain sequence (`DATASET_INTEGRITY`, `CONTRIBUTOR_RISK`, `MODEL_INTEGRITY`, `BEHAVIORAL_ANALYSIS`, `BACKDOOR_TRIGGER`, `INFERENCE_INTEGRITY`, `DISTRIBUTION_SHIFT`).
- **REQ-12.5-02 (Matrix Structural Invariants):** Matrix must enforce symmetry ($C_{ij} = C_{ji}$), zero diagonal ($C_{ii} = 0.0$), bounded values ($C_{ij} \in [0.0, 1.0]$), and rejection of non-finite numbers (NaN/Inf).
- **REQ-12.5-03 (Deterministic Matrix Hash):** Matrix identity must be computed as the SHA-256 digest of canonical RFC 8785 JCS serialized JSON.
- **REQ-12.5-04 (Domain Detection Summary):** Domain mean detection severity $\bar{S}_i \in [0.0, 1.0]$ must be computed over detection-layer evidence: $\bar{S}_i = \frac{1}{|E_i^{\text{det}}|} \sum_{e \in E_i^{\text{det}}} (w_e \cdot c_e \cdot s_e)$.
- **REQ-12.5-05 (Cross-Domain Attenuation):** Attenuation factor $att_j = \prod_{i \ne j, \text{active}(i)} (1 - C_{ij} \cdot \bar{S}_i)$ must be computed multiplicatively across active source domains and applied to yield $\bar{S}_j^{\text{damped}} = \bar{S}_j \cdot att_j$.
- **REQ-12.5-06 (Inactive Domain Zero Damping):** Inactive domains ($|E_i| = 0$ or $\bar{S}_i = 0.0$) must contribute no attenuation ($1 - C_{ij} \cdot 0 = 1.0$).
- **REQ-12.5-07 (Proof Inviolability):** Proof-layer evidence ($layer == PROOF$) must never be attenuated, modified, or reinterpreted by correlation damping.
- **REQ-12.5-08 (Ancestry & Analytical Sufficiency):** Analytical data quality states (such as unverified ancestry) must be propagated in `evidence_sufficiency` without generating disposition decisions.
- **REQ-12.5-09 (Traceability):** Every pair of interacting domains must generate an immutable `CrossDomainContributionTrace`.
- **REQ-12.5-10 (Deterministic Assessment Hash):** Batch correlation assessment must produce a canonical `correlation_hash` using RFC 8785 JCS + SHA-256.

---

## 2. Non-Functional & Security Requirements

- **SEC-12.5-01 (Zero Decision Leakage):** Phase 12.5 must not implement or emit `ACCEPT`, `REVIEW`, `QUARANTINE`, or `REJECT` disposition decisions.
- **SEC-12.5-02 (Zero Risk Engine Leakage):** Phase 12.5 must not implement final universal risk, asset risk, or chain risk formulas.
- **SEC-12.5-03 (100% Offline Air-Gap):** Zero network sockets, zero HTTP/external dependencies.
- **SEC-12.5-04 (Immutability):** All matrix and assessment models must be frozen (`ConfigDict(frozen=True)`).
