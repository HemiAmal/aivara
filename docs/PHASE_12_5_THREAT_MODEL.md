# Phase 12.5 — Threat Model & Security Analysis

**Phase:** Phase 12.5 Evidence Dependency & Correlation Modeling  
**Status:** Complete Threat Assessment  

---

## 1. Threat Vectors and Mitigations (THREAT-CORR-001 to THREAT-CORR-020)

| Threat ID | Threat Description | Attack Vector | Mitigation in Phase 12.5 |
|---|---|---|---|
| **THREAT-CORR-001** | Matrix Dimension Manipulation | Submitting non-7x7 matrix to bypass domain coverage | Fixed $7 \times 7$ validation; raises `InvalidCorrelationMatrixError` |
| **THREAT-CORR-002** | Domain Order Manipulation | Permuting domain order to associate correlations with wrong domains | Strict domain sequence assertion; raises `InvalidDomainOrderError` |
| **THREAT-CORR-003** | Asymmetric Matrix Injection | Submitting asymmetric $C_{ij} \ne C_{ji}$ to distort directional influence | Strict symmetry validation ($|C_{ij} - C_{ji}| \le 10^{-9}$); raises `AsymmetricMatrixError` |
| **THREAT-CORR-004** | Non-Zero Diagonal Injection | Self-damping diagonal $C_{ii} > 0$ to dilute domain severity | Strict zero diagonal validation ($|C_{ii}| \le 10^{-9}$); raises `NonZeroDiagonalError` |
| **THREAT-CORR-005** | Out-of-Range Correlation Values | Injecting $C_{ij} < 0$ or $C_{ij} > 1$ to amplify severity or invert damping | Bound assertion on $[0.0, 1.0]$; raises `CorrelationOutOfRangeError` |
| **THREAT-CORR-006** | NaN/Infinity Injection | Passing non-finite numbers to corrupt math | Pydantic finite float validation; raises `NonFiniteCorrelationError` |
| **THREAT-CORR-007** | Matrix Hash Substitution | Modifying matrix while keeping old hash | Deterministic RFC 8785 JCS SHA-256 computation in `model_validator` |
| **THREAT-CORR-008** | Detection Confidence Manipulation | Feeding confidence $> 1.0$ or $< 0.0$ | Clamped bounded input validation ($c_e \in [0.0, 1.0]$) |
| **THREAT-CORR-009** | Proof Evidence Attenuation | Subjecting proof-layer evidence to correlation damping | Proof inviolability invariant: proof evidence segregated and NEVER attenuated |
| **THREAT-CORR-010** | Cross-Project Contamination | Evaluating correlation across mixed project contexts | Strict project boundary validation; raises `ProjectMismatchError` |
| **THREAT-CORR-011** | Cross-Asset Dependency Fabrication | Linking unrelated assets across domains | Dependency restricted strictly to validated graph nodes |
| **THREAT-CORR-012** | Ancestry Spoofing | Fabricating fake parent ancestry | Incomplete ancestry flagged analytically without decision routing |
| **THREAT-CORR-013** | Evidence Identity Confusion | Mismatched evidence IDs across nodes | Graph node canonical identity tracking |
| **THREAT-CORR-014** | Duplicate Evidence Amplification | Flooding duplicate nodes to bias mean severity | Normalization/ingestion deduplication prior to graph evaluation |
| **THREAT-CORR-015** | Inactive-Domain Semantic Manipulation | Claiming absence of evidence implies safety | Inactive domains contribute zero damping ($att = 1.0$) |
| **THREAT-CORR-016** | Correlation Amplification | Compound damping exceeding $[0.0, 1.0]$ | Multiplicative damping $att_j = \prod (1 - C_{ij} \cdot \bar{S}_i)$ bounded in $[0.0, 1.0]$ |
| **THREAT-CORR-017** | Decision-Layer Leakage | Emitting `ACCEPT`, `REVIEW`, `REJECT` | Static AST audit proving zero decision logic |
| **THREAT-CORR-018** | Risk-Engine Leakage | Calculating universal or asset risk | Static AST audit proving zero risk math |
| **THREAT-CORR-019** | Nondeterministic Result Generation | Random ordering or floating point drift | Canonical multi-key sorting + rounded reproducible floats |
| **THREAT-CORR-020** | Resource Exhaustion | Deep graphs or combinatorially explosive loops | Bounded $O(1)$ matrix operations over 7 fixed domains |
