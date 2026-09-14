# Phase 12.6 — Universal Risk Computation Requirements Specification

**Status:** Authoritative Requirements Specification  
**Authority:** Phase 12.1 Universal Risk Architecture Freeze  
**Module:** `aivara.universal.risk`  

---

## 1. Functional Requirements

| Req ID | Description | Verification Method |
|---|---|---|
| **REQ-RISK-001** | Compute individual evidence contribution $term(e) = w_e \times c_e \times s_e$. | Unit Test (`test_single_evidence_risk`) |
| **REQ-RISK-002** | Apply canonical severity multipliers: `CRITICAL`=1.00, `HIGH`=0.70, `MEDIUM`=0.40, `LOW`=0.10, `INFO`=0.05. | Unit Test (`test_m3_mutate_severity`) |
| **REQ-RISK-003** | Integrate Phase 12.5 domain attenuation factors $att_j$ for detection evidence. | Unit Test (`test_correlation_integration_detection_attenuation`) |
| **REQ-RISK-004** | Enforce proof inviolability: proof-layer evidence is never attenuated ($att = 1.0$). | Unit Test (`test_proof_inviolability_in_risk_computation`) |
| **REQ-RISK-005** | Form ancestry-aware clusters $C_k$ using standardized ancestry tuple. | Unit Test (`test_m7_mutate_ancestry_clustering`) |
| **REQ-RISK-006** | Apply intra-cluster damping $\lambda_{\text{intra}} = 0.15$ to member contributions: $S(C_k) = \min(1, \max + 0.15 \sum \text{other})$. | Unit Test (`test_intra_cluster_damping`) |
| **REQ-RISK-007** | Compute bounded asset risk: $R(A) = 1 - \prod_k (1 - S(C_k))$. | Unit Test (`test_multiple_independent_clusters_composition`) |
| **REQ-RISK-008** | Guarantee strict bounds $0.0 \le R(A) \le 1.0$ for all valid inputs. | Mutation Tests (`test_m16`, `test_m17`) |
| **REQ-RISK-009** | Enforce RFC 8785 JCS + SHA-256 cryptographic identity (`risk_hash`). | Unit Test (`test_m10`, `test_m13`) |
| **REQ-RISK-010** | Perform deterministic rounding via `Decimal` `ROUND_HALF_UP` to 6 decimal places. | Property Test (`test_m12`) |
| **REQ-RISK-011** | Enforce project boundary isolation ($P_{\text{assessment}} = P_{\text{graph}}$). | Unit Test (`test_project_boundary_isolation`) |
| **REQ-RISK-012** | Enforce asset boundary isolation (only evidence targeting asset contributes). | Unit Test (`test_m9_cross_asset_isolation`) |
| **REQ-RISK-013** | Handle missing/incomplete ancestry analytically without fabricating data or decisions. | Unit Test (`test_m18_incomplete_ancestry_propagation`) |
| **REQ-RISK-014** | Zero policy decision generation (no `ACCEPT`, `REVIEW`, `QUARANTINE`, `REJECT`). | Static Audit (`test_zero_decision_dispositions`) |
| **REQ-RISK-015** | Zero proof override logic (no $R=1.0 \rightarrow \text{REJECT}$). | Static Audit (`test_zero_proof_override_in_engine`) |
| **REQ-RISK-016** | Zero chain ($R_{\text{chain}}$) or project ($R_{\text{project}}$) aggregation leakage in 12.6 engine. | Static Audit (`test_zero_project_chain_risk_in_universal_engine`) |
| **REQ-RISK-017** | 100% offline air-gap (zero network/socket imports). | Static Audit (`test_zero_network_imports`) |
| **REQ-RISK-018** | Enforce maximum resource bounds ($E \le 5000, F \le 1000, A \le 250$). | Ceiling Tests |
