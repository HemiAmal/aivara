# Phase 12.6 — Universal Risk Computation Security Threat Model

**Status:** Authoritative Threat Model  
**Authority:** Phase 12.1 Universal Risk Architecture Freeze  
**Module:** `aivara.universal.risk`  

---

## 1. Threat Traceability Matrix

| Threat ID | Threat Description | Mitigating Control | Test Verification | Status |
|---|---|---|---|---|
| **THREAT-RISK-001** | Evidence contribution manipulation | Strict $w_e, c_e, s_e$ mathematical formula with validation | `test_m1_mutate_evidence_weight` | **MITIGATED** |
| **THREAT-RISK-002** | Confidence manipulation | Upstream confidence extraction with $[0,1]$ bounds enforcement | `test_m2_mutate_confidence` | **MITIGATED** |
| **THREAT-RISK-003** | Severity manipulation | Canonical frozen severity multiplier mapping | `test_m3_mutate_severity` | **MITIGATED** |
| **THREAT-RISK-004** | Weight manipulation | Weight clamped and validated $[0,1]$ | `test_m4_mutate_severity_classification` | **MITIGATED** |
| **THREAT-RISK-005** | Cluster duplication | Ancestry tuple canonical grouping | `test_m5_duplicate_evidence_handling` | **MITIGATED** |
| **THREAT-RISK-006** | Evidence double counting | N:M binding resolution on distinct evidence nodes | `test_m6_duplicate_finding_relationship` | **MITIGATED** |
| **THREAT-RISK-007** | Ancestry spoofing | Structural ancestry verification and independent fallback | `test_m7_mutate_ancestry_clustering` | **MITIGATED** |
| **THREAT-RISK-008** | Project boundary violation | Strict graph project ID validation | `test_m8_cross_project_evidence_rejection` | **MITIGATED** |
| **THREAT-RISK-009** | Asset boundary violation | Filtering evidence by primary / affected asset ID | `test_m9_cross_asset_isolation` | **MITIGATED** |
| **THREAT-RISK-010** | Correlation output substitution | Cryptographic correlation hash inclusion in canonical risk hash | `test_m10_mutate_correlation_hash_sensitivity` | **MITIGATED** |
| **THREAT-RISK-011** | Risk policy version substitution | Policy version included in canonical risk hash | `test_m12_mutate_risk_policy_version` | **MITIGATED** |
| **THREAT-RISK-012** | Risk hash substitution | RFC 8785 JCS canonicalization + SHA-256 computation | `test_m13_mutate_risk_hash_immutability` | **MITIGATED** |
| **THREAT-RISK-013** | Numerical overflow/out-of-range | Bound clamp to $[0.0, 1.0]$ and validation | `test_m16_force_risk_greater_than_one_rejection` | **MITIGATED** |
| **THREAT-RISK-014** | NaN/Infinity injection | `math.isnan` / `math.isinf` rejection | `test_m14_inject_nan_rejection`, `test_m15` | **MITIGATED** |
| **THREAT-RISK-015** | Nondeterministic calculation | Deterministic `Decimal` rounding and sorted cluster iteration | `test_universal_risk_all_distinct_assets` | **MITIGATED** |
| **THREAT-RISK-016** | Resource exhaustion | Graph node/edge resource ceilings | Graph validation tests | **MITIGATED** |
| **THREAT-RISK-017** | Risk/decision confusion | Complete exclusion of policy/decision logic from 12.6 engine | `test_zero_decision_dispositions`, `test_m19` | **MITIGATED** |
| **THREAT-RISK-018** | Risk/proof override leakage | Phase 12.6 computes risk score without issuing overrides | `test_zero_proof_override_in_engine` | **MITIGATED** |
| **THREAT-RISK-019** | Cross-asset aggregation leakage | Lineage/propagation calculation reserved for Phase 12.9 | `test_zero_project_chain_risk_in_universal_engine` | **MITIGATED** |
| **THREAT-RISK-020** | Project aggregation leakage | $R_{\text{project}}$ calculation reserved for Phase 12.9 | `test_m20_attempt_project_chain_leakage` | **MITIGATED** |
