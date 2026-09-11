# Phase 6 — Contributor Risk Subsystem Freeze Specification

**Subsystem:** AIVARA Contributor Risk Engine (CRE)  
**Freeze Date:** 2026-09-11  
**Status:** **FROZEN / COMPLETED**  
**Final Test Baseline:** **870 passed, 0 failed, 0 skipped, 0 xfailed** (100% pass rate)

---

## 1. Subsystem Purpose

The Contributor Risk subsystem provides mathematically rigorous, multi-dimensional, evidence-backed statistical profiling for data contributors. It attributes sample observations across multi-contributor environments ($1/K$ fractional attribution), measures deviations from contextual Leave-One-Out (LOO) and class-conditional baselines, bounds statistical variance via Empirical Bayes shrinkage ($M_0 = 20.0$), structures evidence into Dependency-Aware Evidence Families with family dominance, and isolates cryptographic provenance proofs from detection-layer anomaly scoring.

---

## 2. Phase 6 Completion Status

| Subphase | Description | Status |
|---|---|---|
| **Phase 6.1** | Architecture, Design Freeze, and ADRs (ADR-030 to ADR-039) | **COMPLETE / FROZEN** |
| **Phase 6.2** | Domain & Statistical Calculation Engine | **COMPLETE / FROZEN** |
| **Phase 6.3** | Application Service, Persistence, & REST API Layer | **COMPLETE / FROZEN** |
| **Phase 6.4** | Comprehensive Verification & Clean Re-Verification Suite | **COMPLETE / FROZEN** |
| **Phase 6.5** | Final Freeze & Integrity Check | **COMPLETE / FROZEN** |

---

## 3. Core Architectural Invariants

1. **Detection Evidence $\ne$ Maliciousness (ADR-035):** Data anomalies and statistical differentials indicate quality or reliability variation, never human intent, motive, or culpability.
2. **Proof Evidence $\ne$ Detection Score (ADR-030, ADR-034):** Cryptographic provenance verification is discrete/binary (confidence = 1.0) and is strictly isolated from numerical anomaly scoring.
3. **No Scalar Contributor Risk Score (ADR-030):** Contributor Risk is authoritatively represented exclusively as a structured multi-dimensional profile vector (`detection_profile` + `proof_profile`). No scalar aggregate risk score is calculated or exposed.
4. **Conservation of Sample Exposure (ADR-033):** For every sample $s_i$, $\sum_{c} w_{i,c} = 1.0$. Multi-contributor samples are partitioned equally ($w = 1/K$), and effective exposure is $N_c = \sum_i w_{i,c}$.
5. **Contextual Baselines Required (ADR-031):** Metrics are evaluated against Leave-One-Out (LOO) and class-conditional baselines to prevent Simpson's Paradox.
6. **Small Samples Are Conservative (ADR-032):** Beta-Binomial Empirical Bayes shrinkage with prior pseudo-count $M_0 = 20.0$ shrinks small sample estimates ($N_c < 30$) heavily toward the background rate; $N_c < 3.0$ is designated `UNVERIFIABLE`.
7. **Anti-Double-Counting Family Dominance (ADR-034):** Correlated detectors within an evidence family use the maximum supported differential ($\max(\Delta)$) rather than additive sums.
8. **Subsystem Isolation:** Phase 6 $\ne$ Phase 8 (Model Behavioral / Red-Teaming Analysis) and Phase 6 $\ne$ Phase 12 (Universal Risk Engine).
9. **Cryptographic Authority:** Phase 4 remains the sole cryptographic authority; Phase 5.9 remains the sole evidence/provenance lifecycle authority.
10. **Database Freeze:** Zero schema modifications, zero new tables, zero added columns, and zero migrations.

---

## 4. Detection / Proof Separation

- **Detection Profile:** Contains four continuous numerical dimensions evaluated via Empirical Bayes shrinkage:
  - `DIM_LABEL_RELIABILITY` (Confident learning anomaly rate)
  - `DIM_TRANSITION_ASYM` (Targeted label-flipping & noise concentration)
  - `DIM_QUALITY_DIVERGENCE` (Perceptual and compression quality defects)
  - `DIM_DISTRIBUTION_SHIFT` (Feature embedding drift & OOD distance)
- **Proof Profile:** Contains discrete cryptographic verification states:
  - `DIM_PROVENANCE_INTEGRITY` (`verification_status`, `signature_present`, `chain_valid`, `nonce_valid`, `tamper_detected`) with confidence invariant at `1.0`.
- Proof failures do not alter or inflate detection anomaly differentials.

---

## 5. Scalar-Risk Score Prohibition & Database Sentinel

- The REST API never exposes `overall_risk_score`, `risk_score`, or `threat_score`.
- In [`RiskAssessmentModel`](file:///d:/Downloads/Projects/AiVara/backend/aivara/database/models.py), the non-nullable float column `overall_risk_score` stores `-1.0` solely as an out-of-band schema compatibility sentinel representing `NOT_APPLICABLE`.
- Accompanying JSON metadata explicitly declares:
  - `scalar_risk_score_applicable = False`
  - `scalar_risk_score = None`
  - `representation = "STRUCTURED_MULTIDIMENSIONAL_VECTOR"`

---

## 6. Provenance Authority & Taxonomy

Phase 6 reuses the frozen Phase 5.9 provenance taxonomy without modification:
- `VERIFIED`
- `INVALID`
- `MISSING`
- `UNAVAILABLE`
- `MISMATCHED`
- `UNVERIFIABLE`

---

## 7. Semantic Safety Policy

- **Allowed Technical Security Terminology:** Objective technical concepts are permitted (`adversarial example`, `adversarial perturbation`, `adversarial robustness`, `poisoning attack`, `data poisoning experiment`, `backdoor trigger`, `threat model`, `out-of-distribution anomaly`, `directional label transition`).
- **Prohibited Human-Intent Vocabulary:** Terms asserting unproven human intent, guilt, or character are strictly rejected (`malicious`, `maliciously`, `bad actor`, `guilty`, `culpable`, `sabotage`, `fraudulent`, `collusion`, `deliberate`, `intentional`).

---

## 8. Multi-Tenant Isolation & Security

- All service operations and REST endpoints require strict multi-tenant project scoping.
- Cross-project requests fail safely with 404/422 responses and zero disclosure regarding the existence of foreign tenant assets.
- Zero private key, passphrase, filesystem path, or unhandled stack trace leakage.

---

## 9. Determinism, Idempotency, & Offline Operation

- Identical assessment requests produce bit-for-bit canonical payload matches.
- Repeated assessment executions update existing records idempotently without duplicate row generation.
- 100% offline and air-gapped; zero external network, cloud API, or telemetry dependencies.

---

## 10. Known Limitations

- Effective exposure $N_c < 3.0$ triggers `UNVERIFIABLE` status, suppressing numerical differential calculation.
- Evidence graph traversal is bounded to the samples attributed to the specified contributor.

---

## 11. Explicit Phase 7 Boundary

- Phase 6 is strictly limited to dataset contributor risk profiling.
- Phase 7 (Model Robustness, Explainability, & Representation Verification) is completely decoupled and will consume sealed Phase 6 artifacts without altering Phase 6 implementation.

---

## 12. Freeze Declaration

**Phase 6 (Contributor Risk Subsystem) is officially FROZEN.**  
No further functional modifications, schema alterations, or refactoring are permitted.
