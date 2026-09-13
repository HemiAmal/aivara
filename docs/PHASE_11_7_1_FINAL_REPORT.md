# PHASE 11.7.1 — TEMPORAL & WINDOWED DISTRIBUTION SHIFT: ARCHITECTURE & REQUIREMENTS FREEZE FINAL REPORT
======================================================================================================

**PROJECT**: AIVARA — AI Verification & Assurance  
**PARENT PHASE**: PHASE 11 — DISTRIBUTION SHIFT / DATA DRIFT ANALYSIS  
**CURRENT PHASE**: 11.7 — TEMPORAL & WINDOWED DISTRIBUTION SHIFT  
**SUBPHASE**: 11.7.1 — ARCHITECTURE & REQUIREMENTS FREEZE  
**STATUS**: COMPLETE & ARCHITECTURE FROZEN  
**DATE**: 2026-09-13  
**AUTHORITATIVE SUBSYSTEM**: `aivara.drift` (Temporal Orchestration Layer)  

---

## 1. Executive Summary

Phase 11.7.1 establishes the frozen architecture, mathematical methodology, security threat model, cryptographic contract, and formal requirements for temporal and windowed distribution-shift analysis in AIVARA.

Extending the static reference-vs-target paradigm ($\mathcal{P}_{\text{ref}} \leftrightarrow \mathcal{P}_{\text{tgt}}$) of Phases 11.2–11.6, Phase 11.7 partitions sequential time-stamped datasets into deterministic chronological windows ($\mathcal{W}_0, \mathcal{W}_1, \dots, \mathcal{W}_K$). It evaluates cumulative divergence from historical baselines (Baseline-to-Windows) and acute step transitions (Adjacent-Windows) across continuous features, categorical attributes, physical image characteristics, and high-dimensional learned latent representations.

All analyses operate 100% offline, air-gapped, and deterministically, reusing the Phase 11.3 statistical engine with zero mathematical duplication, zero database schema modifications, and strict enforcement of the non-attribution invariant ($\text{Temporal Shift} \ne \text{Malicious Intent}$).

---

## 2. Research Summary

A rigorous evaluation of sequential testing and change-point methodologies was conducted (documented in `docs/PHASE_11_7_RESEARCH_NOTES.md`):
1. **Windowing Topologies**: Fixed non-overlapping windows selected as primary V1 strategy (disjoint, i.i.d. samples, $O(K)$ complexity). Sliding windows supported as secondary with step size bounded to $\delta \ge W/2$.
2. **Change-Point Detection**: Parametric 1D methods (CUSUM, Page-Hinkley) rejected due to Gaussian assumptions; dynamic ADWIN rejected due to 1D constraint. Nonparametric Kernel Change-Point Detection (KCPD / MMD-CPD) accepted for V1 candidate detection via Phase 11.3 Kernel MMD.
3. **Autocorrelation & Seasonality**: Acknowledged as critical sources of false discovery. Addressed via deterministic sample thinning, period-aligned baselines, dual-gate effect size thresholds, and explicit limitation reporting.

---

## 3. Architecture Decisions (ADR-100 Summary)

The governing architectural decisions were committed to `docs/DECISIONS.md` under **ADR-100**:
- Primary reliance on `event_time` over `ingested_at`.
- Strict ISO 8601 UTC microsecond normalization and multi-key deterministic sorting.
- Dual-topology window comparisons: Baseline-to-Windows ($O(K)$) and Adjacent-Windows ($O(K)$).
- 100% reuse of Phase 11.3 `StatisticalDriftEngine`.
- Two-tier Benjamini–Hochberg FDR control ($q^* = 0.05$) across features and across temporal windows.
- Non-attribution invariant enforced on all findings and evidence.

---

## 4. Temporal Data Model

Observations are timestamped by either:
- `event_time`: Physical event generation time (primary).
- `ingested_at`: Server ingestion time (fallback).
- Selection is recorded in `TemporalAnalysisContract.timestamp_field`. Mixing timestamp types within an analysis contract is prohibited.

---

## 5. Timestamp Policy & Normalization

- Format: ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SS.ffffffZ`).
- Strict timezone offset resolution to UTC.
- Multi-key deterministic sort: Primary `timestamp_utc ASC`, Secondary `SHA-256(sample_content) ASC`.

---

## 6. Window Policy

- Window size: $\Delta t$ (fixed time duration) or $N_w$ (sample count).
- Partition intervals: $[\tau_k, \tau_{k+1})$, left-closed, right-open.
- Maximum window count: $K \le 50$.
- Minimum sample size per window: $N_{\min} \ge 30$.

---

## 7. Baseline Policy

- Static historical reference baseline $\mathcal{W}_0$ anchored to an immutable dataset version ID with cryptographic `dataset_hash`.
- Rolling baselines avoided to prevent masking slow gradual drift.

---

## 8. Statistical Policy

- Reuses Phase 11.3 `StatisticalDriftEngine` directly.
- Dual-gate rule: Shift declared only when $p_{\text{adj}} \le 0.05$ AND effect size $\ge$ threshold ($\text{PSI} \ge 0.10, \text{TVD} \ge 0.05, \text{MMD}^2 \ge 0.02, \text{Energy} \ge 1.0$).

---

## 9. Multiple Testing Policy

- Within-window feature family: Benjamini–Hochberg FDR ($q^* = 0.05$).
- Across-window temporal family: Benjamini–Hochberg FDR ($q^* = 0.05$) across the sequence of $K$ baseline window tests. Zero double-FDR applied.

---

## 10. Change-Point Policy

- Candidate change point $\hat{\tau}_c$ localized at window boundary $k^*$ where adjacent discrepancy $D(\mathcal{W}_{k-1}, \mathcal{W}_k)$ achieves a local maximum ($p_{\text{adj}} \le 0.05$).
- Semantics: Statistical onset of regime shift, NOT an attack timestamp.

---

## 11. Persistence Classification

Trajectories classified into:
- `NO_MATERIAL_SHIFT`
- `TRANSIENT_SHIFT` (1-window excursion)
- `PERSISTENT_SHIFT` ($\ge 2$ consecutive shifted windows)
- `GRADUAL_DRIFT` (monotonic divergence over $\ge 3$ windows)
- `ABRUPT_SHIFT` (step jump $> 3\times$ threshold)

---

## 12. Seasonality Policy

- Period-aligned baseline matching supported.
- Explicit limitations reported when $\Delta t < \text{seasonal cycle period}$.

---

## 13. Autocorrelation Policy

- Deterministic sample thinning when serial correlation is present.
- Dual-gate effect size gating shields against false alarms from mild autocorrelation.

---

## 14. Sampling Policy

- Deterministic downsampling derived from canonical contract hash seed when $N_w > 5000$.

---

## 15. Resource Policy

- Maximum windows $K \le 50$.
- Maximum comparisons $2K - 1 \le 99$.
- Memory budget $\le 200\,\text{MB}$.
- $O(K)$ computational complexity.

---

## 16. Security & Air-Gap

- 100% offline; zero external network, DNS, or NTP calls.
- AST scan clean (0 `eval`/`exec`/`pickle`/`subprocess`).

---

## 17. Privacy & Data Minimization

- Raw sample matrices discarded immediately after statistical testing.
- Only summary statistics, window descriptors, evidence, and findings persisted.

---

## 18. Evidence Integration

- Generates `EvidenceModel` records binding temporal boundary hashes, window metrics, and test diagnostics.

---

## 19. Provenance Integration

- Provenance chain: `Dataset → Population → TemporalContract → Windows → StatisticalAnalysis → TemporalProfile → Evidence → Finding`.

---

## 20. Cryptographic Identity

- Strict RFC 8785 JSON Canonicalization Scheme (JCS) + SHA-256 digests:
  - `temporal_contract_hash`
  - `temporal_window_hash`
  - `temporal_drift_profile_hash`

---

## 21. Requirements Summary

All functional (FR-1–10), statistical (SR-1–6), security (SECR-1–4), and non-functional (NFR-1–3) requirements specified in `docs/PHASE_11_7_REQUIREMENTS.md`.

---

## 22. Threat Model Summary

20-scenario security threat model compiled in `docs/PHASE_11_7_THREAT_MODEL.md` covering timestamp forgery, clock skew, window boundary evasion, slow drift poisoning, multiple-testing abuse, and non-attribution invariants.

---

## 23. Test Plan for Phase 11.7.2 Implementation

Test plan defined covering:
1. Timestamp normalization & timezone offset handling.
2. Deterministic window partitioning & sorting.
3. Trajectory classifications (`NO_SHIFT`, `TRANSIENT`, `PERSISTENT`, `GRADUAL`, `ABRUPT`).
4. Change-point candidate localization.
5. Multiple-testing FDR calibration.
6. Cryptographic hash sensitivity & mutation resistance.
7. Full regression suite maintenance (2,048+ tests).

---

## 24. Known Limitations

- V1 requires timestamp metadata; un-timestamped datasets cannot undergo temporal analysis.
- Extremely high-frequency autocorrelation ($< 1\text{s}$) requires operator-declared thinning.
- Complex multi-period seasonality requires period-matched baselines.

---

## 25. Frozen Architecture Decisions

All architecture decisions established in `docs/PHASE_11_7_TEMPORAL_ARCHITECTURE.md`, `docs/PHASE_11_7_REQUIREMENTS.md`, `docs/PHASE_11_7_THREAT_MODEL.md`, `docs/PHASE_11_7_RESEARCH_NOTES.md`, and ADR-100 in `docs/DECISIONS.md` are **PERMANENTLY FROZEN**.

---

## 26. Files Created

1. `docs/PHASE_11_7_RESEARCH_NOTES.md`
2. `docs/PHASE_11_7_THREAT_MODEL.md`
3. `docs/PHASE_11_7_REQUIREMENTS.md`
4. `docs/PHASE_11_7_TEMPORAL_ARCHITECTURE.md`
5. `docs/PHASE_11_7_1_FINAL_REPORT.md`

---

## 27. Files Modified

1. `docs/DECISIONS.md` (Added ADR-100: Temporal and Windowed Distribution Shift Architecture)

---

## 28. Database Status

- 0 new tables.
- 0 migrations.
- 0 schema modifications.
- Project baseline invariant: SQLite primary database confirmed.

---

## 29. Dependency Status

- 0 new dependencies added.

---

## 30. Git Status

- 0 git commits made by agent.
- 0 git pushes made by agent.
- Working tree contains uncommitted architecture documentation for user review.

---

## 31. Final Freeze Decision

**PHASE 11.7.1 — TEMPORAL & WINDOWED DISTRIBUTION SHIFT ARCHITECTURE & REQUIREMENTS IS PERMANENTLY FROZEN.**

- **Architecture**: Formally specified and frozen.
- **Requirements**: Formally specified and frozen.
- **Threat Model**: Formally specified and frozen.
- **Decisions**: Formally recorded in ADR-100.
- **Implementation Status**: Awaiting Phase 11.7.2 authorization.
