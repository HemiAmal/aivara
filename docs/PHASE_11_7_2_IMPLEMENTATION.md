# PHASE 11.7.2 — TEMPORAL & WINDOWED DISTRIBUTION SHIFT: IMPLEMENTATION SPECIFICATION
=======================================================================================

**PROJECT**: AIVARA — AI Verification & Assurance  
**PARENT PHASE**: PHASE 11 — DISTRIBUTION SHIFT / DATA DRIFT ANALYSIS  
**CURRENT PHASE**: 11.7 — TEMPORAL & WINDOWED DISTRIBUTION SHIFT  
**SUBPHASE**: 11.7.2 — IMPLEMENTATION  
**STATUS**: IMPLEMENTATION COMPLETE & VERIFIED  
**DATE**: 2026-09-13  
**AUTHORITATIVE SUBSYSTEM**: `backend/aivara/drift/temporal_engine.py`  

---

## 1. Implementation Architecture

Phase 11.7.2 implements the frozen architecture defined in Phase 11.7.1. The engine provides an end-to-end, offline, deterministic analytical pipeline for evaluating time-series dataset non-stationarity:

```
Raw Observations (event_time, payload, id)
                   ↓
   Timestamp Ingestion & Normalization (ISO 8601 UTC)
                   ↓
   Multi-Key Deterministic Sorting (t_utc ASC, id ASC)
                   ↓
   Window Partitioning (Fixed Intervals / Sliding Windows)
                   ↓
       ┌───────────────────────────┴───────────────────────────┐
       ↓                                                       ↓
Baseline-to-Windows (O(K))                              Adjacent-Windows (O(K))
[W0 vs W1, W0 vs W2, ..., W0 vs Wk]                     [W0 vs W1, W1 vs W2, ..., Wk-1 vs Wk]
       ↓                                                       ↓
Phase 11.3 StatisticalEngine                            Phase 11.3 StatisticalEngine
(KS / Chi2 / Kernel MMD / Energy)                       (KS / Chi2 / Kernel MMD / Energy)
       ↓                                                       ↓
Tier-2 Benjamini-Hochberg FDR                           Tier-2 Benjamini-Hochberg FDR
       └───────────────────────────┬───────────────────────────┘
                                   ↓
                   Dual-Gate Decision Evaluation
           (p_adj <= 0.05 AND Effect Size >= Threshold)
                                   ↓
        Change-Point Candidate Detection & Local Peak Finding
                                   ↓
           Trajectory & Persistence Pattern Classifier
     (NO_SHIFT, TRANSIENT, PERSISTENT, GRADUAL, ABRUPT)
                                   ↓
       Canonical Hashing (RFC 8785 JCS + SHA-256 Digests)
                                   ↓
       Synthesis of FindingModel & EvidenceModel Records
```

---

## 2. Core Components & Module Structure

### 2.1 Schemas & Data Contracts (`backend/aivara/drift/schemas.py`)
- `TemporalObservation`: Encapsulates sample ID, raw timestamp, normalized UTC timestamp, payload (continuous vector, image, or embedding), and metadata.
- `TemporalAnalysisContract`: Immutable contract binding `temporal_analysis_id`, `timestamp_field` (`event_time` vs `ingested_at`), `timezone_policy`, `window_strategy` (`fixed_interval` vs `sliding_window`), `window_size_seconds`, `step_size_seconds`, `max_windows` ($\le 50$), `min_window_samples` ($\ge 30$), `baseline_policy`, and `declared_seasonality_period_seconds`.
- `TemporalWindowAccounting`: Tracks observation counts, valid timestamped samples, missing timestamp samples, invalid timestamp samples, total windows generated, valid windows, and sparse windows.
- `TemporalWindowDescriptor`: Immutable window descriptor with `window_index`, `window_id`, `start_time_utc`, `end_time_utc`, `sample_count`, `is_valid`, and `window_hash`.
- `TemporalComparisonResult`: Pairwise comparison outcome with `comparison_type` (`baseline_to_window` or `adjacent_window`), `reference_window_id`, `target_window_id`, `statistic_method`, `statistic_value`, `raw_p_value`, `adjusted_p_value`, `effect_size`, `is_statistically_significant`, `is_practically_significant`, and `status`.
- `ChangePointCandidate`: Candidate distribution regime transition point capturing `candidate_timestamp_utc`, `adjacent_discrepancy`, `permutation_p_value`, and non-accusatory `supporting_evidence`.
- `TemporalAnalysisProfile`: Authoritative synthesized result profile.

### 2.2 Domain Engine (`backend/aivara/drift/temporal_engine.py`)
- `normalize_timestamp_utc(ts_input, timezone_policy="UTC")`: Converts string, datetime, or epoch float into standard ISO 8601 UTC string (`YYYY-MM-DDTHH:MM:SS.ffffffZ`).
- `sort_temporal_observations(observations)`: Executes deterministic multi-key sorting (Primary `t_utc ASC`, Secondary `sample_id ASC`).
- `TemporalDistributionShiftAnalyzer`: Orchestrates boundary validation, window partitioning, baseline and adjacent hypothesis tests, FDR error control, change-point candidate detection, and trajectory classification.

---

## 3. Statistical Methodology & Multiple Testing Control

1. **Statistical Authority**: 100% reuse of `StatisticalDriftEngine` (Phase 11.3). Zero duplicate statistical math.
2. **Two-Tier Multiple Testing Hierarchy**:
   - *Tier 1 (Within-Window)*: Benjamini-Hochberg FDR control across individual feature tests for tabular datasets.
   - *Tier 2 (Across-Windows)*: Benjamini-Hochberg FDR control ($q^* = 0.05$) across the sequence of $K$ baseline window evaluations.
3. **Dual-Gate Decision Policy**:
   $$\text{Decision} = \text{MATERIAL\_SHIFT} \iff (p_{\text{adj}} \le 0.05) \land (\text{Effect Size} \ge \text{Threshold})$$
   where effect size thresholds are $\text{PSI} \ge 0.10, \text{TVD} \ge 0.05, \text{MMD}^2 \ge 0.02, \text{Energy} \ge 1.0$.

---

## 4. Trajectory & Persistence Classification

- `NO_MATERIAL_SHIFT`: 0 materially shifted windows.
- `TRANSIENT_SHIFT`: Shift observed in an isolated window ($k=1$), reverting to baseline in subsequent periods.
- `PERSISTENT_SHIFT`: Shift sustained across $\ge 2$ consecutive windows.
- `GRADUAL_DRIFT`: Monotonically increasing effect size across $\ge 3$ consecutive windows.
- `ABRUPT_SHIFT`: Acute step transition ($> 3\times$ threshold) appearing in a single adjacent step and persisting.

---

## 5. Non-Attribution Governing Invariant

$$\text{Temporal Distribution Shift} \ne \text{Malicious Intent} \ne \text{Dataset Poisoning} \ne \text{Contributor Fraud}$$
Findings are emitted under `evidence_layer="detection"` and `finding_type="temporal_distribution_shift"`, explicitly stating that temporal divergence reflects non-stationary operational variance and does NOT establish adversary intent.
