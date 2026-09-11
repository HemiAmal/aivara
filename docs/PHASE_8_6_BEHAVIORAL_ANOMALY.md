# PHASE 8.6 — BEHAVIORAL ANOMALY DETECTION ENGINE

**System:** AIVARA — AI Verification & Assurance  
**Phase:** 8.6  
**Status:** IMPLEMENTED / VERIFIED  
**Security Boundary:** Layer 4 — Offline Analysis Layer  

---

## 1. Executive Summary

Phase 8.6 implements the **Behavioral Anomaly Detection Engine** for the AIVARA platform. Its sole objective is to:
> **Determine whether observed model behavior is statistically unusual relative to an appropriate behavioral baseline / reference population.**

Phase 8.6 builds upon and consumes the validated behavioral measurements from:
- **Phase 8.3:** Behavioral Baseline & Reference Profiles (`BehavioralBaseline`)
- **Phase 8.4:** Controlled Perturbation & Sensitivity Experiments (`PerturbationSensitivityResult`)
- **Phase 8.5:** Output Consistency & Stability Analysis (`BehavioralComparisonResult`, `RepeatabilityAnalysisResult`)

---

## 2. Fundamental Semantic Invariant

$$\mathbf{\text{UNUSUAL BEHAVIOR} \neq \text{MALICIOUS BEHAVIOR}}$$

Phase 8.6 strictly enforces semantic neutrality:
- **No Maliciousness Determination:** Unusual behavior may arise from architecture differences, numerical variations, or novel test samples.
- **No Attack/Backdoor/Trigger Claims:** Attacker intent and backdoor presence are explicitly out of scope.
- **No Inference Integrity Verdicts:** Dedicated to Phase 7 and Phase 9.
- **No Universal Risk Scoring:** Universal risk aggregation belongs to Phase 12.

---

## 3. Statistical Methodology

### 3.1 Robust Standardization (Directional Robust Z-Score)
For observation $x$ evaluated against an eligible reference sample population $B = [b_1, \dots, b_N]$:
$$\text{median}(B) = \text{median-of}(B)$$
$$\text{MAD}(B) = \text{median}(\{|b_i - \text{median}(B)|\}_{i=1}^N)$$

When $\text{MAD}(B) > 0$ and sample support is sufficient:
$$\text{robust\_z} = \frac{x - \text{median}(B)}{1.4826 \times \text{MAD}(B)}$$
$$\text{absolute\_robust\_z} = |\text{robust\_z}|$$

#### Directional Robust-Z Threshold Decision Rules:
- **`HIGHER_IS_EXTREME`:** $\text{robust\_z} \ge +\text{threshold}$ (lower values are strictly non-anomalous).
- **`LOWER_IS_EXTREME`:** $\text{robust\_z} \le -\text{threshold}$ (higher values are strictly non-anomalous).
- **`TWO_SIDED`:** $|\text{robust\_z}| \ge \text{threshold}$ (deviations in either direction crossing threshold are anomalous).

### 3.2 Constant Baseline Handling ($\text{MAD} = 0$)
When baseline dispersion is zero ($\text{MAD} = 0$):
- No artificial epsilon ($\epsilon$) is added to the denominator.
- `robust_z` is strictly `None`.
- Empirical comparison is applied:
  - If $x == \text{median}(B) \implies \text{NORMAL}$.
  - If $x \neq \text{median}(B) \implies \text{ANOMALOUS}$ (with explanation explicitly noting zero baseline dispersion).

### 3.3 Directional Empirical Extremeness & Bounds Clamping
Calculates deterministic empirical tail probabilities guaranteed to satisfy $0.0 \le \text{value} \le 1.0$:
- `LOWER_IS_EXTREME`: $P(B \le x) = \min\left(1.0, \max\left(0.0, \frac{\sum \mathbf{1}_{b_i \le x}}{N}\right)\right)$ (used for `prediction_agreement`, `top_k_overlap`, `mean_matched_iou`, `class_agreement_rate`, `ground_truth_miou`, `reference_mask_agreement`, `pixel_agreement_rate`, `finite_value_agreement`, `prediction_agreement_rate`, `finite_value_rate`, `cosine_similarity`).
- `HIGHER_IS_EXTREME`: $P(B \ge x) = \min\left(1.0, \max\left(0.0, \frac{\sum \mathbf{1}_{b_i \ge x}}{N}\right)\right)$ (used for `kl_divergence`, `js_divergence`, `mean_box_displacement`, `l1_distance`, `l2_distance`, `relative_l2_distance`, `max_absolute_difference`, `mean_absolute_difference`, `max_numerical_delta`, `mean_numerical_delta`, `sensitivity_ratio`, `output_distance_l1`, `output_distance_l2`, `prediction_changed`, `latency_ms`, `empty_detection_rate`).
- `TWO_SIDED`: $\min(1.0, \max(0.0, 2 \times \min(P(B \le x), P(B \ge x))))$ clamped in $[0.0, 1.0]$ (used for signed deltas: `confidence_delta`, `entropy_delta`, `margin_delta`, `count_delta`, `mean_confidence_delta`).

### 3.4 Sample Support Categorization
- $N < 5$: `INSUFFICIENT_SUPPORT` (Anomaly classification withheld).
- $5 \le N < 10$: `LOW_SUPPORT`.
- $10 \le N < 30$: `MODERATE_SUPPORT`.
- $N \ge 30$: `ADEQUATE_SUPPORT`.

*Rule:* Insufficient support is never converted into an anomaly score or treated as suspicious.

---

## 4. Multi-Metric Behavioral Families

To prevent false certainty and naive multiple-comparisons errors, metrics are grouped into four behavioral families:
1. `REPEATABILITY`: `prediction_agreement_rate`, `max_numerical_delta`, `mean_numerical_delta`
2. `OUTPUT_CONSISTENCY`: Classification, detection, segmentation, and generic tensor consistency metrics
3. `PERTURBATION_SENSITIVITY`: `sensitivity_ratio`, `output_distance_l1`, `output_distance_l2`, `prediction_changed`
4. `EXECUTION_STABILITY`: `latency_ms`, `finite_value_rate`, `nan_rate`, `inf_rate`

Within each family:
- Tracks `valid_metric_count`, `anomalous_metric_count`.
- Identifies the `dominant_metric` using deterministic tie-breaking (by absolute robust z, empirical extremeness, and alphabetical name).

---

## 5. Architecture & File Layout

```
backend/aivara/behavioral/anomaly/
├── __init__.py           # Unified exports
├── enums.py              # AnomalyStatus, MetricAnomalyStatus, SupportStatus, MetricDirection, etc.
├── exceptions.py         # CrossProjectAnalysisError, IncompatibleAnalysisContextError, etc.
├── schemas.py            # BehavioralAnomalyMetric, BehavioralAnomalyFamily, BehavioralAnomalyAnalysis
├── policy.py             # AnomalyThresholdPolicy, DEFAULT_ANOMALY_POLICY
├── statistics.py         # compute_median, compute_mad, compute_robust_z, filter_finite_values
├── empirical.py          # compute_empirical_extremeness, compute_percentile_rank, compute_support_status
├── explanations.py       # Deterministic, semantically safe human-readable explanation formatters
├── families.py           # Metric family mapping, directionality, and family aggregation
├── identity.py           # RFC 8785 JCS + SHA-256 deterministic anomaly_analysis_id computation
└── engine.py             # BehavioralAnomalyEngineService orchestration
```

---

## 6. Security Boundaries & Operational Constraints

1. **Strict Offline Execution:** Zero external network sockets, zero cloud APIs, zero telemetry.
2. **Controlled Runtime Boundary:** Phase 8.6 does not load or execute ONNX models directly; all execution occurs in Phase 8.2 `ControlledModelExecutor`.
3. **Database Boundary:** Zero schema changes, zero migrations, zero Phase 3 model edits.
4. **Project Isolation:** Observations across differing `project_id` values immediately raise `CrossProjectAnalysisError`.
5. **No Premature Evidence Binding:** In-memory Pydantic result structures only (Phase 8.7 owns evidence/provenance ledger binding).
