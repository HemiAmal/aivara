# PHASE 8.6 — BEHAVIORAL ANOMALY DETECTION ENGINE ARCHITECTURE

**System:** AIVARA — AI Verification & Assurance  
**Phase:** 8.6  
**Status:** IMPLEMENTATION DESIGN SPECIFICATION  
**Security Boundary:** Layer 4 — Offline Analysis Layer  

---

## 1. Executive Summary & Purpose

The purpose of Phase 8.6 is strictly:
> **Determine whether observed model behavior is statistically unusual relative to an appropriate behavioral baseline / reference population.**

Phase 8.6 consumes the validated, deterministic measurements produced by:
- **Phase 8.3:** Behavioral Baseline & Reference Profiles (`BehavioralBaseline`, `ClassificationBehaviorProfile`, `DetectionBehaviorProfile`, etc.)
- **Phase 8.4:** Controlled Perturbation & Sensitivity Experiments (`PerturbationSensitivityResult`)
- **Phase 8.5:** Output Consistency & Stability Analysis (`BehavioralComparisonResult`, `RepeatabilityAnalysisResult`, task-specific stability metrics)

### Non-Goals & Semantic Boundary
Phase 8.6 explicitly **MUST NOT** determine or claim:
1. Maliciousness or compromise
2. Attacker intent or culpability
3. Backdoor or trojan presence
4. Trigger presence or trigger activation
5. Attack success or penetration
6. Inference integrity verdicts (belongs to Phase 7/Phase 9)
7. Distribution shift or dataset drift
8. Universal model risk or security classification (belongs to Phase 12)
9. Evidence / provenance persistence (belongs to Phase 8.7)

### The Semantic Invariant
$$\text{UNUSUAL BEHAVIOR} \neq \text{MALICIOUS BEHAVIOR}$$
Statistically unusual behavior may result from benign architectural characteristics, edge-case sensitivity, numerical differences, or rare test samples. The anomaly detector outputs only statistical behavioral classifications, never security verdicts.

---

## 2. Behavioral Reference Populations & Strict Comparability

### 2.1 Baseline Types
Phase 8.6 supports behavioral reference populations rather than arbitrary magic numbers:
- `BASELINE_REFERENCE`: A reference population derived from Phase 8.3 sealed baselines.
- `REPEATED_EXECUTION_REFERENCE`: A reference population of repeatability runs under identical inputs.
- `PERTURBATION_REFERENCE`: A reference population of sensitivity responses under matching perturbation specifications.

Every anomaly assessment explicitly preserves:
- `baseline_id`: 64-char SHA-256 identifier
- `baseline_type`: Baseline category enum
- `baseline_sample_count`: Total observations in reference
- `baseline_identity`: Full cryptographic provenance hash

### 2.2 Strict Comparability Rule
Observations and baselines are strictly comparable **only** when all required identity and execution context fields match:
- `project_id` (multi-tenant project boundary)
- `model_id` & `model_fingerprint` ($H_{\text{master}}$)
- `task_type` (classification, detection, segmentation, generic tensor)
- `input_set_identity` (matching input set hash where applicable)
- `preprocessing_hash`
- `execution_provider` (e.g. `CPUExecutionProvider` vs `CUDAExecutionProvider`)
- `precision` (e.g. `float32`)

If any required context differs:
$$\text{comparability\_status} = \text{INCOMPARABLE}$$
Cross-project comparisons are rejected with a typed `CrossProjectAnalysisError`.

### 2.3 Baseline Contamination & Trust Filtering
Not all historical observations in a baseline are guaranteed valid. Phase 8.6 enforces:
1. Observations with `BaselineTrustStatus.INVALID` or metric `validity_status == INVALID` are **strictly excluded**.
2. Observations with `UNVERIFIABLE` are handled per policy (included with limitation reporting or excluded if strict trust is required).
3. The analysis records:
   - `total_baseline_count`
   - `eligible_baseline_count`
   - `excluded_baseline_count`
   - `exclusion_reasons`

---

## 3. Statistical Methodology

Phase 8.6 avoids arbitrary hardcoded security numbers and uses robust, distribution-aware empirical statistics.

### 3.1 Robust Standardized Deviation (Directional Robust Z-Score)
For a scalar metric $x$ evaluated against an eligible reference sample sequence $B = [b_1, b_2, \dots, b_N]$:
$$\text{median}(B) = \text{median-of}(B)$$
$$\text{MAD}(B) = \text{median-of}(\{|b_i - \text{median}(B)|\}_{i=1}^N)$$

When $\text{MAD}(B) > 0$ and sample support is sufficient:
$$\text{robust\_z} = \frac{x - \text{median}(B)}{1.4826 \times \text{MAD}(B)}$$
$$\text{absolute\_robust\_z} = |\text{robust\_z}|$$

#### Directional Robust-Z Anomaly Threshold Semantics:
- **`HIGHER_IS_EXTREME`:**
  $$\text{robust\_z} \ge +\text{threshold}$$
  (Lower values, even if large negative, are strictly non-anomalous).
- **`LOWER_IS_EXTREME`:**
  $$\text{robust\_z} \le -\text{threshold}$$
  (Higher values, even if large positive, are strictly non-anomalous).
- **`TWO_SIDED`:**
  $$|\text{robust\_z}| \ge \text{threshold}$$
  (Deviations in either direction crossing magnitude threshold are anomalous).

### 3.2 Constant Baseline Handling ($\text{MAD} = 0$)
When all baseline observations are identical ($\text{MAD} = 0$):
- Do **NOT** add an artificial $\epsilon$ to the denominator.
- `robust_z` is left as `None` (or `NaN` is strictly converted to `None` with `validity_status = VALID`).
- Rely strictly on **empirical rank / extremeness**.
- If $x == \text{median}(B)$, $x$ is within the baseline range $\implies$ `NORMAL`.
- If $x \neq \text{median}(B)$, $x$ is outside the zero-dispersion baseline $\implies$ `ANOMALOUS`, and the human-readable explanation explicitly highlights **zero baseline dispersion**.

### 3.3 Empirical Extremeness & Clamping Bounds
For sample sequence $B = [b_1, \dots, b_N]$ and observation $x$, empirical tail metrics are computed and guaranteed to lie within $[0.0, 1.0]$:
- **Lower-tail extremeness (`LOWER_IS_EXTREME`):**
  $$P(B \le x) = \min\left(1.0, \max\left(0.0, \frac{\sum_{i=1}^N \mathbf{1}_{b_i \le x}}{N}\right)\right)$$
- **Upper-tail extremeness (`HIGHER_IS_EXTREME`):**
  $$P(B \ge x) = \min\left(1.0, \max\left(0.0, \frac{\sum_{i=1}^N \mathbf{1}_{b_i \ge x}}{N}\right)\right)$$
- **Two-sided extremeness (`TWO_SIDED`):**
  $$\text{extremeness} = \min(1.0, \max(0.0, 2 \times \min(P(B \le x), P(B \ge x))))$$

#### Metric Directionality (`MetricDirection`):
- `LOWER_IS_EXTREME`: Used for agreement metrics (e.g. `prediction_agreement`, `top_k_overlap`, `mean_matched_iou`, `class_agreement_rate`, `ground_truth_miou`, `reference_mask_agreement`, `pixel_agreement_rate`, `finite_value_agreement`, `prediction_agreement_rate`, `finite_value_rate`, `cosine_similarity`). Lower values indicate adverse divergence from reference baseline.
- `HIGHER_IS_EXTREME`: Used for distance, error, latency, and perturbation metrics (e.g. `kl_divergence`, `js_divergence`, `mean_box_displacement`, `l1_distance`, `l2_distance`, `relative_l2_distance`, `max_absolute_difference`, `mean_absolute_difference`, `max_numerical_delta`, `mean_numerical_delta`, `sensitivity_ratio`, `output_distance_l1`, `output_distance_l2`, `prediction_changed`, `latency_ms`, `empty_detection_rate`). Higher values indicate adverse deviation.
- `TWO_SIDED`: Used for signed deltas that can deviate meaningfully in either direction from reference (e.g. `confidence_delta`, `entropy_delta`, `margin_delta`, `count_delta`, `mean_confidence_delta`). Deviations in either tail crossing threshold are evaluated as anomalous.

---

## 4. Statistical Support Requirements

Phase 8.6 will not emit a confident statistical classification from sparse data. Support levels:
- $N < 5$: `INSUFFICIENT_SUPPORT` (no anomaly classification made; metric status = `INSUFFICIENT_SUPPORT`)
- $5 \le N < 10$: `LOW_SUPPORT`
- $10 \le N < 30$: `MODERATE_SUPPORT`
- $N \ge 30$: `ADEQUATE_SUPPORT`

**Rule:** `INSUFFICIENT_SUPPORT` is **never** converted into an anomaly score or treated as suspicious.

---

## 5. Multi-Metric Behavioral Families

Metrics are not independent. Grouping metrics into structured behavioral families prevents naive multiple-testing bias and avoids summing or multiplying non-independent $p$-values.

### Behavioral Families:
1. `REPEATABILITY`:
   - `prediction_agreement_rate`, `max_numerical_delta`, `mean_numerical_delta`
2. `OUTPUT_CONSISTENCY`:
   - Classification: `prediction_agreement`, `top_k_overlap`, `confidence_delta`, `kl_divergence`, `js_divergence`, `entropy_delta`, `margin_delta`
   - Detection: `mean_matched_iou`, `class_agreement_rate`, `count_delta`, `mean_confidence_delta`, `mean_box_displacement`
   - Segmentation: `ground_truth_miou`, `reference_mask_agreement`, `pixel_agreement_rate`
   - Generic Tensor: `l1_distance`, `l2_distance`, `relative_l2_distance`, `cosine_similarity`, `max_absolute_difference`, `mean_absolute_difference`, `finite_value_agreement`
3. `PERTURBATION_SENSITIVITY`:
   - `sensitivity_ratio`, `prediction_changed`, `output_distance_l1`, `output_distance_l2`, `confidence_delta`
4. `EXECUTION_STABILITY`:
   - `latency_ms`, `finite_value_rate`, `nan_rate`, `inf_rate`

### Family-Level Aggregation:
For each family:
- `family_name`: Family enum
- `support_status`: Minimum or dominant support status across family metrics
- `metric_count`: Total defined metrics
- `valid_metric_count`: Validly calculated metrics
- `anomalous_metric_count`: Metrics crossing threshold
- `dominant_metric`: The metric exhibiting the most extreme deviation (deterministic tie-breaking by metric name)
- `dominant_extremeness`: The extremeness / absolute robust z of the dominant metric
- `family_status`: `NORMAL | ANOMALOUS | INSUFFICIENT_SUPPORT | PARTIALLY_ANALYZED | UNAVAILABLE | INCOMPARABLE | UNVERIFIABLE`

---

## 6. Overall Behavioral Anomaly Status

The engine evaluates family-level results into a final `BehavioralAnomalyAnalysis`:
- `NORMAL`: All valid families with adequate/moderate support are within statistical thresholds.
- `ANOMALOUS`: At least one valid family contains statistically anomalous evidence.
- `INSUFFICIENT_SUPPORT`: Reference support is below minimum ($N < 5$).
- `PARTIALLY_ANALYZED`: Some families could be analyzed, while others were missing or had insufficient support, with no anomalous findings.
- `UNAVAILABLE`: Required behavioral observations do not exist.
- `INCOMPARABLE`: Observations and baseline have mismatched execution contexts.
- `UNVERIFIABLE`: Observations cannot be mathematically validated.

---

## 7. Deterministic Identity & Serialization

Each analysis is sealed with an immutable RFC 8785 JCS + SHA-256 identity:
$$\text{anomaly\_analysis\_id} = \text{SHA-256}(\text{JCS}(\text{canonical\_payload}))$$
The canonical payload incorporates:
- Schema and implementation versions
- `project_id`, `model_id`, `model_fingerprint`
- `baseline_id`, `observation_id`, `task_type`
- Threshold policy version and configuration
- Sorted metric evaluations and family summaries

---

## 8. Security & Operational Boundaries

1. **Air-Gapped & Offline:** Zero HTTP calls, zero telemetry, zero external ML calls.
2. **No Model Execution:** Phase 8.6 does not load or execute ONNX models directly; all execution remains strictly in Phase 8.2 `ControlledModelExecutor`.
3. **No Database Modification:** In-memory Pydantic results only. No new tables, migrations, or Phase 3 model edits.
4. **Project Isolation:** Cross-tenant comparisons immediately abort with `CrossProjectAnalysisError`.
