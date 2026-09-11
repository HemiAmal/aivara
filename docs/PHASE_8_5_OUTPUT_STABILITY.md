# PHASE 8.5 — OUTPUT CONSISTENCY & STABILITY ANALYSIS ENGINE

**Status:** APPROVED / FROZEN  
**Phase:** 8.5  
**Subsystem:** Behavioural Analysis  
**Repository:** AIVARA — AI Verification & Assurance  
**Verification Baseline:** 1165 / 1165 tests passing (100%) | 0 Regressions

---

## 1. Objective

Phase 8.5 implements the **Output Consistency & Stability Analysis Engine** in the AIVARA Behavioral Analysis subsystem.

The engine establishes a rigorous mathematical framework to measure how model outputs behave across three core experimental regimes:

1. **Repeatability:** Identical inputs and configurations executed repeatedly.
2. **Perturbation Response:** Controlled variations of inputs generated under Phase 8.4 compared with original outputs.
3. **Reference Comparison:** Candidate model outputs compared with compatible Phase 8.3 reference baseline outputs.

```
INPUT
  ↓
CONTROLLED LOCAL EXECUTION (Phase 8.2)
  ↓
OUTPUT OBSERVATION
  ↓
CANONICAL NORMALIZATION
  ↓
PAIRWISE / DISTRIBUTIONAL METRIC CALCULATION
  ↓
STABILITY & CONSISTENCY MEASUREMENT
```

### Core Principle & Semantic Neutrality

Phase 8.5 produces **objective behavioral measurements**; it strictly does not assign semantic verdicts of maliciousness or anomaly:

```
LOW STABILITY            ≠  ANOMALY
HIGH SENSITIVITY         ≠  ATTACK SUCCESS
OUTPUT DIFFERENCE        ≠  MALICIOUSNESS
REFERENCE DISAGREEMENT   ≠  BACKDOOR
```

---

## 2. Comparison Types (`ComparisonType`)

| Comparison Type | Description |
| :--- | :--- |
| `REPEATABILITY` | Compares $N \ge 2$ repeated runs of the same model and input to measure execution determinism. |
| `PERTURBATION_RESPONSE` | Compares model response between source input and Phase 8.4 perturbed input. |
| `REFERENCE_COMPARISON` | Compares candidate model output against a trusted reference model or baseline profile. |
| `GROUND_TRUTH_EVALUATION` | Compares candidate model output against verified dense ground truth annotations. |
| `GENERIC_TENSOR_COMPARISON` | Compares raw numerical tensor outputs without task-specific semantic assumptions. |

---

## 3. Classification Stability Metrics

For classification tasks, the engine calculates:

- **Prediction Agreement:** Binary indicator ($1.0$ or $0.0$) evaluating whether top-1 predicted class is identical.
- **Top-$k$ Set Overlap:** Jaccard similarity index across top-$k$ predicted class sets:
  $$J(A, B) = \frac{|A \cap B|}{|A \cup B|}$$
- **Confidence Delta:** $\Delta c = c_{\text{cand}} - c_{\text{ref}}$.
- **Kullback-Leibler (KL) Divergence:** Calculated **strictly on confirmed normalized probability distributions**:
  $$D_{\text{KL}}(P \parallel Q) = \sum_{i} P_i \ln\left(\frac{P_i}{Q_i + \epsilon}\right)$$
  *(KL divergence is strictly rejected / flagged `UNDEFINED` on unnormalized logits).*
- **Jensen-Shannon (JS) Divergence:** Symmetric, bounded divergence metric:
  $$D_{\text{JS}}(P \parallel Q) = \frac{1}{2} D_{\text{KL}}(P \parallel M) + \frac{1}{2} D_{\text{KL}}(Q \parallel M), \quad M = \frac{1}{2}(P + Q)$$
- **Entropy Delta:** $\Delta H = |H(P) - H(Q)|$.
- **Margin Delta:** $\Delta M = |(P_{(1)} - P_{(2)}) - (Q_{(1)} - Q_{(2)})|$.

---

## 4. Object Detection Consistency Metrics & Bipartite Matching

Detection arrays are never compared by arbitrary indexing. Instead, the engine performs **deterministic greedy matching**:

### Deterministic Matching Algorithm & Explicit Scope
> [!NOTE]
> **Deterministic Greedy Matching Limitation:**  
> The engine implements **deterministic greedy matching**, **NOT a globally optimal Hungarian bipartite assignment**.  
> Potential pairs are ranked strictly by sorting on:
> $$\text{sort\_key} = \big(\text{IoU} \downarrow, \text{class\_match} \downarrow, \text{candidate\_conf} \downarrow, -\text{cand\_idx} \uparrow, -\text{ref\_idx} \uparrow\big)$$
> The algorithm greedily assigns the highest valid overlap ($\text{IoU} \ge 0.5$) with deterministic tie-breaking.

### Computed Detection Metrics
- `matched_detection_count`, `unmatched_candidate_count`, `unmatched_reference_count`.
- `count_delta` = $N_{\text{cand}} - N_{\text{ref}}$.
- `mean_matched_iou`: Average spatial overlap of paired detections.
- `class_agreement_rate`: Proportion of paired detections sharing identical class labels.
- `mean_confidence_delta`: Mean score change across paired detections.
- `mean_box_displacement`: Mean Euclidean centroid shift in pixels:
  $$d_{\text{centroid}} = \sqrt{(c_x - r_x)^2 + (c_y - r_y)^2}$$

---

## 5. Segmentation Consistency Metrics

Phase 8.5 preserves the architectural invariant established in ADR-051 and Phase 8.3:

### Case A: Dense Ground Truth Available
- Populates `ground_truth_miou` using exact categorical Intersection-over-Union per class.
- Sets `evaluation_case = "GROUND_TRUTH_mIoU"`.
- Leaves `reference_mask_agreement = None`.

### Case B: Candidate vs Reference Model (No Ground Truth)
- Populates `reference_mask_agreement` computing spatial categorical overlap between candidate mask $P$ and reference mask $R$.
- Sets `evaluation_case = "REFERENCE_MASK_AGREEMENT"`.
- Leaves `ground_truth_miou = None`.
- **Strict Invariant:** Model-to-model mask agreement is **never** termed ground-truth mIoU.

### Case C: Incompatible Masks / Neither Available
- Returns `MetricValidityStatus.INCOMPATIBLE` or `UNAVAILABLE`. Masks are never silently resized.

---

## 6. Generic Tensor Distance Metrics

For raw numerical tensors where semantic task descriptors are absent:
- **Shape & Dtype Agreement:** Exact dimension and type match verification.
- **$L_1$ Distance (Manhattan Norm):** $\|A - B\|_1 = \sum_i |A_i - B_i|$.
- **$L_2$ Distance (Euclidean Norm):** $\|A - B\|_2 = \sqrt{\sum_i (A_i - B_i)^2}$.
- **Relative $L_2$ Distance:** $\frac{\|A - B\|_2}{\|B\|_2}$. If $\|B\|_2 = 0$, returns $0.0$ if $\|A - B\|_2 = 0$, otherwise returns `None` with `validity_status = MetricValidityStatus.UNDEFINED` (non-finite denominator).
- **Cosine Similarity Conventions:**
  > [!IMPORTANT]
  > **AIVARA Cosine Zero-Vector Conventions:**  
  > Mathematical cosine similarity is undefined when either vector has zero norm. AIVARA defines explicit, deterministic conventions:
  > 1. $\mathbf{u} = \mathbf{0} \land \mathbf{v} = \mathbf{0} \implies \text{cosine\_similarity} = 1.0$ (AIVARA convention for identical null representations).
  > 2. $(\mathbf{u} = \mathbf{0} \oplus \mathbf{v} = \mathbf{0}) \implies \text{cosine\_similarity} = 0.0$ (AIVARA safe fallback convention).
- **Max Absolute Difference:** $\max_i |A_i - B_i|$ ($L_\infty$ norm).
- **Mean Absolute Difference (MAE):** $\frac{1}{N} \sum_i |A_i - B_i|$.
- **Finite-Value Agreement:** Proportion of elements where finiteness agrees.

---

## 7. Repeatability Analysis (`RepeatabilityAnalysisResult`)

Evaluates determinism across $N \ge 2$ identical execution runs:
- `prediction_agreement_rate`: Top-1 prediction consistency across runs.
- `max_numerical_delta`: Maximum absolute float discrepancy.
- `mean_numerical_delta`: Mean absolute float discrepancy.
- `determinism_status`:
  - `DETERMINISTIC`: $\max \Delta = 0.0$.
  - `NUMERICALLY_STABLE`: $\max \Delta < 10^{-5}$.
  - `NONDETERMINISTIC`: $\max \Delta \ge 10^{-5}$.
- Bound to hardware execution parameters (`execution_provider`, `device`, `runtime_version`, `precision`).

---

## 8. Perturbation Sensitivity Measurement (`PerturbationSensitivityResult`)

Integrates directly with Phase 8.4 perturbation specifications to evaluate sensitivity:
- Preserves `source_input_hash`, `perturbed_input_hash`, `perturbation_id`, `perturbation_type`.
- Measures input-space distance ($L_1, L_2, \text{RMSE}$).
- Measures output-space distance ($L_1, L_2$).

### Zero-Denominator Sensitivity Semantics

To ensure mathematical validity without fabricating finite metrics when denominators vanish:

| Case | Condition | `sensitivity_ratio` | `sensitivity_status` | `input_unchanged` | `output_changed` |
| :--- | :--- | :---: | :--- | :---: | :---: |
| **Case A** | $\Delta_{\text{in}} = 0 \land \Delta_{\text{out}} = 0$ | `None` | `NOT_APPLICABLE` | `True` | `False` |
| **Case B** | $\Delta_{\text{in}} = 0 \land \Delta_{\text{out}} > 0$ | `None` | `UNDEFINED_NON_FINITE_DENOMINATOR` | `True` | `True` |
| **Case C** | $\Delta_{\text{in}} > 0 \land \Delta_{\text{out}} = 0$ | `0.0` | `VALID` | `False` | `False` |
| **Case D** | $\Delta_{\text{in}} > 0 \land \Delta_{\text{out}} > 0$ | $\frac{\Delta_{\text{out}}}{\Delta_{\text{in}}}$ | `VALID` | `False` | `True` |

---

## 9. Input & Output Distance Metrics

- **Input Distance:** Measured on raw pixel tensors ($L_1, L_2, \text{RMSE}, \text{MAD}$).
- **Output Distance:** Task-appropriate metrics (divergence for probabilities, matching IoU for detection, mask agreement for segmentation, $L_1/L_2$ for generic tensors).

---

## 10. Robust Numerical Handling

The engine traps edge cases safely without returning unhandled `NaN`/`Inf` or silent zeros:
- Non-finite outputs $\to$ metric validity marked `UNVERIFIABLE`.
- Zero-norm denominators $\to$ marked `UNDEFINED` with explicit reason codes; no silent division-by-zero.
- Empty detection sets $\to$ matches = 0, count delta computed correctly.

---

## 11. Support Semantics

Every metric result carries `support_count` indicating the number of contributing samples or elements. Small sample sizes retain documented limitations; no population-level inferences are drawn.

---

## 12. Deterministic Identities

- **`comparison_id`:** RFC 8785 JCS + SHA-256 over `(project_id, source_observation_id, target_observation_id, comparison_type, task_type, implementation_version)`.
- **`metric_id`:** RFC 8785 JCS + SHA-256 over `(metric_name, formula_version, parameters)`.
- **`analysis_id` / `sensitivity_id`:** RFC 8785 JCS + SHA-256 over execution telemetry, model identity, and input/output hashes.

---

## 13. Multi-Tenant Project Isolation

Pairwise comparison strictly validates that `source_observation` and `target_observation` belong to the identical `project_id`. Attempts to compare across projects raise `BehavioralError` with error code `CROSS_PROJECT_COMPARISON`.

---

## 14. Security & Offline Operation

- Metric calculations operate exclusively on validated data structures; no models are loaded inside metric code.
- 100% offline and air-gapped; zero external network sockets or telemetry.
- Zero subprocess execution or arbitrary code evaluation.

---

## 15. Database Boundary

**ZERO DATABASE SCHEMA CHANGES.**  
All consistency, repeatability, and comparison structures remain pure domain/service models without ORM migrations or tables.

---

## 16. Boundary with Phase 8.6

Phase 8.5 calculates **measurements**.  
Phase 8.6 will apply statistical anomaly algorithms (e.g. MAD, Robust $z$-scores) and define frozen anomaly thresholds.

---

## 17. Test Results

- **Phase 8.5 Targeted Test Suite:** 24 / 24 PASS (100%)
- **Phase 8.4 Perturbation Suite:** 24 / 24 PASS (100%)
- **Phase 8.3 Baseline Engine Suite:** 22 / 22 PASS (100%)
- **Phase 8.2 Runtime Boundary Suite:** 23 / 23 PASS (100%)
- **Phase 7 Model Integrity Suite:** 202 / 202 PASS (100%)
- **Full Repository Suite:** 1165 / 1165 PASS (100%)
- **Regressions:** 0

---

## 18. Known Limitations

1. **Probability Space Metric Applicability:** KL divergence and Jensen-Shannon divergence require normalized categorical probability distributions; unnormalized logits return `MetricValidityStatus.UNDEFINED`.
2. **Deterministic Greedy Matching vs Optimal Assignment:** Object detection matching uses deterministic greedy ranking rather than global Hungarian optimization; in edge cases with conflicting overlapping boxes, greedy tie-breaking is enforced.
3. **Dense Mask Grid Alignment:** Segmentation comparison requires identical spatial mask resolutions; disparate spatial grids are flagged `INCOMPATIBLE` rather than interpolated.
