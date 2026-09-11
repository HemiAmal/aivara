# PHASE 8.3 — BEHAVIOURAL BASELINE & REFERENCE PROFILE ENGINE

**Status:** APPROVED / FROZEN  
**Phase:** 8.3  
**Subsystem:** Behavioural Analysis  
**Repository:** AIVARA — AI Verification & Assurance  
**Verification Baseline:** 1117 / 1117 tests passing (100%) | 0 Regressions

---

## 1. Objective

Phase 8.3 establishes the **Behavioural Baseline & Reference Profile Engine** within the AIVARA verification framework.

Its primary purpose is to construct deterministic, canonical behavioral reference profiles from controlled model observations. These reference profiles define **what was observed** and provide an immutable, mathematically sound basis against which future phases (e.g., Phase 8.4 Perturbation Analysis, Phase 8.5 Output Stability, Phase 8.6 Behavioral Anomaly Detection) can compare candidate model behaviors.

### Core Principle & Semantic Neutrality

A behavioral baseline describes **WHAT WAS OBSERVED**; it does not assert **WHAT IS MALICIOUS**.

```
BASELINE DEVIATION       ≠  MALICIOUSNESS
REFERENCE DIFFERENCE     ≠  ATTACK SUCCESS
UNUSUAL RESPONSE         ≠  BACKDOOR
NUMERICAL DIFFERENCE     ≠  DELIBERATE SABOTAGE
```

Phase 8.3 intentionally establishes the **expected behavioral baseline** without performing anomaly scoring, backdoor discovery, or risk synthesis.

---

## 2. Baseline Taxonomy

Phase 8.3 defines a typed taxonomy representing the origin and nature of reference data (`BaselineType`):

| Baseline Type | Description |
| :--- | :--- |
| `TRUSTED_REFERENCE_MODEL` | A cryptographically verified reference model executed on the identical controlled input set. |
| `REFERENCE_EXECUTION_PROFILE` | A previously measured behavioral profile from the same model/configuration under identical conditions. |
| `HISTORICAL_PROFILE` | An established behavioral profile compiled from compatible historical observations. |
| `EXPECTED_BEHAVIOR_SPECIFICATION` | Explicit, contractually declared behavioral constraints (e.g., class vocabulary, latency ceilings). |
| `NO_BASELINE` | Explicit representation that no reference baseline exists; baselines are **never manufactured**. |

---

## 3. Trust Model

Baselines carry an explicit trust state (`BaselineTrustStatus`), propagating cryptographic and Phase 7 integrity evidence:

| Trust Status | Semantics |
| :--- | :--- |
| `VERIFIED` | Full cryptographic and structural integrity verified via Phase 7 Master Model Fingerprint ($H_{\text{master}}$) and Merkle proofs. |
| `UNVERIFIABLE` | Reference artifact lacks verifiable provenance or cryptographic proof chain. |
| `INVALID` | Reference artifact failed integrity checks, was tampered with, or contains broken contracts. |
| `UNAVAILABLE` | Reference model or evidence is absent. |

A reference model that fails integrity verification is strictly marked `INVALID` and prevented from serving as a valid reference baseline.

---

## 4. Identity Model & Baseline Identity Hash

Every behavioral baseline possesses a deterministic, canonical 64-character lowercase SHA-256 identity hash (`baseline_id`).

### Deterministic Digest Construction

The `baseline_id` binds the following canonical tuple via RFC 8785 JSON Canonicalization Scheme (JCS):

$$\text{baseline\_id} = \text{SHA-256}\Big(\text{JCS}\big(\langle \text{project\_id}, \text{model\_id}, \text{model\_fingerprint}, \text{task\_type}, \text{input\_set\_identity}, \text{execution\_provider}, \text{baseline\_type}, \text{profile\_hash}, \text{preprocessing\_hash} \rangle\big)\Big)$$

- Python object hashes and non-deterministic memory addresses are strictly prohibited.
- Modifying any component of the model fingerprint, inputs, execution environment, or preprocessing contract deterministically changes the `baseline_id`.

---

## 5. Input Set Identity (`input_set_id`)

The observation set is identified by a deterministic 64-character SHA-256 digest (`input_set_id`).

### Canonical Ordering & Hashing

1. For each input item $i$, a canonical sample digest $\text{sample\_hash}_i$ is computed from input arrays (using contiguous C-order bytes) and associated metadata.
2. The list of sample descriptors is sorted canonically by `input_id`.
3. The aggregate `input_set_id` is computed:

$$\text{input\_set\_id} = \text{SHA-256}\Big(\text{JCS}\big(\text{canonical\_sorted\_descriptors}\big)\Big)$$

The `input_set_id` is invariant to input discovery order, but changes immediately if any input is added, removed, altered, or re-associated.

---

## 6. Support Semantics (`BaselineSupportStatus`)

To prevent small sample sets from producing falsely authoritative reference distributions, Phase 8.3 enforces strict sample support thresholds:

- **$N < 5$:** Classified as `BaselineSupportStatus.INSUFFICIENT_SUPPORT`. The resulting `BehavioralBaseline.baseline_status` is marked `INSUFFICIENT_SUPPORT`, and a documented limitation is attached.
- **$N \ge 5$:** Classified as `BaselineSupportStatus.ADEQUATE_SUPPORT`.

Population-level inferences are never drawn from statistically inadequate observations.

---

## 7. Classification Profiles (`ClassificationBehaviorProfile`)

For classification tasks, the engine compiles deterministic profile distributions:

- **Prediction Frequency & Proportions:** Discrete class frequency mapping ($\text{count}(c)$) and normalized proportions ($p(c)$).
- **Top-1 Distribution:** Top-1 predicted class frequencies across samples.
- **Confidence Statistics:** Numerically stable min, max, mean, median, std, p25, p75, p95 across top-1 confidence values.
- **Entropy Statistics:** Shannon entropy calculated **strictly when outputs are confirmed probabilities**:
  $$H(p) = -\sum_{c} p_c \ln(p_c)$$
  Entropy is strictly **omitted** when outputs are raw logits or unbounded scores.
- **Prediction Margins:** Top-1 minus top-2 score differences where multidimensional outputs exist.
- **Finite Output Rate:** Proportion of outputs containing purely finite IEEE 754 floating-point values.

---

## 8. Object Detection Profiles (`DetectionBehaviorProfile`)

For object detection tasks, the engine compiles spatial and categorical distributions:

- **Detection Count Statistics:** Distribution of bounding box counts per sample image.
- **Class Frequency Distribution:** Discrete detection counts per predicted category.
- **Box Confidence Statistics:** Min, max, mean, median, std, and percentiles of bounding box confidence scores.
- **Bounding Box Area Statistics:** Distribution of box areas ($\text{width} \times \text{height}$).
- **Empty-Detection Frequency:** Proportion of evaluated samples yielding zero detections.
- **Finite Output Rate:** Proportions of valid bounding boxes and scores.

---

## 9. Segmentation Profiles (`SegmentationBehaviorProfile`)

Phase 8.3 strictly adheres to ADR-051 and frozen architecture rules regarding segmentation evaluation:

### Case A: Dense Ground Truth Masks Available
- Evaluates categorical Intersection-over-Union per class and aggregates exact mean IoU:
  $$\text{mIoU} = \frac{1}{|C|} \sum_{c \in C} \frac{|P_c \cap G_c|}{|P_c \cup G_c|}$$
- Populates `ground_truth_miou`.
- Sets `evaluation_case = "GROUND_TRUTH_mIoU"`.
- Leaves `reference_mask_agreement = None`.

### Case B: Reference Model Output Available (No Dense Ground Truth)
- Computes spatial categorical agreement between candidate model mask $P$ and reference model mask $R$:
  $$\text{Agreement} = \frac{1}{|C|} \sum_{c \in C} \frac{|P_c \cap R_c|}{|P_c \cup R_c|}$$
- Populates `reference_mask_agreement`.
- Sets `evaluation_case = "REFERENCE_MASK_AGREEMENT"`.
- Leaves `ground_truth_miou = None`.
- **Strict Invariant:** Model-to-model mask agreement is **never** termed ground-truth mIoU.

### Case C: Neither Ground Truth nor Reference Mask Available
- Records class pixel counts, mask shapes, and proportions.
- Sets `ground_truth_miou = None`, `reference_mask_agreement = None`.
- Sets `evaluation_case = "UNAVAILABLE"`.

---

## 10. Numerical Profiles (`NumericalProfile`)

To prevent non-finite IEEE 754 artifacts from contaminating baseline profiles, the engine computes per-tensor numerical statistics:

- Per-tensor metrics: `min`, `max`, `mean`, `std`.
- Finite rate: $\frac{\text{count}(\text{finite})}{\text{total elements}}$.
- NaN rate: $\frac{\text{count}(\text{NaN})}{\text{total elements}}$.
- Inf rate: $\frac{\text{count}(\pm\text{Inf})}{\text{total elements}}$.
- Non-finite values are trapped and summarized; they never cause silent division-by-zero or corrupted aggregations.

---

## 11. Latency Profiles (`LatencyProfile`)

Execution latency is highly sensitive to the runtime environment. Phase 8.3 binds latency metrics directly to hardware and runtime parameters:

- Summary statistics: `count`, `min`, `max`, `mean`, `median`, `std`, `p25`, `p75`, `p95` (in milliseconds).
- Hardware & Runtime Binding:
  - `execution_provider` (`CPUExecutionProvider` or `CUDAExecutionProvider`)
  - `device` (e.g. `cpu`, `cuda:0`)
  - `runtime_version` (e.g. ONNX Runtime version)
  - `precision` (e.g. `float32`, `float16`)

Latency profiles measured under `CPUExecutionProvider` are strictly non-comparable to profiles measured under `CUDAExecutionProvider`.

---

## 12. Repeatability Observations (`RepeatabilityProfile`)

Phase 8.3 supports recording baseline determinism observations:

- `repeated_runs`: Count of identical repeat evaluations.
- `prediction_agreement_rate`: Proportion of runs yielding identical top-1 predictions.
- `max_numerical_delta`: Maximum absolute element-wise floating-point difference across runs.
- `determinism_status`: `DETERMINISTIC | NUMERICALLY_STABLE | NONDETERMINISTIC`.

*(Full multi-iteration output stability analysis is deferred to Phase 8.5).*

---

## 13. Comparability Rules (`validate_baseline_comparability`)

Two behavioral baselines or candidate runs are comparable **only** when compatible on all essential operational dimensions:

1. **Task Type:** Must match identically (`candidate_task == baseline_task`).
2. **Input Set Identity:** Must have identical `input_set_id`.
3. **Preprocessing Hash:** If defined, preprocessing digests must match.
4. **Execution Provider:** CPU and CUDA baselines are strictly segregated.

If compatibility checks fail, the engine returns `is_comparable = False` with explicit failure reason codes (`TASK_TYPE_MISMATCH`, `INPUT_SET_MISMATCH`, `PREPROCESSING_MISMATCH`, `EXECUTION_PROVIDER_MISMATCH`). Comparisons are never forced.

---

## 14. Reference Model Relationship

When establishing a `TRUSTED_REFERENCE_MODEL` baseline:
- Reference model asset ID (`reference_model_id`) and Master Fingerprint (`reference_model_fingerprint`) are bound.
- Reference integrity status is consumed directly from Phase 7 interfaces.
- If Phase 7 verification indicates tampering or failure, trust status is set to `INVALID` or `UNVERIFIABLE`.

---

## 15. Expected Behavior Specifications (`ExpectedBehaviorSpecification`)

System or user-supplied constraints (e.g., allowable classes, max latency ceiling, minimum confidence) can be bound to the baseline.

- All such constraints carry `is_user_specified: True`.
- User specifications are treated strictly as administrative expectations, **never as learned empirical ground truth**.

---

## 16. Missing-Data Handling

The engine handles incomplete or missing data explicitly:
- Missing confidence / logits $\to$ statistical fields set to `None`, documented in `limitations`.
- Missing ground truth $\to$ `evaluation_case = "UNAVAILABLE"`, `ground_truth_miou = None`.
- Fabricated or synthetic default values are **never** injected.

---

## 17. Determinism Guarantee

Determinism is strictly guaranteed through:
- Canonical sorting of dictionary keys and class distributions.
- RFC 8785 JSON Canonicalization Scheme (JCS) serialization.
- SHA-256 cryptographic hashing for all identity and profile digests.
- Stable numpy floating-point accumulators.

---

## 18. Security Enforcement

All execution underpinning baseline generation is governed by the frozen Phase 8.2 Safe Runtime Observation Boundary:
- Path traversal, UNC paths, symlink escapes rejected.
- Private keys, database files, and `.git` trees isolated.
- Timeout (10.0s hard ceiling) and batch size (64 ceiling) enforced.
- Memory and tensor element limits enforced.

---

## 19. Offline Operation

All profile generation is 100% offline and air-gapped. Zero network sockets, remote APIs, telemetry, or external registries are contacted.

---

## 20. Database Boundary

**ZERO DATABASE SCHEMA CHANGES.**  
No new ORM tables, columns, or Alembic migrations were introduced in Phase 8.3. Baseline structures remain pure Pydantic domain models.

---

## 21. Future Anomaly Detection Boundary

Phase 8.3 intentionally halts at profile construction:
- **No** MAD / z-score anomaly thresholds (Phase 8.6).
- **No** perturbation generators (Phase 8.4).
- **No** backdoor or trigger discovery (Phase 9).
- **No** risk scoring or universal risk synthesis (Phase 12).

---

## 22. Test Results

- **Phase 8.3 Targeted Test Suite:** 22 / 22 PASS (100%)
- **Phase 8.2 Runtime Boundary Suite:** 23 / 23 PASS (100%)
- **Phase 7 Model Integrity Suite:** 202 / 202 PASS (100%)
- **Full Repository Test Suite:** 1117 / 1117 PASS (100%)
- **Phase 7 & Database Regressions:** 0

---

## 23. Limitations

1. **Statistical Sample Floor:** Baselines generated with sample size $N < 5$ are marked `INSUFFICIENT_SUPPORT` and cannot serve as high-confidence statistical references.
2. **Device-Specific Latency:** Latency profiles are bound to specific execution providers and hardware devices; cross-device latency comparison is non-comparable.
3. **Logits vs Probabilities:** Shannon entropy is computed only when output tensors are explicitly confirmed to be normalized probabilities.
4. **Segmentation Ground Truth:** Dense ground-truth mIoU is calculated only when dense categorical ground-truth masks are provided; reference model mask overlap is recorded strictly as `reference_mask_agreement`.
