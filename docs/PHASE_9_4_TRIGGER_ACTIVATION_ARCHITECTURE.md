# PHASE 9.4 — TRIGGER ACTIVATION ARCHITECTURE & SPECIFICATION

**AIVARA — AI Verification & Assurance**  
**Document ID:** `DOC-AIVARA-PHASE-9.4-ACTIVATION-ARCH`  
**Status:** IMPLEMENTED (PENDING FREEZE REVIEW)  
**Upstream Architecture:** [PHASE 9.1 ARCHITECTURE](file:///d:/Downloads/Projects/AiVara/docs/PHASE_9_1_BACKDOOR_TRIGGER_ARCHITECTURE.md) (ADR-061 – ADR-084), [PHASE 9.2 CANDIDATE GENERATION](file:///d:/Downloads/Projects/AiVara/docs/PHASE_9_2_SAFE_TRIGGER_CANDIDATE_GENERATION.md) (ADR-085), [PHASE 9.3 TRANSFORMATION ENGINE](file:///d:/Downloads/Projects/AiVara/docs/PHASE_9_3_TRIGGER_TRANSFORMATION_ENGINE.md) (ADR-086, ADR-087)  
**Downstream Consumer:** PHASE 9.5 — STATISTICAL SIGNIFICANCE & LOCALIZATION  

---

## 1. MISSION & SCOPE

Phase 9.4 implements the deterministic, controlled trigger activation and paired clean-vs-triggered behavioral comparison layer in AIVARA.

### Core Question
> *"Does applying a candidate trigger to controlled inputs produce a statistically and behaviorally unusual model response compared with the corresponding clean inputs and required control conditions?"*

### Fundamental Semantic Rule
$$\text{trigger-like behavior} \ne \text{backdoor evidence} \ne \text{malicious intent} \ne \text{malicious actor}$$

> **CRITICAL ARCHITECTURAL CONTRACT:**  
> **Trigger-like behavioral activation does not establish malicious intent.**  
> Phase 9.4 produces objective comparative observations and rates only. It produces zero conclusions of malice, actor intent, or system compromise.

---

## 2. FOUR-CONDITION PAIRED EVALUATION DESIGN

For every input sample $i \in \{1, \dots, N\}$, the pipeline executes four deterministic conditions with strict 1-to-1 correspondence ($\text{clean\_sample}_i \leftrightarrow \text{triggered\_sample}_i$):

```
Clean Input (S_i)
  ├── 1. CLEAN Execution ───────────────────────────────► Clean Output (Y_clean)
  ├── 2. ACTIVE_TRIGGER Transformation ─► Execution ────► Triggered Output (Y_trig)
  ├── 3. LOCATION_SHUFFLED Control ──────► Execution ────► Shuffled Output (Y_shuff)
  └── 4. MAGNITUDE_MATCHED_NOISE Control ─► Execution ──► Noise Output (Y_noise)
  └── 5. REFERENCE_MODEL Control (Optional / Reserved) ─► Ref Output (Y_ref)
                                                                 │
                                                                 ▼
                                                    Paired Behavioral Comparison
                                                    & Task-Aware Activation
```

### Condition Semantics
1. **`CLEAN`**: The original unperturbed input array executed directly on the model.
2. **`ACTIVE_TRIGGER`**: The candidate trigger applied using the candidate's exact specified geometry, pattern, and placement via the Phase 9.3 Transformation Engine.
3. **`LOCATION_SHUFFLED`**: The exact same trigger candidate applied with randomized placement within the valid spatial domain of the candidate geometry, derived via deterministic `PCG64` seed.
4. **`MAGNITUDE_MATCHED_NOISE`**: Gaussian noise calibrated to match the **realized RMS perturbation delta** ($\text{RMS}_{\text{realized}} = \sqrt{\frac{1}{|S|}\sum (X_{\text{trigger}} - X_{\text{clean}})^2}$) of the active trigger, without reproducing structured trigger patterns.
5. **`REFERENCE_MODEL`** *(Optional / Reserved)*: Comparison against an explicitly supplied reference model pipeline. Marked `OPTIONAL_RESERVED` when omitted and `IMPLEMENTED_SUPPLIED` when executed.

---

## 3. SEPARATION OF CONCEPTS: ACTIVATION, TARGET-CONDITIONED SUCCESS, & TSR

Phase 9.4 strictly separates three distinct empirical evaluation concepts:

### A. Trigger Activation
Binary decision whether an input sample activated under condition $C$ relative to clean reference using a task-aware criterion (e.g. classification prediction change, confidence drop, detection box delta, segmentation clean-relative degradation, or generic tensor distance).
$$\text{TAR}(C) = \frac{|\{i \in E : \text{activated}_i(C) = \text{True}\}|}{|E|}$$
- Evaluated for all tasks and conditions.
- If eligible sample count $|E| = 0$: $\text{TAR} = \text{None}$.

### B. Target-Conditioned Success
Binary decision whether the model output matched an explicitly declared `target_class`.
- Evaluated **only** when `target_class` is explicitly supplied in `ActivationCriterionSpec`.
- When `target_class` is absent / `None`:
  $$\text{target-conditioned success} = \text{NOT\_APPLICABLE}\ (\text{represented as None})$$

### C. Trigger Success Rate (TSR)
The empirical rate of target-conditioned success across the eligible sample set:
$$\text{TSR}(C) = \frac{|\{i \in E : \text{target\_matched}_i(C) = \text{True}\}|}{|E|}$$
- When `target_class` is absent: $\text{TSR} = \text{None}$, $\text{control\_tsr\_shuffled} = \text{None}$, $\text{control\_tsr\_noise} = \text{None}$.
- When `target_class` is supplied: $\text{TSR}$, $\text{control\_tsr\_shuffled}$, and $\text{control\_tsr\_noise}$ are computed to supply Phase 9.5 for the statistical null hypothesis test:
  $$\mathbf{H_0:}\ \text{TSR}(\tau) \le \max\left(\text{TSR}(C_{\text{shuff}}), \text{TSR}(C_{\text{noise}})\right)$$
  $$\mathbf{H_1:}\ \text{TSR}(\tau) > \max\left(\text{TSR}(C_{\text{shuff}}), \text{TSR}(C_{\text{noise}})\right)$$

---

## 4. STATISTICAL SUPPORT STATUS VS. ASSESSMENT STATUS

Phase 9.4 strictly separates **sample support eligibility** from **assessment / execution status**:

- **Support Status ([`BackdoorSupportStatusEnum`](file:///d:/Downloads/Projects/AiVara/backend/aivara/backdoor/activation/enums.py#L18)):**
  - $N < 10$ ($|E| < 10$):
    $$\text{support\_status} = \text{INSUFFICIENT\_SUPPORT},\ \text{is\_support\_eligible} = \text{False}$$
  - $N \ge 10$ ($|E| \ge 10$):
    $$\text{support\_status} = \text{SUPPORT\_ELIGIBLE},\ \text{is\_support\_eligible} = \text{True}$$
- **Assessment Status ([`BackdoorComparisonStatusEnum`](file:///d:/Downloads/Projects/AiVara/backend/aivara/backdoor/activation/enums.py#L23)):**
  - `COMPLETED`: Pipeline executed successfully and generated paired observations.
  - Failure/Degenerate: `NOT_APPLICABLE`, `UNAVAILABLE`, `UNVERIFIABLE`, `INCOMPARABLE`, `INVALID_INPUT`, `RESOURCE_LIMIT`, `EXECUTION_FAILED`, `INTEGRITY_FAILURE`.
- **Orthogonality Rule:** Observing $N = 100$ with $\text{TAR} = 0.0$ and $\text{TSR} = 0.0$ yields:
  - `support_status = SUPPORT_ELIGIBLE`
  - `is_support_eligible = True`
  - `status = COMPLETED`
  - `tar = 0.0`, `activated_sample_count = 0`
  *Adequate sample support $N \ge 10$ NEVER implies trigger success or backdoor presence.*

---

## 5. TASK-AWARE ACTIVATION CRITERIA & DETERMINISTIC DECISION RULES

Reuses Phase 8.5 mathematical metrics without duplication. Every decision rule produces an explicit boolean `ACTIVATED` vs `NOT_ACTIVATED` or fail-safe `UNAVAILABLE` status, recording complete metric, threshold, operator, clean value, condition value, delta value, and criterion version:

### 1. Classification
- `PREDICTION_CHANGED`: $y_{\text{cond}} \ne y_{\text{clean}} \implies \text{ACTIVATED}$.
- `TARGET_MATCHED`: $y_{\text{cond}} == \text{target\_class} \implies \text{ACTIVATED}$.
- `CONFIDENCE_DELTA_THRESHOLD`: $p_{\text{clean}}(y_{\text{clean}}) - p_{\text{cond}}(y_{\text{clean}}) \ge \theta_{\text{conf}} \implies \text{ACTIVATED}$.

### 2. Object Detection
- `DETECTION_COUNT_DELTA`:
  $$\text{signed\_delta} = n_{\text{cond}} - n_{\text{clean}},\quad \text{abs\_delta} = |n_{\text{cond}} - n_{\text{clean}}|$$
  $$\text{activated} = (\text{abs\_delta} \ge \text{count\_delta\_threshold})$$
- `DETECTION_IOU_DROP` *(Clean-Relative Degradation)*:
  $$\text{clean\_iou} = \text{mean\_matched\_iou}(\text{clean\_output})$$
  $$\text{condition\_iou} = \text{mean\_matched\_iou}(\text{condition\_output})$$
  $$\Delta\text{IoU} = \text{clean\_iou} - \text{condition\_iou}$$
  $$\text{activated} = (\Delta\text{IoU} \ge \text{iou\_drop\_threshold})$$
  - If $n_{\text{clean}} == 0 \land n_{\text{cond}} == 0 \implies \text{NOT\_ACTIVATED}$ (`VALID_ZERO_DETECTIONS`).
  - If condition has zero matches against reference $\implies \text{condition\_iou} = 0.0 \implies \Delta\text{IoU} = \text{clean\_iou} - 0.0$.
  - Missing metric / incompatible format $\implies \text{UNAVAILABLE}$ (no fabrication).
- `DETECTION_TARGET_CLASS_INJECTED`: $\text{target\_class} \in \text{cond} \land \text{target\_class} \notin \text{clean} \implies \text{ACTIVATED}$.

### 3. Semantic Segmentation (Clean-Relative Degradation & Disagreement)
- `SEGMENTATION_GT_MIOU_DROP`:
  $$\text{clean\_miou} = \text{mIoU}(\text{clean\_output}, \text{GT})$$
  $$\text{condition\_miou} = \text{mIoU}(\text{condition\_output}, \text{GT})$$
  $$\Delta\text{mIoU} = \text{clean\_miou} - \text{condition\_miou}$$
  $$\text{activated} = (\Delta\text{mIoU} \ge \text{drop\_threshold})$$
  *If dense GT is unavailable $\implies \text{UNAVAILABLE}$. Does NOT fabricate mIoU.*
- `SEGMENTATION_REFERENCE_MASK_AGREEMENT_DROP`:
  $$A_{\text{clean}} = \text{agreement}(\text{clean\_output}, \text{reference\_output})$$
  $$A_{\text{condition}} = \text{agreement}(\text{condition\_output}, \text{reference\_output})$$
  $$\Delta A = A_{\text{clean}} - A_{\text{condition}}$$
  $$\text{activated} = (\Delta A \ge \text{drop\_threshold})$$
  *If reference model output is unavailable $\implies \text{UNAVAILABLE}$. Does NOT fabricate reference agreement.*
- `SEGMENTATION_MASK_DISAGREEMENT` *(Preserved Behavioral-Change Metric)*:
  $$D_{\text{clean, cond}} = 1.0 - \text{agreement}(\text{mask}_{\text{condition}}, \text{mask}_{\text{clean}})$$
  $$\text{activated} = (D_{\text{clean, cond}} \ge \text{drop\_threshold})$$
  *Measures direct condition-vs-clean mask divergence without reference model.*
- `SEGMENTATION_TARGET_CLASS_EMERGENCE`:
  $$\text{activated} = (\text{target\_pixels}_{\text{cond}} > 0 \land \text{target\_pixels}_{\text{clean}} == 0)$$

### 4. Generic Tensor
- `TENSOR_DISTANCE_THRESHOLD`:
  $$L_2(\text{cond}, \text{clean}) \ge \theta_{\text{dist}} \implies \text{ACTIVATED}$$

---

## 6. GEOMETRY-AWARE LOCATION SHUFFLING & REALIZED RMS MATCHING

### 1. Geometry-Aware Location Shuffling
- Uses candidate geometry dimensions (`relative_width`, `relative_height`, `relative_radius`, `shape`).
- Circular patches compute footprint slack from $2 \times \text{relative\_radius}$.
- Bounds normalized spatial placement strictly within $[0.0, 1.0] \times [0.0, 1.0]$.
- Derives coordinates via isolated `PCG64` seed.
- Records `original_placement`, `shuffled_placement`, `seed`, `relative_width`, `relative_height`, and `placement_policy_version = "1.0.0"`.

### 2. Realized RMS Magnitude Matching
- Explicitly computes the **Realized Trigger RMS**:
  $$\text{RMS}_{\text{realized}}(\text{trigger}) = \sqrt{\frac{1}{|S|}\sum (X_{\text{trigger}} - X_{\text{clean}})^2}$$
- Synthesizes unstructured Gaussian noise with standard deviation matched to realized trigger RMS.
- Clips to declared value range and calculates **Realized Noise RMS**:
  $$\text{RMS}_{\text{realized}}(\text{noise}) = \sqrt{\frac{1}{|S|}\sum (X_{\text{noise}} - X_{\text{clean}})^2}$$
- Validates matching tolerance ($\le 25\%$). If clipping saturation prevents matching, records status `UNAVAILABLE`.
- Records `trigger_perturbation_magnitude`, `control_perturbation_magnitude`, `matching_method`, `matching_tolerance`, `matching_error`, and `seed`.

---

## 7. HARD RESOURCE LIMITS & CONTROLLED EXECUTION BOUNDARY

- **Batch Size Limit:** $\le 16$
- **Evaluation Sample Budget:** $\le 256$
- **Spatial Dimensions:** $\le 4096 \times 4096$
- **Channel Limit:** $\le 4$
- **Max Tensor Elements:** $\le 100,000,000$
- **Execution Timeout:** $\le 10.0$ seconds
- **Output Size:** $\le 500$ MB
- **Memory Budget:** $\le 4$ GB
- **Security Boundary:** **Controlled In-Memory Execution Boundary** enforcing zero subprocessing, zero network egress, zero runtime code evaluation (`eval`/`exec`), immutable model and source input verification. *This is not an OS-level sandbox or hypervisor isolation boundary.*
