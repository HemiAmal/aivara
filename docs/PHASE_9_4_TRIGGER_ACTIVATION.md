# PHASE 9.4 — TRIGGER ACTIVATION & CLEAN-vs-TRIGGERED BEHAVIORAL COMPARISON

**AIVARA — AI Verification & Assurance**  
**Document ID:** `DOC-AIVARA-PHASE-9.4-ACTIVATION-SPEC`  
**Status:** IMPLEMENTED (PENDING FINAL FREEZE APPROVAL)  
**Applicable Phases:** Phase 9.4 (Active), Phase 8 (Frozen Dependency), Phase 9.1–9.3 (Frozen Dependencies)  

---

## 1. EXECUTIVE SUMMARY & OBJECTIVE

Phase 9.4 implements the deterministic, controlled trigger activation and paired clean-vs-triggered behavioral comparison engine.

### Purpose
To answer defensibly, reproducibly, and without bias:
> *"Does applying a candidate trigger to controlled inputs produce a statistically and behaviorally unusual model response compared with the corresponding clean inputs and required control conditions?"*

### Fundamental Semantic Rule
$$\text{trigger-like behavior} \ne \text{backdoor evidence} \ne \text{malicious intent} \ne \text{malicious actor}$$

> **CRITICAL ARCHITECTURAL CONTRACT:**  
> **Trigger-like behavioral activation does not establish malicious intent.**  
> Phase 9.4 restricts all findings to objective, verifiable mathematical observations. It produces zero judgments of malice, actor intent, or system compromise.

---

## 2. FOUR-CONDITION CONTROL STRUCTURE

Each evaluation sample $i \in \{1, \dots, N\}$ is evaluated under four distinct conditions with strict 1-to-1 pairing ($\text{clean\_sample}_i \leftrightarrow \text{triggered\_sample}_i$):

| Condition | Description | Determinism & Boundary Mechanism |
|---|---|---|
| `CLEAN` | Source input without any perturbation. | Direct evaluation; byte immutability verified. |
| `ACTIVE_TRIGGER` | Trigger applied using candidate geometry, pattern, and placement. | Phase 9.3 Transformation Engine. |
| `LOCATION_SHUFFLED` | Identical candidate trigger placed at pseudorandom valid spatial coordinates. | Deterministic `PCG64` seed from input identity; geometry-aware placement bounds. |
| `MAGNITUDE_MATCHED_NOISE` | Perturbation with matched realized RMS magnitude without spatial pattern. | Deterministic Gaussian noise matched to realized RMS delta ($\le 25\%$ tolerance). |
| `REFERENCE_MODEL` *(Optional)* | Comparison against an explicitly supplied reference model. | Marked `OPTIONAL_RESERVED` when omitted; `IMPLEMENTED_SUPPLIED` when executed. |

---

## 3. SEPARATION OF METRICS, SUPPORT ELIGIBILITY, & DENOMINATOR SAFETY

### A. Trigger Activation Rate (TAR)
$$\text{TAR}(C) = \frac{|\{i \in E : \text{activated}_i(C) = \text{True}\}|}{|E|}$$
- $E$ is the set of eligible paired observations.
- If $|E| = 0$: $\text{TAR} = \text{None}$.

### B. Target-Conditioned Success & Trigger Success Rate (TSR)
- Evaluated **only** when `target_class` is explicitly supplied in `ActivationCriterionSpec`.
- When `target_class` is absent:
  $$\text{target\_matched\_sample\_count} = \text{None}$$
  $$\text{TSR} = \text{None},\ \text{control\_tsr\_shuffled} = \text{None},\ \text{control\_tsr\_noise} = \text{None}$$
- When `target_class` is supplied:
  $$\text{TSR}(C) = \frac{|\{i \in E : \text{target\_matched}_i(C) = \text{True}\}|}{|E|}$$
- This directly supplies Phase 9.5 with empirical rates for the paired permutation test:
  $$\mathbf{H_0:}\ \text{TSR}(\tau) \le \max\left(\text{TSR}(C_{\text{shuff}}), \text{TSR}(C_{\text{noise}})\right)$$

### C. Statistical Support Status vs. Execution Status
- Support Status:
  - If $|E| < 10$: `support_status = INSUFFICIENT_SUPPORT`, `is_support_eligible = False`.
  - If $|E| \ge 10$: `support_status = SUPPORT_ELIGIBLE`, `is_support_eligible = True`.
- Execution Status:
  - `status = COMPLETED` (denoting assessment pipeline completion).
- **Core Invariant:** Sample support $N \ge 10$ is strictly orthogonal to behavioral activation. $N = 100$ with zero activations yields `support_status = SUPPORT_ELIGIBLE`, `status = COMPLETED`, $\text{TAR} = 0.0$, and $\text{TSR} = 0.0$ (never a trigger success).

---

## 4. ARCHITECTURAL DECISION RECORD: ADR-088

### Title
**ADR-088: Paired Trigger Activation and Controlled Behavioral Comparison**

### Context
Evaluating whether a model exhibits trigger-like vulnerability requires comparing triggered executions against both clean baselines and empirical controls (location-shuffled triggers and magnitude-matched noise) on identical input samples across diverse model modalities.

### Decision
1. **Paired Correspondence:** All evaluations must enforce a 1-to-1 sample pairing ($\text{clean\_sample}_i \leftrightarrow \text{triggered\_sample}_i$). Unpaired sample evaluations are strictly rejected.
2. **Four Conditions:** Implement `CLEAN`, `ACTIVE_TRIGGER`, `LOCATION_SHUFFLED`, and `MAGNITUDE_MATCHED_NOISE` as standard evaluation conditions.
3. **Deterministic PCG64 Randomness:** Derive all control condition seeds using RFC 8785 JCS + SHA-256 over canonical sample identity. Global RNG state is strictly prohibited.
4. **Task-Aware Activation & Decision Rules:**
   - **Detection Count Delta:** $\text{abs\_delta} = |n_{\text{cond}} - n_{\text{clean}}| \ge \text{count\_delta\_threshold} \ge 1$.
   - **Detection IoU Drop:** $\Delta\text{IoU} = \text{clean\_iou} - \text{condition\_iou} \ge \text{iou\_drop\_threshold}$ (clean-relative degradation).
   - **Segmentation Clean-Relative Drop:**
     - Ground Truth: $\Delta\text{mIoU} = \text{clean\_miou} - \text{condition\_miou} \ge \theta_{\text{drop}}$ (dense GT).
     - Reference Agreement: $\Delta A = A_{\text{clean, ref}} - A_{\text{condition, ref}} \ge \theta_{\text{drop}}$ (reference model).
     - Direct Clean-vs-Condition Disagreement: $D = 1.0 - \text{agreement}(\text{cond}, \text{clean}) \ge \theta_{\text{drop}}$ (separate behavioral change metric).
   - Reuses Phase 8.5 metrics without duplication.
5. **Realized RMS Matching:** Magnitude matched noise computes and matches the realized RMS delta ($\sqrt{\frac{1}{|S|}\sum (X_{\text{trig}} - X_{\text{clean}})^2}$) within declared tolerance ($\le 25\%$).
6. **Geometry-Aware Location Shuffling:** Shuffled coordinates are bounded by candidate dimensions and spatial slack across all candidate families (patches, circles, grids, perturbations).
7. **Denominator & Target Safety:** TAR and TSR fail-safe to `None` if denominators are zero or target labels are absent.
8. **Support Eligibility Separation:** Explicit `support_status` (`SUPPORT_ELIGIBLE` vs `INSUFFICIENT_SUPPORT`) separated from assessment status (`COMPLETED`).
9. **Zero Database Changes:** Zero database schema modifications or migrations (`DATABASE SCHEMA CHANGES = 0`).
10. **No Maliciousness Inference:** No taxonomy values or report conclusions asserting backdoor compromise or malicious actor presence.

### Status
**ACCEPTED / IMPLEMENTED**

---

## 5. HARD RESOURCE LIMITS & CONTROLLED EXECUTION BOUNDARY

- **Batch Size Limit:** $\le 16$
- **Evaluation Sample Budget:** $\le 256$
- **Spatial Dimensions:** $\le 4096 \times 4096$
- **Channel Limit:** $\le 4$
- **Max Tensor Elements:** $\le 100,000,000$
- **Execution Timeout:** $\le 10.0$ seconds
- **Output Size:** $\le 500$ MB
- **Memory Budget:** $\le 4$ GB
- **Security Boundary:** **Controlled In-Memory Execution Boundary** enforcing zero subprocessing, zero network egress, zero runtime code evaluation (`eval`/`exec`), immutable model and source input verification. *This is not an OS-level sandbox or hypervisor isolation boundary.*

---

## 6. LIMITATIONS & FUTURE PHASE 9.5 INTERFACE

1. **Detection Orientation:** Phase 9.4 records empirical activation and comparison rates. It does NOT perform formal statistical hypothesis testing or claim backdoor compromise.
2. **Phase 9.5 Downstream Interface:** Phase 9.5 consumes Phase 9.4's paired observations (`PairedObservation`), `TSR(trigger)`, `TSR(location_shuffled)`, and `TSR(magnitude_matched_noise)` to compute empirical $p$-values via paired permutation tests ($B = 1,000$), Clopper-Pearson confidence intervals, Benjamini-Hochberg FDR adjustments, and spatial trigger localization grids.
