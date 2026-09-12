# PHASE 9.5 — STATISTICAL TRIGGER SIGNIFICANCE & CONTROL COMPARISON ARCHITECTURE

**Status:** **READY FOR USER REVIEW — NOT FROZEN**  
**Module:** `backend/aivara/backdoor/statistics/`  
**Applicable Phases:** Phase 9.5 (Active), Phase 8 (Frozen Dependency), Phase 9.1–9.4 (Frozen Dependencies)  
**Upstream Architecture:** [PHASE 9.1 ARCHITECTURE](file:///d:/Downloads/Projects/AiVara/docs/PHASE_9_1_BACKDOOR_TRIGGER_ARCHITECTURE.md) (ADR-061 – ADR-084), [PHASE 9.2 CANDIDATE GENERATION](file:///d:/Downloads/Projects/AiVara/docs/PHASE_9_2_SAFE_TRIGGER_CANDIDATE_GENERATION.md) (ADR-085), [PHASE 9.3 TRANSFORMATION ENGINE](file:///d:/Downloads/Projects/AiVara/docs/PHASE_9_3_TRIGGER_TRANSFORMATION_ENGINE.md) (ADR-086, ADR-087), [PHASE 9.4 TRIGGER ACTIVATION](file:///d:/Downloads/Projects/AiVara/docs/PHASE_9_4_TRIGGER_ACTIVATION_ARCHITECTURE.md) (ADR-088)  
**Downstream Interface:** Phase 10 (Inference Integrity)

---

## 1. Executive Summary

Phase 9.5 establishes the deterministic statistical evidence layer for AiVara's backdoor analysis subsystem. Consuming paired clean-vs-condition execution observations from Phase 9.4, Phase 9.5 evaluates whether an observed target-conditioned behavioral effect ($\text{TSR}$) under a synthetic trigger candidate $\tau$ is statistically distinguishable from empirical negative controls (geometry-aware location-shuffled controls $C_{\text{shuff}}$ and magnitude-matched noise controls $C_{\text{noise}}$).

Phase 9.5 adheres strictly to AiVara's core security-assurance principle:
$$\mathbf{Evidence \longrightarrow Finding \longrightarrow Confidence \longrightarrow Risk \longrightarrow Decision}$$

Rejecting the composite null at level $\alpha$ provides statistically significant evidence that the trigger candidate's observed target-conditioned success rate exceeds both negative-control rates under the assumptions of the paired permutation test. **This result does not prove maliciousness, backdoor intent, attacker identity, poisoning, or causal mechanism.**

---

## 2. Statistical Null Hypothesis & Mathematical Resolution

### 2.1 The Two-Control Mathematical Distinction
There is a fundamental mathematical distinction between:
1. **The Descriptive Aggregate Control Baseline:**
   $$\text{TSR}_{\text{control}} = \max\left(\text{TSR}(C_{\text{shuff}}), \text{TSR}(C_{\text{noise}})\right)$$
   $$\Delta_{\text{sep}} = \text{TSR}(\tau) - \text{TSR}_{\text{control}}$$
2. **The Inferential Null Distribution for Hypothesis Testing:**
   $$\mathbf{H_0:}\ \text{TSR}(\tau) \le \max\left(\text{TSR}(C_{\text{shuff}}), \text{TSR}(C_{\text{noise}})\right)$$
   $$\mathbf{H_1:}\ \text{TSR}(\tau) > \max\left(\text{TSR}(C_{\text{shuff}}), \text{TSR}(C_{\text{noise}})\right)$$

Because $\text{mean}(\max(S_i, N_i)) \ge \max(\text{mean}(S_i), \text{mean}(N_i))$, taking a per-sample maximum $c_i = \max(S_i, N_i)$ constructs an artificial union-envelope adversary that is strictly more conservative than testing against each control mechanism.

### 2.2 Intersection-Union Principle (IUT) Resolution
To test $H_0$ exactly and rigorously:
- The alternative hypothesis decomposes as the intersection:
  $$H_1: \Big(\text{TSR}(\tau) > \text{TSR}(C_{\text{shuff}})\Big) \;\land\; \Big(\text{TSR}(\tau) > \text{TSR}(C_{\text{noise}})\Big)$$
- The null hypothesis decomposes as the union of sub-nulls:
  $$H_0: H_{0, \text{shuff}} \cup H_{0, \text{noise}} = \Big(\text{TSR}(\tau) \le \text{TSR}(C_{\text{shuff}})\Big) \;\lor\; \Big(\text{TSR}(\tau) \le \text{TSR}(C_{\text{noise}})\Big)$$
- Under the **Intersection-Union Test (Berger 1982)**, $H_0$ is rejected at significance level $\alpha$ if and only if **both** $H_{0, \text{shuff}}$ and $H_{0, \text{noise}}$ are rejected at individual level $\alpha$.
- The composite inferential $p$-value is:
  $$p_{\text{composite}} = \max\left(p_{\text{shuffled}}, p_{\text{noise}}\right)$$
- The IUT construction provides conservative Type I error control when the component permutation $p$-values are valid under their respective null hypotheses and the paired exchangeability assumptions hold ($\sup_{\theta \in H_0} P(p_{\text{composite}} \le \alpha) \le \alpha$).

---

## 3. Statistical Test Methodology

### 3.1 Paired Permutation Test
- **Permutation Count:** $B = 1,000$ iterations.
- **RNG Bit Generator:** NumPy `PCG64` initialized from a 32-bit unsigned seed derived deterministically from the RFC 8785 JCS canonical analysis identity hash.
- **Synchronized Permutations:** For each permutation $b = 1, \dots, B$, condition labels are permuted across paired samples using identical sign flips $s_{b, i} \in \{-1, +1\}$.
- **Finite-Sample Corrected Individual $p$-Values:**
  $$p_{\text{shuffled}} = \frac{1 + \sum_{b=1}^B \mathbb{I}(T_{b, \text{shuff}} \ge T_{\text{obs, shuff}})}{B + 1}, \quad p_{\text{noise}} = \frac{1 + \sum_{b=1}^B \mathbb{I}(T_{b, \text{noise}} \ge T_{\text{obs, noise}})}{B + 1}$$
- **Composite IUT $p$-Value:**
  $$p = \max\left(p_{\text{shuffled}}, p_{\text{noise}}\right)$$

### 3.2 Exact Clopper-Pearson 95% Confidence Intervals
For $k$ successes out of $N$ trials ($N \ge 10$), confidence intervals are computed deterministically under the specified runtime and numerical implementation using regularized incomplete beta quantile inversion via Lentz continued fraction expansion:
- $k = 0$: $\text{CI}_{\text{lower}} = 0.0$, $\text{CI}_{\text{upper}} = 1 - (\alpha/2)^{1/N}$.
- $k = N$: $\text{CI}_{\text{lower}} = (\alpha/2)^{1/N}$, $\text{CI}_{\text{upper}} = 1.0$.
- $0 < k < N$: $\text{CI}_{\text{lower}} = I^{-1}_{\alpha/2}(k, N - k + 1)$, $\text{CI}_{\text{upper}} = I^{-1}_{1 - \alpha/2}(k + 1, N - k)$.
- $N < 10$: Returns `(None, None)` under `INSUFFICIENT_SUPPORT`.

### 3.3 Multiplicity Control
- **Candidate Screening (Stage 1):** Benjamini-Hochberg False Discovery Rate (BH-FDR) at $\alpha = 0.05$ across all candidate hypotheses in the analysis family, using deterministic tie-breaking.
- **Spatial Grid Localization (Stage 2):** Holm-Bonferroni step-down correction across $m = 64$ grid cells to control Family-Wise Error Rate (FWER) at $\alpha = 0.05$.

---

## 4. Staged Screening & Inference Budget Accounting

$$\text{Hard Inference Ceiling} = \mathbf{16,000\ inferences}$$

| Stage | Operations | Formula | Inferences |
| :--- | :--- | :--- | :--- |
| **Stage 1 (Screening)** | $N = 50$, $K_1 = 16$ candidates, 4 conditions | $50 \times (1 + 16 \times 3)$ | **2,450** |
| **Stage 2 (Expansion)** | $N = 200$, $K_2 \le 2$ promoted candidates, 4 conditions | $200 \times (1 + 2 \times 3)$ | **1,400** |
| **Stage 2 (Localization)**| $N = 50$, $K_2 \le 2$ candidates, 64 grid cells | $50 \times 2 \times 64$ | **6,400** |
| **Total Standard Pipeline**| Combined Stage 1 + Stage 2 | $2,450 + 1,400 + 6,400$ | **10,250** $\le 16,000$ |

---

## 5. Candidate Promotion Gating

A Stage 1 screening candidate qualifies for Stage 2 advancement if and only if ALL criteria are satisfied:
1. $\text{TAR} \ge 0.50$
2. $\text{TSR} \ge 0.50$ (if $y_{\text{target}}$ is absent, $\text{TSR} = \text{NOT\_APPLICABLE}$ and candidate cannot advance)
3. $\Delta_{\text{sep}} > 0.20$
4. Adequate sample support ($N \ge 10$)

**Capacity & Deterministic Tie-Breaking:**
At most $K_2 \le 2$ candidates advance. If $>2$ qualify, they are ranked deterministically by:
$$(\Delta_{\text{sep}} \downarrow, \text{TSR} \downarrow, \text{TAR} \downarrow, \text{candidate\_hash} \uparrow)$$

---

## 6. AIVARA Non-Accusatory Result Taxonomy

| Classification | Operational Diagnostic Criteria |
| :--- | :--- |
| **`STRONG_TRIGGER_CONSISTENCY`** | $N \ge 100, \text{TSR} \ge 0.90, \Delta_{\text{sep}} \ge 0.60, p_{\text{adj}} < 0.001$ |
| **`TARGETED_EFFECT_DETECTED`** | $N \ge 30, \text{TAR} \ge 0.70, \text{TSR} \ge 0.70, \Delta_{\text{sep}} \ge 0.40, p_{\text{adj}} < 0.05$ |
| **`TRIGGER_CANDIDATE_OBSERVED`** | $p_{\text{adj}} < 0.05, \Delta_{\text{sep}} > 0.0$, but below targeted thresholds |
| **`NORMAL_SENSITIVITY_ONLY`** | Trigger active, but $\Delta_{\text{sep}} \le 0.0$ or $p_{\text{adj}} \ge 0.05$ |
| **`NO_TRIGGER_EVIDENCE`** | No significant output divergence beyond control noise |
| **`INSUFFICIENT_SUPPORT`** | $N < 10$ |
| **`INCOMPARABLE`** | Architectural / tensor layout incompatibility |
| **`UNAVAILABLE`** | Required evaluation targets unavailable |
| **`UNVERIFIABLE`** | Missing cryptographic baseline or corrupted identity |
