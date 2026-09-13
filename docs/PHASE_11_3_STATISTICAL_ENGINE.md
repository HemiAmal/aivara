# PHASE 11.3 — STATISTICAL DISTRIBUTION SHIFT ENGINE SPECIFICATION
## Authoritative Two-Sample Hypothesis Testing, Multiple Testing Error Control, and Dual-Gate Decision Architecture

**Date:** 2026-09-13  
**Project:** AIVARA — AI Verification & Assurance  
**Phase:** 11.3 (Statistical Distribution Shift Engine)  
**Parent Phase:** Phase 11 — Distribution Shift / Data Drift Analysis  
**Governing Rule:** Phases 0–10, Phase 11.1, and Phase 11.2 are PERMANENTLY FROZEN.  

---

## 1. PURPOSE & ARCHITECTURAL OBJECTIVE

Phase 11.2 establishes: **"WHAT DATA ARE WE COMPARING?"** (Constructing and sealing the canonical `ComparisonBoundaryResult`).  
Phase 11.3 answers: **"ARE THE TWO VALIDATED POPULATIONS STATISTICALLY AND PRACTICALLY DIFFERENT?"**

The Statistical Distribution Shift Engine provides non-parametric two-sample hypothesis testing, physical and standardized effect-size estimation, Benjamini–Hochberg False Discovery Rate (FDR) multiple-testing correction, dual-gate decision synthesis, and immutable cryptographic analysis identity derivation.

> [!IMPORTANT]
> **Core Ethical & Assurance Principle:**
> `DISTRIBUTION SHIFT != MALICIOUS INTENT`
> Distribution shift is objective mathematical evidence of population divergence. It is NOT proof of data poisoning, backdoor trigger injection, malicious manipulation, contributor fraud, or attacker intent.

---

## 2. STATISTICAL METHOD CAPABILITY MATRIX

| Method ID | Modality / Input | Statistic ($T$) | Null Hypothesis ($H_0$) | Alternative ($H_1$) | Effect Size Metric | Computational Complexity |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `kolmogorov_smirnov_2sample` | 1D Continuous | $D = \sup_x \|F_{\text{ref}}(x) - F_{\text{tgt}}(x)\|$ | $F_{\text{ref}}(x) = F_{\text{tgt}}(x) \, \forall x$ | $F_{\text{ref}}(x) \neq F_{\text{tgt}}(x)$ | Population Stability Index (PSI), Standardized $W_1/\sigma$ | $O((N+M) \log (N+M))$ |
| `wasserstein_1d` | 1D Continuous | $W_1 = \int_0^1 \|F_{\text{ref}}^{-1}(t) - F_{\text{tgt}}^{-1}(t)\| dt$ | $P_{\text{ref}} = P_{\text{tgt}}$ | $P_{\text{ref}} \neq P_{\text{tgt}}$ | Physical feature shift units ($W_1$) | $O((N+M) \log (N+M))$ |
| `population_stability_index` | 1D Binned Continuous | $\text{PSI} = \sum (p_b - q_b) \ln(p_b / q_b)$ | $P_{\text{ref}} = P_{\text{tgt}}$ in quantile bins | $P_{\text{ref}} \neq P_{\text{tgt}}$ in quantile bins | $\text{PSI} \in [0, \infty)$ (Laplace smoothed) | $O(B)$ after quantile binning |
| `chi_square_test` | Categorical Labels | $\chi^2 = \sum \frac{(O_c - E_c)^2}{E_c}$ | $P_{\text{tgt}}(Y = c) = P_{\text{ref}}(Y = c)$ | $P_{\text{tgt}}(Y = c) \neq P_{\text{ref}}(Y = c)$ | Total Variation Distance (TVD), JSD | $O(C)$ |
| `total_variation_distance` | Categorical Labels | $\text{TVD} = \frac{1}{2} \sum \|p_c - q_c\|$ | $P_{\text{ref}} = P_{\text{tgt}}$ | $P_{\text{ref}} \neq P_{\text{tgt}}$ | $\text{TVD} \in [0, 1]$ | $O(C)$ |
| `jensen_shannon_divergence` | Categorical Labels | $\text{JSD} = \frac{1}{2} D_{\text{KL}}(P \parallel M) + \frac{1}{2} D_{\text{KL}}(Q \parallel M)$ | $P = Q$ | $P \neq Q$ | $\text{JSD} \in [0, 1]$ (base-2) | $O(C)$ |
| `kernel_mmd` | Multivariate / Embeddings | $\text{MMD}^2 = \mathbb{E}[k(x,x')] + \mathbb{E}[k(y,y')] - 2\mathbb{E}[k(x,y)]$ | $P_X = P_Y$ in RKHS | $P_X \neq P_Y$ in RKHS | Empirical $\text{MMD}^2 \ge 0.0$ | $O((N+M)^2)$ |
| `energy_distance` | Multivariate Metric Space | $\mathcal{E} = 2\mathbb{E}\|X - Y\|_2 - \mathbb{E}\|X - X'\|_2 - \mathbb{E}\|Y - Y'\|_2$ | $P_X = P_Y$ | $P_X \neq P_Y$ | Empirical $\mathcal{E} \ge 0.0$ | $O((N+M)^2)$ |
| `permutation_test` | Non-Parametric Resampling | $p = \frac{1 + \sum [T^{(b)} \ge T_{\text{obs}}]}{1 + B}$ | Exchangeability under pooled null | Non-exchangeable | Exact finite-sample calibration | $O(B \cdot \text{Cost}(T))$ |

---

## 3. MULTIPLE HYPOTHESIS TESTING & ERROR CONTROL

When evaluating $K$ continuous features simultaneously:
1. **Benjamini–Hochberg (BH) False Discovery Rate (FDR)**:
   - Controls the expected proportion of false positive discoveries at $q^* = 0.05$.
   - Procedure:
     $$p_{(1)} \le p_{(2)} \le \dots \le p_{(K)}$$
     $$q_{(i)} = \min_{j \ge i} \left( \min\left(1.0, \frac{K}{j} p_{(j)}\right) \right)$$
   - A feature hypothesis is statistically significant if and only if $q_{(i)} \le 0.05$.
2. **Testing Family Isolation**:
   - Continuous features form one testing family.
   - Categorical label distributions and multivariate embeddings are evaluated independently to prevent power dilution across distinct modalities.

---

## 4. DUAL-GATE DECISION FRAMEWORK

AIVARA enforces strict separation between statistical detectability (p-value / q-value) and operational impact (effect size):

```
                       STATISTICAL SIGNIFICANCE GATE
                         (q-value <= 0.05 / p <= 0.05)
                                /             \
                              YES             NO
                              /                 \
        PRACTICAL EFFECT GATE                    PRACTICAL EFFECT GATE
         (PSI >= 0.10, etc.)                      (PSI >= 0.10, etc.)
            /            \                          /            \
          YES            NO                       YES            NO
          /                \                      /                \
   MATERIAL_SHIFT   SIGNIFICANT_SHIFT       SHIFT_DETECTED    NO_SHIFT_DETECTED
```

### State Semantics:
- **`NO_SHIFT_DETECTED`**: No statistical divergence, effect sizes negligible.
- **`SHIFT_DETECTED`**: Moderate effect size observed, but statistical sample size insufficient for significance.
- **`SIGNIFICANT_SHIFT`**: Statistically significant divergence detected, but physical effect size is negligible (Large Sample Fallacy protection).
- **`MATERIAL_SHIFT`**: Statistically significant AND practically meaningful divergence confirmed.
- **`INSUFFICIENT_DATA`**: Sample size $N < 30$, preventing valid asymptotic or empirical conclusions.
- **`INVALID` / `UNVERIFIABLE`**: Boundary invalid or cross-project contamination detected.

---

## 5. NUMERICAL ROBUSTNESS & SECURITY GUARANTEES

1. **Non-Finite Trapping:** Immediate detection of `NaN`, $+\infty$, and $-\infty$ with fail-closed rejection.
2. **Laplace Smoothing:** Additive smoothing ($\epsilon = 10^{-6}$) applied to all histogram and categorical bins, preventing $\ln(0)$ and zero division.
3. **Zero / Constant Distributions:** Safe handling of $[5,5,5,...]$ vs $[5,5,5,...]$ ($D=0, p=1.0$) and $[5,5,5,...]$ vs $[6,6,6,...]$ ($D=1, p=0.0$).
4. **Air-Gapped & Safe:** 100% pure Python and NumPy. Zero `eval`, `exec`, `pickle`, `subprocess`, `os.system`, or network access.
5. **Deterministic PRNG:** Permutation testing and subsampling use deterministic seeds derived from input identity digests.

---

## 6. INTEGRATION WITH AIVARA ARCHITECTURE

- **Finding Model:** Emits standard `FindingModel` with `evidence_layer="detection"`, `finding_type="distribution_shift"`, calibrated statistical confidence $\in [0.5, 0.99]$, and non-accusatory recommendations.
- **Evidence Model:** Emits standard `EvidenceModel` with `evidence_layer="detection"`, `evidence_type="statistical_drift_evidence"`, and SHA-256 canonicalized payload hashes.
- **Analysis Identity:**
  $$\text{analysis\_result\_hash} = \text{SHA-256}(\text{RFC-8785}(\text{canonical\_analysis\_descriptor}))$$
