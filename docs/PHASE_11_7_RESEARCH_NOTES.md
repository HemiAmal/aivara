# PHASE 11.7 — TEMPORAL & WINDOWED DISTRIBUTION SHIFT: RESEARCH NOTES
==================================================================================

**PROJECT**: AIVARA — AI Verification & Assurance  
**PARENT PHASE**: PHASE 11 — DISTRIBUTION SHIFT / DATA DRIFT ANALYSIS  
**SUBPHASE**: 11.7.1 — ARCHITECTURE & REQUIREMENTS FREEZE  
**STATUS**: AUTHORITATIVE RESEARCH SYNTHESIS  
**DATE**: 2026-09-13  

---

## 1. Executive Summary & Research Objectives

Phase 11.7 extends AIVARA's distribution shift assurance capabilities from static two-sample comparisons ($\mathcal{P}_{\text{ref}} \text{ vs } \mathcal{P}_{\text{tgt}}$) to sequential, time-ordered distributions ($\mathcal{P}_{t_0}, \mathcal{P}_{t_1}, \dots, \mathcal{P}_{t_K}$). The mission of this research is to evaluate sequential distribution testing, windowing topologies, change-point detection algorithms, autocorrelation effects, seasonality phenomena, and multiple-testing corrections to establish a deterministic, offline, air-gapped, and statistically robust temporal drift architecture.

---

## 2. Evaluation of Windowing Strategies

| Strategy | Methodology | Strengths | Weaknesses | Computational Cost | Determinism | AIVARA Fit | V1 Decision |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **A. Fixed Non-Overlapping Windows** | Partition time into disjoint intervals $[t_{k}, t_{k+1})$ of fixed duration $\Delta t$ or fixed sample size $N_w$. | Simple, disjoint samples ensure independent statistical comparisons; zero observation overlap. | Boundary edge effects; may miss gradual drift crossing window boundaries. | $O(K \cdot C_{\text{stat}})$ | High (strict timestamp partitioning) | Excellent | **ACCEPTED (Primary V1 Strategy)** |
| **B. Rolling / Sliding Windows** | Window $[t - W, t)$ slides forward by step $\delta < W$. | Continuous monitoring; responsive to short-term regime shifts. | Adjacent windows share $1 - \delta/W$ samples, introducing heavy sample dependence and violating i.i.d. assumptions in hypothesis tests. | $O\left(\frac{T}{\delta} \cdot C_{\text{stat}}\right)$ | High | Moderate (requires autocorrelation awareness) | **ACCEPTED (Secondary V1 Strategy with Calibrated Step $\delta \ge W/2$)** |
| **C. Expanding / Cumulative Windows** | Windows $[t_0, t_k)$ expand from fixed origin $t_0$. | High statistical power on later windows as sample size grows. | Early shifts get diluted by accumulated historical mass; high computational growth. | $O(K^2)$ sample growth | High | Poor | **REJECTED for V1** |
| **D. Baseline vs. Successive Windows** | Compares fixed baseline window $\mathcal{W}_0$ (or reference dataset $\mathcal{D}_{\text{ref}}$) to each $\mathcal{W}_k$. | Direct measurement of divergence from reference state; answers "how far has system drifted from baseline?". | Does not detect short-term step changes between consecutive recent windows. | $O(K \cdot C_{\text{stat}})$ | High | Essential | **ACCEPTED (Primary V1 Comparison Topology)** |
| **E. Adjacent / Stepwise Windows** | Compares each window $\mathcal{W}_{k-1}$ directly to $\mathcal{W}_k$. | Identifies local acceleration and acute transitions; answers "did distribution change between consecutive periods?". | Cannot detect slow, cumulative gradual drift where step size $\Delta \ll$ threshold. | $O((K-1) \cdot C_{\text{stat}})$ | High | Essential | **ACCEPTED (Secondary V1 Comparison Topology)** |

---

## 3. Evaluation of Change-Point Detection (CPD) Algorithms

| Method | Statistical Principle | Assumptions | Strengths | Limitations | Determinism | Offline Suitability | V1 Decision |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CUSUM (Cumulative Sum)** | Sequential likelihood ratio tracking cumulative mean deviations. | Known parametric distribution (typically Gaussian); 1D continuous data. | Fast, exact stopping time for mean shifts. | Poor multivariate scaling; assumes parametric distribution. | High | High | **REJECTED (Too rigid for multimodal CV/tabular features)** |
| **Page-Hinkley Test** | Variant of CUSUM with variable threshold for sudden changes. | Stationary variance; known nominal mean. | Highly sensitive to abrupt positive/negative jumps. | High false positive rate under heavy-tailed distributions. | High | High | **REJECTED for V1** |
| **ADWIN (Adaptive Windowing)** | Compares sub-windows using Hoeffding bounds to dynamically resize window. | Bounded 1D random variables $\in [0, 1]$; independent samples. | Parameter-free window sizing; mathematically guaranteed false positive rate. | Strictly 1D; heuristic heuristics for multivariate/embedding data. | High | High | **REJECTED for V1 (Focus on full $D$-dimensional multivariate embeddings)** |
| **PELT (Pruned Exact Linear Time)** | Dynamic programming minimizing cost function with linear pruning. | Additive cost function (e.g., negative log-likelihood or nonparametric kernel loss). | Exact optimal segmentation; $O(N)$ expected time. | Hyperparameter penalty $\beta$ tuning is sensitive to noise; high computational cost in high dimensions. | High | High | **REJECTED for V1 (Excessive computational complexity for batch assurance)** |
| **Kernel Change-Point Detection (KCPD / MMD-CPD)** | Maximum Mean Discrepancy (MMD) two-sample test on sliding candidate split points. | Nonparametric RKHS embedding; characteristic kernel (Gaussian RBF). | Directly operates on high-dimensional representations ($D=384, 2048$); no density estimation. | Requires $O(N^2)$ pairwise kernel matrix computation; bounded sample size necessary. | High | High | **ACCEPTED (V1 Change-Point Candidate Detection via Phase 11.3 MMD Engine)** |

---

## 4. Evaluation of Statistical Independence, Autocorrelation & Seasonality

### 4.1 Autocorrelation & Sample Dependence
- **Problem**: Temporal series frequently exhibit serial correlation $\text{Corr}(X_t, X_{t+k}) \ne 0$. Standard two-sample tests (KS, Chi-Square, MMD) assume independent and identically distributed (i.i.d.) observations within each population. Positive autocorrelation artificially deflates empirical variance and inflates test statistics, leading to false discovery inflation ($p$-values artificially small).
- **V1 Architectural Policy**:
  1. *Subsampling & Thinning*: Enforce minimum temporal gap between sampled observations when serial correlation is detected.
  2. *Dual-Gate Effect Size Pruning*: Reject shifts where $p < \alpha$ unless practical effect size ($\text{PSI} \ge 0.10, \text{TVD} \ge 0.05, \text{MMD}^2 \ge 0.02$) is also satisfied. Effect sizes are substantially more robust to mild autocorrelation than asymptotic $p$-values.
  3. *Conservative Minimum Window Size*: Mandate $N_{\min} \ge 30$ per window to ensure stable empirical estimation.

### 4.2 Seasonality & Periodic Cycles
- **Problem**: Production datasets experience legitimate diurnal, weekly, and monthly cycles (e.g., day/night illumination in cameras, weekday/weekend traffic patterns). A naive temporal test comparing Monday to Sunday will detect distribution shift that is benign and cyclical rather than structural drift.
- **V1 Architectural Policy**:
  1. *Seasonality-Aligned Baselines*: Support period-matched reference baseline windows (e.g., comparing Monday 09:00–12:00 to reference Monday 09:00–12:00).
  2. *Limitation Disclosure*: Explicitly report non-stationarity limitations in `TemporalAnalysisProfile.limitations` whenever window duration $\Delta t < \text{seasonal cycle period}$.
  3. *Non-Attribution*: Explicitly declare that temporal shift indicates non-stationarity and does NOT prove anomalous or malicious behavior.

---

## 5. Multiple Hypothesis Testing Across Temporal Windows

### 5.1 Test Family Formulation
When evaluating $K$ temporal windows across $M$ features:
- Total number of individual hypothesis tests = $K \times M$ (for feature drift) or $K$ (for global representation drift).
- If tested independently at $\alpha = 0.05$, the Family-Wise Error Rate $\text{FWER} = 1 - (1 - 0.05)^K \to 1.0$ as $K$ increases.

### 5.2 Two-Tier Multiple Testing Hierarchy
1. **Tier 1 (Within-Window Feature Family)**: For a given window $\mathcal{W}_k$, apply Benjamini–Hochberg False Discovery Rate (FDR) control at $q^* = 0.05$ across all $M$ evaluated features (reusing Phase 11.3 / Phase 11.4 authority).
2. **Tier 2 (Across-Window Temporal Family)**: For global window comparisons against baseline $\mathcal{W}_0 \leftrightarrow \mathcal{W}_k$, apply Benjamini–Hochberg FDR correction across the sequence of $K$ window $p$-values to control global false discovery rate over the temporal monitoring horizon.

---

## 6. Distinguishing Research Findings from Frozen Decisions

| Aspect | Research Landscape | Frozen AIVARA V1 Decision | Rationale |
| :--- | :--- | :--- | :--- |
| **Timestamp Model** | Event time, Ingestion time, Processing time | **Event Time (Primary) & Ingestion Time (Fallback)** | Ingestion time can be manipulated by batch pipeline latency; Event time reflects true physical reality. Explicit metadata tracks which field was selected. |
| **Window Strategy** | Dynamic ADWIN, PELT, Rolling, Fixed | **Fixed Non-Overlapping Windows + Baseline-vs-Windows Comparison** | Guarantees deterministic, reproducible boundaries with independent sample partitions and bounded $O(K)$ computational overhead. |
| **Change-Point Detection** | Online sequential CUSUM, Bayesian CPD | **Offline Nonparametric Bounded Kernel MMD Split-Point Evaluation** | Reuses frozen Phase 11.3 engine; operates deterministically on high-dimensional representations without parametric assumptions. |
| **Statistical Engine** | Custom temporal drift algorithms | **100% Reuse of Phase 11.3 Engine** | Preserves Phase 11.3 as sole statistical authority; zero duplicate code. |
| **Attribution** | Root-cause attribution models | **Strict Non-Attribution Policy** | Shift $\ne$ Attack $\ne$ Poisoning $\ne$ Malice. Findings strictly report observable distributional divergence. |

---

## 7. Conclusions & Architectural Readiness

The research confirms that temporal distribution shift can be implemented deterministically, offline, and with bounded complexity by orchestrating Phase 11.2 population boundaries, Phase 11.3 statistical primitives, Phase 11.4 feature schemas, Phase 11.5 image descriptors, and Phase 11.6 representation contracts.
