# PHASE 11 — STATISTICAL DISTRIBUTION SHIFT RESEARCH NOTES
## Technical Research on Statistical Two-Sample Testing, Effect Sizes, Multiple Hypothesis Testing, and Multi-Modal Drift Analysis

**Date:** 2026-09-13  
**Project:** AIVARA — AI Verification & Assurance  
**Phase:** 11.1 (Research & Architecture Freeze)  
**Parent Phase:** Phase 11 — Distribution Shift / Data Drift Analysis  

---

## 1. THEORETICAL FOUNDATION OF DISTRIBUTION SHIFT

In computer vision and machine learning assurance, distribution shift occurs when the joint probability distribution of features $X \in \mathcal{X}$ and labels $Y \in \mathcal{Y}$ differs between a trusted reference population $P_{\text{ref}}(X, Y)$ and a target population $P_{\text{target}}(X, Y)$:
$$P_{\text{ref}}(X, Y) \neq P_{\text{target}}(X, Y)$$

### Canonical Factorizations & Shift Typologies
From probability theory, the joint distribution factors as:
1. **Covariate Shift / Feature Drift**:
   $$P_{\text{target}}(X) \neq P_{\text{ref}}(X) \quad \text{while} \quad P_{\text{target}}(Y \mid X) = P_{\text{ref}}(Y \mid X)$$
   The input feature distribution changes (e.g. lighting conditions, sensor noise, resolution, demographic shifts), but the underlying ground truth mapping from image to label remains invariant.
2. **Prior Probability Shift / Label Shift**:
   $$P_{\text{target}}(Y) \neq P_{\text{ref}}(Y) \quad \text{while} \quad P_{\text{target}}(X \mid Y) = P_{\text{ref}}(X \mid Y)$$
   The marginal class proportions shift (e.g. seasonal appearance of specific object classes), while the appearance of each class conditional on the label is unchanged.
3. **Concept Drift / Posterior Shift**:
   $$P_{\text{target}}(Y \mid X) \neq P_{\text{ref}}(Y \mid X)$$
   The semantic meaning or definition of the target variable changes for given visual features (e.g. diagnostic criteria changes in medical imaging).
4. **Domain Shift**:
   A combination of covariate and concept shifts arising from systemic transitions between distinct acquisition domains (e.g. synthetic rendering vs. real-world photography, or day vs. night cameras).

---

## 2. COMPARATIVE EVALUATION OF STATISTICAL METHODS

| Method | Supported Data | Mathematical Formulation | Computational Complexity | Sensitivity & Sample Behavior | Interpretability | Offline AIVARA Suitability |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Two-Sample Kolmogorov–Smirnov (KS) Test** | 1D Continuous | $D_{n,m} = \sup_x |F_{\text{ref},n}(x) - F_{\text{target},m}(x)|$ | $O(N \log N + M \log M)$ (fast sorting) | High sensitivity to median/scale shifts; sensitive in the central body of the distribution, less sensitive in extreme tails. | High ($D \in [0, 1]$ represents maximum vertical CDF gap; exact asymptotic p-value). | **EXCELLENT (Core 1D Test)** |
| **Wasserstein Distance ($W_1$ / Earth Mover's Distance)** | 1D Continuous & Metric Spaces | $W_1(P, Q) = \int_{-\infty}^{\infty} |F_{\text{ref}}(x) - F_{\text{target}}(x)| \, dx$ | $O(N \log N + M \log M)$ for 1D via sorted quantile differences | Measures physical work required to transform one distribution into another; retains true feature measurement units. | Very High (direct physical magnitude of shift; unaffected by sample size blowing up p-values). | **EXCELLENT (Core Effect Size)** |
| **Population Stability Index (PSI)** | 1D Binned Continuous & Categorical | $\text{PSI} = \sum_{b=1}^B (p_b - q_b) \ln(p_b / q_b)$ where $p_b = \frac{n_b}{N}, q_b = \frac{m_b}{M}$ | $O(B)$ after quantile binning | Standardized industry benchmark; requires laplacian smoothing ($+10^{-6}$) to avoid $\ln(0)$ or division by zero. | High ($\text{PSI} < 0.1$ stable, $0.1 \le \text{PSI} < 0.25$ moderate, $\ge 0.25$ significant). | **EXCELLENT (Tabular/Binned Benchmark)** |
| **Chi-Square ($\chi^2$) Contingency / Goodness-of-Fit** | Categorical / Discrete Classes | $\chi^2 = \sum_{c=1}^C \frac{(O_c - E_c)^2}{E_c}$ | $O(C)$ | Highly sensitive to class proportion shifts; requires expected count $E_c \ge 5$ per cell. | High (standard test statistic with $\text{df} = C - 1$ degrees of freedom). | **EXCELLENT (Core Categorical Test)** |
| **Total Variation Distance (TVD)** | Categorical / Discrete Probability | $\delta(P, Q) = \frac{1}{2} \sum_{c=1}^C |p_c - q_c| = \sup_{A} |P(A) - Q(A)|$ | $O(C)$ | Bounded $\delta \in [0, 1]$; maximum difference in probability assigned to any subset of categories. | Very High (intuitive percentage discrepancy between label distributions). | **EXCELLENT (Core Categorical Effect Size)** |
| **Jensen–Shannon Divergence (JSD)** | Discrete & Binned Probabilities | $\text{JSD}(P \parallel Q) = \frac{1}{2} D_{\text{KL}}(P \parallel M) + \frac{1}{2} D_{\text{KL}}(Q \parallel M)$ where $M = \frac{P+Q}{2}$ | $O(C)$ or $O(B)$ | Symmetric, bounded $\in [0, 1]$ (base-2) or $[0, \ln 2]$ (base-e); square root $\sqrt{\text{JSD}}$ is a true metric. | High (information-theoretic measure of distribution divergence). | **EXCELLENT (Discrete Divergence)** |
| **Kernel Maximum Mean Discrepancy (MMD)** | Multivariate / High-Dimensional (Embeddings, Image Descriptors) | $\text{MMD}^2(P, Q) = \mathbb{E}[k(x,x')] + \mathbb{E}[k(y,y')] - 2\mathbb{E}[k(x,y)]$ | $O((N+M)^2)$ (or $O(B \cdot (N+M)^2)$ with permutation testing) | Non-parametric test in Reproducing Kernel Hilbert Space (RKHS); captures all higher-order moments. Bandwidth $\gamma$ calibrated via median heuristic. | Moderate (statistical distance in RKHS; significance established via permutation null distribution). | **EXCELLENT (Core Multivariate Test)** |
| **Energy Distance** | Multivariate Continuous | $\mathcal{E}(P, Q) = 2\mathbb{E}\|X - Y\|_2 - \mathbb{E}\|X - X'\|_2 - \mathbb{E}\|Y - Y'\|_2$ | $O((N+M)^2)$ | Metric distance characterizing equality of multivariate distributions without requiring kernel bandwidth tuning. | High (zero if and only if distributions are identical; monotonic in Euclidean distance). | **EXCELLENT (Multivariate Robust Test)** |
| **Permutation Null Hypothesis Testing** | Arbitrary Non-Parametric Statistics | Randomly permute pooled samples $B$ times to construct empirical null distribution $T^{(1)}, \dots, T^{(B)}$; $p = \frac{1 + \sum [T^{(b)} \ge T_{\text{obs}}]}{1 + B}$ | $O(B \cdot \text{Cost}(T))$ | Exact finite-sample validity without parametric normality assumptions. | High (directly interpretable empirical p-value). Deterministic PRNG seed ensures reproducibility. | **EXCELLENT (Deterministic Calibration)** |

---

## 3. MULTIPLE HYPOTHESIS TESTING & ERROR CONTROL

When an automated pipeline evaluates distribution shift across $K$ individual features (e.g. 50 image descriptors or 128 embedding dimensions), testing each at significance level $\alpha = 0.05$ without correction inflates the Family-Wise Error Rate (FWER):
$$\text{FWER} = 1 - (1 - \alpha)^K \xrightarrow[K=50]{} 1 - (0.95)^{50} \approx 0.923 \quad (92.3\% \text{ chance of at least one false positive})$$

### Error Control Strategies Evaluated:
1. **Benjamini–Hochberg (BH) False Discovery Rate (FDR)**:
   - Controls the expected proportion of false discoveries among rejected hypotheses: $\text{FDR} \le q^*$.
   - Procedure: Sort p-values $p_{(1)} \le p_{(2)} \le \dots \le p_{(K)}$. Find largest $k$ such that $p_{(k)} \le \frac{k}{K} q^*$. Reject all $H_{(i)}$ for $i \le k$.
   - **Recommendation:** Default for feature-level drift reporting ($q^* = 0.05$). Maintains strong statistical power while bounding spurious drift alerts.
2. **Holm–Bonferroni Step-Down Procedure**:
   - Strongly controls FWER ($\text{FWER} \le \alpha$) without the severe conservatism of standard single-step Bonferroni.
   - Procedure: Compare $p_{(i)} \le \frac{\alpha}{K - i + 1}$. Stop at the first non-rejection.
   - **Recommendation:** Used when declaring definitive high-severity global shift.

---

## 4. STATISTICAL SIGNIFICANCE VS. PRACTICAL EFFECT SIZE

A critical pitfall in automated dataset monitoring is confusing **statistical significance** (p-value) with **practical/operational significance** (effect size).

- **The Large Sample Fallacy:** With $N = 100,000$ samples, a trivial shift of $0.001\%$ in pixel brightness yields $p < 10^{-15}$ under the KS test, despite having zero operational impact on downstream neural network predictions.
- **The Small Sample Pitfall:** With $N = 15$ samples, a massive distribution shift might yield $p = 0.12$ due to low statistical power, leading to dangerous false negatives if p-values are used alone.

### Dual-Gate Decision Framework
Phase 11 adopts a deterministic dual-gate evaluation:
$$\text{Shift Status} = f(\text{Statistical Significance}, \text{Effect Size}, \text{Sample Adequacy})$$

1. **`NO_SHIFT_DETECTED`**: $p \ge \alpha$ and effect size below moderate threshold.
2. **`SIGNIFICANT_SHIFT`**: $p < \alpha_{\text{corrected}}$, but effect size is small (statistically detectable drift, minimal operational impact).
3. **`MATERIAL_SHIFT`**: $p < \alpha_{\text{corrected}}$ **AND** effect size exceeds practical threshold (e.g. $\text{PSI} \ge 0.25$, or $W_1 > \theta_{\text{practical}}$, or $\text{MMD} > 0.05$ with $p < 0.01$).
4. **`INSUFFICIENT_DATA`**: Reference sample size $N < N_{\text{min}}$ or target sample size $M < M_{\text{min}}$ ($N_{\text{min}} = 30$).

---

## 5. IMAGE DISTRIBUTION SHIFT METHODOLOGY

Raw pixel-level comparisons alone do not adequately reflect semantic visual domain changes. Image shift in AIVARA Phase 11 operates on structured, multi-tier representations:

1. **Tier 1: Global Geometric & Acquisition Descriptors**
   - Resolution (width, height), aspect ratio, channel counts, compression formats, file sizes.
2. **Tier 2: Photometric & Statistical Color Descriptors**
   - Per-channel luminance histograms (mean, variance, skewness, kurtosis in RGB, HSV, and LAB color spaces).
   - Dynamic range, contrast, saturation, image entropy.
3. **Tier 3: Spatial Frequency & Structural Descriptors**
   - Laplacian variance (focus/blurriness measure).
   - High-frequency edge density via Sobel/Canny gradient statistics.
   - Perceptual hash distributions (pHash, dHash Hamming distance distributions).
4. **Tier 4: Deep Latent Embeddings (Tier 4)**
   - Latent representation vectors extracted from local, verified models (`AIModelModel`).
   - Evaluated via Kernel MMD, Energy Distance, and Cosine Dispersion.

---

## 6. SAMPLE SIZE BOUNDS & NUMERICAL STABILITY

1. **Minimum Sample Size Floor:**
   - Universal minimum: $N \ge 30, M \ge 30$. Below this threshold, two-sample asymptotic approximations break down, and the system transitions to `INSUFFICIENT_DATA`.
2. **Deterministic Subsampling Budget:**
   - To guarantee $O(1)$ upper-bounded memory and CPU latency during quadratic kernel calculations ($O((N+M)^2)$), datasets exceeding $N_{\text{max}} = 5,000$ samples are deterministically subsampled using fixed PRNG seeds derived from dataset identity hashes.
3. **Numerical Safety Controls:**
   - **Zero Division / Logarithms:** Laplacian additive smoothing ($\epsilon = 10^{-6}$) applied to all bin frequencies.
   - **Non-Finite Trapping:** Immediate sanitization and filtering of `NaN`, $+\infty$, $-\infty$ with dedicated logging of numerical anomalies.
   - **Matrix Degeneracy:** Clamping eigenvalues / kernel distances to $\ge 0.0$ to prevent negative square roots under floating-point precision loss.
