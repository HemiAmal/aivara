# PHASE 11.4 — FEATURE & DATASET DRIFT ANALYSIS SPECIFICATION
## Authoritative Feature Localization, Deterministic Ranking, Label Distribution Analysis, and Dataset-Level Synthesis

**Date:** 2026-09-13  
**Project:** AIVARA — AI Verification & Assurance  
**Phase:** 11.4 (Feature & Dataset Drift Analysis)  
**Parent Phase:** Phase 11 — Distribution Shift / Data Drift Analysis  
**Governing Rule:** Phases 0–10, Phase 11.1, Phase 11.2, and Phase 11.3 are PERMANENTLY FROZEN.  

---

## 1. PURPOSE & ARCHITECTURAL FLOW

Phase 11.2 establishes: **"WHAT populations are we comparing?"** (`ComparisonBoundaryResult`)  
Phase 11.3 establishes: **"ARE the populations statistically different?"** (`StatisticalAnalysisResult`)  
Phase 11.4 answers: **"WHICH FEATURES, LABELS, AND DATASET-LEVEL CHARACTERISTICS ARE RESPONSIBLE FOR THE OBSERVED DISTRIBUTIONAL DIFFERENCE?"**

```
Phase 11.2 Validated Comparison Boundary
                  ↓
Phase 11.3 Statistical Analysis Result
                  ↓
Phase 11.4 Feature & Dataset Drift Analyzer
   ├── Numerical Feature Localization
   ├── Categorical Feature Localization
   ├── Label / Class Distribution & Imbalance
   ├── Deterministic Feature Ranking (Severity & Effect Size)
   ├── Dataset-Level Metric Synthesis & Invariant Reconciliation
   ├── Standard FindingModel & EvidenceModel Generation
   └── Cryptographic Dataset Drift Profile Identity
```

> [!IMPORTANT]
> **Core Semantic & Ethical Guardrails:**
> - `DISTRIBUTION SHIFT != MALICIOUS INTENT`
> - `FEATURE DRIFT != DATASET COMPROMISE`
> - `CLASS SHIFT != LABEL ATTACK`
> - `DATASET SHIFT != MODEL FAILURE`
> Drift analysis localizes and attributes distributional differences. It is NOT proof of data poisoning, backdoor triggers, contributor fraud, or model compromise.

---

## 2. NUMERICAL FEATURE LOCALIZATION

For each continuous numerical feature $f \in \mathcal{F}_{\text{num}}$:
1. **Statistical Consumption:** Directly extracts Two-Sample KS statistic $D$, raw $p$-value, Benjamini–Hochberg adjusted $q$-value, 1D Wasserstein distance $W_1$, and Population Stability Index (PSI) from Phase 11.3 without independent recalculation.
2. **Impact Level Mapping (`DriftImpactLevel`):**
   - $\text{PSI} \ge 0.25$ AND $q \le 0.05 \implies$ `HIGH`
   - $0.10 \le \text{PSI} < 0.25$ AND $q \le 0.05 \implies$ `MEDIUM`
   - $q \le 0.05$ with negligible effect size $\implies$ `LOW` (`SIGNIFICANT_SHIFT`)
   - Non-significant with negligible effect size $\implies$ `NEGLIGIBLE` (`NO_SHIFT_DETECTED`)
3. **Structured Feature Profile:** Emits `FeatureDriftProfile` with `category=COVARIATE_NUMERICAL`, `feature_type=NUMERICAL`, effect metrics, sample sizes, and limitations.

---

## 3. CATEGORICAL & LABEL DISTRIBUTION ANALYSIS

1. **Categorical Feature Localization:**
   - Evaluates Total Variation Distance (TVD $\in [0, 1]$), Jensen–Shannon Divergence (JSD $\in [0, 1]$), and Chi-Square goodness-of-fit.
   - Emits `FeatureDriftProfile` with `category=COVARIATE_CATEGORICAL`, `feature_type=CATEGORICAL`.
2. **Label / Class Distribution Shift ($P(Y)$):**
   - Quantifies label proportion shifts between $P(Y_{\text{ref}})$ and $P(Y_{\text{target}})$.
   - Explicitly detects:
     - **Unseen Classes:** Classes present in target but absent in reference.
     - **Missing Classes:** Classes present in reference but absent in target.
     - **Class Imbalance:** Computes target imbalance ratio $\frac{\max_c P(Y=c)}{\min_c P(Y=c)}$. Ratios $\ge 10.0$ trigger `is_imbalanced = True`.
   - Emits structured `LabelDriftProfile`.

---

## 4. DETERMINISTIC FEATURE RANKING

Features are ranked deterministically based on statistical severity and operational effect magnitude rather than raw $p$-values:

$$\text{Rank Key} = \left( -\text{Priority}(\text{shift\_status}), -\text{effect\_size}, \text{feature\_name} \right)$$

1. **Status Priority:** `MATERIAL_SHIFT` (4) $>$ `SHIFT_DETECTED` (3) $>$ `SIGNIFICANT_SHIFT` (2) $>$ `NO_SHIFT_DETECTED` (1).
2. **Effect Size:** Descending effect size (PSI / TVD / standardized Wasserstein).
3. **Tie Breaker:** Lexicographical ascending `feature_name` ensures 100% deterministic output across all runtime environments.

---

## 5. DATASET-LEVEL SYNTHESIS & INVARIANT RECONCILIATION

The engine reconciles dataset-level dimensions:
- $\text{total\_features\_evaluated} = \text{total\_numerical\_features} + \text{total\_categorical\_features}$
- $\text{materially\_shifted\_feature\_count} \le \text{statistically\_significant\_feature\_count} + |\text{unseen\_classes}|$
- Tracks `untestable_features` explicitly without corrupting evaluated metrics.
- Avoids arbitrary percentage simplifications (e.g. avoiding "80% dataset drift" in favor of granular dimensional summaries).

---

## 6. INTEGRATION WITH AIVARA ARCHITECTURE

1. **Finding Model (`FindingModel`):**
   - Reuses existing SQLAlchemy/Pydantic models (`evidence_layer="detection"`, `finding_type="feature_dataset_drift"`).
   - Calibrated statistical confidence $\in [0.5, 0.99]$.
   - Non-accusatory recommendations.
2. **Evidence Model (`EvidenceModel`):**
   - Reuses existing model (`evidence_type="feature_dataset_drift_evidence"`).
   - Stores canonicalized localized feature summaries, label distributions, and untestable dimensions.
3. **Cryptographic Analysis Identity:**
   $$\text{dataset\_drift\_profile\_hash} = \text{SHA-256}(\text{RFC-8785}(\text{canonical\_profile\_descriptor}))$$
