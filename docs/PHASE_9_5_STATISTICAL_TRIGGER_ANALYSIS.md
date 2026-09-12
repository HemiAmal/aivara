# PHASE 9.5 — STATISTICAL TRIGGER ANALYSIS & CONTROL COMPARISON GUIDE

**Phase:** Phase 9.5  
**Status:** **READY FOR USER REVIEW — NOT FROZEN**  
**Package:** `aivara.backdoor.statistics`  
**Downstream Interface:** Phase 10 (Inference Integrity)

---

## Overview

The `aivara.backdoor.statistics` package provides deterministic statistical significance testing, exact confidence interval estimation, multiple testing adjustments, and spatial grid localization for synthetic trigger candidate evaluations.

Rejecting the composite null at level $\alpha$ provides statistically significant evidence that the trigger candidate's observed target-conditioned success rate exceeds both negative-control rates under the assumptions of the paired permutation test. **This result does not prove maliciousness, backdoor intent, attacker identity, poisoning, or causal mechanism.**

### Key Capabilities:
1. **Paired Permutation Testing via Intersection-Union Principle (`evaluate_paired_permutation_test`):**
   - $B = 1000$ permutations with NumPy `PCG64` initialized from canonical identity seed.
   - Evaluates paired permutation tests against both location-shuffled and magnitude-matched noise controls.
   - Combines via Intersection-Union Principle: $p = \max(p_{\text{shuffled}}, p_{\text{noise}})$, rigorously testing $H_0: \text{TSR}(\tau) \le \max(\text{TSR}(C_{\text{shuff}}), \text{TSR}(C_{\text{noise}}))$.
   - The IUT construction provides conservative Type I error control when the component permutation $p$-values are valid under their respective null hypotheses and the paired exchangeability assumptions hold.
   - Finite-sample correction $p = \frac{1 + \text{exceedances}}{B + 1}$.
2. **Exact Clopper-Pearson 95% Confidence Intervals (`clopper_pearson_confidence_interval`):**
   - Deterministic under the specified runtime and numerical implementation using regularized incomplete beta quantile inversion.
   - Zero external dependency on SciPy.
   - Gated support: returns `(None, None)` when sample count $N < 10$.
3. **Multiplicity Adjustments (`benjamini_hochberg_fdr`, `holm_bonferroni_step_down`):**
   - Benjamini-Hochberg FDR control at $\alpha = 0.05$ across screening candidates with deterministic tie-breaking.
   - Holm-Bonferroni FWER step-down correction across $8 \times 8 = 64$ spatial grid cells.
4. **Staged Candidate Promotion (`evaluate_stage2_promotion`):**
   - Enforces Stage 2 gates: $\text{TAR} \ge 0.50$, $\text{TSR} \ge 0.50$, $\Delta_{\text{sep}} > 0.20$, $N \ge 10$, cap $K_2 \le 2$.
5. **Inference Budget Accounting (`compute_budget_accounting`, `validate_budget_ceiling`):**
   - Enforces Stage 1 (2,450), Stage 2 (7,800), and Hard Ceiling (16,000) limits.

---

## Code Example

```python
from aivara.backdoor.statistics import (
    StatisticalAnalysisEngine,
    compute_budget_accounting,
)

# Initialize deterministic engine
engine = StatisticalAnalysisEngine(
    permutation_count=1000,
    alpha=0.05,
    confidence_level=0.95,
)

# Evaluate Phase 9.4 activation assessments
assessment = engine.evaluate_assessments(
    project_id="proj_001",
    activation_assessments=[activation_assessment_1, activation_assessment_2],
    target_class=1,
)

for summary in assessment.candidate_summaries:
    print(f"Candidate: {summary.candidate_hash}")
    print(f"  TSR: {summary.tsr:.4f}")
    print(f"  Control Baseline: {summary.control_baseline_tsr:.4f}")
    print(f"  Delta Sep: {summary.delta_separation:.4f}")
    print(f"  Raw IUT p-value: {summary.raw_p_value:.4f}")
    print(f"  BH-FDR Adjusted p-value: {summary.adjusted_p_value:.4f}")
    print(f"  Taxonomy: {summary.taxonomy_classification.value}")
```
