# AIVARA — Contributor Aggregation Engine Architecture Specification
## Phase 5.8.1: Architecture Review & Design Freeze

**Version:** 1.0.0-frozen  
**Status:** DESIGN FROZEN (Implementation Target: Phase 5.8)  
**Security Classification:** Local / Air-Gapped Assurance Engine  
**Target Sub-System:** Phase 5.8 — Contributor Aggregation Engine (CAE)  
**Evidence Layer:** `evidence_layer="detection"` (ADR-028 / ADR-029 compliant)

---

## 1. Executive Summary & Scope

The **Contributor Aggregation Engine (CAE)** is an offline, air-gapped analytical sub-system designed to aggregate dataset-level and sample/annotation-level evidence (produced in Phases 5.4, 5.5, 5.6, and 5.7) into **contributor-associated statistical profiles**.

```
  Phase 5.4: Near-Duplicate Evidence
  Phase 5.5: Label Anomaly Evidence
  Phase 5.6: Label-Flipping Evidence
  Phase 5.7: OOD & Image Quality Evidence
                    │
                    ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ Phase 5.8: Contributor Aggregation Engine (CAE)             │
  │                                                             │
  │ 1. Deterministic Multi-Contributor Fractional Attribution   │
  │ 2. Exposure Normalization & Subgroup-Aware Baselines        │
  │ 3. Conservative Wilson Lower Bound / Bayesian Shrinkage     │
  │ 4. Contributor Transition & Quality Differentials (Delta)   │
  │ 5. Multi-Signal Evidence Diversity (Non-Additive)           │
  │ 6. Concentration Profiling (HHI / Gini / Anomaly Share)     │
  │ 7. Small-Sample & Unattributed Guardrails                   │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
                                 ▼
               Structured Immutable Contributor Profiles
                   (evidence_layer="detection")
                                 │
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
       Phase 5.9 Provenance Ledger       Phase 8 Executive Risk
```

### Foundational Semantic Invariants

```
   ┌──────────────────────────────────────────────────────────────────────────┐
   │                                                                          │
   │   CONTRIBUTOR EVIDENCE ≠ CONTRIBUTOR GUILT                               │
   │   CONTRIBUTOR ANOMALY CONCENTRATION ≠ MALICIOUSNESS                      │
   │   STATISTICAL DEVIATION ≠ SABOTAGE                                       │
   │   CONTRIBUTOR SPECIALIZATION ≠ DATA POISONING                            │
   │                                                                          │
   └──────────────────────────────────────────────────────────────────────────┘
```

1. **Strictly Observational:** The CAE outputs objective statistical summaries under `evidence_layer="detection"`.
2. **Zero Attribution of Intent:** The engine **NEVER** asserts "malicious contributor", "contributor guilt", "saboteur", "poisoning attack", "fraud", or "deliberate manipulation".
3. **No Risk / Quarantine Decisions:** The CAE does **NOT** compute threat scores, risk rankings, or disposition decisions (`accept`/`review`/`quarantine`). Attribution of risk is exclusively reserved for downstream risk synthesis (Phase 8).
4. **Estimated Latent Labels ($\hat{y}^*$):** Latent labels derived from model predictions are always treated as statistical estimates, never as ground truth.

---

## 2. Contributor Baseline & Subgroup-Aware Comparison

To avoid **Simpson's Paradox** and spurious findings (e.g., a contributor specializing in night-time imagery being falsely flagged for high underexposure rates), the engine defines two comparison baselines:

```
                      Dataset Baseline Architecture
                                     │
           ┌─────────────────────────┴─────────────────────────┐
           ▼                                                   ▼
1. Global Leave-One-Out (LOO) Baseline           2. Subgroup-Aware Stratified Baseline
   - Dataset excluding Contributor C                - Same class / sensor / domain subgroup
   - Base = D \ {c}                                   excluding Contributor C
   - Evaluates broad dataset deviation              - Base = D_(subgroup) \ {c}
                                                    - Evaluates within-domain deviation
```

### 2.1 Formal Baseline Definitions

For a given metric $M$ and contributor $c$:
1. **Contributor Rate:**
   $$R_c(M) = \frac{\sum_{s \in \mathcal{S}_c} w_{s,c} \cdot \mathbb{I}(s \text{ has } M)}{\sum_{s \in \mathcal{S}_c} w_{s,c}}$$
   where $w_{s,c}$ is the fractional attribution weight of sample $s$ to contributor $c$.
2. **Global Background Rate (LOO):**
   $$R_{\text{bg}}(M) = \frac{\sum_{s \notin \mathcal{S}_c} \mathbb{I}(s \text{ has } M)}{|\mathcal{S} \setminus \mathcal{S}_c|}$$
3. **Subgroup-Aware Background Rate ($g \in \text{Subgroups}$):**
   $$R_{\text{sub}, g}(M) = \frac{\sum_{s \in \mathcal{S}_g \setminus \mathcal{S}_c} \mathbb{I}(s \text{ has } M)}{|\mathcal{S}_g \setminus \mathcal{S}_c|}$$

---

## 3. Exposure Normalization & Statistical Uncertainty

### 3.1 Exposure Normalization Principle
Raw anomaly counts are strictly invalid for contributor comparison. A contributor with 10 anomalies out of 10 samples ($100\%$) must be distinguished from a contributor with 50 anomalies out of 5,000 samples ($1\%$).

### 3.2 Conservative Wilson Score Interval Lower Bound
To prevent small contributor sample sizes from generating inflated confidence scores, all rates use the **Wilson 95% Confidence Interval Lower Bound**:
$$w^-(k, n, z) = \frac{\hat{p} + \frac{z^2}{2n} - z \sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$
where $\hat{p} = k / n$, $n$ is contributor exposure, and $z = 1.96$ (for 95% confidence).

- **For $n < 5$:** $w^-(k, n) \to 0.0$, preventing tiny contributors from generating strong anomaly findings.
- **For large $n$:** $w^-(k, n) \to \hat{p}$, converging to the true empirical rate.

### 3.3 Contributor Differentials ($\Delta$)
For metric $M$:
$$\Delta(c) = R_c(M) - R_{\text{bg}}(M)$$
The differential is reported alongside the standard error $\text{SE}(\Delta) = \sqrt{\frac{R_c(1-R_c)}{n_c} + \frac{R_{\text{bg}}(1-R_{\text{bg}})}{N_{\text{bg}}}}$ to provide statistical grounding.

---

## 4. Multi-Contributor Attribution Policy

Computer vision datasets often assign multiple contributors/annotators to a single sample (e.g., ImageContributor junction).

```
                      Multi-Contributor Sample s
                      (Contributors: [C1, C2, C3])
                                   │
             ┌─────────────────────┴─────────────────────┐
             ▼                                           ▼
  Equal Fractional Attribution                Shared Evidence Tagging
  w_(s, C1) = 1/3                             is_shared = True
  w_(s, C2) = 1/3                             shared_contributor_count = 3
  w_(s, C3) = 1/3
```

### Frozen Attribution Rules:
1. **Fractional Weighting:** If sample $s$ has $K$ associated contributors, each contributor receives fractional attribution weight $w_{s, c} = \frac{1}{K}$.
2. **Linear Conservation:** $\sum_{c \in \mathcal{C}_s} w_{s, c} = 1.0$. The total anomaly count in the dataset is strictly conserved across contributor aggregations without artificial inflation.
3. **Shared Metadata Flag:** When $K > 1$, findings record `is_shared_attribution=True` and `co_contributors=(...)` for transparency.

---

## 5. Unknown & Missing Contributor Handling

1. **Unattributed Container:** Samples with missing, null, or empty contributor metadata are aggregated into a deterministic pseudo-contributor: `UNATTRIBUTED`.
2. **Preservation Guarantee:** Anomaly evidence for unattributed samples is fully computed, preserved, and reported under `category="UNATTRIBUTED_EVIDENCE"`. Zero evidence is dropped.

---

## 6. Evidence Concentration & Diversity (Non-Additive)

### 6.1 Concentration Metrics
1. **Dataset Anomaly Share:**
   $$\text{Share}_c(M) = \frac{\text{Anomalies}_c(M)}{\text{Total Anomalies in Dataset}(M)}$$
2. **Herfindahl-Hirschman Index (HHI) for Anomaly Dispersion:**
   $$\text{HHI}(M) = \sum_{c=1}^C \left( \text{Share}_c(M) \right)^2 \in [0.0, 1.0]$$
   - $\text{HHI} \approx 1.0$: Anomalies concentrated in a single contributor.
   - $\text{HHI} \approx 0.0$: Anomalies dispersed evenly across all contributors.

### 6.2 Multi-Signal Evidence Diversity
Contributors may display multiple distinct anomaly signals across independent detectors:
- Label Inconsistencies (Phase 5.5)
- Directional Flipping (Phase 5.6)
- Near-Duplicates (Phase 5.4)
- Out-of-Distribution Distance (Phase 5.7)
- Physical Quality Degradation (Phase 5.7)

**Mandatory Non-Additive Rule:**
The engine **NEVER** simply sums anomaly counts across detectors into an opaque composite score. Instead, it computes an **Evidence Diversity Profile**:
$$\text{DiversityCount}(c) = \sum_{k \in \text{Detectors}} \mathbb{I}(w^-(k_c, n_c) > \tau_k)$$
Preserves the full vector of detector signals independently.

---

## 7. Domain Specialization vs. Systematic Bias

Contributors frequently have legitimate domain specializations (e.g., sensor calibration annotators, specific vehicle class annotators, high-latitude snow imagery).

```
                      Contributor Specialization Check
                                      │
          ┌───────────────────────────┴───────────────────────────┐
          ▼                                                       ▼
Class / Sensor Specialization                            Concentrated Anomaly Pattern
- High proportion of Class A                             - High error rate within Class A
- Low error rate within Class A                          - Systematic directional transition
- Statistically aligned with domain                      - Disjoint from domain physics
          │                                                       │
          ▼                                                       ▼
finding_category=                                        finding_category=
"CONTRIBUTOR_CLASS_DISTRIBUTION"                         "CONTRIBUTOR_LABEL_TRANSITION"
(is_anomalous=False, is_specialization=True)             (is_anomalous=True, is_specialization=False)
```

1. **Specialization Metric:** Evaluates contributor class entropy $H(c) = -\sum p_{c, y} \log_2 p_{c, y}$ vs. dataset class entropy $H(\mathcal{D})$. Low entropy indicates specialization, not corruption.
2. **Subgroup Normalization:** Error rates are conditioned on the contributor's specialized classes rather than global averages.

---

## 8. Small-Data Guardrails & Fallbacks

| Condition | Threshold | Engine Behavior | Output Status |
| :--- | :--- | :--- | :--- |
| **Micro-Contributor** | $n_c < 5$ | Bypasses statistical differentials; reports raw counts only. | `INSUFFICIENT_CONTRIBUTOR_SUPPORT` |
| **Small Contributor** | $5 \le n_c < 25$ | Computes Wilson lower bound with conservative shrinkage ($w^-$). | `LOW_SUPPORT_PROFILED` |
| **Zero Background** | $N_{\text{bg}} = 0$ (Sole Contributor) | Skips comparative differential $\Delta$; reports internal rates only. | `SOLO_CONTRIBUTOR_NO_BASELINE` |
| **Small Dataset** | $N < 25$ | Outputs dataset-level insufficient support warning. | `INSUFFICIENT_DATASET_SUPPORT` |

---

## 9. Finding Taxonomy

| Category | Description | Primary Evidence Source |
| :--- | :--- | :--- |
| `CONTRIBUTOR_ANOMALY_CONCENTRATION` | High concentration of overall dataset anomalies in single contributor. | Anomaly Share $> 0.50$, $\text{HHI} > 0.40$ |
| `CONTRIBUTOR_LABEL_TRANSITION` | Significant directional label transition differential $\Delta T(c) > 0.30$. | Phase 5.6 Transition Matrix |
| `CONTRIBUTOR_OOD_CONCENTRATION` | Substantial elevation in OOD sample rate relative to background. | Phase 5.7 OOD Scoring ($w^- > \tau_{\text{bg}}$) |
| `CONTRIBUTOR_QUALITY_CONCENTRATION` | High rate of physical image quality degradation (blur, exposure, noise).| Phase 5.7 Image Quality Metrics |
| `CONTRIBUTOR_DUPLICATE_CONCENTRATION`| Elevated rate of internal near-duplicate submissions. | Phase 5.4 Near-Duplicate Graph |
| `CONTRIBUTOR_CLASS_DISTRIBUTION` | Descriptive report of contributor class/domain specialization. | Class Entropy $H(c)$ |
| `CONTRIBUTOR_MULTI_SIGNAL_EVIDENCE` | Multi-detector evidence concurrence without double counting. | Evidence Diversity Profile ($\ge 3$ signals) |
| `INSUFFICIENT_CONTRIBUTOR_SUPPORT` | Contributor sample size $n_c < 5$ precludes statistical conclusions. | Support Guardrail |
| `UNATTRIBUTED_EVIDENCE` | Preserved evidence for samples without contributor metadata. | Missing Contributor Ingestion |

---

## 10. Immutable Domain Models

```python
from enum import Enum
from typing import Dict, Any, Tuple, Optional, List
from pydantic import BaseModel, ConfigDict, Field

class ContributorCategory(str, Enum):
    CONTRIBUTOR_ANOMALY_CONCENTRATION = "CONTRIBUTOR_ANOMALY_CONCENTRATION"
    CONTRIBUTOR_LABEL_TRANSITION = "CONTRIBUTOR_LABEL_TRANSITION"
    CONTRIBUTOR_OOD_CONCENTRATION = "CONTRIBUTOR_OOD_CONCENTRATION"
    CONTRIBUTOR_QUALITY_CONCENTRATION = "CONTRIBUTOR_QUALITY_CONCENTRATION"
    CONTRIBUTOR_DUPLICATE_CONCENTRATION = "CONTRIBUTOR_DUPLICATE_CONCENTRATION"
    CONTRIBUTOR_CLASS_DISTRIBUTION = "CONTRIBUTOR_CLASS_DISTRIBUTION"
    CONTRIBUTOR_MULTI_SIGNAL_EVIDENCE = "CONTRIBUTOR_MULTI_SIGNAL_EVIDENCE"
    INSUFFICIENT_CONTRIBUTOR_SUPPORT = "INSUFFICIENT_CONTRIBUTOR_SUPPORT"
    UNATTRIBUTED_EVIDENCE = "UNATTRIBUTED_EVIDENCE"

class ContributorEvidenceMetric(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    
    metric_name: str = Field(..., min_length=1)
    contributor_count: float = Field(..., ge=0.0, description="Weighted anomaly count for contributor")
    contributor_exposure: float = Field(..., ge=0.0, description="Weighted total exposure for contributor")
    contributor_rate: float = Field(..., ge=0.0, le=1.0)
    wilson_lower_bound: float = Field(..., ge=0.0, le=1.0, description="Conservative 95% Wilson lower bound")
    background_count: float = Field(..., ge=0.0)
    background_exposure: float = Field(..., ge=0.0)
    background_rate: float = Field(..., ge=0.0, le=1.0)
    rate_differential: float = Field(..., description="Contributor rate minus background rate")
    standard_error: float = Field(..., ge=0.0)
    anomaly_share: float = Field(..., ge=0.0, le=1.0, description="Fraction of dataset anomalies attributed to contributor")

class ContributorEvidenceProfile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    
    contributor_id: str = Field(..., min_length=1)
    total_samples_contributed: int = Field(..., ge=0)
    weighted_sample_exposure: float = Field(..., ge=0.0)
    shared_sample_count: int = Field(..., ge=0)
    metrics: Dict[str, ContributorEvidenceMetric] = Field(default_factory=dict)
    class_distribution: Dict[str, float] = Field(default_factory=dict, description="Class proportion distribution")
    class_entropy: float = Field(..., ge=0.0, description="Shannon entropy of contributed classes")
    evidence_diversity_count: int = Field(..., ge=0, description="Number of independent anomaly signals exceeding threshold")
    is_sufficient_support: bool = Field(..., description="Whether contributor exposure >= min_support (n >= 5)")

class ContributorScanFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    
    finding_id: str = Field(..., min_length=1)
    contributor_id: str = Field(..., min_length=1)
    category: ContributorCategory = Field(...)
    evidence_layer: str = Field(default="detection")
    severity: str = Field(default="LOW", description="LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(..., ge=0.0, le=1.0)
    profile: Optional[ContributorEvidenceProfile] = Field(default=None)
    explanation: str = Field(..., min_length=1)
    limitations: Tuple[str, ...] = Field(default_factory=tuple)

class ContributorAggregationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    
    scan_id: str = Field(..., min_length=1)
    dataset_name: str = Field(..., min_length=1)
    dataset_fingerprint: str = Field(..., min_length=64, max_length=64)
    total_contributors: int = Field(..., ge=0)
    profiled_contributors: int = Field(..., ge=0)
    unattributed_sample_count: int = Field(..., ge=0)
    anomaly_hhi: Dict[str, float] = Field(default_factory=dict, description="HHI concentration per anomaly type")
    profiles: Dict[str, ContributorEvidenceProfile] = Field(default_factory=dict)
    findings: Tuple[ContributorScanFinding, ...] = Field(default_factory=tuple)
    diagnostics: Dict[str, Any] = Field(default_factory=dict)
```

---

## 11. Computational Complexity & Performance Budget

```
Target Workload: 100,000 samples, 500 contributors, 50,000 evidence items in < 5 seconds CPU time
```

| Operation | Complexity | Implementation Strategy |
| :--- | :--- | :--- |
| **Evidence Ingestion & Indexing** | $\mathcal{O}(E)$ | Hash map index on `sample_id` and `annotation_id`. |
| **Contributor Attribution Mapping** | $\mathcal{O}(N)$ | Single-pass iteration over `CanonicalSample` manifest. |
| **Fractional Anomaly Accumulation** | $\mathcal{O}(N + E)$ | Vectorized accumulator per contributor and metric. |
| **Wilson Bounds & Differentials** | $\mathcal{O}(C \cdot M)$ | Direct constant-time mathematical evaluations ($M \le 10$ metrics). |
| **Concentration (HHI / Gini)** | $\mathcal{O}(C \cdot M)$ | Fast array operations over anomaly shares. |
| **Overall Engine Complexity** | $\mathcal{O}(N + C + E)$ | Linear execution; zero nested $O(N \cdot C)$ scanning. |

---

## 12. Comprehensive Testing Strategy (32 Scenarios)

1. **Single Contributor Mapping:** 100% of sample evidence cleanly maps to single contributor.
2. **Multi-Contributor Fractional Attribution:** Sample with 3 contributors distributes $1/3$ weight each without inflating totals.
3. **Linear Anomaly Conservation:** Sum of contributor anomaly counts equals exact dataset anomaly total.
4. **Unattributed Container:** Samples with null/missing contributors map to `UNATTRIBUTED`.
5. **Tiny Contributor Guardrail ($n < 5$):** Emits `INSUFFICIENT_CONTRIBUTOR_SUPPORT`; zero false-positive anomaly findings.
6. **Small Contributor Shrinkage ($5 \le n < 25$):** Wilson lower bound shrinks rates conservatively.
7. **Large Contributor Precision ($n \ge 1000$):** Wilson lower bound converges to empirical rate.
8. **Contributor Anomaly Concentration:** Contributor with $80\%$ of dataset anomalies triggers `CONTRIBUTOR_ANOMALY_CONCENTRATION`.
9. **Label Transition Differential:** Contributor with elevated $\Delta T > 0.35$ triggers `CONTRIBUTOR_LABEL_TRANSITION`.
10. **OOD Elevation Differential:** Contributor with elevated OOD rate relative to background identified.
11. **Image Quality Anomaly Concentration:** High rate of blurred/noisy submissions captured in profile.
12. **Near-Duplicate Concentration:** Contributor submitting internal duplicates identified via graph mapping.
13. **Class Specialization (Legitimate):** Contributor focusing on single class with zero errors receives `CONTRIBUTOR_CLASS_DISTRIBUTION` without anomaly flags.
14. **Subgroup-Aware Baseline:** Nighttime contributor compared against nighttime baseline to avoid false exposure flags.
15. **Solo Contributor Mode ($N_{\text{bg}} = 0$):** Single-contributor dataset handled gracefully without division-by-zero.
16. **Multi-Signal Evidence Concurrence:** Contributor with label, OOD, and duplicate signals receives `CONTRIBUTOR_MULTI_SIGNAL_EVIDENCE`.
17. **Correlated Signal De-duplication:** Correlated blur and OOD signals documented without score addition.
18. **Zero Anomaly Baseline:** Dataset with 0 anomalies produces clean profiles.
19. **Herfindahl-Hirschman Index (HHI):** Highly concentrated anomaly distribution yields $\text{HHI} > 0.50$.
20. **Dispersed Anomaly HHI:** Evenly distributed anomalies yield $\text{HHI} < 0.10$.
21. **Deterministic Reproducibility:** Bit-exact identical output across multiple runs with same inputs.
22. **NaN / Inf / Zero-Division Protection:** Zero exposure, zero background, and degenerate values handled safely.
23. **Cross-Dataset ID Isolation:** Prevents sample ID collisions across dataset versions.
24. **No Malicious Language Invariant:** Complete audit of generated findings and explanations for absence of prohibited terms.
25. **No Final Risk Score Invariant:** Confirms zero threat scores, quarantine dispositions, or culpability ratings.
26. **Offline Air-Gapped Execution:** 100% execution without network calls or external APIs.
27. **Estimated Latent Label Semantics:** Verifies $\hat{y}^*$ is documented as estimate, not ground truth.
28. **Temporal Evidence Preservation:** Preserves timestamp ranges when present in sample metadata.
29. **Malformed Evidence Resilience:** Missing fields in upstream findings handled gracefully with diagnostics.
30. **Large-Scale Performance Benchmark:** 10,000 samples and 100 contributors process in $< 1.0\text{s}$.
31. **Adversarial Specialization Case:** Heavy class specialization does not produce false label flipping findings.
32. **Zero Database Changes:** Verifies no database mutations or migrations.

---

## 13. Explicit Non-Goals & Architectural Boundaries

1. **No Contributor Guilt / Threat Scoring:** The engine does not assign guilt, compute threat scores, or decide penalties.
2. **No Quarantine / Rejection Actions:** Access control and contribution filtering belong to downstream governance.
3. **No Cryptographic Provenance Ledger Writing:** Provenance ledger sealing belongs to Phase 5.9.
4. **No Database Persistence:** Database writes and ORM modifications are out of scope.
5. **No Network Telemetry:** Operates 100% locally and air-gapped.

---

## 14. Frozen Architectural Decisions

- **Dec-5.8-1:** Linear fractional attribution ($w_{s,c} = 1/K$) for multi-contributor samples to conserve dataset totals.
- **Dec-5.8-2:** Conservative Wilson 95% confidence lower bound for all contributor anomaly rates; strict $n < 5$ guardrail.
- **Dec-5.8-3:** Subgroup-aware baselines alongside global leave-one-out baselines to eliminate Simpson's Paradox.
- **Dec-5.8-4:** Non-additive Multi-Signal Evidence Diversity profiles; zero composite risk score summation.
- **Dec-5.8-5:** Explicit `UNATTRIBUTED` pseudo-contributor to preserve evidence on missing metadata.
- **Dec-5.8-6:** Strict semantic invariant: $\text{CONTRIBUTOR EVIDENCE} \ne \text{CONTRIBUTOR GUILT}$, `evidence_layer="detection"`.
