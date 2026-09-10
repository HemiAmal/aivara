# AIVARA — Label-Flipping Detection Architecture Specification
## Phase 5.6.1: Architecture Review & Design Freeze

**Version:** 1.0.0-frozen  
**Status:** DESIGN FROZEN (Implementation Target: Phase 5.6)  
**Security Classification:** Local / Air-Gapped Assurance Engine  
**Target Sub-System:** Phase 5.6 — Label-Flipping Detection Engine (LFDE)  
**Evidence Layer:** `evidence_layer="detection"` (ADR-028 compliant)

---

## 1. Executive Summary & Scope

The **Label-Flipping Detection Engine (LFDE)** is an offline, air-gapped statistical audit sub-system designed to detect systematic, directional, and targeted label transition patterns in contributed computer vision datasets.

### Foundational Invariant: LABEL-FLIPPING EVIDENCE ≠ MALICIOUSNESS
In real-world data collection, systematic label transitions occur for diverse non-adversarial reasons, including:
- Ambiguous class taxonomies and ontology overlapping (e.g., *Sedan* vs. *Coupe*).
- Systematic annotator misunderstandings of class guidelines.
- Unbalanced visual representations and sensor lighting conditions.
- Asymmetric visual hierarchies.

Therefore:
1. The LFDE **NEVER** asserts "malicious intent", "poisoning attacks", "contributor sabotage", "tampering", or "contributor guilt".
2. The LFDE outputs strictly observational statistical evidence under `evidence_layer="detection"`.
3. Downstream attribution and risk synthesis are exclusively reserved for Phase 5.8 (Contributor Risk Engine) and Phase 8 (Executive Risk Engine).

```
                      Phase 5.5 Outputs
               (OOF Predictions, Thresholds t_j,
                 Margins, Latent Estimates y*)
                               │
                               ▼
           ┌───────────────────────────────────────┐
           │ Phase 5.6: Label-Flipping Engine      │
           │                                       │
           │ 1. Empirical Transition Matrix T[i,j] │
           │ 2. Asymmetry & Directionality Analysis│
           │ 3. Target Concentration (HHI/Entropy) │
           │ 4. Contributor Transition Differentials│
           │ 5. Model-Bias & Reciprocal Filters    │
           │ 6. Wilson / Bayesian Uncertainty      │
           └───────────────────┬───────────────────┘
                               │
                               ▼
              Structured Immutable Findings
              (evidence_layer="detection")
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
   Phase 5.8 Contributor Risk           Phase 8 Executive Risk
```

---

## 2. Supported Annotation Modalities

| Modality / Format | Support Status | Operational Scope |
| :--- | :--- | :--- |
| **ImageFolder Classification** | **Full Support** | Evaluates global image label transitions against out-of-fold visual latent estimates $\hat{y}^*$. |
| **COCO / YOLO Object Detection (Class Labels)** | **Full Support** | Audits localized bounding-box Region of Interest (RoI) category transitions. Each box annotation is an atomic analytical unit. |
| **Bounding Box Spatial Coordinates ($[x,y,w,h]$)** | **Unsupported / Out-of-Scope** | Spatial box jitter and coordinate drift belong to Image Quality / Box Anomaly analysis (Phase 5.7). |
| **Dense Segmentation Masks** | **Unsupported** | Marked as `UNSUPPORTED / UNVERIFIABLE`. |
| **Continuous Regression Targets** | **Unsupported** | Marked as `UNSUPPORTED / UNVERIFIABLE`. |

---

## 3. Threat & Analytical Taxonomy

The LFDE formalizes a granular taxonomy to distinguish random annotation errors from structured transitions:

```
                                Dataset Label Inconsistencies
                                              │
                    ┌─────────────────────────┴─────────────────────────┐
                    ▼                                                   ▼
            Isotropic / Random                                Structured / Systematic
          (Uniform noise across classes)                                │
                                              ┌─────────────────────────┴─────────────────────────┐
                                              ▼                                                   ▼
                                    Symmetric Confusion                               Directional Transition
                                   (Reciprocal: A <---> B)                                (Asymmetric: A ---> B)
                                    - Visual overlap                                      - Systematic bias
                                    - Granular ontology                                   - Target substitution
                                    - Model limitation                                    - Class collapse
```

### Detailed Analytical Categories:

1. **Random Label Noise (Isotropic):**
   - Noise is uniformly distributed across all $K-1$ alternative classes without directional preference.
   - Low transition concentration; low pairwise asymmetry.

2. **Class-Dependent Label Noise:**
   - Error rates vary by class difficulty, but errors from class $A$ disperse across multiple plausible classes $\{B, C, D\}$.

3. **Reciprocal Class Confusion ($A \leftrightarrow B$):**
   - Symmetric confusion where samples of class $A$ are frequently labeled as $B$, and samples of class $B$ are similarly labeled as $A$ ($N_{A \to B} \approx N_{B \to A}$).
   - Indicates visual boundary ambiguity or model capacity limits, **NOT** label flipping.

4. **Directional Label Transition ($A \to B$):**
   - Statistically significant asymmetry where class $A$ transitions to $B$ ($N_{A \to B} \gg N_{B \to A}$), but with moderate dispersion.

5. **Targeted Label Flipping ($A \implies B$):**
   - Extreme directional concentration where samples of class $A$ are overwhelmingly and selectively assigned to target class $B$, exhibiting high prediction confidence, high margin, and strong asymmetry.

6. **Many-to-One Collapse ($\{A, B, C\} \to D$):**
   - Multiple distinct source classes transition disproportionately into a single sink class $D$.

7. **One-to-Many Dispersion ($A \to \{B, C, D\}$):**
   - Source class $A$ is fragmented across multiple classes, typical of an ill-defined parent category.

8. **Contributor-Associated Label Transition:**
   - A directional transition $A \to B$ whose frequency within contributor $c$'s submissions exceeds the baseline dataset rate by a statistically significant margin.

9. **Sparse Isolated Anomalies:**
   - Single or sporadic misclassifications lacking cluster support or repetitive directionality.

---

## 4. Relationship & Interface with Phase 5.5

Phase 5.6 builds directly upon Phase 5.5 without recomputing feature extractions, cross-validation folds, or confident learning baselines:

```
Phase 5.5 (LADE):
  Question: "Which individual samples/labels exhibit statistical anomaly?"
  Outputs:  LabelPrediction, Thresholds t_j, Joint Distribution Q_ij, Margins, Anomaly Scores.

Phase 5.6 (LFDE):
  Question: "Across the dataset and contributor subsets, is there structured evidence of
             directional, asymmetric, or targeted class-to-class transitions?"
  Outputs:  LabelTransitionMatrix, DirectionalAsymmetry, TargetedFlipScore,
            ContributorTransitionDifferential, Structured Findings.
```

---

## 5. Mathematical Formulation

Let the dataset consist of $N$ evaluated analytical units with $K$ classes $\{1, \dots, K\}$:
- Observed label: $\tilde{y}_n \in \{1, \dots, K\}$
- Estimated latent label: $\hat{y}^*_n = \arg\max_{k} (\hat{P}(y = k \mid x_n) - t_k)$ (from Phase 5.5 confident learning).
- $\mathcal{X}_{\tilde{y}=i} = \{n : \tilde{y}_n = i\}$: subset of samples observed with label $i$.

> **CRITICAL INVARIANT:** $\hat{y}^*$ is an estimated latent statistical quantity, **NEVER** ground truth.

### 5.1 Transition Count Matrix ($N_{i, j}$)
The unnormalized transition count matrix $N_{i, j}$ records the number of samples whose observed label is $i$ and whose estimated latent class is $j$:
$$N_{i, j} = \left| \{ n : \tilde{y}_n = i \text{ and } \hat{y}^*_n = j \} \right|$$

- **Diagonal ($N_{i, i}$):** Consistent samples where observed label agrees with latent estimate.
- **Off-Diagonal ($N_{i, j}$ for $i \ne j$):** Transition instances from observed class $i$ to estimated latent class $j$.

### 5.2 Conditional Transition Rate ($T_{i \to j}$)
The empirical row-normalized conditional transition probability:
$$T_{i \to j} = P(\hat{y}^* = j \mid \tilde{y} = i) = \frac{N_{i, j}}{|\mathcal{X}_{\tilde{y}=i}|} = \frac{N_{i, j}}{\sum_{k=1}^K N_{i, k}}$$

$$\sum_{j=1}^K T_{i \to j} = 1.0 \quad \forall i \in \{1, \dots, K\}$$

### 5.3 Directional Asymmetry Index ($\text{Asym}(i, j)$)
Measures the directional skew between class $i$ and class $j$:
$$\text{Asym}(i, j) = \frac{N_{i, j} - N_{j, i}}{N_{i, j} + N_{j, i} + \epsilon} \in [-1.0, 1.0]$$

- $\text{Asym}(i, j) \approx 0.0$: Perfectly reciprocal/symmetric confusion.
- $\text{Asym}(i, j) > 0.6$: Strong directional transition from $i$ towards $j$.
- $\text{Asym}(i, j) < -0.6$: Reverse directional transition from $j$ towards $i$.

### 5.4 Noise Concentration Index ($\text{NCI}_{i \to j}$)
To differentiate targeted flipping from generalized multi-class dispersion, we measure the proportion of total off-diagonal noise from class $i$ captured by specific class $j$:
$$\text{NCI}_{i \to j} = \frac{N_{i, j}}{\sum_{k \ne i} N_{i, k} + \epsilon} \in [0.0, 1.0]$$

- $\text{NCI}_{i \to j} \to 1.0$: All noise from class $i$ concentrates exclusively into class $j$ (Targeted).
- $\text{NCI}_{i \to j} \approx \frac{1}{K-1}$: Noise is uniformly dispersed across all classes (Isotropic).

---

## 6. Targeted Label-Flipping Scoring Engine

To prevent false positives from naive sample counts or high-volume majority classes, AIVARA defines a composite, statistically discounted **Targeted Flipping Score ($\text{TFS}_{i \to j} \in [0.0, 1.0]$)**:

$$\text{TFS}_{i \to j} = \text{SupportDiscount}(N_{i, j}) \times T_{i \to j} \times \max(0.0, \text{Asym}(i, j)) \times \text{NCI}_{i \to j}$$

### 6.1 Statistical Support Discount Function
Prevents high scores from small-sample flukes using an asymptotic sigmoid scaling:
$$\text{SupportDiscount}(n) = \frac{1}{1 + e^{-0.5 \cdot (n - n_{\text{target}})}}$$
where default $n_{\text{target}} = 6$. For $n < 3$, $\text{SupportDiscount} \approx 0.0$.

### 6.2 Wilson Score Lower Bound for Transition Confidence
For statistical confidence estimation under small-sample uncertainty, LFDE computes the lower bound of the Wilson Score Interval for binomial proportion $p = T_{i \to j}$ with sample size $n = |\mathcal{X}_{\tilde{y}=i}|$ at confidence level $Z = 1.96$ ($95\%$ CI):

$$w^{-}(p, n) = \frac{p + \frac{Z^2}{2n} - Z \sqrt{\frac{p(1-p)}{n} + \frac{Z^2}{4n^2}}}{1 + \frac{Z^2}{n}}$$

This lower bound $w^{-}$ serves as the robust, non-inflated foundation for finding confidence $\text{Conf}_{i \to j}$.

---

## 7. Model-Bias & Natural Confusion Controls

A fundamental hazard in label-flipping detection is mistaking **model feature weakness** or **inherent ontology overlap** for dataset manipulation. LFDE implements three explicit controls:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Model-Bias Control Triad                           │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
         ┌─────────────────────────────┼─────────────────────────────┐
         ▼                             ▼                             ▼
  [ Reciprocal Filter ]      [ Dispersion Filter ]      [ Margin Threshold ]
   If Asym(i,j) <= 0.35       If NCI(i,j) <= 0.35        If avg(Margin) <= 0.20
   -> Flag as:                -> Flag as:                -> Flag as:
   RECIPROCAL_CONFUSION       CLASS_DISPERSION           MODEL_DISAGREEMENT
   (Confidence Discounted)    (Not Targeted Flip)        (Low Confidence)
```

1. **Reciprocal Confusion Filter:** If $N_{i, j} \ge 3$ and $N_{j, i} \ge 3$ with $|\text{Asym}(i, j)| < 0.35$, the pattern is classified as `RECIPROCAL_CLASS_CONFUSION` with `is_targeted=False`.
2. **Dispersion Filter:** If class $i$ error is distributed across $\ge 3$ alternative classes with $\text{NCI}_{i \to j} < 0.35$, the finding is classified as `ONE_TO_MANY_CONFUSION`.
3. **Average Latent Margin Constraint:** True label flips exhibit sharp out-of-fold feature alignment with the target class. If the mean Phase 5.5 prediction margin $\overline{\text{Margin}}_{i \to j} < 0.20$, confidence is discounted by $50\%$.

---

## 8. Contributor-Specific Transition Differentials

While Phase 5.8 performs multi-signal risk aggregation, Phase 5.6 extracts clean, isolated **Contributor Transition Differentials**:

For each contributor $c$ contributing samples to class $i$:
$$T_{i \to j}^{(c)} = \frac{N_{i, j}^{(c)}}{|\mathcal{X}_{\tilde{y}=i}^{(c)}|}$$

$$\Delta T_{i \to j}^{(c)} = T_{i \to j}^{(c)} - T_{i \to j}^{(\text{dataset}\setminus c)}$$

### Finding Semantics:
- If $\Delta T_{i \to j}^{(c)} > 0.25$ with support $N_{i, j}^{(c)} \ge 3$, LFDE emits a `CONTRIBUTOR_ASSOCIATED_LABEL_TRANSITION` finding.
- **Strict Invariant:** The finding strictly describes the statistical concentration differential. It **NEVER** asserts that contributor $c$ is malicious or culpable.

---

## 9. Small Dataset & Rare Class Guardrails

LFDE strictly adheres to the frozen AIVARA guardrail baseline:

| Condition | Action & Classification |
| :--- | :--- |
| **Total Dataset $N < 25$** | Transition analysis is skipped. Emits `INSUFFICIENT_EVIDENCE` (`confidence=0.0`). |
| **Class Sample Count $< 5$** | Class excluded from source transition matrix. Marked `INSUFFICIENT_SUPPORT`. |
| **Pair Transition Count $N_{i, j} < 3$** | Marked `INSUFFICIENT_SUPPORT`. Cannot trigger `POSSIBLE_LABEL_FLIP`. |
| **Singleton Class ($N=1$)** | Marked `UNVERIFIABLE`. |
| **Contributor Class Count $< 5$** | Contributor differential analysis skipped for that class. |

---

## 10. Taxonomic Finding Categories

Every finding emitted by Phase 5.6 belongs to `evidence_layer="detection"`:

1. **`POSSIBLE_LABEL_FLIP`:** High-confidence, strongly asymmetric, concentrated directional transition from class $A \to B$ ($\text{TFS} > 0.40$, $\text{Asym} > 0.50$, $\text{NCI} > 0.50$, $N_{A \to B} \ge 3$).
2. **`DIRECTIONAL_LABEL_TRANSITION`:** Statistically significant asymmetric transition with moderate concentration ($\text{Asym} > 0.40$, $N_{A \to B} \ge 3$).
3. **`SYSTEMATIC_CLASS_TRANSITION`:** Broad transition affecting $> 20\%$ of source class volume.
4. **`RECIPROCAL_CLASS_CONFUSION`:** Symmetric bidirectional confusion between classes $A$ and $B$ ($|\text{Asym}| \le 0.35$), indicative of visual similarity or ontology overlap.
5. **`MANY_TO_ONE_COLLAPSE`:** $\ge 3$ distinct source classes systematically transitioning into a single sink class.
6. **`CONTRIBUTOR_ASSOCIATED_LABEL_TRANSITION`:** Transition $A \to B$ heavily concentrated within contributions from a specific contributor identifier.
7. **`INSUFFICIENT_SUPPORT`:** Insufficient sample count to evaluate transition reliability ($N < 25$ or $N_{i, j} < 3$).
8. **`MODEL_UNAVAILABLE`:** Upstream feature extractor/model missing or incompatible.

---

## 11. Immutable Domain Models (Design Specification)

```python
class LabelFlipCategory(str, Enum):
    POSSIBLE_LABEL_FLIP = "possible_label_flip"
    DIRECTIONAL_LABEL_TRANSITION = "directional_label_transition"
    SYSTEMATIC_CLASS_TRANSITION = "systematic_class_transition"
    RECIPROCAL_CLASS_CONFUSION = "reciprocal_class_confusion"
    MANY_TO_ONE_COLLAPSE = "many_to_one_collapse"
    CONTRIBUTOR_ASSOCIATED_LABEL_TRANSITION = "contributor_associated_label_transition"
    INSUFFICIENT_SUPPORT = "insufficient_support"
    MODEL_UNAVAILABLE = "model_unavailable"

class LabelTransitionPair(BaseModel):
    model_config = ConfigDict(frozen=True)
    source_category_id: int
    source_category_name: str
    target_category_id: int
    target_category_name: str
    transition_count: int = Field(..., ge=0)
    reverse_transition_count: int = Field(..., ge=0)
    transition_rate: float = Field(..., ge=0.0, le=1.0)
    reverse_transition_rate: float = Field(..., ge=0.0, le=1.0)
    asymmetry_index: float = Field(..., ge=-1.0, le=1.0)
    noise_concentration_index: float = Field(..., ge=0.0, le=1.0)
    targeted_flip_score: float = Field(..., ge=0.0, le=1.0)
    average_margin: float
    wilson_lower_bound: float = Field(..., ge=0.0, le=1.0)

class ContributorTransitionSummary(BaseModel):
    model_config = ConfigDict(frozen=True)
    contributor_id: str
    source_category_id: int
    target_category_id: int
    contributor_transition_count: int
    contributor_source_total: int
    contributor_transition_rate: float
    dataset_baseline_rate: float
    rate_differential: float
    support_adequate: bool

class LabelFlipFinding(BaseModel):
    model_config = ConfigDict(frozen=True)
    finding_id: str
    source_category_id: int
    source_category_name: str
    target_category_id: Optional[int] = None
    target_category_name: Optional[str] = None
    category: LabelFlipCategory
    targeted_flip_score: float = Field(..., ge=0.0, le=1.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence_layer: str = "detection"  # ADR-028 compliance
    affected_sample_ids: Tuple[str, ...] = Field(default_factory=tuple)
    affected_annotation_ids: Tuple[str, ...] = Field(default_factory=tuple)
    contributor_summaries: Tuple[ContributorTransitionSummary, ...] = Field(default_factory=tuple)
    transition_metrics: Optional[LabelTransitionPair] = None
    limitations: List[str] = Field(default_factory=list)

class LabelFlipScanResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    total_samples: int
    evaluated_samples: int
    transition_matrix: List[List[float]] = Field(default_factory=list)
    raw_count_matrix: List[List[int]] = Field(default_factory=list)
    findings: Tuple[LabelFlipFinding, ...] = Field(default_factory=tuple)
    model_state: ModelState = Field(default=ModelState.MODEL_AVAILABLE)
    warnings: List[str] = Field(default_factory=list)
    capability_info: Dict[str, Any] = Field(default_factory=dict)
```

---

## 12. Security & Robustness Boundary

1. **Malicious / Corrupted Inputs:** Rejects NaN/Inf probabilities, out-of-range class indices, negative counts, and invalid Unicode identifiers safely.
2. **Streaming & Bounded Memory:** Computes transition summaries using $K \times K$ integer accumulators with constant $O(K^2)$ memory, independent of sample size $N$.
3. **Air-Gapped Guarantee:** Zero network calls, zero external web requests, zero telemetry.
4. **Deterministic Reproducibility:** Fixed seeds and deterministic tie-breaking ensure identical findings across runs.

---

## 13. Computational Complexity

- **Extraction & Unit Processing:** $O(N)$
- **Transition Matrix Accumulation:** $O(N)$
- **Pairwise Metric & Asymmetry Analysis:** $O(K^2)$
- **Contributor Differential Analysis:** $O(C \cdot K^2)$ where $C$ is unique contributors.
- **Overall Complexity:** $O(N + (1 + C) K^2)$, scaling linearly with sample volume and comfortably handling $100\text{k}+$ annotations in $< 1\text{s}$.

---

## 14. Phase 5.6 Test Strategy (Pre-Implementation Plan)

1. `test_transition_count_matrix_construction`: Verification of $N_{i, j}$ integer counts.
2. `test_row_normalized_transition_probabilities`: Verification that $\sum_j T_{i \to j} = 1.0$.
3. `test_perfect_diagonal_clean_dataset`: Clean dataset yields identity transition matrix.
4. `test_asymmetric_targeted_flip_detection`: $A \to B$ flip flagged as `POSSIBLE_LABEL_FLIP`.
5. `test_reciprocal_confusion_not_flagged_as_flip`: $A \leftrightarrow B$ symmetric noise marked `RECIPROCAL_CLASS_CONFUSION`.
6. `test_many_to_one_class_collapse`: $\{A, B, C\} \to D$ flagged as `MANY_TO_ONE_COLLAPSE`.
7. `test_one_to_many_dispersion_not_targeted`: Uniform noise marked as general noise.
8. `test_contributor_associated_differential`: High contributor delta triggers `CONTRIBUTOR_ASSOCIATED_LABEL_TRANSITION`.
9. `test_small_dataset_guardrail`: $N < 25$ emits `INSUFFICIENT_SUPPORT`.
10. `test_rare_class_guardrail`: Class $< 5$ samples excluded from source flipping.
11. `test_sparse_transition_guardrail`: $N_{i, j} < 3$ rejected from flip triggers.
12. `test_singleton_class_guardrail`: $N=1$ marked unverifiable.
13. `test_wilson_confidence_lower_bound`: Verification of conservative small-sample confidence.
14. `test_object_detection_roi_transitions`: Localized bounding box class auditing.
15. `test_unsupported_segmentation_masks`: Dense masks safely rejected as unverifiable.
16. `test_unsupported_continuous_regression`: Continuous targets safely rejected as unverifiable.
17. `test_model_unavailable_state`: Missing models return structured unverified states.
18. `test_model_incompatible_state`: Ontology mismatch handled safely.
19. `test_no_baseline_retraining_invariant`: Guarantees zero customer model mutation.
20. `test_semantic_invariant_no_malicious_language`: Strict verification of neutral language.
21. `test_deterministic_reproducibility`: Identical inputs generate identical finding IDs.
22. `test_nan_inf_malformed_input_resilience`: Robust handling of corrupt statistical values.
23. `test_extreme_class_imbalance`: Robustness under 100:1 class ratio.
24. `test_large_scale_performance`: Sub-second execution on $50\text{k}+$ annotations.

---

## 15. Explicit Non-Goals & Frozen Decisions

### Explicit Non-Goals:
- **No Malicious Attribution:** Phase 5.6 does not determine intent, sabotage, or threat actors.
- **No Baseline Retraining:** Customer production models are never modified or retrained.
- **No Database Schema Mutations:** Zero database migrations or table modifications.
- **No Bounding Box Geometry Analysis:** Bounding box spatial drift is deferred to Phase 5.7.
- **No Contributor Risk Scoring:** Aggregate contributor reputation scoring is deferred to Phase 5.8.

### Frozen Architectural Decisions:
1. All findings strictly carry `evidence_layer="detection"`.
2. Transition matrices use row-normalized conditional probabilities $T_{i \to j} = P(\hat{y}^* = j \mid \tilde{y} = i)$.
3. Targeted label-flipping requires three concurrent criteria: strong asymmetry ($\text{Asym} > 0.5$), high concentration ($\text{NCI} > 0.5$), and adequate support ($N_{i, j} \ge 3$).
4. Symmetric confusion ($|\text{Asym}| \le 0.35$) is explicitly categorized as `RECIPROCAL_CLASS_CONFUSION`.
5. Contributor differentials are strictly descriptive differentials without culpability conclusions.
