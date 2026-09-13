# PHASE 11.8 ARCHITECTURE: CONTRIBUTOR & SOURCE-AWARE DISTRIBUTION SHIFT

================================================================================
PROJECT: AIVARA — AI Verification & Assurance
SUBSYSTEM: Phase 11 — Distribution Shift / Data Drift Analysis
PHASE: 11.8 — Contributor & Source-Aware Distribution Shift
SUBPHASE: 11.8.1 — Architecture & Requirements Freeze
STATUS: COMPLETE & AUTHORITATIVE
DATE: September 13, 2026
================================================================================

## 1. Architectural Overview & Philosophy

Phase 11.8 extends AIVARA's distribution-shift assurance framework to evaluate data heterogeneity across **data contributors, acquisition sources, hardware devices, and collection pipelines**. 

While prior subphases evaluated population-level drift (Phase 11.4), image drift (Phase 11.5), representation drift (Phase 11.6), and temporal drift (Phase 11.7), Phase 11.8 partitions populations along provenance dimensions to answer:
$$\text{"Does the statistical distribution of data diverge systematically across declared data sources?"}$$

```
+-----------------------------------------------------------------------------------+
|                           PHASE 11.8 ARCHITECTURAL PIPELINE                       |
+-----------------------------------------------------------------------------------+
|  [Layer 1: Source Attribute Extraction]                                           |
|       Raw Observations + Metadata --> Source Attribute Selector                   |
|                                                                                   |
|  [Layer 2: Deterministic Canonicalization & Pseudonymization]                     |
|       Unicode NFKC --> Lowercase --> Trim --> Project-Scoped HMAC/SHA-256 Pseudonym|
|                                                                                   |
|  [Layer 3: Group Formation & Accounting]                                          |
|       Eligible Groups (N >= 30) | Insufficient Groups (N < 30) | Missing / Invalid |
|                                                                                   |
|  [Layer 4: Reference Binding & Subsampling]                                       |
|       Explicit Reference Source (or Baseline Population) --> Seeded Subsampling   |
|                                                                                   |
|  [Layer 5: O(G) Linear Pairwise Statistical Dispatch (Phase 11.3)]               |
|       Continuous: KS + PSI | Categorical: Chi-Square + TVD | Embedding: MMD/Energy|
|                                                                                   |
|  [Layer 6: Multiple Testing Control (Phase 11.3)]                                 |
|       Benjamini-Hochberg FDR Control (q* = 0.05) per Comparison Family            |
|                                                                                   |
|  [Layer 7: Dual-Gate Shift Decision]                                              |
|       (p_adj <= 0.05) AND (EffectSize >= Threshold) --> Material Shift Decision   |
|                                                                                   |
|  [Layer 8: Confounding & Label Skew Analysis]                                     |
|       Marginal P(X|S) vs Class Distribution P(Y|S) --> Simpson's Paradox Warning   |
|                                                                                   |
|  [Layer 9: Canonical Cryptographic Profile (RFC 8785 JCS + SHA-256)]              |
|       Immutable Source Analysis Profile Digest --> Content Addressed Identity     |
|                                                                                   |
|  [Layer 10: Non-Attribution Evidence & Finding Synthesis]                         |
|       EvidenceModel (evidence_layer="detection") --> Objective FindingModel       |
+-----------------------------------------------------------------------------------+
```

### 1.1 Non-Attribution Invariant
Phase 11.8 is strictly an observational detection subsystem. It does **NOT** perform causal attribution, legal judgment, or adversarial intent classification.
$$\text{SOURCE-ASSOCIATED DISTRIBUTION SHIFT} \ne \text{MALICIOUS INTENT}$$
$$\text{SOURCE-ASSOCIATED DISTRIBUTION SHIFT} \ne \text{DATASET POISONING}$$
$$\text{SOURCE-ASSOCIATED DISTRIBUTION SHIFT} \ne \text{CONTRIBUTOR FRAUD}$$
$$\text{SOURCE-ASSOCIATED DISTRIBUTION SHIFT} \ne \text{MODEL COMPROMISE}$$

A source-associated shift simply indicates that the statistical properties of samples submitted under that identifier differ significantly from the certified reference baseline (e.g., due to different sensor calibration, geographic variation, or annotator guidelines).

---

## 2. Source & Contributor Abstraction

### 2.1 Unified Source Attribute Context
To handle diverse metadata structures without rigid schema coupling, Phase 11.8 defines a generic `SourceContext` abstraction:
- **`raw_source_id`**: The raw string identifier extracted from metadata (e.g., `"Vendor_Alpha"`, `"Camera_04"`, `"Annotator_102"`).
- **`source_type`**: `SourceType` enum (`CONTRIBUTOR`, `ACQUISITION_CHANNEL`, `COLLECTION_SITE`, `DEVICE_HARDWARE`, `PIPELINE_VERSION`, `CUSTOM_GROUP`).
- **`canonical_source_id`**: Deterministically normalized string.
- **`pseudonym_id`**: Project-isolated pseudonymized hash.

### 2.2 Source Attribute Selector
The analysis contract specifies where source metadata is located via `SourceAttributeSelector`:
- `attribute_key`: String key path into sample metadata (e.g., `"contributor_id"`, `"source"`, `"metadata.camera_serial"`).
- `fallback_policy`: Enum (`FAIL_CLOSED`, `ASSIGN_UNKNOWN`, `ASSIGN_MISSING`).

---

## 3. Source Identity Trust Model

AIVARA explicitly separates **Source Claims** from **Source Proofs**:
1. **Source Claim (Layer 1 Detection)**:
   - Ingested metadata in CSVs, JSON manifests, or image headers is treated as an unauthenticated assertion.
   - Analysis results measure distributions associated with the *claimed* identifier.
2. **Source Proof (Layer 2 Cryptographic Proof)**:
   - If digital signatures are attached (Phase 4 / Phase 10 Ed25519 signatures), signature verification is executed independently.
   - An unverified source claim is never promoted to cryptographic proof of origin.

---

## 4. Deterministic Canonicalization Pipeline

To eliminate homoglyph attacks, whitespace collisions, and case inconsistencies, all raw source strings undergo a strict 5-stage canonicalization pipeline:

$$\text{raw\_string} \xrightarrow{\text{Unicode NFKC}} \text{s}_1 \xrightarrow{\text{Strip Non-Printable}} \text{s}_2 \xrightarrow{\text{Trim Whitespace}} \text{s}_3 \xrightarrow{\text{Lowercase Fold}} \text{canonical\_source\_id}$$

```python
def canonicalize_source_id(raw_id: str) -> str:
    if raw_id is None:
        return "missing"
    # Step 1: Unicode NFKC normalization
    s = unicodedata.normalize("NFKC", str(raw_id))
    # Step 2: Strip control / non-printable characters
    s = "".join(ch for ch in s if ch.isprintable())
    # Step 3: Strip leading/trailing whitespace & collapse multiple spaces
    s = re.sub(r"\s+", " ", s).strip()
    # Step 4: Lowercase fold
    s = s.lower()
    # Step 5: Validation & fallback
    if not s:
        return "missing"
    if len(s) > 128:
        s = s[:128]
    return s
```

---

## 5. Group Formation & Hierarchy

Observations are partitioned by their `canonical_source_id`.
- **Flat vs Hierarchical**: In v1, source groups are partitioned as a flat partition of $G$ distinct groups.
- **Hierarchical Path Representation**: Hierarchical source tags (e.g., `Org/Site/Device`) are encoded as delimited canonical path strings: `"org_a/site_1/dev_04"`. This enables hierarchical grouping via prefix selectors without introducing recursive statistical complexity in v1.

---

## 6. Accounting & Reconciliation

Every analysis execution computes an exact, non-leaking reconciliation accounting balance:

```
Total Observations (N_total)
  ├── Eligible Groups Samples (Sum of N_g where N_g >= 30)
  ├── Insufficient Data Samples (Sum of N_g where 1 <= N_g < 30)
  ├── Missing Metadata Samples (N_missing)
  ├── Invalid Metadata Samples (N_invalid)
  └── Unknown Metadata Samples (N_unknown)
```

**Reconciliation Invariant**:
$$N_{\text{total}} = \sum_{g \in \text{Eligible}} N_g + \sum_{g \in \text{Insufficient}} N_g + N_{\text{missing}} + N_{\text{invalid}} + N_{\text{unknown}}$$

---

## 7. Group Size Requirements & Imbalance Policy

- **Minimum Sample Size ($N_{\text{min}} = 30$)**: Groups with $N_g < 30$ cannot achieve reliable asymptotic power for Two-Sample KS or Chi-Square tests and transition to `INSUFFICIENT_DATA`.
- **Maximum Sample Budget ($N_{\text{max}} = 5,000$)**: Groups with $N_g > 5000$ undergo deterministic uniform subsampling to 5,000 samples using Phase 11.2 seeded PRNG (`random.Random(seed)`).
- **Deterministic Subsampling Seed**:
  $$\text{seed} = \text{int}(\text{SHA-256}(\text{project\_id} \mathbin{\Vert} \text{dataset\_id} \mathbin{\Vert} \text{canonical\_source\_id} \mathbin{\Vert} \text{contract\_hash})[:8], 16)$$

---

## 8. Comparison Topologies

### 8.1 Evaluated Topologies

| Topology | Complexity | Pros | Cons / Hazards | v1 Status |
|---|---|---|---|---|
| **Source-vs-Reference** | $O(G)$ | Immutable baseline; clear directionality; no circularity. | Requires explicit reference selection. | **PRIMARY (Selected)** |
| **Source-vs-Baseline Population** | $O(G)$ | Reuses Phase 11.2 reference population; fully automated. | Reference may contain mixed historical sources. | **SECONDARY (Selected)** |
| **Leave-One-Source-Out (LOSO)** | $O(G)$ | Automated reference synthesis. | Simpson's paradox; dominant group contamination; circularity. | **DEFERRED** |
| **Pairwise All-Against-All** | $O(G^2)$ | Complete source-to-source mapping. | Extreme compute overhead; severe FDR multiplicity penalty. | **DEFERRED (Future Work)** |

### 8.2 Primary Topology ($O(G)$ Linear)
For each eligible source group $s_g \in \{s_1, \dots, s_G\}$, the engine evaluates:
$$\mathcal{P}_{s_g} \longleftrightarrow \mathcal{P}_{\text{reference}}$$
Total comparisons: exactly $G$ comparisons per feature.

---

## 9. Statistical Engine Reuse & Multiple Testing

### 9.1 100% Phase 11.3 Delegation
Phase 11.8 implements **0 duplicate statistical tests**. All tests are delegated to `StatisticalDriftEngine`:
- **Continuous 1D Features**: Two-Sample Kolmogorov-Smirnov (`two_sample_ks`) + Population Stability Index (`calculate_psi`).
- **Categorical & Label Features**: Chi-Square Independence (`chi_square_drift`) + Total Variation Distance (`calculate_tvd`).
- **High-Dimensional Embeddings**: Maximum Mean Discrepancy (`kernel_mmd_permutation`) or Energy Distance (`energy_distance_permutation`).

### 9.2 Benjamini-Hochberg FDR Multiplicity Control
For $M$ features tested across $G$ source groups:
- **Comparison Family**: The set of all source comparisons for a specific feature: $\{p_1^{(f)}, p_2^{(f)}, \dots, p_G^{(f)}\}$.
- **Adjustment**: `apply_benjamini_hochberg(p_values_dict, alpha=0.05)`.
- Adjusted $p$-values $p_{\text{adj}, g}^{(f)}$ are preserved alongside raw $p$-values.

---

## 10. Dual-Gate Decision Engine & Effect Metrics

Shift declaration requires both statistical and physical practical significance:
$$\text{Shift}(s_g, f) = \text{TRUE} \iff (p_{\text{adj}, g}^{(f)} \le 0.05) \land (\text{EffectSize}(s_g, \text{ref}, f) \ge \theta_{\text{effect}})$$

| Modality | Statistical Test | Physical Effect Metric | Effect Threshold ($\theta$) |
|---|---|---|---|
| Continuous Numerical | Two-Sample KS | Population Stability Index (PSI) | $\ge 0.10$ |
| Categorical / Classes | Chi-Square Test | Total Variation Distance (TVD) | $\ge 0.05$ |
| High-Dimensional Vectors | Kernel MMD | Discrepancy ($\text{MMD}^2$) | $\ge 0.02$ |
| Image Descriptors | Two-Sample KS | Population Stability Index (PSI) | $\ge 0.10$ |

---

## 11. Confounding, Label Skew & Simpson's Paradox

### 11.1 Confounding Hazard
A source may exhibit severe marginal feature drift $P(X \mid S)$ purely because it specializes in a specific object class (e.g., Contributor A only labels night-time thermal images).

### 11.2 AIVARA Confounding Mitigation:
1. The engine computes both marginal feature drift $\mathcal{P}(X \mid S)$ and source class proportions $\mathcal{P}(Y \mid S)$.
2. If class distribution TVD between source and reference is significant ($\text{TVD}_{\text{label}} \ge 0.15$), the profile records `potential_label_confounding = True`.
3. Finding descriptions include an explicit caveat: *"Observed feature divergence is accompanied by substantial class label skew ($\text{TVD} = X$), which may confound marginal feature analysis."*

---

## 12. Cross-Phase Subsystem Composition

```
Phase 11.2 (Boundary & Sampling)       --> Reused for dataset boundaries & seeded PRNG subsampling
Phase 11.3 (Statistical Engine)        --> Reused for KS, Chi-Square, MMD, Energy, and BH FDR
Phase 11.4 (Feature Drift)             --> Reused for tabular feature definitions & PSI
Phase 11.5 (Image Drift)               --> Reused for ImageDescriptor features (histograms, aspect)
Phase 11.6 (Representation Drift)      --> Reused for DINOv2 ViT-S/14 384-d embeddings & contracts
Phase 11.7 (Temporal Drift)            --> Consumed as contextual metadata (time spans)
Phase 6 (Contributor Risk)             --> Future consumer of Phase 11.8 detection evidence
```

---

## 13. Privacy, Pseudonymization & Project Isolation

### 13.1 Project-Scoped Deterministic Pseudonymization
To prevent cross-project contributor linkability:
$$\text{PseudonymID} = \text{SHA-256}(\text{project\_id} \mathbin{\Vert} \text{salt} \mathbin{\Vert} \text{canonical\_source\_id})[:16]$$
- Same contributor in Project A $\to$ `pseudonym_7f8a9...`
- Same contributor in Project B $\to$ `pseudonym_3b2c1...`
- Cross-project linkage is mathematically infeasible without the project salt.

### 13.2 Privacy Invariants:
- Raw contributor PII is never stored in `FindingModel` or `EvidenceModel`.
- High-dimensional feature matrices and raw images are transiently evaluated in memory and never stored in persistent profile JSON.

---

## 14. Cryptographic Identity & Hashing

All profile and group descriptor hashes follow strict **RFC 8785 JSON Canonicalization Scheme (JCS) + SHA-256**:

$$\text{profile\_hash} = \text{SHA-256}(\text{RFC8785\_JCS}(\text{CanonicalSourceAnalysisProfile}))$$

### Bound Parameters in Canonical Hash:
1. `project_id`, `dataset_id`, `population_id`
2. `source_attribute_key`, `canonical_group_hashes`
3. `reference_source_id` / `reference_population_hash`
4. `comparison_topology`, `subsampling_seed`, `statistical_policy`
5. `comparison_results` (status, $p_{\text{adj}}$, effect size, metric)
6. `schema_version`

---

## 15. FindingModel & EvidenceModel Synthesis

### 15.1 FindingModel Schema
- `evidence_layer`: Strictly `"detection"` (Layer 1 Detection).
- `finding_type`: `"source_distribution_shift"`.
- `severity`: Derived deterministically from maximum effect size and shift status (`INFO`, `LOW`, `MEDIUM`, `HIGH`).
- `confidence`: Calibrated statistical confidence $\in [0.0, 1.0]$ based on sample size and test power.
- `description`: Strictly neutral, non-accusatory summary.

### 15.2 EvidenceModel Schema
- `evidence_type`: `"source_distribution_shift"`.
- `content`: Binds `profile_hash`, `source_group_descriptors`, `comparison_results`, `accounting`, and `confounding_indicators`.

---

## 16. Failure Matrix

| Failure Mode | Detection Point | Engine Behavior | Output Status | Finding / Alert Generated |
|---|---|---|---|---|
| Missing Source Metadata | Layer 1 Extraction | Captured into `N_missing` | Valid Accounting | `HIGH_MISSING_SOURCE_METADATA_RATE` (if $>10\%$) |
| Malformed / Unparseable Source | Layer 2 Canonicalization | Captured into `N_invalid` | Valid Accounting | `INVALID_SOURCE_METADATA` |
| Small Group Size ($N < 30$) | Layer 3 Group Formation | Group marked `INSUFFICIENT_DATA` | Excluded from Tests | `INSUFFICIENT_GROUP_DATA` |
| High Sybil Fragmentation | Layer 3 Group Formation | Accounted in Sub-threshold | Valid Accounting | `EXCESSIVE_SOURCE_FRAGMENTATION` (if $>20\%$) |
| Exceeded Group Limit ($G > 50$) | Layer 3 Group Formation | Raises `ResourceLimitExceededError` | Abort / Top-G Mode | Error Raised |
| Reference Source Missing | Layer 4 Reference Binding | Raises `TemporalAnalysisError` / `InvalidBaseline` | Abort Fail-Closed | Error Raised |
| Non-Finite Values (NaN/$\pm\infty$) | Layer 5 Statistical Dispatch | Trapped & Filtered / Error | Fail-Closed | `DATASET_NONFINITE_VALUES` |
| Zero Statistical Variance | Layer 5 Statistical Dispatch | Returns $p=1.0, \text{effect}=0.0$ | `NO_MATERIAL_SHIFT` | Descriptive Metadata Note |
| Project ID Contamination | Layer 9 Cryptographic Hashing | Rejects Cross-Tenant Data | Abort Fail-Closed | `CrossProjectContaminationError` |

---

## 17. Comprehensive Test Plan

A dedicated verification suite (`tests/test_source_distribution_shift.py`) will cover all 55 requirements across 12 comprehensive suites:
1. `test_01_to_07_canonicalization_and_extraction`: Unicode NFKC, trimming, homoglyph resistance, case folding.
2. `test_08_to_14_group_formation_and_accounting`: Reconciliation equations, missing/invalid handling, flat/hierarchical paths.
3. `test_15_to_18_group_size_bounds_and_subsampling`: $N_{\text{min}}=30$ floor, $N_{\text{max}}=5000$ ceiling, seeded deterministic PRNG.
4. `test_19_to_24_statistical_engine_reuse_and_fdr`: KS, Chi-Square, MMD, Energy Distance, BH FDR $q^*=0.05$.
5. `test_25_to_30_dual_gate_decisions_and_thresholds`: PSI, TVD, $\text{MMD}^2$, Energy thresholds, raw vs adjusted $p$-values.
6. `test_31_to_35_confounding_and_simpsons_paradox`: Label skew detection, conditional warning generation.
7. `test_36_to_39_sybil_fragmentation_and_dominance`: Sub-threshold volume alerts, dominant group handling.
8. `test_40_to_44_privacy_pseudonymization_and_isolation`: Project-scoped HMAC, cross-project unlinkability, zero PII leakage.
9. `test_45_to_48_cryptographic_hashes_and_sensitivity`: RFC 8785 JCS, SHA-256 profile digests, mutation sensitivity.
10. `test_49_to_51_finding_and_evidence_synthesis`: `FindingModel`, `EvidenceModel`, non-accusatory language.
11. `test_52_to_54_security_ast_scan_and_offline`: 0 forbidden constructs, 100% air-gapped execution, input immutability.
12. `test_55_cross_phase_compatibility`: Phase 11.2, 11.3, 11.4, 11.5, 11.6, 11.7 integration.
