# PHASE 11.1 — DISTRIBUTION SHIFT & DATA DRIFT ARCHITECTURE SPECIFICATION
## Authoritative Architecture, Requirements, and Operational Semantics for Population Drift Assurance

**Date:** 2026-09-13  
**Project:** AIVARA — AI Verification & Assurance  
**Phase:** 11.1 (Architecture & Requirements Freeze)  
**Parent Phase:** Phase 11 — Distribution Shift / Data Drift Analysis  
**Governing Rule:** Phases 0–10 are PERMANENTLY FROZEN. Zero modifications permitted.

---

## 1. PROBLEM DEFINITION

In multi-contributor, multi-version dataset curation and production computer vision pipelines, changes in data collection environments, sensor equipment, seasonal conditions, and contributor demographics cause the statistical distribution of incoming data to diverge from the baseline training distribution. 

Undetected distribution shift degrades model performance, invalidates baseline safety assumptions, and introduces operational fragility. AIVARA Phase 11 introduces a formal, deterministic, offline, and statistically sound **Distribution Shift / Data Drift Analysis Subsystem** to quantify, attribute, and record distribution discrepancies between trusted reference populations and target datasets.

---

## 2. GOALS

1. **Deterministic Two-Sample Shift Quantification:** Provide rigorous, non-parametric statistical tests (KS, Wasserstein, PSI, MMD, Energy Distance, Chi-Square, TVD) to compare reference and target distributions across 1D continuous, categorical, multi-dimensional visual descriptors, and latent embeddings.
2. **Dual-Gate Decision Framework:** Separate statistical significance (p-values) from practical effect sizes (physical distances / index metrics) to prevent false alerts on large sample sizes.
3. **Multi-Hypothesis Testing Error Control:** Implement Benjamini–Hochberg False Discovery Rate (FDR) and Holm–Bonferroni Family-Wise Error Rate (FWER) corrections across multi-feature test suites.
4. **Unified Finding & Evidence Synthesis:** Seamlessly emit standard `FindingModel` and `EvidenceModel` records without creating duplicate models or database schemas.
5. **Project-Isolated & Offline Execution:** Maintain 100% local, air-gapped execution with strict multi-tenant project boundary enforcement and zero cloud dependencies.

---

## 3. NON-GOALS

1. **No Accusatory Culpability Attribution:** Phase 11 does NOT determine attacker malice, data poisoning intent, or fraudulent intent. Shift is treated purely as objective statistical evidence.
2. **No Dynamic Model Retraining / Adaptation:** Phase 11 is an assurance and auditing system, not an active domain adaptation or automated retraining framework.
3. **No Cloud / Remote API Dependencies:** Phase 11 does not use remote embedding endpoints, cloud telemetry, or third-party web services.
4. **No Premature Detector Implementation in Phase 11.1:** Phase 11.1 freezes requirements and architecture; concrete engines and detectors are implemented in subsequent subphases (Phases 11.2+).

---

## 4. THREAT MODEL SUMMARY

- **Detected Threats:** Covariate shift (lighting, resolution, color), label distribution skew ($P(Y)$), latent representation drift ($P(Z)$), temporal dataset erosion, and contributor-specific distribution anomalies.
- **Evasion Protections:** Multi-modal RKHS kernels (MMD, Energy Distance) defend against moment-matching distribution mimicry. Fixed PRNG seeds eliminate non-deterministic sampling jitter.
- **Fail-Closed Guardrails:** Subsamples below $N_{\text{min}} = 30$ trigger explicit `INSUFFICIENT_DATA` states. Missing reference datasets trigger `UNVERIFIABLE` errors.
- *(Full specification detailed in `docs/PHASE_11_THREAT_MODEL.md`)*.

---

## 5. FORMAL SHIFT TAXONOMY

Phase 11 formalizes the following taxonomy of distribution shifts:

```
                                 DISTRIBUTION SHIFT
                                         │
        ┌────────────────────────────────┼────────────────────────────────┐
        ▼                                ▼                                ▼
 COVARIATE SHIFT                 PRIOR / LABEL SHIFT             LATENT / EMBEDDING SHIFT
  (Input P(X))                      (Labels P(Y))                 (Representation P(Z))
   ├── Photometric (Color/Luminance) ├── Class Proportions         ├── Kernel MMD in RKHS
   ├── Geometric (Aspect/Size)       ├── Missing / New Classes     └── Energy Distance
   └── Frequency (Sharpness/Texture) └── Contributor Label Bias
```

### Shift Types & Supported Modalities for AIVARA v1:
1. **`COVARIATE_IMAGE_SHIFT`**: Continuous photometric (RGB/HSV histograms, luminance, saturation, contrast) and geometric (resolution, aspect ratio) divergence.
2. **`LABEL_DISTRIBUTION_SHIFT`**: Categorical shifts in class frequencies, class disappearance, or unexpected class emergence evaluated via Chi-Square and Total Variation Distance (TVD).
3. **`EMBEDDING_REPRESENTATION_SHIFT`**: Latent feature vector divergence extracted from local, verified models evaluated via Maximum Mean Discrepancy (MMD) and Energy Distance.
4. **`CONTRIBUTOR_SCOPED_SHIFT`**: Evaluating whether a specific contributor's submitted subset deviates materially from the global project baseline.
5. **`DATASET_VERSION_SHIFT`**: Longitudinal drift trajectory between sequential dataset versions ($V_n \to V_{n+1}$).

---

## 6. REFERENCE DISTRIBUTION MODEL

A reference distribution represents the **trusted baseline population**. The architecture enforces:
1. **Explicit Selection:** The caller or project configuration must explicitly specify `reference_dataset_id` or `reference_dataset_version_id`. The system NEVER guesses or silently chooses an arbitrary default dataset.
2. **Immutability & Integrity:** The reference dataset must possess a verified cryptographic hash (`dataset_hash`) and reside in the same `project_id`.
3. **Pre-computed Baseline Profiles:** To optimize multi-target comparisons, computed reference feature distributions may be cached as deterministic baseline artifacts linked by reference version hash.

---

## 7. TARGET DISTRIBUTION MODEL

The target distribution represents the **evaluated population**. The architecture supports:
1. **Full Target Dataset / Version:** Auditing an entire newly ingested dataset version ($V_{\text{target}}$) against $V_{\text{ref}}$.
2. **Sample Subsets / Batches:** Auditing a specific batch (`batch_id`) or contributor submission (`contributor_id`) against $V_{\text{ref}}$.
3. **Inference Input Buffers:** Comparing recent operational inference inputs against training baselines.

---

## 8. STATISTICAL METHODOLOGY

| Modality / Target | Primary Statistical Test | Effect Size Metric | Decision Policy |
| :--- | :--- | :--- | :--- |
| **Continuous 1D Features** | Two-Sample Kolmogorov–Smirnov (KS) | 1D Wasserstein Distance ($W_1$), Population Stability Index (PSI) | $p < \alpha_{\text{FDR}}$ AND ($W_1 > \theta_W$ OR $\text{PSI} \ge 0.10$) |
| **Categorical / Label Proportions** | Chi-Square ($\chi^2$) Goodness-of-Fit | Total Variation Distance (TVD), Jensen–Shannon Divergence (JSD) | $p < \alpha$ AND ($\text{TVD} > 0.05$ OR $\text{JSD} > 0.02$) |
| **High-Dimensional Descriptors** | Kernel Maximum Mean Discrepancy (MMD) with Permutation Null | Empirical MMD Distance ($\text{MMD}^2$) | $p_{\text{perm}} < 0.05$ AND $\text{MMD} > 0.02$ |
| **Multivariate Metric Spaces** | Energy Distance | Non-parametric Energy Statistic | $p_{\text{perm}} < 0.05$ AND $\text{Energy} > 1.0$ |

---

## 9. MULTIPLE HYPOTHESIS TESTING CORRECTION

When testing $K$ distinct feature dimensions:
- **Default Feature-Level Correction:** Benjamini–Hochberg (BH) procedure controlling False Discovery Rate at $q^* = 0.05$.
- **Conservative Family-Level Correction:** Holm–Bonferroni step-down procedure controlling Family-Wise Error Rate at $\alpha = 0.05$ when declaring a global dataset alert.
- **Reporting Invariant:** Both raw p-values and adjusted p-values are preserved in `EvidenceModel.data_json`.

---

## 10. EFFECT SIZE POLICY

To eliminate the sample-size dependency of raw p-values:
- **Continuous Features:** Report standardized Wasserstein distance $\frac{W_1}{\sigma_{\text{ref}}}$ and PSI.
- **Categorical Distributions:** Report TVD $\in [0, 1]$ (maximum percentage class shift).
- **Latent Vectors:** Report empirical MMD and Energy statistics.
- **Materiality Thresholds:**
  - $\text{PSI} < 0.10$: Minor / Negligible Shift
  - $0.10 \le \text{PSI} < 0.25$: Moderate Shift
  - $\text{PSI} \ge 0.25$: Material / Significant Shift

---

## 11. SAMPLE SIZE & POWER POLICY

- **Minimum Threshold:** $N_{\text{ref}} \ge 30$ and $N_{\text{target}} \ge 30$.
- **Insufficiency Transition:** If either sample size is $< 30$, the status is set to `INSUFFICIENT_DATA`.
- **Subsampling Upper Bound:** If $N > 5,000$, deterministic random subsampling with seed derived from $\text{SHA-256}(\text{dataset\_id})$ is applied to cap pairwise kernel computations.

---

## 12. IMAGE ANALYSIS SCOPE

Image feature extraction operates entirely offline using deterministic local transforms:
1. **Color & Photometrics:** Mean, variance, skewness of R, G, B and H, S, V channels.
2. **Luminance & Contrast:** Grayscale histogram (32 bins), dynamic range, RMS contrast.
3. **Geometry:** Width, height, aspect ratio distribution.
4. **Spatial Frequency:** Laplacian variance (blur detection), gradient edge density.

---

## 13. EMBEDDING ANALYSIS SCOPE

1. **Local Model Extraction:** Latent feature embeddings are generated solely via locally registered, verified models (`AIModelModel`).
2. **Fallback Behavior:** If no local model is available or embedding extraction is disabled in configuration, the system returns `UNAVAILABLE` for embedding drift while executing image/label drift normally.

---

## 14. TEMPORAL & VERSION TRAJECTORY SCOPE

1. **Version-to-Version Drift:** Evaluates $V_1 \to V_2 \to \dots \to V_n$ sequentially, tracking cumulative drift distance relative to $V_1$ and incremental drift relative to $V_{n-1}$.
2. **Window-Based Ingestion:** Audits chronological ingestion batches partitioned by creation timestamps.

---

## 15. CONTRIBUTOR-SCOPED ANALYSIS SCOPE

1. **Contributor Profile:** Compares individual contributor sample contributions ($S_c$) against the remaining population ($S_{\neg c}$).
2. **Strict Evidence Framing:** Results are recorded as `contributor_distribution_evidence` without accusatory conclusions regarding contributor intent.

---

## 16. DATASET VERSION COMPARISON SCOPE

Integrates directly with `DatasetVersionModel`. Analyzes sample additions, sample deletions, class balance shifts, and feature drift between any two specified version IDs in a project.

---

## 17. EVIDENCE MODEL INTEGRATION

- **Model Reused:** Existing `EvidenceModel` (SQLAlchemy) and `EvidenceCreate` / `EvidenceRead` (Pydantic).
- **`evidence_layer`**: `"detection"` (ADR-028).
- **`evidence_type`**: `"statistical_drift_evidence"`.
- **`data_json` Payload:** Contains test statistics, p-values, corrected p-values, effect sizes, sample counts, and affected dimension lists.

---

## 18. FINDING MODEL INTEGRATION

- **Model Reused:** Existing `FindingModel` (SQLAlchemy) and `FindingCreate` / `FindingRead` (Pydantic).
- **`finding_type`**: `"distribution_shift"`.
- **`affected_asset_type`**: `"dataset"` or `"dataset_version"`.
- **`severity` Mapping:**
  - `INFO`: Negligible shift ($\text{PSI} < 0.10$).
  - `LOW` / `MEDIUM`: Moderate shift ($0.10 \le \text{PSI} < 0.25$).
  - `HIGH`: Material shift ($\text{PSI} \ge 0.25$ on critical features).
  - `CRITICAL`: Severe class disappearance or pervasive multi-modal shift.
- **`confidence`**: Calibrated statistical confidence $\in [0.5, 1.0)$ reflecting sample power and test significance.

---

## 19. RISK INTEGRATION

Findings automatically flow into `orchestration_service.py` and `RiskAssessmentModel`. High-severity material shifts contribute to overall dataset and project risk scores.

---

## 20. PROVENANCE INTEGRATION

Upon completion of an analysis run, a `ProvenanceRecordModel` entry is committed:
- `action`: `"ANALYZE_DISTRIBUTION_SHIFT"`.
- `target_type`: `"dataset_version"`.
- `input_hash`: SHA-256 digest of reference and target dataset hashes + configuration.
- `output_hash`: SHA-256 digest of generated analysis results.

---

## 21. SECURITY BOUNDARIES

- **100% Air-Gapped:** Zero external HTTP/network calls.
- **Safe Execution:** Zero `eval`, `exec`, `pickle`, `subprocess`, `os.system`.
- **Sandboxed Paths:** Strict project root boundary checks.

---

## 22. RESOURCE LIMITS

- `max_samples_evaluated`: 5,000 per distribution (subsampled deterministically if larger).
- `max_features_evaluated`: 4,096.
- `max_permutations`: 100 default (maximum 1,000).
- `task_timeout_seconds`: 300 seconds.

---

## 23. API BOUNDARY

Future Phase 11 REST endpoints will be located at:
- `POST /api/v1/projects/{project_id}/distribution-shift/evaluate`
- `GET /api/v1/projects/{project_id}/distribution-shift/tasks/{task_id}`
- `GET /api/v1/projects/{project_id}/distribution-shift/tasks/{task_id}/events` (SSE)
- `GET /api/v1/projects/{project_id}/distribution-shift/versions/{version_id}/summary`

All responses wrapped in standard `ApiResponse[T]`.

---

## 24. DATABASE DECISION

**Zero Database Schema Changes**. No new tables, columns, migrations, or indexes. All data is persisted in existing tables (`datasets`, `dataset_versions`, `samples`, `findings`, `evidence`, `provenance_records`, `audit_events`).

---

## 25. UI BOUNDARY (FUTURE REQUIREMENTS)

The eventual dashboard will display:
- Reference Baseline Identifier vs. Target Population Identifier.
- Global Shift Status Badge (`NO_SHIFT_DETECTED`, `MODERATE_SHIFT`, `MATERIAL_SHIFT`, `INSUFFICIENT_DATA`).
- Interactive Feature Divergence Table (Feature Name, KS Statistic, Wasserstein Distance, PSI, Raw p-value, Corrected p-value).
- Class Proportion Comparison Bar Charts ($P_{\text{ref}}(Y)$ vs $P_{\text{target}}(Y)$).
- Non-accusatory explanatory summary.

---

## 26. FAILURE MODES & HANDLING

1. `REFERENCE_NOT_FOUND` $\to$ Returns 404 / `INVALID_REFERENCE_ERROR`.
2. `PROJECT_MISMATCH` $\to$ Fails closed with `CrossProjectContaminationError`.
3. `INSUFFICIENT_SAMPLE_SIZE` $\to$ Returns `status="INSUFFICIENT_DATA"`.
4. `NON_FINITE_FEATURES` $\to$ Traps and cleans NaNs; logs numerical warning.
5. `TASK_CANCELLED` $\to$ Cooperative cancellation halts loop, persists `CANCELLED` status.

---

## 27. KNOWN LIMITATIONS

1. **Unlabeled Target Data:** Label distribution shift ($P(Y)$) cannot be computed when target data is unannotated.
2. **Subsampling Approximations:** Datasets $> 5,000$ samples use deterministic subsampling; extreme tail anomalies may be diluted.
3. **Local Embedding Speed:** High-dimensional embedding extraction on CPU is compute-intensive; GPU acceleration or pre-extracted embeddings are supported when available.

---

## 28. FUTURE EXTENSIONS

- Support for pre-computed offline reference feature registries.
- Support for spatio-temporal video trajectory shift.
- Dynamic feature importance weighting based on downstream model sensitivity.
