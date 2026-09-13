# PHASE 11.2 — REFERENCE & TARGET DISTRIBUTION BOUNDARY SPECIFICATION
## Authoritative Population Boundaries, Compatibility Verification, and Canonical Comparison Contracts

**Date:** 2026-09-13  
**Project:** AIVARA — AI Verification & Assurance  
**Phase:** 11.2 (Reference & Target Distribution Boundary)  
**Parent Phase:** Phase 11 — Distribution Shift / Data Drift Analysis  
**Governing Rule:** Phases 0–10 and Phase 11.1 are PERMANENTLY FROZEN. Zero modifications permitted.

---

## 1. REFERENCE DISTRIBUTION SEMANTICS

The reference distribution represents the **authoritative, trusted baseline population** against which future statistical drift evaluations are conducted.

- **Explicit Identification:** Must be explicitly declared via `reference_dataset_id` (and optional `reference_dataset_version_id`). Arbitrary, dynamic, or heuristic selection of default datasets is strictly prohibited.
- **Auditable Provenance:** The reference dataset must exist within the project tenant and be anchored by a verified cryptographic content hash (`dataset_hash`).
- **Population Subsets:** A reference population may encompass a complete dataset, an explicit dataset version, or a filtered subset (by contributor, temporal window, or class whitelist).

---

## 2. TARGET DISTRIBUTION SEMANTICS

The target distribution represents the **population under audit**.

- **Explicit Declaration:** Declared via `target_dataset_id` (and optional `target_dataset_version_id`).
- **Flexible Scope:** Supports whole-dataset comparisons, version transitions ($V_n \to V_{n+1}$), ingestion batches, contributor-specific submissions, or explicit sample lists.
- **Reproducibility:** Selection parameters are serialized into immutable descriptors, ensuring identical population extraction across multiple runs.

---

## 3. DATASET IDENTITY & VERSIONING BOUNDARY

- Reuses existing Phase 5 dataset identity schemas without modification.
- Evaluates comparisons across:
  1. `Dataset A (Version 1)` vs `Dataset A (Version 2)` (Longitudinal version drift)
  2. `Dataset A (Version 1)` vs `Dataset B (Version 1)` (Cross-dataset population drift)
  3. `Dataset A (Contributor 1)` vs `Dataset A (Contributor 2)` (Contributor-scoped drift)

---

## 4. POPULATION SELECTION & FILTERING

The `PopulationSelector` descriptor supports five deterministic selection modes:
1. `COMPLETE_DATASET`: Encompasses all valid sample records within the dataset.
2. `DATASET_VERSION`: Filters sample records bound to a specific `dataset_version_id`.
3. `CONTRIBUTOR_SUBSET`: Filters samples contributed by `contributor_id`.
4. `TEMPORAL_WINDOW`: Filters samples within `[time_start, time_end]` ISO 8601 UTC timestamps.
5. `CLASS_SUBSET`: Filters samples whose annotated label matches a sorted `class_filter` whitelist.
6. `EXPLICIT_SAMPLES`: Selects exact sample records matching a unique `sample_ids` list.

---

## 5. DETERMINISTIC SAMPLING & SUBSAMPLING BUDGET

To guarantee $O(1)$ upper-bounded memory and CPU latency during quadratic kernel calculations ($O((N+M)^2)$):
- **Maximum Sample Budget ($N_{\text{max}} = 5,000$):** If a filtered population exceeds 5,000 samples, deterministic subsampling is applied.
- **Seeded Subsampling (`DETERMINISTIC_SEEDED`):** Uses `np.random.RandomState(seed)` over sorted sample IDs to ensure bitwise reproducible subset selection.
- **Hash Ranking Subsampling (`HASH_RANKING`):** Computes $\text{SHA-256}(\text{sample\_id} + \text{salt})$ and sorts lexicographically, selecting the top $K$ samples.
- **Uncontrolled Randomness Forbidden:** The exact seed, method, and selected sample ID hash are immutably sealed in the comparison contract.

---

## 6. SAMPLE SIZE BOUNDARIES ($N_{\text{min}} = 30$)

- **Minimum Floor:** $N_{\text{ref}} \ge 30$ and $N_{\text{target}} \ge 30$.
- **Insufficiency State:** If either population yields $< 30$ samples, the comparison boundary status transitions fail-closed to `INSUFFICIENT_DATA`.
- **Diagnostic Findings:** Emits `insufficient_reference_population` or `insufficient_target_population` finding with severity `medium`.

---

## 7. COMPATIBILITY VALIDATION

Before statistical testing, reference and target representations must be validated for structural compatibility:

### 7.1 Tabular / Numeric Feature Compatibility
- **Dimension Check:** $D_{\text{ref}} == D_{\text{target}} \le 4096$. Mismatch $\to$ `INCOMPATIBLE_DIMENSIONS`.
- **Feature Name Check:** Exact set equality of feature names. Mismatch $\to$ `INCOMPATIBLE_SCHEMA`.
- **Data Type Check:** Mismatched column types (e.g. float vs string) $\to$ `INCOMPATIBLE_SCHEMA`.

### 7.2 Label Vocabulary Compatibility
- **Format Match:** Both must use identical annotation schemas (e.g. `classification`, `detection`).
- **Vocabulary Check:** If target contains classes not present in reference, status transitions to `UNSEEN_CLASSES_PRESENT` and emits a warning finding, but permits analysis.

### 7.3 Image Format Compatibility
- **Channels & Color Space:** Verifies matching channel counts (e.g. 3 vs 3) and color spaces (e.g. RGB vs RGB). Mismatch $\to$ `INCOMPATIBLE_MODALITY`.

### 7.4 Latent Representation Compatibility
- **Model Binding:** If modality is `LATENT_EMBEDDING`, verifies matching embedding dimensions and model identifiers (`model_id`). Embeddings from different models cannot be compared $\to$ `INCOMPATIBLE_REPRESENTATION`.

---

## 8. CANONICAL COMPARISON CONTRACT & BOUNDARY HASH

The comparison boundary is serialized into an immutable `ComparisonContract` containing 18 canonical fields:
```json
{
  "analysis_version": "1.0",
  "feature_descriptor_hash": "<hash_or_empty>",
  "label_descriptor_hash": "<hash_or_empty>",
  "max_samples_budget": 5000,
  "modality": "image",
  "project_id": "proj_01",
  "reference_dataset_id": "ds_ref",
  "reference_dataset_version_id": "v1",
  "reference_population_hash": "<hash>",
  "reference_sample_count": 50,
  "representation_descriptor_hash": "<hash_or_empty>",
  "resource_policy_version": "1.0",
  "sampling_method": "none",
  "sampling_seed": -1,
  "schema_version": "1.0",
  "target_dataset_id": "ds_target",
  "target_dataset_version_id": "v2",
  "target_population_hash": "<hash>",
  "target_sample_count": 60
}
```

$$\text{comparison\_boundary\_hash} = \text{SHA-256}(\text{RFC8785\_JCS}(\text{canonical\_dict}))$$

- **Mutation Coverage:** Mutating any single field alters the `comparison_boundary_hash` (100% verified).

---

## 9. POPULATION IDENTITY HASHES

Each resolved population derives two cryptographic digests:
1. `sample_ids_hash`: SHA-256 over sorted selected sample ID strings.
2. `population_selection_hash`: SHA-256 over canonical descriptor of dataset ID, version ID, selector criteria, sample counts, and `sample_ids_hash`.

---

## 10. FINDING & EVIDENCE INTEGRATION

- **Reused Entities:** Existing `FindingModel` and `EvidenceModel` (ADR-028).
- **Finding Types Emitted by Boundary:**
  - `insufficient_reference_population` (Severity: Medium)
  - `insufficient_target_population` (Severity: Medium)
  - `unseen_classes_detected` (Severity: Low)
  - `incompatible_schema_detected` (Severity: High)
- **Zero Schema Changes:** 0 new database tables or columns.

---

## 11. SECURITY & RESOURCE BOUNDARIES

- **100% Air-Gapped & Offline:** Zero external network calls.
- **Path Sandboxing:** Relative path normalization rejects directory traversal (`..`), UNC paths, and Windows drive escapes via `aivara.dataset.path_security`.
- **Numerical Sanitization:** NaN and $\pm\infty$ rejected during RFC 8785 canonical serialization.
- **Dimension Ceiling:** Maximum feature dimensionality $D \le 4096$.
- **Population Cap:** Maximum pre-filtered pool $N \le 1,000,000$.

---

## 12. KNOWN LIMITATIONS

1. **Unlabeled Target Annotations:** Label compatibility checks cannot run if target sample records omit `label_json`.
2. **Subsampling Tail Approximations:** Bounding datasets to $N=5000$ guarantees $O(1)$ latency but may dilute microscopic single-sample outlier clusters.
