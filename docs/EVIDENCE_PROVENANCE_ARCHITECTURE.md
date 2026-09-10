# AIVARA — Evidence + Provenance Architecture Specification
## Phase 5.9.1: Architecture Review & Design Freeze

**Version:** 1.0.0-draft  
**Status:** DESIGN FROZEN (Implementation Not Started)  
**Security Classification:** Local / Air-Gapped Assurance Engine  
**Target Sub-System:** Phase 5.9 — Evidence Generation & Provenance Ledger Integration  

---

## 1. Executive Summary & Purpose

The **Evidence & Provenance Architecture** establishes the binding bridge in AIVARA connecting statistical, machine learning, computer vision, and anomaly detection results (the **Detection Layer**) to tamper-evident, verifiable cryptographic commitments and audit trails (the **Proof Layer**).

AIVARA operates on the authoritative project pipeline:
```
EVIDENCE → FINDING → CONFIDENCE → RISK → DECISION
```

Phase 5.9 is responsible exclusively for the initial stage:
```
EVIDENCE → FINDING (bound to Cryptographic Provenance)
```

The primary objective of Phase 5.9 is to ensure that every analytical result emitted by Phase 5 detection components (ingestion, fingerprinting, Merkle verification, near-duplicate detection, label anomaly scoring, targeted label-flipping analysis, out-of-distribution distance, image quality degradation, and contributor aggregation) can be deterministically reproduced, uniquely identified, cross-referenced across dataset/sample/contributor/model entities, and verified against the Phase 4 cryptographic provenance ledger without violating architectural boundaries or conflating detection evidence with cryptographic proof.

---

## 2. Foundational Semantic Safety Invariants

This architecture strictly enforces eight foundational semantic safety invariants:

| # | Invariant | Architectural Enforcement |
| :--- | :--- | :--- |
| **I1** | **Evidence $\ne$ Finding** | Evidence represents raw, unaggregated, objective analytical measurements or observations (e.g., Tenengrad sharpness = 12.4, OOD $k\text{NN}$ distance = 4.82). A Finding represents a structured, context-aware assurance observation derived from one or more evidence items (e.g., sample exhibits elevated blur anomaly). |
| **I2** | **Detection Evidence $\ne$ Cryptographic Proof** | Analytical/statistical evidence is classified under `evidence_layer="detection"`. Cryptographic signatures, hash chain continuity, Merkle inclusion proofs, and tamper checks are classified under `evidence_layer="proof"`. Detection evidence does NOT become proof merely because it is hashed or committed to a ledger. |
| **I3** | **Cryptographic Authenticity $\ne$ Analytical Correctness** | A valid Ed25519 signature or untampered provenance record proves only that the record was authored by an authorized key and has not been altered in transit/storage. It does NOT prove that the underlying ML detector's classification or statistical test is objectively true or free of bias. |
| **I4** | **Statistical Association $\ne$ Causation** | Elevated anomaly rates associated with a contributor, class, or sensor batch represent statistical correlations. They do not prove that the entity caused the anomaly or acted intentionally. |
| **I5** | **Anomaly $\ne$ Maliciousness** | Anomalous data points, label discrepancies, OOD shifts, and duplicate clusters are neutral observations. They may result from sensor noise, lighting variations, edge cases, domain divergence, or annotator guidelines. The terms `malicious`, `sabotage`, `poisoning`, `fraud`, `attacker`, and `intent` are strictly forbidden in Phase 5 findings. |
| **I6** | **Evidence Diversity $\ne$ Evidence Independence** | Multiple observations across correlated modalities (e.g., an image with low sharpness, underexposure, and high noise) do not constitute independent proofs of defect. Correlated signals must be explicitly grouped and contextualized. |
| **I7** | **Multiple Observations $\ne$ Composite Risk Score** | Phase 5.9 binds and structures evidence for consumption by downstream engines. It strictly PROHIBITS computing composite risk formulas (e.g., $\text{Risk} = \sum w_i e_i$ or $\text{Threat} = \text{Count} \times \text{Severity}$). Holistic risk scoring and decisioning belong exclusively to **Phase 12 (Evidence + Risk Engine)**. (Phase 8 provides Behavioural Analysis evidence, not risk decisioning). |
| **I8** | **Contributor Evidence $\ne$ Contributor Guilt** | High anomaly concentrations attributed to a contributor represent exposure-normalized empirical measurements. They must never be phrased as accusations of wrongdoing or culpability. |

---

## 3. Scope & Non-Goals

### 3.1 In-Scope Capabilities
1. **Deterministic Evidence Identity:** Canonical RFC 8785 (JCS) serialization and SHA-256 evidence hashing across all Phase 5 analytical outputs.
2. **Finding Synthesis & Evidence Binding:** Relational and cryptographic binding between `FindingModel` and `EvidenceModel` (formalized conceptually as an $N:M$ relationship).
3. **Multi-Entity Provenance Tracing:** Bidirectional traceability connecting findings and evidence to `DatasetVersion`, `Sample`, `Annotation`, `Contributor`, `AIModel`, `ModelFingerprint`, `InferenceRecord`, and `ProvenanceRecord`.
4. **Dataset Fingerprint Binding:** Cryptographic binding of analytical results to specific dataset manifest hashes and Merkle roots.
5. **Model & Reference Distribution Binding:** Cryptographic binding of model-dependent detections to model hashes, weight fingerprints, and reference dataset digests.
6. **Configuration & Version Lineage:** Immutable recording of detector configurations, algorithm versions, thresholds, and policy parameters required for full scan reproducibility.
7. **Audit & Provenance Ledger Integration:** Recording structured `EVIDENCE_GENERATED`, `FINDING_GENERATED`, and `PROVENANCE_BOUND` events into the Phase 4 hash-linked audit chain and Ed25519-signed provenance ledger.
8. **Explicit Degradation & Provenance States:** Structured handling of missing, incomplete, unverified, or mismatched provenance without false assertions.

### 3.2 Explicit Non-Goals
1. **Risk Scoring & Decisioning:** No calculation of project/dataset risk scores, risk levels, or disposition determinations (`ACCEPT`, `REVIEW`, `QUARANTINE`). Risk scoring is reserved exclusively for **Phase 12 (Evidence + Risk Engine)**.
2. **Database Schema Alterations:** Zero migrations, table creations, or column modifications. All bindings utilize existing Phase 3 schema fields and JSON structures.
3. **Cryptographic Engine Modification:** Phase 4 (`backend/aivara/crypto/`) remains completely frozen. Phase 5.9 consumes existing crypto APIs as a client.
4. **Online Services & Remote Calls:** Zero telemetry, cloud vision APIs, or external key management calls. Phase 5.9 operates 100% offline.
5. **Data/Model Mutation:** Analysis and evidence generation are strictly read-only and non-destructive.

---

## 4. Detection Layer vs. Proof Layer Separation

AIVARA strictly maintains the two-layer assurance model defined in ADR-028:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           AIVARA ASSURANCE ARCHITECTURE                 │
├────────────────────────────────────┬────────────────────────────────────┤
│          DETECTION LAYER           │            PROOF LAYER             │
│       (evidence_layer="detection") │        (evidence_layer="proof")    │
├────────────────────────────────────┼────────────────────────────────────┤
│ • Statistical anomaly scores       │ • RFC 8785 Canonical hashes        │
│ • Computer vision quality metrics  │ • SHA-256 Merkle root integrity    │
│ • Confident learning noise scores  │ • Ed25519 digital signatures       │
│ • OOD distance metrics (kNN / MAD) │ • Hash-linked provenance chain     │
│ • Contributor rate differentials   │ • Tamper-evident audit ledger      │
│ • Near-duplicate Hamming distances │ • Genesis nonce & sequence checks  │
├────────────────────────────────────┼────────────────────────────────────┤
│ Confidence: Empirical [0.0, 1.0)   │ Confidence: Exactly 1.0 (ADR-028)  │
│ Truth: Probabilistic / Statistical │ Truth: Cryptographic / Deterministic│
└────────────────────────────────────┴────────────────────────────────────┘
```

### 4.1 Cross-Layer Interaction Rules
1. A detection-layer finding must NEVER have `evidence_layer="proof"`.
2. A proof-layer finding must NEVER have `confidence < 1.0` (enforced by Pydantic model validator).
3. Hashing or signing a detection-layer evidence item does NOT promote it to `evidence_layer="proof"`. The signed record is a proof of *record authorship and integrity*, while the evidence inside remains a detection.
4. If a proof-layer check fails (e.g., Merkle inclusion mismatch, signature invalidity), the resulting finding is classified under `evidence_layer="proof"` with `severity="critical"` and `confidence=1.0`.

---

## 5. Evidence Identity & Canonical Hashing

### 5.1 Evidence Determinism
An analytical evidence item must have a deterministic, content-derived identity. Generating the same evidence from the same dataset version, detector configuration, and model must yield an identical `evidence_hash`.

### 5.2 Deterministic Evidence Payload (`EvidenceContent`)
The hashable content of an evidence item consists of strictly deterministic fields:

```json
{
  "evidence_layer": "detection",
  "evidence_type": "label_anomaly_confident_learning",
  "project_id": "proj-uuid-1234",
  "dataset_version_id": "ds-ver-uuid-5678",
  "dataset_fingerprint": "a3f5e1...64hex",
  "target_asset_type": "sample",
  "target_asset_id": "sample-uuid-9012",
  "target_asset_hash": "c8b2d4...64hex",
  "detector_id": "die_label_anomaly",
  "detector_version": "1.0.0",
  "detector_config_hash": "e91c7a...64hex",
  "model_fingerprint": "3d81b9...64hex",
  "reference_fingerprint": "NONE",
  "measurements": {
    "given_label": 3,
    "predicted_label": 7,
    "label_issue_score": 0.8742,
    "normalized_margin": -0.612,
    "joint_prob": 0.0412
  }
}
```

### 5.3 Excluded Non-Deterministic Fields
The following fields are strictly EXCLUDED from the `evidence_hash` computation:
- Database primary keys (`id` / UUIDv4 generated at insert time)
- Wall-clock timestamps (`created_at`, `updated_at`, scan start/end time)
- Local filesystem paths (`artifact_path`, file system directories)
- In-memory object pointers or runtime thread IDs
- Ephemeral execution run IDs

### 5.4 Hashing Boundary Specification
Evidence hashing directly leverages the frozen Phase 4 cryptographic engine:
$$\text{EvidenceHash} = \text{SHA256}(\text{JCS\_RFC8785}(\text{EvidenceContent}))$$

Using `aivara.crypto.canonical.canonical_json` and `aivara.crypto.hashing.sha256_canonical_json`. No custom or duplicate hashing routines are permitted.

---

## 6. Evidence Types & Granularities

Phase 5.9 supports 9 distinct evidence types across varying granularities:

| Evidence Type | Originating Engine | Granularity | Key Measurements / Data Payload |
| :--- | :--- | :--- | :--- |
| `dataset_fingerprint_manifest` | Phase 5.3 | Dataset-level | Manifest SHA-256, sample count, format, class list, partition digest. |
| `merkle_inclusion_proof` | Phase 5.3 | Sample / Tree | Merkle root, leaf index, leaf hash, audit path hashes, verification status. |
| `near_duplicate_relationship` | Phase 5.4 | Pair / Cluster | Query hash, match hash, Hamming distance, normalized similarity, match type. |
| `label_anomaly_score` | Phase 5.5 | Sample / Annotation | Given label, predicted label, noise score, margin, self-confidence. |
| `label_flipping_transition` | Phase 5.6 | Class-pair / Aggregate | Source class, target class, transition rate $\hat{T}_{ij}$, baseline rate, Fisher p-value. |
| `image_quality_metrics` | Phase 5.7 | Sample-level | Variance of Laplacian (blur), Tenengrad sharpness, exposure clipping, CIELAB color cast, SNR dB, JPEG blockiness. |
| `ood_distance_score` | Phase 5.7 | Sample-level | Feature mode (Tier 1 / Tier 2), $k\text{NN}$ distance, MAD threshold $\tau_{\text{OOD}}$, standardized distance. |
| `distribution_shift_evidence` | Phase 5.7 | Dataset / Split | MMD distance, Energy distance, permutation test p-value, divergence factors. |
| `contributor_aggregation_profile` | Phase 5.8 | Contributor-level | Sample count $n$, anomaly count $k$, Wilson interval $[w^-, w^+]$, rate diff $\Delta$, HHI, diversity count. |

Each evidence type preserves its specific metrics in `data_json`. Evidence is NEVER collapsed into a lossy, single scalar score.

---

## 7. Evidence ↔ Finding Conceptual Cardinality ($N : M$)

### 7.1 Separation of Responsibilities
- **Evidence (`EvidenceModel`):** The immutable, objective data record containing exact mathematical/statistical measurements.
- **Finding (`FindingModel`):** The contextualized assurance observation created when evidence meets or exceeds configured policy criteria.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        RAW EVIDENCE (Immutable)                         │
│ • Sample ID: sample-481                                                 │
│ • Tenengrad Sharpness: 14.2 (Threshold: 50.0)                           │
│ • Laplacian Variance: 8.1 (Threshold: 100.0)                            │
│ • SNR: 11.4 dB (Threshold: 20.0 dB)                                     │
│ • Evidence Hash: 4e7a...                                                │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ triggers
┌────────────────────────────────────▼────────────────────────────────────┐
│                        DERIVED FINDING (Contextualized)                 │
│ • Finding Type: IMAGE_QUALITY_DEGRADATION                               │
│ • Title: "Sample exhibits severe blur and low signal-to-noise ratio"    │
│ • Severity: MEDIUM                                                      │
│ • Confidence: 0.88                                                      │
│ • Evidence Layer: "detection"                                           │
│ • Disposition: REVIEW                                                   │
│ • References: [Evidence ID: ev-101]                                     │
└─────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Conceptual $N:M$ Relationship
The domain relationship between Evidence and Findings is strictly **$N : M$ (Many-to-Many)**:
1. **One Finding $\to$ Many Evidence Items ($1 : N$):** A single composite finding (e.g., `CONTRIBUTOR_MULTI_SIGNAL_EVIDENCE` or `IMAGE_QUALITY_DEGRADATION`) synthesizes multiple underlying evidence items across distinct modalities (e.g., blur metric, underexposure metric, and label noise).
2. **One Evidence Item $\to$ Many Findings ($1 : M$):** A single analytical evidence item (e.g., sample-level image blur evidence) can support multiple findings:
   - Primary: A sample-level `IMAGE_QUALITY_DEGRADATION` finding.
   - Derived / Aggregated: A contributor-level `CONTRIBUTOR_QUALITY_CONCENTRATION` finding.
   - Cross-Cutting: A dataset-level `DISTRIBUTION_SHIFT_WARNING` finding.

### 7.3 Primary vs. Derived Finding Semantics in Phase 3 Schema Compatibility
In the current Phase 3 database schema:
- `EvidenceModel.finding_id` is a foreign key representing the **Primary Originating Finding** (the immediate finding created when the detector first emitted the evidence item).
- **Secondary / Derived Findings** (e.g., contributor aggregates, multi-signal clusters) reference the underlying evidence via deterministic immutable identifiers stored in structured JSON:
  - `FindingModel.metadata_json["referenced_evidence_ids"] = ["ev-uuid-1", "ev-uuid-2"]`
  - `FindingModel.metadata_json["referenced_evidence_hashes"] = ["4e7a...64hex", "9b1c...64hex"]`

### 7.4 Limitations of Metadata-Only Referencing & Future Schema Requirement
- **Documented Limitation:** Representing secondary relationships inside `metadata_json` provides JSON-level traceability and cryptographic hash binding, but lacks relational integrity guarantees (such as database-level `ON DELETE RESTRICT` foreign keys across multiple parent findings or index-accelerated relational joins).
- **Future Schema Requirement (Phase 12 / Future Enhancements):** When full relational graph traversal and risk aggregation are implemented in Phase 12, a dedicated junction entity (`finding_evidence` table linking `finding_id` and `evidence_id`) will be introduced to formalize $N:M$ constraints at the database engine level.
- **Phase 5.9.1 Constraint:** **ZERO database schema modifications are performed in Phase 5.9.1.** The current implementation maintains 100% compatibility with the existing Phase 3 schema.

---

## 8. Finding Semantics & Language Policy

### 8.1 Objective Finding Vocabulary
Findings must use strictly descriptive, objective terminology:
- `ELEVATED_ANOMALY_RATE`
- `POTENTIAL_LABEL_MISMATCH`
- `ASYMMETRIC_CLASS_TRANSITION`
- `ELEVATED_OUT_OF_DISTRIBUTION_DISTANCE`
- `IMAGE_QUALITY_DEGRADATION`
- `NEAR_DUPLICATE_CLUSTER`
- `CONTRIBUTOR_CONCENTRATION_OBSERVED`
- `CRYPTOGRAPHIC_INTEGRITY_VERIFIED`
- `PROVENANCE_SIGNATURE_MISMATCH`

### 8.2 Prohibited Accusatory Vocabulary
The following words are **STRICTLY FORBIDDEN** in all Phase 5 finding titles, descriptions, recommendations, and metadata:
- `malicious`, `malice`, `bad actor`, `adversary`, `attacker`
- `guilty`, `culpable`, `sabotage`, `fraud`, `collusion`
- `poisoning`, `backdoor`, `trojan`, `attack` (unless in reference to an explicit attack benchmark in the test suite)
- `deliberate`, `intentional`, `dishonest`

Any finding violating this vocabulary policy will be rejected during validation.

---

## 9. Confidence Semantics

Confidence in AIVARA is never a single blended scalar. Different layers and detection methods produce distinct, rigorously defined confidence metrics:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          CONFIDENCE TAXONOMY                            │
├──────────────────────────────┬──────────────────────────────────────────┤
│ METRIC TYPE                  │ MATHEMATICAL DEFINITION / SOURCE         │
├──────────────────────────────┼──────────────────────────────────────────┤
│ Cryptographic Proof          │ Exactly 1.0 (Binary: Signature / Merkle) │
│ Statistical Lower Bound      │ 95% Wilson Score Interval Lower Bound w⁻ │
│ Confident Learning Margin    │ Normalized probability difference        │
│ OOD Standardized Distance    │ Standardized MAD distance d_norm         │
│ Image Quality Composite      │ Calibrated quality index in [0.0, 1.0]   │
│ Contributor Rate Certainty   │ Sample support & variance penalty        │
└──────────────────────────────┴──────────────────────────────────────────┘
```

### 9.1 Rules for `Finding.confidence`
1. **Proof-Layer Finding:** `confidence` MUST be exactly `1.0`. Any value other than `1.0` raises a validation error (ADR-028).
2. **Detection-Layer Finding:** `confidence` must be in $[0.0, 1.0)$, reflecting the calibrated detector certainty:
   - For statistical tests: based on $(1 - p\text{-value})$ or empirical lower bounds.
   - For distance metrics: sigmoidal normalization of standardized distance $1 / (1 + e^{-d})$.
   - For small sample support ($n < 5$): confidence capped at $< 0.30$ or finding emitted as `INSUFFICIENT_SUPPORT` with `confidence=0.0`.
3. **No Fabricated Confidence:** If a detector cannot provide a defensible mathematical confidence score, `confidence` defaults to `0.50` with an explicit reason recorded in `metadata_json.confidence_rationale`.

---

## 10. Traceability Graph & Schema Entity Bindings

### 10.1 Complete Traceability Graph

```
                   ┌──────────────────────────────────┐
                   │           ProjectModel           │
                   └─────────────────┬────────────────┘
                                     │ 1:N
                   ┌─────────────────▼────────────────┐
                   │           DatasetModel           │
                   └─────────────────┬────────────────┘
                                     │ 1:N
                   ┌─────────────────▼────────────────┐
                   │        DatasetVersionModel       │◄────────────────────────┐
                   └─────────────────┬────────────────┘                         │
                                     │ 1:N                                      │
                   ┌─────────────────▼────────────────┐                         │
                   │           SampleModel            │                         │
                   └──────┬────────────────────┬──────┘                         │
                          │ 1:N                │ 1:N                            │
     ┌────────────────────▼─────┐        ┌─────▼────────────────────┐           │
     │     AnnotationRecord     │        │ SampleContributorModel   │           │
     └────────────────────┬─────┘        └─────┬────────────────────┘           │
                          │                    │                                │
                          │                    ▼                                │
                          │              ┌──────────────────────────┐           │
                          │              │     ContributorModel     │           │
                          │              └─────┬────────────────────┘           │
                          │                    │                                │
                          └───────────┬────────┘                                │
                                      │ references                              │
                                      ▼                                         │
                          ┌───────────────────────────┐                         │
                          │       EvidenceModel       │                         │
                          └───────────┬───────────────┘                         │
                                      │ N:M (Primary FK + Metadata refs)        │
                          ┌───────────▼───────────────┐                         │
                          │       FindingModel        │                         │
                          └───────────┬───────────────┘                         │
                                      │ committed by                            │
                          ┌───────────▼───────────────┐                         │
                          │   ProvenanceRecordModel   │─────────────────────────┘
                          └───────────┬───────────────┘  binds dataset_hash & Merkle root
                                      │ logged to
                          ┌───────────▼───────────────┐
                          │      AuditEventModel      │
                          └───────────────────────────┘
```

### 10.2 Entity Cardinalities & Foreign Keys

| Parent Entity | Child Entity | Relationship | DB Enforcement | On Delete Policy |
| :--- | :--- | :--- | :--- | :--- |
| `Project` | `Dataset` | $1 : N$ | Foreign Key (`project_id`) | CASCADE |
| `Dataset` | `DatasetVersion` | $1 : N$ | Foreign Key (`dataset_id`) | CASCADE |
| `DatasetVersion` | `Sample` | $1 : N$ | Foreign Key (`dataset_version_id`) | CASCADE |
| `Sample` | `SampleContributor` | $1 : N$ | Foreign Key (`sample_id`) | CASCADE |
| `Contributor` | `SampleContributor` | $1 : N$ | Foreign Key (`contributor_id`) | RESTRICT |
| `Project` | `AIModel` | $1 : N$ | Foreign Key (`project_id`) | CASCADE |
| `AIModel` | `ModelFingerprint` | $1 : N$ | Foreign Key (`model_id`) | CASCADE |
| `Finding` | `Evidence` | $N : M$ | Primary FK (`finding_id`) + JSON refs | RESTRICT |
| `Project` | `Finding` | $1 : N$ | Foreign Key (`project_id`) | RESTRICT |
| `Project` | `ProvenanceRecord` | $1 : N$ | Foreign Key (`project_id`) | RESTRICT |
| `Project` | `AuditEvent` | $1 : N$ | Foreign Key (`project_id`) | RESTRICT |

---

## 11. Provenance Binding Architecture

### 11.1 Provenance Record Role
A `ProvenanceRecordModel` provides an immutable cryptographic seal committing an analytical scan execution, its configuration, and its emitted findings to the Phase 4 hash chain.

```json
{
  "project_id": "proj-uuid-1234",
  "record_type": "DATASET_SCAN_FINDINGS_COMMITTED",
  "actor": "system:die_orchestrator",
  "action": "SEAL_FINDINGS",
  "target_type": "dataset_version",
  "target_id": "ds-ver-uuid-5678",
  "input_hash": "a3f5e1...64hex (dataset_fingerprint)",
  "output_hash": "8c21a4...64hex (merkle_root_of_evidence_hashes)",
  "metadata_json": {
    "audit_run_id": "run-uuid-9999",
    "execution_identity_hash": "f4b2e8...64hex",
    "detector_versions": {
      "die_fingerprinting": "1.0.0",
      "die_duplicates": "1.0.0",
      "die_label_anomaly": "1.0.0",
      "die_label_flipping": "1.0.0",
      "die_ood_quality": "1.0.0",
      "die_contributors": "1.0.0"
    },
    "finding_count": 14,
    "evidence_count": 42,
    "dataset_fingerprint": "a3f5e1...",
    "merkle_root": "b7c2d9...",
    "model_fingerprint": "3d81b9...",
    "scan_config_hash": "e91c7a..."
  },
  "sequence_number": 42,
  "nonce": "9f2c8a...64hex",
  "previous_record_hash": "5d1e4f...64hex",
  "record_hash": "1a2b3c...64hex",
  "signer_key_id": "key-ed25519-01",
  "signature": "304502...base64"
}
```

### 11.2 Verification Separation Invariant
Downstream consumers must strictly maintain:
$$\text{VALID\_SIGNATURE}(\text{ProvenanceRecord}) \ne \text{ANALYTICAL\_ACCURACY}(\text{Evidence})$$
A verified signature confirms non-repudiation, tamper-evidence, and integrity of the execution record. The validity of analytical detection claims is governed by statistical methodology and empirical thresholds.

---

## 12. Dataset Fingerprint & Version Binding

### 12.1 Required Dataset Bindings
Every Phase 5 analytical scan and evidence item must record:
1. `dataset_id`: Relational container ID.
2. `dataset_version_id`: Specific immutable version ID.
3. `dataset_fingerprint`: 64-character SHA-256 manifest hash.
4. `merkle_root`: Canonical Merkle root of all normalized sample hashes.

### 12.2 Anti-Staleness Protection
If a dataset is modified or re-ingested under a new version:
1. The new version receives a distinct `dataset_version_id`, `dataset_fingerprint`, and `merkle_root`.
2. Any query attempting to bind evidence from Version A to Version B will detect a fingerprint mismatch:
   $$\text{dataset\_fingerprint}_{\text{Evidence}} \ne \text{dataset\_fingerprint}_{\text{Version B}} \implies \text{STALE\_VERSION\_REJECTED}$$
3. Evidence is never silently transferred across dataset versions.

---

## 13. Model & Reference Baseline Binding

### 13.1 Model-Dependent Detectors
Certain Phase 5 detectors depend on external reference models or datasets:
- **Label Anomaly Detector:** Uses predicted probability vectors $\hat{\boldsymbol{p}}_i$ from a reference classification model.
- **OOD Feature Extractor:** Uses Tier 2 deep visual embeddings from a frozen model backbone.
- **Drift Detector:** Uses an explicit baseline/reference dataset manifest.

### 13.2 Required Model/Reference Bindings
When a model or reference dataset is used, the evidence must record:
- `model_id`: Relational model identifier.
- `model_fingerprint`: SHA-256 weight/structure digest from `ModelFingerprintModel`.
- `model_version`: Exact model version string.
- `reference_dataset_id`: Identifier of reference baseline dataset (if applicable).
- `reference_fingerprint`: SHA-256 manifest hash of reference dataset.
- `feature_mode`: `TIER1_STATISTICAL` or `TIER2_DEEP_EMBEDDING`.

### 13.3 Unavailable Provenance Handling
If a model has no registered fingerprint:
- `model_fingerprint` is set to `"UNAVAILABLE"`.
- The evidence is flagged with `metadata_json.model_provenance_status = "MISSING_FINGERPRINT"`.
- The engine does NOT crash or hallucinate a synthetic fingerprint.

---

## 14. Configuration & Policy Versioning

### 14.1 Reproducibility Contract
An analytical scan is 100% reproducible if and only if all configuration parameters are preserved. Every scan computes a deterministic `config_hash`:
$$\text{ConfigHash} = \text{SHA256}(\text{JCS\_RFC8785}(\text{NormalizedConfigDict}))$$

### 14.2 Mandatory Config Parameters Recorded
- **Duplicate Detection:** Hamming distance threshold $\tau_{\text{dist}}$, hash algorithm (`phash_64`), indexing method.
- **Label Anomaly:** Confidence threshold $\tau_{\text{margin}}$, cleanlab filter mode, pruning strategy.
- **Label Flipping:** Min support $N_{\text{min}}$, transition differential $\Delta_{\text{thresh}}$, Fisher significance $\alpha$.
- **Image Quality:** Blur threshold, Tenengrad threshold, clipping limits, noise bounds.
- **OOD:** Distance metric ($L_2$ / Cosine), $k$-neighbors, MAD multiplier $c_{\text{MAD}}$, feature mode.
- **Contributor Aggregation:** Min contributor support ($n=5$), Wilson confidence level ($z=1.96$), HHI threshold.

---

## 15. Correlated Evidence & Multi-Signal Handling

### 15.1 Preservation of Orthogonality
Different detectors measure distinct phenomena. For example:
- A blurred image is an **image quality anomaly**.
- A medical image inside a traffic sign dataset is an **OOD anomaly**.
- A mislabeled dog as a cat is a **label anomaly**.

These signals may co-occur on a single sample. Phase 5.9 preserves each evidence item independently:
1. Each evidence item maintains its unique `evidence_type` and numerical metrics.
2. A multi-signal finding (e.g., `SAMPLE_MULTI_ANOMALY`) links to all relevant evidence IDs without summing scores.
3. The count of distinct anomaly types is recorded as `diversity_count`, NOT as an arithmetic threat score.

---

## 16. Missing, Incomplete, and Invalid Provenance States

Phase 5.9 defines an explicit state machine for provenance evaluation:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     PROVENANCE EVALUATION STATES                        │
├─────────────────────────┬───────────────────────────────────────────────┤
│ STATE                   │ MEANING & SYSTEM ACTION                       │
├─────────────────────────┼───────────────────────────────────────────────┤
│ PROVENANCE_VERIFIED     │ Full cryptographic verification passed        │
│ PROVENANCE_UNAVAILABLE  │ No cryptographic ledger entry exists yet      │
│ PROVENANCE_INCOMPLETE   │ Partial records (e.g. unsigned / missing key) │
│ UNKNOWN_FINGERPRINT     │ Asset hash not found in registered database   │
│ FINGERPRINT_MISMATCH    │ Asset modified; observed hash != ledger hash  │
│ SIGNATURE_INVALID       │ Cryptographic signature check failed          │
│ STALE_DATASET_VERSION   │ Evidence references an older dataset version  │
│ MODEL_MISMATCH          │ Model weights altered since scan execution    │
│ CROSS_PROJECT_REJECTED  │ Attempted cross-project asset binding         │
└─────────────────────────┴───────────────────────────────────────────────┘
```

### 16.1 Missing Provenance $\ne$ Tampering
A missing provenance record indicates that cryptographic tracking has not been initialized for the artifact (e.g., ad-hoc developer testing). It does NOT constitute evidence of an adversarial attack or tampering.

---

## 17. Cross-Project & Cross-Dataset Safety

### 17.1 Cross-Project Isolation
- Every database query and binding operation filters strictly by `project_id`.
- The database schema enforces `project_id` foreign keys with `RESTRICT` on deletion.
- Provenance records and audit events verify that `record.project_id == expected_project_id`. Cross-project binding attempts fail immediately with `SecurityError("CROSS_PROJECT_CONTAMINATION")`.

---

## 18. Temporal Consistency & Timestamps

### 18.1 Timestamp Taxonomy
To avoid temporal conflation, AIVARA distinguishes:
- `dataset_created_at`: Original dataset acquisition / file timestamp.
- `model_trained_at`: AI model compilation / export timestamp.
- `scan_executed_at`: Analytical scan run time.
- `provenance_sealed_at`: Cryptographic signing and ledger commitment time.

### 18.2 Monotonicity Policy
- Timestamps are used for human chronological auditing and log ordering.
- Provenance ledger ordering is strictly governed by `sequence_number` (monotonic integer), NOT wall-clock timestamps.
- Clock skew does NOT invalidate cryptographic chain integrity.

---

## 19. Audit Integration & Tamper-Evident Logging

### 19.1 Audited Events in Phase 5.9
The following events are recorded in `AuditEventModel`:
1. `DATASET_SCAN_STARTED`: Scan initialization, target dataset, detector list.
2. `DATASET_SCAN_COMPLETED`: Scan termination, summary counts, execution status.
3. `FINDINGS_COMMITTED`: Batch persistence of synthesized findings.
4. `PROVENANCE_SEALED`: Provenance record signed and linked to hash chain.
5. `PROVENANCE_VERIFIED`: Downstream verification of findings against ledger.

### 19.2 Non-Audited Operations
To prevent audit log bloat and performance degradation:
- Individual loop iterations over samples ($100\text{K}$ samples do NOT emit $100\text{K}$ audit events).
- In-memory intermediate metric calculations.
- Read-only queries and exploratory finding fetches.

---

## 20. Partial-Scan & Detector Failure Semantics

### 20.1 Fault Isolation
Phase 5 detectors execute as independent, modular analysis tasks:
- If `LabelAnomalyDetector` fails (e.g., missing model logits), `ImageQualityDetector` and `NearDuplicateDetector` continue execution.
- Emitted findings from successful detectors are preserved and committed.
- Failed detectors emit a structured `SCAN_EXECUTION_WARNING` finding (`severity="info"`, `finding_type="DETECTOR_EXECUTION_PARTIAL"`).
- The scan is flagged as `status="partial_success"`, never as a false complete scan.

---

## 21. Idempotency & Comprehensive Execution Identity

### 21.1 Foundational Invariant
$$\text{If a change can alter the analytical result, that change MUST participate in execution identity.}$$

A simple string concatenation of four fields is insufficient because two analytically distinct executions could collide if model weights, detector versions, reference datasets, preprocessing logic, or policy thresholds change.

### 21.2 Structured Canonical Execution Identity Payload (`ExecutionIdentityPayload`)
The execution identity is defined as a structured canonical JSON payload containing every input parameter, model dependency, dataset binding, and version that influences analytical detection:

```json
{
  "project_id": "proj-uuid-1234",
  "dataset_version_id": "ds-ver-uuid-5678",
  "dataset_fingerprint": "a3f5e1...64hex",
  "detector_id": "die_label_anomaly",
  "detector_version": "1.0.0",
  "engine_version": "1.0.0",
  "policy_version": "1.0.0",
  "preprocessing_hash": "c7a19d...64hex",
  "model_id": "model-uuid-9012",
  "model_fingerprint": "3d81b9...64hex",
  "model_version": "2.1.0",
  "reference_dataset_id": "ref-ds-uuid-3456",
  "reference_dataset_fingerprint": "8b91c2...64hex",
  "detector_config_hash": "e91c7a...64hex"
}
```

### 21.3 Canonical Serialization & Hashing Boundary
The `execution_identity_hash` is computed using the frozen Phase 4 RFC 8785 canonical serialization and SHA-256 hashing engine:
$$\text{ExecutionIdentityHash} = \text{SHA256}(\text{JCS\_RFC8785}(\text{ExecutionIdentityPayload}))$$

### 21.4 Field Specifications & Optional Detector-Specific Inputs
- **Always Required:** `project_id`, `dataset_version_id`, `dataset_fingerprint`, `detector_id`, `detector_version`, `engine_version`, `detector_config_hash`.
- **Detector-Specific / Optional (Normalized to `"NONE"` when not applicable):**
  - `model_id`, `model_fingerprint`, `model_version`: Mandatory for model-dependent detectors (Label Anomaly, Deep OOD); normalized to `"NONE"` for model-free detectors (Near-Duplicate, Image Quality).
  - `reference_dataset_id`, `reference_dataset_fingerprint`: Mandatory for drift/reference detectors; normalized to `"NONE"` when using internal baselines.
  - `preprocessing_hash`: Mandatory when non-standard image rescaling/normalization is applied; normalized to `"STANDARD_V1"` otherwise.
  - `policy_version`: Mandatory when policy-based pruning rules are active; normalized to `"DEFAULT"` otherwise.
- **Behavior when Required Identity is Unavailable:** If a detector requires a model fingerprint but none is registered, `model_fingerprint` is set to `"UNAVAILABLE"`, and the execution identity deterministically reflects the unverified/fallback mode without collision.

### 21.5 Repeated Execution & Re-Scan Behavior
- **Exact Match (`IDEMPOTENT_HIT`):** When a scan is executed with an identical `ExecutionIdentityHash` matching a prior completed scan:
  - Default Action (`SKIP`): The engine returns existing finding and evidence IDs immediately without redundant compute.
  - Audit Trail: Emits an audit event `SCAN_IDEMPOTENT_HIT` documenting query reuse.
- **Input Perturbation (`NEW_EXECUTION`):** If *any* parameter changes (e.g., threshold adjusted, model weights updated, detector upgraded, dataset version incremented), a distinct `ExecutionIdentityHash` is produced:
  - Prior findings remain intact under their original scan identity.
  - New findings are created under a new `audit_run_id` without cross-execution collision.

---

## 22. Security Boundary & Input Hardening

### 22.1 Untrusted Input Defenses
1. **Path Traversal:** File paths in evidence payloads are validated via `aivara.dataset.path_security` to ensure containment within project root.
2. **Numeric Sanitization:** All floating-point metrics are sanitized; `NaN`, `+Inf`, and `-Inf` are rejected and replaced with `None` or structured error codes.
3. **Unicode Normalization:** String identifiers and category names undergo strict NFC normalization before canonical hashing.
4. **Metadata Size Caps:** `metadata_json` payloads in findings and evidence are bounded to $\le 64\text{ KB}$ to prevent database memory exhaustion.

---

## 23. Performance & Computational Complexity

### 23.1 Target Complexity
Phase 5.9 evidence binding operates with linear computational complexity:
$$\mathcal{O}(E + F + P)$$
where:
- $E$ is total evidence items ($\le 100\text{K}$)
- $F$ is total findings ($\le 10\text{K}$)
- $P$ is provenance records ($\le 10$)

### 23.2 Performance Optimizations
- **Bulk Insertion:** Evidence and finding items are committed in transactional batches ($1\text{K}$ items per batch).
- **Single-Pass Hashing:** Each evidence hash is computed exactly once at creation time.
- **Zero Pairwise Evidence Cross-Products:** Findings reference pre-indexed evidence IDs without $\mathcal{O}(E^2)$ scans.

---

## 24. 100% Offline & Air-Gapped Execution

Phase 5.9 operates with zero external network connectivity:
- All cryptographic keys are loaded from local secure storage.
- All hashing and canonical serialization run in-process on CPU.
- No telemetry, third-party analytics, cloud vision APIs, or remote license checks.

---

## 25. Database Constraints & Schema Compatibility

### 25.1 Zero Database Alterations
Phase 5.9 requires **ZERO database changes**. All necessary entities and fields exist in Phase 3 models:
- `FindingModel`: `evidence_layer`, `severity`, `confidence`, `disposition`, `metadata_json`.
- `EvidenceModel`: `evidence_layer`, `evidence_type`, `data_json`, `artifact_hash`, `evidence_hash`.
- `ProvenanceRecordModel`: `record_type`, `input_hash`, `output_hash`, `signature`, `record_hash`.
- `AuditEventModel`: `event_type`, `event_hash`, `sequence_number`.

---

## 26. Phase 4 Cryptographic Foundation Reuse

Phase 5.9 strictly reuses existing Phase 4 modules without duplication:
- **Canonical Serialization:** `aivara.crypto.canonical.canonical_json`
- **SHA-256 Hashing:** `aivara.crypto.hashing.sha256_canonical_json`
- **Key Management:** `aivara.crypto.keys.KeyManager`
- **Signing & Verification:** `aivara.crypto.signing.Signer`, `aivara.crypto.verification.Verifier`
- **Provenance Chain:** `aivara.crypto.chain.ProvenanceChainEngine`
- **Audit Logging:** `aivara.crypto.audit.AuditLogger`

---

## 27. Answers to the 30 Architectural Review Questions

```
==============================================================================
               AIVARA PHASE 5.9.1 ARCHITECTURAL REVIEW ANSWERS
==============================================================================
```

### 1. What exactly identifies evidence?
Evidence is identified deterministically by its `evidence_hash`, computed as the SHA-256 digest of the canonical RFC 8785 JSON serialization of its immutable core content: `evidence_layer`, `evidence_type`, `project_id`, `dataset_version_id`, `dataset_fingerprint`, `target_asset_type`, `target_asset_id`, `target_asset_hash`, `detector_id`, `detector_version`, `detector_config_hash`, `model_fingerprint`, and exact `measurements`.

### 2. How is evidence hashed?
Using Phase 4's RFC 8785 canonical serialization bridge:
`sha256_canonical_json(canonical_evidence_dict)`.

### 3. Which fields are protected?
All fields defining the analytical measurement, asset identities, detector configurations, model fingerprints, and dataset versions. Database UUIDs, execution timestamps, and local file paths are excluded from the hash to preserve determinism.

### 4. What makes evidence reproducible?
Given the identical dataset fingerprint, sample content hash, model fingerprint, detector version, and detector configuration parameters, the generated evidence payload and `evidence_hash` are bit-for-bit identical across any execution environment.

### 5. How does evidence reference a sample?
Through `target_asset_type="sample"`, `target_asset_id=Sample.id`, `target_asset_hash=Sample.file_hash_sha256`, and embedded sample references in `data_json`.

### 6. How does evidence reference an annotation?
Through `target_asset_type="annotation"`, `target_asset_id=Annotation.id` (or bounding box index), and canonical annotation hash in `data_json.annotation_hash`.

### 7. How does evidence reference a contributor?
Through `data_json.contributor_id`, `data_json.contributor_external_id`, and exact fractional attribution weight $w_{s,c} = 1/K$ established by Phase 5.8.

### 8. How does evidence reference a model?
Through `model_id`, `model_version`, and `model_fingerprint` (SHA-256 weight/structure digest) recorded in `data_json`.

### 9. How does evidence reference a reference dataset?
Through `data_json.reference_dataset_id` and `data_json.reference_fingerprint` (SHA-256 manifest digest of the baseline dataset).

### 10. How does evidence reference configuration?
Through `detector_config_hash` in the evidence header and the full dictionary of applied thresholds, distance metrics, and hyperparameters stored in `data_json.config`.

### 11. How does a finding reference evidence?
Via the primary relational foreign key `EvidenceModel.finding_id = FindingModel.id` for originating evidence, plus structured lists `metadata_json.referenced_evidence_ids` and `metadata_json.referenced_evidence_hashes` for multi-signal / derived findings.

### 12. Can one finding reference multiple evidence items?
Yes. Composite findings (e.g., `CONTRIBUTOR_MULTI_SIGNAL_EVIDENCE` or `IMAGE_QUALITY_DEGRADATION` combining blur, exposure, and noise) link to multiple underlying `EvidenceModel` rows, formalizing the $N:M$ conceptual model.

### 13. Can one evidence item support multiple findings?
Yes. An evidence item is linked to its primary originating finding via foreign key and can be referenced by additional derived findings via `metadata_json.referenced_evidence_ids`.

### 14. How are correlated evidence items represented?
Correlated evidence items share a common `correlation_group_id` in `data_json` and explicitly list related evidence types without treating them as independent statistical proofs.

### 15. How are unavailable provenance states represented?
Via explicit state enums (`PROVENANCE_UNAVAILABLE`, `MISSING_FINGERPRINT`, `UNVERIFIABLE_INPUT`) recorded in `metadata_json.provenance_status`, rather than failing silently or assuming validity.

### 16. How are cross-project mismatches detected?
Every query and binding strictly validates that `target.project_id == session.project_id`. Any mismatch triggers an immediate `SecurityError("CROSS_PROJECT_CONTAMINATION")`.

### 17. How are stale dataset versions detected?
The evidence's embedded `dataset_fingerprint` is compared against the target dataset version's current `dataset_hash`. Mismatches trigger `STALE_DATASET_VERSION`.

### 18. How is model/reference mismatch detected?
By comparing the evidence's `model_fingerprint` against the active model's registered `ModelFingerprintModel.fingerprint_value`. Mismatches trigger `MODEL_FINGERPRINT_MISMATCH`.

### 19. How is cryptographic validity separated from analytical validity?
Cryptographic validity evaluates digital signatures and hash chain continuity (`evidence_layer="proof"`). Analytical validity evaluates statistical thresholds and CV metrics (`evidence_layer="detection"`). A valid signature proves who created the record, not whether the ML prediction is correct.

### 20. How are partial detector failures represented?
Successful detectors emit valid evidence and findings; failed detectors emit structured `DETECTOR_EXECUTION_PARTIAL` info findings. The scan outcome is recorded as `partial_success`.

### 21. How is repeated execution made idempotent?
Using a structured canonical `ExecutionIdentityPayload` containing all inputs that affect analytical output (project, dataset version/fingerprint, detector ID/version/config hash, model ID/fingerprint/version, reference dataset/fingerprint, preprocessing hash, and policy version) hashed via Phase 4 RFC 8785 + SHA-256 (`ExecutionIdentityHash`).

### 22. What is audited?
High-level lifecycle transitions: scan start, scan completion, findings batch commitment, provenance sealing, and tamper verification checks.

### 23. What is NOT audited?
Per-sample iteration loops, intermediate array calculations, and read-only finding queries.

### 24. What remains deterministic?
All evidence content dictionaries, canonical JSON serializations, SHA-256 hashes, Merkle root calculations, execution identity hashes, and statistical metric calculations.

### 25. What happens when provenance is missing?
The evidence remains valid detection data, but its provenance status is marked as `PROVENANCE_UNAVAILABLE`. Downstream engines are informed that cryptographic non-repudiation is absent.

### 26. What happens when evidence is malformed?
Malformed evidence items (invalid schema, missing required fields, `NaN` values) are rejected at the validation layer and recorded as validation errors without corrupting the batch.

### 27. What happens when a cryptographic signature is invalid?
The verification service returns `AuditVerificationResult(valid=False, status="PROVENANCE_SIGNATURE_MISMATCH")` and generates a critical proof-layer finding (`confidence=1.0`).

### 28. What happens when evidence is valid but analytical confidence is low?
The finding is generated with the corresponding low `confidence` score (e.g. `0.25`), or flagged as `INSUFFICIENT_SUPPORT` if sample support is below minimum thresholds.

### 29. Does any Phase 5.9 operation produce a risk/threat score?
**NO.** Phase 5.9 strictly PROHIBITS computing composite risk scores, threat levels, or disposition decisions. Overall risk aggregation and risk decisioning belong exclusively to **Phase 12 (Evidence + Risk Engine)**. (Phase 8 provides Behavioural Analysis, not risk decisioning).

### 30. Can Phase 5.9 run fully offline?
**YES.** Phase 5.9 is 100% offline, air-gapped capable, with zero remote network dependencies, cloud APIs, or telemetry.

---

## 28. Implementation Checklist for Phase 5.9

When Phase 5.9 implementation is authorized, the implementation will deliver:

- [ ] **Evidence Schemas & Canonical Builders (`backend/aivara/dataset/evidence/schemas.py`):**
  - Frozen Pydantic models for `EvidenceContent`, `EvidencePayload`, `EvidenceTypeEnum`, `ProvenanceBindingState`, `ExecutionIdentityPayload`.
  - Invariant validator enforcing prohibited vocabulary and deterministic hashing rules.
- [ ] **Deterministic Evidence Hashing Bridge (`backend/aivara/dataset/evidence/hasher.py`):**
  - Canonical RFC 8785 serialization bridge utilizing Phase 4 `sha256_canonical_json`.
  - Structured `ExecutionIdentityHash` and `EvidenceHash` builders stripping non-deterministic fields.
- [ ] **Finding Synthesis & Evidence Binder (`backend/aivara/dataset/evidence/binder.py`):**
  - Multi-signal finding builder linking $N:M$ evidence items (primary foreign keys + metadata reference arrays).
  - Traceability mapping across dataset version, samples, annotations, and contributors.
- [ ] **Provenance Ledger Adapter (`backend/aivara/dataset/evidence/provenance_adapter.py`):**
  - Client interface consuming Phase 4 `ProvenanceService` and `AuditService`.
  - Batch sealing of scan findings with Ed25519 signatures and hash chain linking.
- [ ] **Unit & Integration Test Suite (`tests/test_evidence_provenance.py`):**
  - Comprehensive test suite validating determinism, hashing boundaries, multi-signal bindings, missing provenance states, cross-project protection, and vocabulary enforcement.
