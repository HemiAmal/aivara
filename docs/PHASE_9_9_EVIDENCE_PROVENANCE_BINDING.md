# Phase 9.9 — Evidence & Cryptographic Provenance Binding Layer

## 1. Objective
Phase 9.9 establishes the integration adapter layer connecting the Phase 9 Backdoor / Trigger Analysis statistical and behavioral evaluation engine (`StatisticalAnalysisAssessment`, `CandidateStatisticalSummary`, `SpatialLocalizationSummary`) to AIVARA's frozen Phase 4 and Phase 5.9 cryptographic provenance and evidence foundations.

This ensures all trigger candidate evaluations, paired permutation test statistics, multiple comparison corrections, and spatial localizations are sealed into immutable, content-addressed, Ed25519-signed provenance audit trails with strict multi-tenant project isolation and zero database schema modifications.

---

## 2. Architecture

```
+-------------------------------------------------------------------------+
| Phase 9.5 Statistical Analysis Engine                                   |
| (StatisticalAnalysisAssessment, CandidateStatisticalSummary)            |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| backend/aivara/backdoor/evidence.py                                     |
|  - create_backdoor_evidence(assessment, candidate_summary, ...)         |
|  - compute_backdoor_evidence_hash() [RFC 8785 JCS + SHA-256]            |
|  - compute_backdoor_execution_identity_hash()                           |
|  - seal_backdoor_evidence() [DRAFT -> SEALED]                           |
|  - to_phase5_evidence_payload()                                         |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| BackdoorProvenanceBindingService                                        |
|  - Validates tenant project isolation                                   |
|  - EvidenceFindingBinder: synthesizes FindingModel & EvidenceModel rows  |
|  - ProvenanceBindingAdapter: seals Ed25519 hash-linked record into     |
|    ProvenanceRecordModel (sequence_number, nonce, signature)            |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Phase 4 Cryptographic Provenance Ledger & Phase 5.9 Finding Repository   |
+-------------------------------------------------------------------------+
```

---

## 3. Evidence Schema & Bound Attributes

The canonical evidence content (`BackdoorEvidenceContent`) captures all semantic analytical inputs and results needed to reproduce and independently verify the analysis:

- **Project & Asset Identity:** `project_id`, `model_id`, `model_fingerprint`, `sample_set_hash`.
- **Candidate & Transformation:** `candidate_hash`, `transformation_hash`.
- **Linked Assessments:** `activation_assessment_id`, `statistical_analysis_id`.
- **Behavioral & Statistical Metrics:**
  - `target_class`
  - `tar` (Trigger Activation Rate)
  - `tsr` (Trigger Success Rate)
  - `raw_tsr_shuffled`, `raw_tsr_noise`
  - `control_baseline_tsr` ($\max(\text{TSR}_{\text{shuff}}, \text{TSR}_{\text{noise}})$)
  - `sample_envelope_tsr` ($\text{mean}(\max(\text{shuff}_i, \text{noise}_i))$)
  - `delta_separation` ($\text{TSR}_{\text{trigger}} - \text{TSR}_{\text{control}}$)
  - `confidence_interval_low`, `confidence_interval_high` (Clopper-Pearson 95% CI)
  - `permutation_count` ($B = 1000$)
  - `p_value` (Intersection-Union Test composite permutation $p$-value)
  - `p_value_shuffled`, `p_value_noise`
  - `adjusted_p_value` (Benjamini-Hochberg FDR corrected)
  - `is_significant_after_fdr`
- **Spatial Localization:** `spatial_localization` (bounded bounding-box, focal center, coverage ratio, spatial concentration).
- **Taxonomy & Audit:** `taxonomy_classification`, `budget_inferences_total`, `policy_version`, `analysis_version`, `schema_version`.

*Boundedness Guarantee:* Raw image tensors, model weight arrays, and unbounded execution traces are strictly forbidden from evidence serialization; only cryptographic digests, bounded summaries, and metrics participate.

---

## 4. Canonicalization & Deterministic Evidence Identity

Evidence identity computation strictly complies with Phase 4 RFC 8785 JSON Canonicalization Scheme (JCS) and SHA-256:

$$\text{evidence\_id} = \text{SHA-256}(\text{JCS}(\text{BackdoorEvidenceContent}))$$

Any semantic modification to candidate hashes, TSR, control baseline, permutation count, $p$-values, or model fingerprints produces a completely distinct 64-hex lowercase digest.

---

## 5. Execution Identity

Reuses the established Phase 5.9 execution identity mechanism:

$$\text{execution\_id} = \text{SHA-256}(\text{JCS}(\text{ExecutionParameters}))$$

Binds project ID, model ID, model fingerprint, sample set hash, statistical analysis ID, detector ID, detector version, and policy version to ensure idempotency and prevent duplicate scan runs under identical conditions.

---

## 6. Provenance Binding & Cryptographic Guarantees

Sealing is coordinated by `BackdoorProvenanceBindingService`:
1. Validates project isolation (raises `CrossProjectContaminationError` on mismatch or missing project).
2. Synthesizes a `FindingModel` with associated `EvidenceModel` items.
3. Seals findings using `ProvenanceBindingAdapter.seal_scan_findings()`, generating a hash-chained `ProvenanceRecordModel`:
   - SHA-256 `record_hash`
   - Secure cryptographic `nonce`
   - Monotonically increasing `sequence_number`
   - Unbroken `previous_record_hash`
   - Digital signature generated via Ed25519 key handle
   - Audit trail recorded in `audit_events`

---

## 7. Lifecycle States & Tamper Detection

- **Lifecycle:** `DRAFT` $\to$ `SEALED`. Only `SEALED` records are eligible for cryptographic provenance verification.
- **Provenance Evaluation States:** Uses canonical frozen Phase 5.9 vocabulary: `VERIFIED`, `INVALID`, `MISSING`, `UNAVAILABLE`, `MISMATCHED`, `UNVERIFIABLE`.
- **Tamper Resistance:** Modifying any byte of `record_hash`, `payload_hash`, or evidence content causes `ProvenanceService.verify_record()` to return `overall_valid=False` and `record_valid=False`.

---

## 8. Missing-State & Non-Accusatory Semantics

- **Preservation of Absence:** `None` / missing fields (e.g. absent spatial localization for non-promoted candidates) are preserved as `None` in JSON serialization and are never silently coerced to `0` or false constants.
- **Semantic Safety:** Evidence payloads and finding summaries strictly adhere to observational terminology (`trigger candidate`, `trigger-conditioned behavior`, `targeted output shift`, `statistical significance`). Speculative or culpability-assigning terms (`malicious`, `attacker_intent`, `backdoor_confirmed`) are forbidden.

---

## 9. Downstream Interface to Phase 9.10

Phase 9.10 (REST API & Task Integration) will consume `BackdoorProvenanceBindingService` to bind background task execution results and expose sealed provenance verification endpoints via standard FastAPI routers.
