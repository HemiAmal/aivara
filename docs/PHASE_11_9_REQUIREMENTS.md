# Phase 11.9: Evidence, Findings & Multi-Modal Risk Integration Requirements

**Project**: AIVARA — AI Verification & Assurance  
**Phase**: 11 — Distribution Shift / Data Drift Analysis  
**Subphase**: 11.9.1 — Architecture & Requirements Freeze  
**Status**: FORMAL SPECIFICATION (50 Requirements)  
**Date**: September 2026  

---

## 1. Requirement Taxonomy & Conventions

Requirements are formally numbered by category:
- **FR-11.9**: Functional Integration Requirements
- **STAT-11.9**: Statistical & Evidential Calibration Requirements
- **RISK-11.9**: Risk Modeling & Double-Counting Mitigation Requirements
- **DECISION-11.9**: Decision Policy & Human-in-the-Loop Requirements
- **SEC-11.9**: Security & Threat Mitigation Requirements
- **CRYPTO-11.9**: Cryptographic Identity & Content-Addressing Requirements
- **PRIV-11.9**: Privacy & Multi-Tenant Isolation Requirements
- **AUDIT-11.9**: Audit Trail & Explainability Requirements
- **COMPAT-11.9**: Cross-Phase Interoperability Requirements
- **PERF-11.9**: Resource Limits & Performance Boundedness Requirements
- **OFFLINE-11.9**: Offline Air-Gap Execution Requirements

---

## 2. Formal Requirements Matrix (50 / 50)

### 2.1 Functional Integration Requirements (FR)
- **FR-11.9-001 (Unified Assurance Pipeline)**: The integration engine shall implement the strict 5-stage transformation pipeline: $\text{Evidence} \longrightarrow \text{Finding} \longrightarrow \text{Confidence} \longrightarrow \text{Risk} \longrightarrow \text{Decision}$.
- **FR-11.9-002 (Heterogeneous Evidence Ingestion)**: The engine shall ingest and process evidence from all upstream subsystems (Phase 4 Provenance, Phase 5 Dataset Integrity, Phase 6 Contributor Risk, Phase 7 Model Integrity, Phase 8 Behavioral Analysis, Phase 9 Backdoor/Trigger Analysis, Phase 10 Inference Integrity, and Phase 11.1–11.8 Distribution Shift).
- **FR-11.9-003 (Deterministic Evidence Deduplication)**: The engine shall deduplicate incoming evidence records by computing canonical content digests $\text{SHA-256}(\text{RFC8785}(e.\text{data\_json}))$ to prevent duplicate ingestion.
- **FR-11.9-004 (Evidential Ancestry Clustering)**: The engine shall group evidence items sharing the same primary asset ancestor (`dataset_version_id`, `model_fingerprint`, `source_group_id`, `window_id`) into unified Ancestry Clusters.
- **FR-11.9-005 (Finding Synthesis from Detection Clusters)**: The engine shall synthesize composite `FindingModel` records representing multi-modal corroborated shifts without mutating underlying individual detection findings.
- **FR-11.9-006 (Non-Attribution Finding Semantics)**: All synthesized finding descriptions and titles shall use purely descriptive, observational language (e.g., `"Multi-modal distribution shift observed"`) and shall strictly prohibit accusatory terms (`"malicious"`, `"poisoning"`, `"fraud"`, `"culpability"`).

### 2.2 Statistical & Evidential Calibration Requirements (STAT)
- **STAT-11.9-001 (Proof vs. Detection Layer Separation)**: The engine shall strictly segregate Proof Layer evidence ($\text{Confidence} = 1.0$) from Detection Layer evidence ($\text{Confidence} \in [0.0, 1.0]$).
- **STAT-11.9-002 (Detection Confidence Calibration)**: Detection confidence shall be derived directly from FDR-adjusted statistical p-values ($c_e = \max(0.50, \min(0.99, 1.0 - p_{\text{adj}}))$) or metric-specific effect calibrations.
- **STAT-11.9-003 (Statistical Meaning of p-Values)**: Statistical p-values shall not be converted directly into probabilities of attack or maliciousness.
- **STAT-11.9-004 (Proof Non-Compensability)**: Proof Layer violations (hash mismatches, signature breaks, replay failures) shall be non-compensable and shall never be averaged or diluted by high statistical p-values ($p > 0.05$).
- **STAT-11.9-005 (Safe Negative Evidence Handling)**: Absence of detected drift ($p > 0.05$, $H_0$ retained) shall be recorded as `"NO_MATERIAL_SHIFT_DETECTED"` and shall never be asserted as mathematical proof of safety.

### 2.3 Risk Modeling & Double-Counting Mitigation Requirements (RISK)
- **RISK-11.9-001 (Normalized Risk Index Bounds)**: Composite overall risk scores and component scores shall be strictly bounded in $[0.0, 1.0]$.
- **RISK-11.9-002 (Risk Score Semantic Meaning)**: The risk score shall represent a decision-relevant operational exposure index under a versioned policy, NOT a probability of attack or fraud.
- **RISK-11.9-003 (Multi-Modal Double-Counting Protection)**: When multiple detectors (Phases 11.4, 11.5, 11.6, 11.7, 11.8) observe the same physical shift on a shared asset cluster, the engine shall apply the damped cluster aggregation rule with inter-modality correlation factor $\lambda_{\text{corr}} = 0.10$.
- **RISK-11.9-004 (Temporal and Source Disambiguation)**: Temporal drift (11.7) and source drift (11.8) derived from the same underlying asset subset shall be merged into a single multi-dimensional risk contributor.
- **RISK-11.9-005 (Transparent Rule-Based Risk Weighting)**: Risk weights across evidence categories (Integrity, Quality, Representation, Temporal, Provenance) shall be explicit, deterministic, and version-controlled. Black-box neural/ML risk scorers are strictly prohibited.

### 2.4 Decision Policy & Human-in-the-Loop Requirements (DECISION)
- **DECISION-11.9-001 (Deterministic Disposition Mapping)**: The engine shall map risk scores and proof violations to five canonical dispositions: `ACCEPT`, `REVIEW`, `QUARANTINE`, `REJECT`, `INSUFFICIENT_EVIDENCE`.
- **DECISION-11.9-002 (Mandatory Proof Rejection)**: Any active Proof Layer finding shall immediately trigger `REJECT` disposition regardless of detection risk score.
- **DECISION-11.9-003 (Quarantine & Review Thresholds)**: Detection risk scores shall trigger:
  - $\text{Risk} < 0.30 \implies \text{ACCEPT}$
  - $0.30 \le \text{Risk} < 0.65 \implies \text{REVIEW}$
  - $0.65 \le \text{Risk} < 0.85 \implies \text{QUARANTINE}$
  - $\text{Risk} \ge 0.85 \implies \text{REJECT}$
- **DECISION-11.9-004 (Human-in-the-Loop Review Queue)**: Dispositions of `REVIEW` and `QUARANTINE` shall generate explicit human review rationale descriptors detailing contributing evidence.
- **DECISION-11.9-005 (Decision Policy Versioning)**: Any modification to threshold values or weighting parameters shall require an incremented `decision_policy_version` and generate a distinct `decision_policy_hash`.

### 2.5 Security & Threat Mitigation Requirements (SEC)
- **SEC-11.9-001 (Prohibited AST Construct Validation)**: The engine source code shall contain 0 instances of `eval`, `exec`, `pickle`, `os.system`, or `subprocess`.
- **SEC-11.9-002 (Input Immutability Assurance)**: Ingested evidence records, contracts, and boundary results shall not be mutated in-place during evaluation.
- **SEC-11.9-003 (Fail-Closed Handling on Unanalyzed Dimensions)**: If required modalities are missing or unanalyzed, the engine shall emit `INSUFFICIENT_EVIDENCE` and route to `REVIEW` instead of defaulting to `ACCEPT`.
- **SEC-11.9-004 (Discrepant Modality Conflict Flagging)**: If two high-confidence detectors emit conflicting shift conclusions on the same asset, the engine shall emit `CONFLICTING_EVIDENCE` advisory and escalate to review.
- **SEC-11.9-005 (Finite Numeric Sanitization)**: All input floats shall be validated for non-finite values (`NaN`, `Inf`, `-Inf`) and sanitized to bounded floats prior to risk calculation.

### 2.6 Cryptographic & Verification Requirements (CRYPTO)
- **CRYPTO-11.9-001 (RFC 8785 Canonical JSON Serialization)**: All data dictionaries participating in cryptographic digests shall be serialized strictly using RFC 8785 Canonical JSON Serialization (JCS).
- **CRYPTO-11.9-002 (Evidence Set Digest)**: The engine shall compute `evidence_set_hash = SHA-256(RFC8785([e.evidence_hash for e in sorted_evidence]))`.
- **CRYPTO-11.9-003 (Risk & Decision Policy Digest)**: The engine shall compute `policy_hash = SHA-256(RFC8785(canonical_policy_dict))`.
- **CRYPTO-11.9-004 (Integrated Assurance Profile Hash)**: The engine shall compute `integrated_profile_hash = SHA-256(RFC8785(canonical_profile_dict))` over all stable profile attributes.
- **CRYPTO-11.9-005 (Mutation Sensitivity)**: Any alteration in evidence inputs, policy weights, thresholds, or project IDs shall deterministically change the resulting `integrated_profile_hash`.

### 2.7 Privacy & Multi-Tenant Isolation Requirements (PRIV)
- **PRIV-11.9-001 (Zero Cross-Tenant Risk Leakage)**: Evidence and findings from Project A shall never influence risk calculation or disposition for Project B.
- **PRIV-11.9-002 (Project Mismatch Rejection)**: If any evidence record project ID contradicts the target evaluation `project_id`, the engine shall immediately raise `ProjectMismatchError`.
- **PRIV-11.9-003 (Contributor PII Protection)**: Raw contributor identities in integrated findings and risk rationales shall be strictly replaced with project-scoped pseudonyms (`derive_project_scoped_pseudonym`).
- **PRIV-11.9-004 (Ephemeral High-Dimensional Payloads)**: Raw image buffers, feature matrices, and embedding vectors shall be processed ephemerally and excluded from stored risk assessments.

### 2.8 Auditability & Explainability Requirements (AUDIT)
- **AUDIT-11.9-001 (Traceable Lineage Chain)**: Every generated `RiskAssessment` shall maintain an explicit audit trail linking `Decision` $\to$ `RiskScore` $\to$ `Findings` $\to$ `EvidenceIDs` $\to$ `RawArtifactHashes`.
- **AUDIT-11.9-002 (Plain-Language Rationale Generation)**: The engine shall synthesize human-readable explainability text explaining the exact quantitative factors and thresholds leading to the decision.
- **AUDIT-11.9-003 (Component Risk Decomposition)**: The engine shall expose a decomposed `component_scores_json` dictionary breaking down risk by dimension (Integrity, Quality, Latent Drift, Temporal, Source).
- **AUDIT-11.9-004 (Historical Immutability)**: Re-evaluating an historical evidence set under a new policy version shall create a distinct new `RiskAssessment` record without modifying prior historical evaluations.

### 2.9 Cross-Phase Compatibility Requirements (COMPAT)
- **COMPAT-11.9-001 (Phase 4 Provenance Interoperability)**: Ingests Phase 4 cryptographic chain validation evidence without altering ledger structure.
- **COMPAT-11.9-002 (Phase 5 Dataset Integrity Interoperability)**: Ingests Phase 5 sample corruption, duplication, and label flipping evidence.
- **COMPAT-11.9-003 (Phase 6 Contributor Risk Interoperability)**: Consumes Phase 6 empirical Bayes contributor risk vectors as contextual risk inputs without altering Phase 6 models.
- **COMPAT-11.9-004 (Phase 7 Model Integrity Interoperability)**: Ingests Phase 7 weight fingerprinting and structural anomaly evidence.
- **COMPAT-11.9-005 (Phase 8 Behavioral Analysis Interoperability)**: Ingests Phase 8 runtime perturbation and anomaly evidence.
- **COMPAT-11.9-006 (Phase 9 Trigger Analysis Interoperability)**: Ingests Phase 9 backdoor activation evidence with non-attribution semantics.
- **COMPAT-11.9-007 (Phase 10 Inference Integrity Interoperability)**: Ingests Phase 10 input-output binding and replay verification evidence.
- **COMPAT-11.9-008 (Phase 11.1–11.8 Distribution Shift Interoperability)**: Seamlessly unifies tabular, image, embedding, temporal, and source drift outputs.

### 2.10 Performance & Resource Limits Requirements (PERF)
- **PERF-11.9-001 (Maximum Evidence Budget)**: The engine shall process up to $E_{\max} = 1000$ evidence items per evaluation run; inputs exceeding this limit shall raise `ResourceLimitExceededError`.
- **PERF-11.9-002 (Maximum Findings Budget)**: The engine shall support up to $F_{\max} = 200$ active findings per integrated profile.
- **PERF-11.9-003 (Linear Aggregation Complexity)**: Evidence clustering, deduplication, and risk scoring shall execute in strictly linear time $O(E)$ relative to evidence count.
- **PERF-11.9-004 (Bounded Memory Overhead)**: Memory consumption for risk aggregation shall not exceed 100MB for maximum batch size ($E=1000$).

### 2.11 Offline Air-Gap Execution Requirements (OFFLINE)
- **OFFLINE-11.9-001 (Zero Network Dependencies)**: The engine shall execute 100% offline with zero imports of `requests`, `httpx`, `urllib`, `socket`, `dns`, or external cloud SDKs.
- **OFFLINE-11.9-002 (Self-Contained Rule Execution)**: All risk aggregation, decision logic, and canonical hashing shall rely solely on local deterministic algorithms.
