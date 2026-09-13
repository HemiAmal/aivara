# PHASE 11.8 REQUIREMENTS: CONTRIBUTOR & SOURCE-AWARE DISTRIBUTION SHIFT

================================================================================
PROJECT: AIVARA — AI Verification & Assurance
SUBSYSTEM: Phase 11 — Distribution Shift / Data Drift Analysis
PHASE: 11.8 — Contributor & Source-Aware Distribution Shift
SUBPHASE: 11.8.1 — Architecture & Requirements Freeze
STATUS: COMPLETE & AUTHORITATIVE
DATE: September 13, 2026
================================================================================

## 1. Requirement Taxonomy & Conventions

This specification defines the authoritative requirements for **Phase 11.8: Contributor & Source-Aware Distribution Shift**. 

Requirements are categorized and systematically numbered:
- **FR-11.8-xxx**: Functional Requirements
- **STAT-11.8-xxx**: Statistical & Analytical Requirements
- **SEC-11.8-xxx**: Security & Threat Mitigation Requirements
- **PRIV-11.8-xxx**: Privacy, Isolation & Pseudonymization Requirements
- **CRYPTO-11.8-xxx**: Cryptographic Identity & Hashing Requirements
- **PERF-11.8-xxx**: Performance, Complexity & Resource Bound Requirements
- **DATA-11.8-xxx**: Schema, Accounting & Data Integrity Requirements
- **COMPAT-11.8-xxx**: Cross-Phase Architectural Compatibility Requirements

---

## 2. Functional Requirements (FR)

- **FR-11.8-001 (Source Attribute Extraction)**: The system MUST extract source/contributor identifiers from observation metadata according to an explicit `SourceAttributeSelector` defined in the analysis contract.
- **FR-11.8-002 (Deterministic Canonicalization)**: The system MUST normalize all extracted raw source identifiers via Unicode NFKC normalization, whitespace trimming, lowercase folding, and non-printable character removal before group partitioning.
- **FR-11.8-003 (Group Partitioning)**: The system MUST partition observations into distinct source groups based on their canonical source identifiers.
- **FR-11.8-004 (Explicit Reference Source Selection)**: The system MUST support comparing each target source group against an explicitly declared reference source or a validated reference population (Phase 11.2).
- **FR-11.8-005 (Linear Comparison Topology)**: The system MUST execute comparisons using an $O(G)$ linear topology ($\mathcal{P}_{s_g} \leftrightarrow \mathcal{P}_{\text{ref}}$ for each eligible source $g \in \{1 \dots G\}$). Pairwise $O(G^2)$ all-pairs comparisons are strictly prohibited in v1.
- **FR-11.8-006 (Group Eligibility Classification)**: The system MUST classify every formed source group into one of the explicit status states: `ELIGIBLE`, `INSUFFICIENT_DATA`, `INVALID`, `UNKNOWN`, or `EXCLUDED`.
- **FR-11.8-007 (Source Group Accounting)**: The system MUST compute and output strict reconciliation accounting such that: $\text{Total} = \text{Eligible} + \text{Insufficient} + \text{Missing} + \text{Invalid} + \text{Unknown}$.
- **FR-11.8-008 (Multi-Modality Shift Evaluation)**: The system MUST support source-aware shift analysis across tabular continuous features (Phase 11.4), tabular categorical/label features (Phase 11.4), image descriptors (Phase 11.5), and latent embeddings (Phase 11.6).
- **FR-11.8-009 (Dual-Gate Shift Decision)**: The system MUST evaluate shift for each source-feature comparison using dual gating: declared shift requires both adjusted statistical significance ($p_{\text{adj}} \le 0.05$) AND practical effect size ($\text{Effect} \ge \theta_{\text{effect}}$).
- **FR-11.8-010 (Confounding & Label Skew Surfacing)**: The system MUST compute source-specific label/class distributions $\mathcal{P}(Y \mid S)$ and explicitly flag potential label confounding in findings when source class proportions diverge significantly from the reference.
- **FR-11.8-011 (Source Ranking)**: The system MUST deterministically rank analyzed sources based on composite shift severity: $(\text{ShiftStatus} \downarrow, \text{MaxEffectSize} \downarrow, \text{MinAdjustedP} \uparrow, \text{SampleCount} \downarrow, \text{SourceID} \uparrow)$.
- **FR-11.8-012 (Finding Synthesis)**: The system MUST synthesize standard `FindingModel` instances with `evidence_layer = "detection"`, attaching structured source distribution profiles without accusatory terminology.
- **FR-11.8-013 (Evidence Model Generation)**: The system MUST generate standard `EvidenceModel` records linking dataset identity, population identity, source metadata hash, statistical test results, and profile digests.

---

## 3. Statistical & Analytical Requirements (STAT)

- **STAT-11.8-001 (Statistical Authority Delegation)**: The system MUST delegate all two-sample hypothesis test computations and metric calculations directly to Phase 11.3 `StatisticalDriftEngine`. Zero duplicate statistical mathematics is permitted.
- **STAT-11.8-002 (Continuous Feature Testing)**: Continuous features MUST be evaluated using Two-Sample Kolmogorov-Smirnov (KS) tests and Population Stability Index (PSI).
- **STAT-11.8-003 (Categorical & Label Testing)**: Categorical features and label distributions MUST be evaluated using Chi-Square Goodness-of-Fit / Independence tests and Total Variation Distance (TVD).
- **STAT-11.8-004 (Representation Space Testing)**: High-dimensional embeddings MUST be evaluated using Kernel Maximum Mean Discrepancy (MMD) or Energy Distance with permutation testing.
- **STAT-11.8-005 (Multiple Testing Control)**: The system MUST apply Benjamini–Hochberg False Discovery Rate (FDR) control at nominal $q^* = 0.05$ across all source comparisons within each feature family.
- **STAT-11.8-006 (Prohibition of Double FDR)**: The system MUST adjust raw $p$-values exactly once per comparison family; nested or repeated FDR applications ($BH(BH(p)))$ are strictly prohibited.
- **STAT-11.8-007 (Sample Size Floor)**: Source groups with sample size $N_g < 30$ MUST NOT be submitted to hypothesis tests and MUST transition to `INSUFFICIENT_DATA`.
- **STAT-11.8-008 (Dual-Gate Effect Thresholds)**: The system MUST enforce approved effect thresholds: $\text{PSI} \ge 0.10$, $\text{TVD} \ge 0.05$, $\text{MMD}^2 \ge 0.02$, $\text{Energy} \ge 1.0$.
- **STAT-11.8-009 (Effect-Metric Compatibility)**: The system MUST compare effect sizes strictly against their own metric-specific thresholds; cross-metric threshold comparisons are prohibited.
- **STAT-11.8-010 (Statistical Non-Attribution)**: Statistical significance and practical effect size MUST be interpreted strictly as evidence of distributional heterogeneity, NEVER as proof of intent, fraud, or data poisoning.

---

## 4. Security & Threat Mitigation Requirements (SEC)

- **SEC-11.8-001 (Offline Execution Invariant)**: The subsystem MUST operate 100% offline without remote network calls, HTTP requests, cloud AI services, DNS resolution, or external identity providers.
- **SEC-11.8-002 (AST Security Cleanliness)**: All Phase 11.8 code MUST be free of `eval()`, `exec()`, `pickle`, `subprocess`, `os.system`, or unvetted dynamic imports.
- **SEC-11.8-003 (Input Immutability)**: The analysis engine MUST NOT mutate input observation dictionaries, arrays, or metadata structures.
- **SEC-11.8-004 (Sybil Fragmentation Alert)**: When the volume of samples in sub-threshold groups ($N_g < 30$) exceeds 20% of total observations, the system MUST emit an explicit `EXCESSIVE_SOURCE_FRAGMENTATION` advisory finding.
- **SEC-11.8-005 (Missing Metadata Rate Alert)**: When the proportion of observations with missing or invalid source metadata exceeds 10%, the system MUST emit a `HIGH_MISSING_SOURCE_METADATA_RATE` finding.
- **SEC-11.8-006 (Source Claim vs Proof)**: Ingested source identifiers MUST be marked and reported as claimed metadata, distinguishing them from cryptographically verified identities (Phase 4 / Phase 10).
- **SEC-11.8-007 (Fail-Closed Validation)**: Malformed contracts, conflicting parameters, or corrupted sample structures MUST cause the engine to fail closed with specific domain exceptions.

---

## 5. Privacy, Isolation & Pseudonymization Requirements (PRIV)

- **PRIV-11.8-001 (Project Boundary Isolation)**: All source grouping, analysis, and profiling MUST be strictly isolated to the enclosing project tenant. Cross-project data aggregation or leakage is strictly prohibited.
- **PRIV-11.8-002 (Deterministic Pseudonymization)**: Contributor identifiers in persistent records and findings MUST be pseudonymized using project-scoped HMAC/SHA-256: $\text{Pseudonym} = \text{SHA-256}(\text{project\_id} \mathbin{\Vert} \text{salt} \mathbin{\Vert} \text{canonical\_id})[:16]$.
- **PRIV-11.8-003 (Cross-Project Unlinkability)**: A contributor active across Project A and Project B MUST produce distinct, unlinkable pseudonymized identifiers in each project.
- **PRIV-11.8-004 (Zero Raw PII Persistence)**: Raw email addresses, real names, or un-pseudonymized personal identifiers MUST NOT be serialized into `FindingModel`, `EvidenceModel`, or public-facing export profiles.
- **PRIV-11.8-005 (Raw Vector Non-Persistence)**: High-dimensional feature matrices and image embedding arrays MUST NOT be stored in persistent profile descriptors.

---

## 6. Cryptographic Identity & Hashing Requirements (CRYPTO)

- **CRYPTO-11.8-001 (RFC 8785 JCS Serialization)**: All cryptographic identity hashes for descriptors and profiles MUST use RFC 8785 JSON Canonicalization Scheme (JCS) prior to SHA-256 hashing.
- **CRYPTO-11.8-002 (Source Group Descriptor Hash)**: Each `SourceGroupDescriptor` MUST compute a deterministic SHA-256 digest over: `(project_id, source_id, canonical_id, sample_count, sample_id_list_hash, earliest_timestamp, latest_timestamp)`.
- **CRYPTO-11.8-003 (Source Analysis Profile Hash)**: `SourceAnalysisProfile` MUST compute a deterministic profile hash over its canonical configuration, group descriptor hashes, and comparison results.
- **CRYPTO-11.8-004 (Mutation Sensitivity)**: Any mutation of source assignment, sample payload, baseline reference, statistical configuration, or sampling seed MUST produce a completely different profile hash.
- **CRYPTO-11.8-005 (Stable Field Inclusion)**: Dynamic runtime parameters (e.g., wall-clock execution duration, memory addresses, random UUIDs) MUST NOT be included in canonical hashing payloads.

---

## 7. Performance, Complexity & Resource Bound Requirements (PERF)

- **PERF-11.8-001 (Maximum Group Cardinality)**: The system MUST enforce a maximum source group limit of $G_{\text{max}} = 50$. Submissions with $> 50$ distinct sources MUST raise `ResourceLimitExceededError`.
- **PERF-11.8-002 (Maximum Group Sample Budget)**: Individual source groups with sample count $N_g > 5000$ MUST be deterministically subsampled to $N_{\text{subsample}} = 5000$ using Phase 11.2 seeded PRNG.
- **PERF-11.8-003 (Linear Algorithmic Complexity)**: Total execution complexity MUST scale as $O(G \cdot N_{\text{subsample}} \cdot M)$ where $G \le 50$, $N_{\text{subsample}} \le 5000$, and $M \le 100$ features.
- **PERF-11.8-004 (Memory Upper Bound)**: Transient memory footprint for source grouping and statistical dispatch MUST not exceed 100 MB for standard 5,000-sample evaluations.

---

## 8. Schema, Accounting & Data Integrity Requirements (DATA)

- **DATA-11.8-001 (Zero Database Migrations)**: Phase 11.8 MUST NOT create new database tables, alter existing columns, or add Alembic migrations. SQLite architecture is preserved.
- **DATA-11.8-002 (Zero Public API Mutations)**: Phase 11.8 architecture phase MUST NOT alter public HTTP endpoints.
- **DATA-11.8-003 (Reconciliation Invariant)**: In every analysis execution, the observation accounting equation MUST strictly balance:
  $$\text{total\_observations} = \sum_{g \in \text{Eligible}} N_g + \sum_{g \in \text{Insufficient}} N_g + N_{\text{missing}} + N_{\text{invalid}} + N_{\text{unknown}}$$
- **DATA-11.8-004 (Deterministic Ordering)**: Observations within each source group MUST be deterministically sorted by `(timestamp ASC, sample_id ASC)` before subsampling.

---

## 9. Cross-Phase Architectural Compatibility Requirements (COMPAT)

- **COMPAT-11.8-001 (Phase 11.2 Boundary Reuse)**: Group subsampling and population validation MUST reuse Phase 11.2 boundary contracts.
- **COMPAT-11.8-002 (Phase 11.3 Statistics Reuse)**: All univariate, categorical, and multivariate statistical tests MUST be delegated to Phase 11.3 `StatisticalDriftEngine`.
- **COMPAT-11.8-003 (Phase 11.4 Feature Reuse)**: Tabular feature definitions and PSI/TVD metrics MUST align with Phase 11.4 schemas.
- **COMPAT-11.8-004 (Phase 11.5 Image Reuse)**: Image source evaluations MUST consume Phase 11.5 `ImageDescriptor` structures.
- **COMPAT-11.8-005 (Phase 11.6 Representation Reuse)**: Representation-space source evaluations MUST consume frozen 384-d DINOv2 embeddings and Phase 11.6 contracts.
- **COMPAT-11.8-006 (Phase 11.7 Temporal Separation)**: Source-aware analysis MUST NOT reimplement windowing or change-point detection; temporal context is consumed purely as metadata.
- **COMPAT-11.8-007 (Phase 6 Contributor Risk Separation)**: Phase 11.8 produces source distribution detection evidence; it MUST NOT compute or overwrite Phase 6 contributor risk scores.

---

## 10. Summary of Architectural Requirements

| Requirement Category | Total Count | Verification Strategy |
|---|---|---|
| Functional (FR) | 13 | Dedicated Unit & Integration Tests |
| Statistical (STAT) | 10 | Synthetic Shift & Invariant Tests |
| Security (SEC) | 7 | AST Scans & Offline Air-Gap Verification |
| Privacy (PRIV) | 5 | Cross-Project Linkage & Pseudonym Tests |
| Cryptography (CRYPTO) | 5 | RFC 8785 JCS & SHA-256 Mutation Tests |
| Performance (PERF) | 4 | Complexity Scaling & Benchmark Tests |
| Data & Schema (DATA) | 4 | Accounting Balance & Schema Invariant Tests |
| Compatibility (COMPAT) | 7 | Cross-Phase Integration Tests |
| **Total Phase 11.8 Requirements** | **55** | **Comprehensive Multi-Suite Verification** |
