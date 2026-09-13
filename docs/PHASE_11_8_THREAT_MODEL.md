# PHASE 11.8 THREAT MODEL: CONTRIBUTOR & SOURCE-AWARE DISTRIBUTION SHIFT

================================================================================
PROJECT: AIVARA — AI Verification & Assurance
SUBSYSTEM: Phase 11 — Distribution Shift / Data Drift Analysis
PHASE: 11.8 — Contributor & Source-Aware Distribution Shift
SUBPHASE: 11.8.1 — Architecture & Requirements Freeze
STATUS: COMPLETE & AUTHORITATIVE
DATE: September 13, 2026
================================================================================

## 1. Scope & Objective

This document formalizes the threat model for **Contributor and Source-Aware Distribution Shift Analysis (Phase 11.8)** in AIVARA. It identifies attack surfaces, adversarial behaviors, metadata manipulation vectors, statistical evasion strategies, privacy vulnerabilities, and operational failure modes that could compromise the integrity, correctness, confidentiality, or trustworthiness of source-aware assurance assessments.

---

## 2. Threat Actor Profiles & Trust Assumptions

### 2.1 Threat Actor Profiles
1. **Adversarial Contributor (Insider / External Vendor)**: Seeks to inject corrupted, out-of-distribution, or subtly backdoored data while evading source-level detection.
2. **Untrusted Metadata Manipulator**: Possesses write access to dataset ingestion manifests, EXIF headers, or contributor tags; attempts to spoof or reassign source identities.
3. **Sybil / Distributed Adversary**: Controls multiple synthetic contributor accounts to fragment attack payloads and bypass minimum sample size constraints ($N_{\text{min}} = 30$).
4. **Curious Auditor / Observer**: Analyzes exported AIVARA audit reports across projects to deanonymize or link contributors across organizational boundaries.

### 2.2 Trust Assumptions
- **Host Security**: The AIVARA backend executes in a hardened, offline, single-tenant environment (Air-gapped / Localhost).
- **Cryptographic Authority**: SHA-256 and RFC 8785 JSON Canonicalization Scheme (JCS) are cryptographically sound.
- **Upstream Immobility**: Phases 0–10 and 11.1–11.7 are permanently frozen and tamper-proof.
- **Source Claim vs Proof**: Source/contributor metadata in dataset manifests is treated as **unverified claims** unless backed by cryptographic digital signatures (Phase 4 / Phase 10).

---

## 3. Comprehensive 20-Scenario Threat Matrix

### TM-11.8-01: Source Identity Spoofing (Camouflage Attack)
- **Threat**: An adversary submits anomalous or out-of-distribution data tagged with the identifier of a reputable, high-trust contributor (`trusted_vendor_01`).
- **Attack Surface**: Ingestion manifest `contributor_id` / `source_id` string fields.
- **Impact**: Shift is attributed to the benign contributor, distorting their historical baseline profile and potentially masking the adversary's involvement.
- **Mitigation**: AIVARA treats metadata as observational context, NOT cryptographic proof of origin. Finding synthesis uses strictly descriptive language ("Data associated with claimed source X exhibits shift"). If Phase 4 Ed25519 signatures are present, signature verification is independently evaluated.
- **Residual Limitation**: Without digital signatures on raw data submissions, unauthenticated metadata spoofing cannot be cryptographically refuted at Layer 1.

### TM-11.8-02: Source Fragmentation (Sybil Group Evasion)
- **Threat**: An adversary splits 1,000 anomalous samples across 50 distinct contributor identifiers (20 samples each).
- **Attack Surface**: Contributor group partition logic.
- **Impact**: Each individual group has $N_g = 20 < N_{\text{min}} = 30$, causing all groups to be marked `INSUFFICIENT_DATA` and evading statistical two-sample tests.
- **Mitigation**: Source accounting reconciles total observations against eligible vs ineligible groups. High volumes of sub-threshold samples trigger a dedicated metadata finding: `EXCESSIVE_SOURCE_FRAGMENTATION_DETECTED`.
- **Residual Limitation**: If the total fragmented volume is small relative to the global dataset, it cannot be statistically isolated to a specific sub-group without prior clustering.

### TM-11.8-03: Source Merging / Trojan Piggybacking
- **Threat**: An adversary injects a small fraction of poisoned samples (e.g., 50 samples) into a massive legitimate source group containing 10,000 samples.
- **Attack Surface**: Source group aggregation.
- **Impact**: The small poisoned fraction is diluted in the source's overall distribution, yielding $p > 0.05$ or negligible effect size ($\text{PSI} < 0.10$), evading detection.
- **Mitigation**: Complemented by Phase 11.6 representation outlier analysis and Phase 9 backdoor trigger localization.
- **Residual Limitation**: Source-level shift analysis measures macro-distributional divergence; low-rate poisoning (<1%) within a large source requires dedicated point-anomaly / trigger detectors.

### TM-11.8-04: Metadata Stripping & Null Flooding
- **Threat**: Adversary strips contributor and source fields from data items, setting them to `null`, empty string, or whitespace.
- **Attack Surface**: Metadata parser and ingestion validator.
- **Impact**: Data is dumped into unclassified or unmonitored pools.
- **Mitigation**: Strict source accounting captures all `MISSING`, `INVALID`, and `UNKNOWN` entries into explicit `TemporalWindowAccounting` / `SourceGroupAccounting`. Datasets with missing source rates exceeding threshold ($\ge 10\%$) generate an assurance finding: `HIGH_MISSING_SOURCE_METADATA_RATE`.
- **Residual Limitation**: Statistical distribution shift cannot be computed for sources that have no metadata.

### TM-11.8-05: Unicode Canonicalization & Homoglyph Collision
- **Threat**: Adversary creates source identifiers with visually identical or equivalent characters (e.g., Latin 'A' `U+0041` vs Cyrillic 'А' `U+0410`, or trailing zero-width spaces).
- **Attack Surface**: Group aggregation dictionary keys.
- **Impact**: Fragmented groups, duplicate profiles, or unintended partition splits.
- **Mitigation**: Deterministic canonicalization pipeline: Unicode NFKC normalization, whitespace trimming, lowercase conversion, and non-printable character stripping prior to group assignment.
- **Residual Limitation**: Semantic aliases (e.g., `lab_1` vs `first_laboratory`) cannot be resolved without explicit domain alias configuration.

### TM-11.8-06: Cross-Project Contributor Deanonymization & Linkability
- **Threat**: Adversary inspects audit reports from Project A and Project B to track a specific contributor's contributions across projects.
- **Attack Surface**: Exported `FindingModel`, `EvidenceModel`, and `SourceAnalysisProfile` JSON payloads.
- **Impact**: Contributor privacy violation, breach of confidentiality agreements or GDPR compliance.
- **Mitigation**: Project-scoped deterministic pseudonymization: $\text{Pseudonym} = \text{SHA-256}(\text{project\_id} \mathbin{\Vert} \text{salt} \mathbin{\Vert} \text{canonical\_id})[:16]$. Identical contributors in different projects produce completely distinct, unlinkable pseudonyms.
- **Residual Limitation**: Project administrators with access to the raw ingestion database can map pseudonyms back to raw IDs locally within their own project.

### TM-11.8-07: Source Dominance Masking
- **Threat**: A single dominant contributor provides 95% of total dataset volume, with 5 minority contributors providing 1% each.
- **Attack Surface**: Pooled baseline comparison topology.
- **Impact**: If a pooled complement baseline is used, the dominant contributor's data defines the baseline for all others, while the dominant contributor is compared against an unrepresentative 5% sample.
- **Mitigation**: Enforce **Source-vs-Reference ($O(G)$)** topology with an explicit, immutable reference population (Phase 11.2) rather than dynamic unweighted pooling.
- **Residual Limitation**: If the explicit reference population itself is dominated by a single vendor, the baseline reflects that vendor's distribution.

### TM-11.8-08: Reference Source Poisoning
- **Threat**: An adversary designates a compromised or non-stationary source as the authoritative `reference_source`.
- **Attack Surface**: Comparison contract specification.
- **Impact**: All clean target sources are falsely flagged as shifted, while the corrupted reference appears as the ground truth.
- **Mitigation**: Reference sources must be explicitly declared and cryptographically anchored by dataset version hashes (`reference_dataset_version_id`, `dataset_hash`). Baseline modification during target evaluation is strictly prohibited.
- **Residual Limitation**: User selection of an inappropriate reference baseline cannot be automatically overridden by the algorithm.

### TM-11.8-09: Replay of Historical Source Metadata on Altered Payloads
- **Threat**: Adversary copies valid historical source metadata from a verified audit and attaches it to altered, shifted data vectors.
- **Attack Surface**: Offline audit re-execution.
- **Impact**: False claim that current shifted data is identical to historical verified submissions.
- **Mitigation**: Cryptographic content-addressing: `SourceGroupDescriptor` and `SourceAnalysisProfile` hash both the metadata and the SHA-256 digests of all constituent sample payloads. Altered data instantly changes the profile digest.
- **Residual Limitation**: Replay attacks are detectable upon profile hash verification, but requires re-running verification.

### TM-11.8-10: Source Reassignment Tampering
- **Threat**: After an audit reveals Contributor A is severely shifted, an adversary alters the local database to reassign those samples to Contributor B.
- **Attack Surface**: Database records / JSON metadata.
- **Impact**: Shift is fraudulently attributed to Contributor B in subsequent reports.
- **Mitigation**: Cryptographic provenance ledger (Phase 4 / Phase 11.9) commits immutable hash chains of the original analysis profile. Any post-audit reassignment produces a hash mismatch during provenance verification.
- **Residual Limitation**: Requires running provenance ledger verification to detect post-hoc tampering.

### TM-11.8-11: Simpson's Paradox Exploitation
- **Threat**: An adversary intentionally structures data submission such that class-conditional distributions are normal, but marginal distributions appear shifted (or vice versa), inducing false positive alerts.
- **Attack Surface**: Marginal feature analysis without label conditioning.
- **Impact**: False positive alarms or incorrect attribution of sensor shift when the true driver is benign class specialization.
- **Mitigation**: Dual reporting: System analyzes and reports both marginal feature shift $\mathcal{P}(X \mid S)$ and label/class distributions $\mathcal{P}(Y \mid S)$. Findings explicitly surface class distribution skew as a potential confounding factor.
- **Residual Limitation**: Full conditional testing $\mathcal{P}(X \mid Y=y, S)$ across all classes is computationally bounded and requires sufficient samples per $(y, s)$ cell ($N_{y,s} \ge 30$).

### TM-11.8-12: Multiplicity Inflation / P-Hacking via Source Proliferation
- **Threat**: Adversary creates 50 artificial source groups, expecting that with uncorrected testing at $\alpha = 0.05$, several groups will achieve $p < 0.05$ purely by random chance.
- **Attack Surface**: Multiple hypothesis testing across source groups.
- **Impact**: False positive shift findings generated on clean, homogeneous data.
- **Mitigation**: Mandatory Benjamini–Hochberg False Discovery Rate (FDR) control at $q^* = 0.05$ across all source comparisons within each feature family.
- **Residual Limitation**: False positive rate is bounded to $\le 5\%$ of declared discoveries under FDR, not strictly 0.

### TM-11.8-13: Resource Exhaustion via High Cardinality Source Flooding (DoS)
- **Threat**: Adversary submits a dataset containing 100,000 distinct source identifiers, attempting to trigger out-of-memory crashes or quadratic compute loops.
- **Attack Surface**: Group partitioning and statistical comparison orchestration.
- **Impact**: Denial of Service (DoS) of the AIVARA analysis engine.
- **Mitigation**: Hard resource limits: Maximum source group count $G_{\text{max}} = 50$, maximum samples per group $N_{\text{max}} = 5,000$. Datasets exceeding $G_{\text{max}}$ abort with `ResourceLimitExceededError` or restrict evaluation to top-ranked groups by volume.
- **Residual Limitation**: Sources beyond $G_{\text{max}}$ are excluded from detailed statistical comparison and summarized in aggregate accounting.

### TM-11.8-14: Unbalanced Sample Size Power Distortion
- **Threat**: Contributor A has $N_A = 5,000$ samples (massive statistical power, $p < 0.0001$ for tiny deviations), while Contributor B has $N_B = 35$ samples (low statistical power, $p = 0.08$ for large deviations).
- **Attack Surface**: Hypothesis test $p$-value comparison.
- **Impact**: Contributor A is flagged for trivial noise, while Contributor B's severe shift is overlooked if relying solely on $p$-values.
- **Mitigation**: Dual-gate decision framework: Statistical significance ($p_{\text{adj}} \le 0.05$) AND practical effect threshold ($\text{PSI} \ge 0.10$, $\text{TVD} \ge 0.05$). Contributor A's tiny divergence fails the effect gate; Contributor B's divergence is evaluated against physical distance metrics.
- **Residual Limitation**: Very small groups ($N < 30$) cannot achieve reliable statistical power and are fail-closed to `INSUFFICIENT_DATA`.

### TM-11.8-15: Representation Space Extraction Manipulation
- **Threat**: Adversary injects adversarial perturbations specifically designed to bypass linear feature metrics while altering high-dimensional latent representations.
- **Attack Surface**: Representation space analysis.
- **Impact**: Feature drift (Phase 11.4) reports clean status while latent representations are corrupted.
- **Mitigation**: Phase 11.8 integrates multivariate representation testing (Kernel MMD, Energy Distance) over frozen Phase 11.6 DINOv2 embeddings per source group.
- **Residual Limitation**: Relies on the representational coverage of the frozen DINOv2 ViT-S/14 backbone.

### TM-11.8-16: Source-Time Interaction Confounding
- **Threat**: Contributor A submitted all samples in January; Contributor B submitted all samples in July. Seasonal drift is falsely attributed to Contributor A.
- **Attack Surface**: Cross-dimensional temporal/source analysis.
- **Impact**: Misattributing temporal environmental non-stationarity to contributor heterogeneity.
- **Mitigation**: Metadata cross-referencing: Source profiles record temporal spans (`earliest_timestamp`, `latest_timestamp`). Disjoint temporal coverage is explicitly flagged as a confounding risk in finding summaries.
- **Residual Limitation**: Disentangling temporal from contributor shift without overlapping collection windows is mathematically unidentifiable.

### TM-11.8-17: Malicious Finding Framing & Defamation Risk
- **Threat**: An auditor or automated tool uses AIVARA finding output to accuse a legitimate contractor of fraud, sabotage, or malicious dataset poisoning.
- **Attack Surface**: Automated finding synthesis text and risk score generation.
- **Impact**: Unjust legal, organizational, or financial liability against benign contributors whose data naturally shifted (e.g., medical imaging hardware upgrade).
- **Mitigation**: Non-attribution invariant enforced in finding synthesis: `evidence_layer = "detection"`, neutral observational language strictly mandated ("Statistically significant distribution divergence observed in data associated with source X"). Accusatory terms (`malicious`, `poisoning`, `fraud`, `attack`) are strictly forbidden.
- **Residual Limitation**: Downstream human interpreters must be trained on the AIVARA evidence philosophy.

### TM-11.8-18: Non-Deterministic PRNG Subsampling Bias
- **Threat**: Uncontrolled random seeds in group subsampling produce varying drift conclusions across repeated runs of identical datasets.
- **Attack Surface**: Group subsampling logic.
- **Impact**: Non-reproducible audit reports, failure of audit dispute verification.
- **Mitigation**: Deterministic PRNG seeding derived via SHA-256 over `(project_id, dataset_id, source_id, contract_hash)` using Python's `random.Random(seed)` per Phase 11.2 standards.
- **Residual Limitation**: None. Bitwise reproducibility is guaranteed.

### TM-11.8-19: Unchecked Data Mutation During Grouping
- **Threat**: Group partitioning functions inadvertently modify in-memory observation objects or tensor payloads.
- **Attack Surface**: Group partitioner memory operations.
- **Impact**: Corrupted data inputs for downstream analysis phases.
- **Mitigation**: Input immutability contract: Grouping operates on shallow references or detached views; original arrays and dictionaries are never mutated in-place.
- **Residual Limitation**: Verified via unit tests asserting pre- and post-analysis object equality.

### TM-11.8-20: Cross-Modal Feature Incompatibility
- **Threat**: Source metadata contains mixed modalities (e.g., continuous pixel arrays in some records, categorical text tags in others) passed to inappropriate statistical tests.
- **Attack Surface**: Modality dispatcher.
- **Impact**: Runtime unhandled exceptions or mathematically invalid test statistics (e.g., running Two-Sample KS on discrete string tokens).
- **Mitigation**: Strict schema validation and modality typing per Phase 11.3 / 11.4 / 11.5 / 11.6 rules. Discrete strings are routed exclusively to Chi-Square/TVD; continuous tensors to KS/PSI/MMD.
- **Residual Limitation**: Incompatible features are logged as validation failures and excluded from statistical scoring.

---

## 4. Threat Model Summary & Security Controls

| Threat Category | Primary Risk | Key Architectural Control |
|---|---|---|
| **Identity & Provenance** | Spoofing, Reassignment, Replay | Cryptographic Content-Addressing & RFC 8785 Profiles |
| **Statistical Integrity** | Sybil Evasion, Multiplicity, Imbalance | Full Accounting, BH FDR $q^*=0.05$, Dual-Gate Decisions |
| **Privacy & Confidentiality** | Cross-Project Contributor Linkage | Project-Scoped Deterministic Pseudonymization |
| **System Availability** | High-Cardinality DoS Flooding | Hard Resource Limits ($G \le 50, N \le 5000$) |
| **Assurance Trust** | Accusatory Blame & False Attribution | Non-Attribution Invariant & Strictly Neutral Findings |
