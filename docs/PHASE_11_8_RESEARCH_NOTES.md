# PHASE 11.8 RESEARCH NOTES: CONTRIBUTOR & SOURCE-AWARE DISTRIBUTION SHIFT

================================================================================
PROJECT: AIVARA — AI Verification & Assurance
SUBSYSTEM: Phase 11 — Distribution Shift / Data Drift Analysis
PHASE: 11.8 — Contributor & Source-Aware Distribution Shift
SUBPHASE: 11.8.1 — Architecture & Requirements Freeze
STATUS: COMPLETE & AUTHORITATIVE
DATE: September 13, 2026
================================================================================

## 1. Executive Summary & Research Motivation

In machine learning and computer vision assurance, training and validation datasets rarely originate from a single monolithic, homogeneous source. Instead, real-world data aggregation pipelines ingest samples across disparate contributors, collection sites, imaging devices, sensor modalities, geographic regions, and data curation partners. 

While previous Phase 11 subphases focused on population-level dataset drift (Phase 11.4), image-specific shift (Phase 11.5), representation-space manifold drift (Phase 11.6), and time-ordered temporal non-stationarity (Phase 11.7), Phase 11.8 addresses **contributor- and source-aware distribution shift**.

The core mission of Phase 11.8 is to rigorously evaluate whether the statistical distribution of features, labels, or representations varies systematically as a function of data provenance attributes (e.g., contributor identity, acquisition channel, recording hardware, or collection site). Crucially, this evaluation must adhere strictly to AIVARA's fundamental non-attribution invariant: **identifying a source-associated distributional divergence is observational detection evidence, NOT proof of malicious intent, dataset poisoning, or contributor fraud.**

---

## 2. Technical Literature & Foundational Theory

### 2.1 Dataset Shift and Domain Adaptation Across Sources
In statistical learning theory, distribution shift across sources is formalized under the domain generalization / domain adaptation framework (Ben-David et al., 2010; Koh et al., WILDS Benchmark, 2021). Let $\mathcal{S} = \{s_1, s_2, \dots, s_G\}$ denote a set of categorical source groups. For each source $s \in \mathcal{S}$, data points $(X, Y) \sim \mathcal{P}_s(X, Y)$ are drawn from a source-specific joint distribution over input space $\mathcal{X}$ and target space $\mathcal{Y}$.

Dataset shift across sources manifests in several distinct statistical regimes:
1. **Covariate Shift Across Sources**: $\mathcal{P}_{s_i}(X) \neq \mathcal{P}_{s_j}(X)$ while conditional label distributions remain invariant: $\mathcal{P}_{s_i}(Y \mid X) = \mathcal{P}_{s_j}(Y \mid X)$. This occurs when contributors photograph different object types, use different focal lengths, or operate in different lighting environments.
2. **Prior Probability (Label) Shift Across Sources**: $\mathcal{P}_{s_i}(Y) \neq \mathcal{P}_{s_j}(Y)$ while class-conditional feature distributions remain invariant: $\mathcal{P}_{s_i}(X \mid Y) = \mathcal{P}_{s_j}(X \mid Y)$. For example, Contributor A submits 80% benign samples and 20% defective samples, whereas Contributor B submits 50% defective samples.
3. **Concept Drift / Conditional Shift Across Sources**: $\mathcal{P}_{s_i}(Y \mid X) \neq \mathcal{P}_{s_j}(Y \mid X)$, indicating divergent labeling standards, annotator subjectivity, or conflicting ground truth definitions across contributors.
4. **Acquisition / Batch Effects**: Systematic discrepancies introduced by recording hardware (sensor noise, white balance curves, compression codecs, optical distortions) rather than semantic object changes (Leek et al., Nature Reviews Genetics 2010).

### 2.2 Confounding and Simpson's Paradox
A major hazard in multi-source distribution analysis is **Simpson's Paradox** and unconditioned confounding.
Suppose Source $A$ collects images primarily in indoor settings (Class: Office, 90%) while Source $B$ collects images outdoors (Class: Street, 90%). An unconditional comparison of marginal feature distributions $P(X \mid S=A)$ vs $P(X \mid S=B)$ will reveal massive statistical shift (e.g., color temperature, edge density, illumination). However, within any single class $y \in \mathcal{Y}$, the conditional distributions $P(X \mid Y=y, S=A)$ and $P(X \mid Y=y, S=B)$ might be completely indistinguishable.

**Key Design Principle for AIVARA:**
Unconditional source comparisons must clearly declare that observed marginal shifts may be driven by label imbalance $\mathcal{P}(Y \mid S)$ rather than intrinsic within-class sensor/feature anomalies. The system must report both marginal source statistics $\mathcal{P}(X \mid S)$ and class proportions $\mathcal{P}(Y \mid S)$, surfacing potential confounding factors without drawing speculative causal conclusions.

### 2.3 Leave-One-Source-Out (LOSO) vs. Source-vs-Reference Topologies
When analyzing $G$ sources, there are multiple possible comparison topologies:
1. **Pairwise All-Against-All ($O(G^2)$)**:
   - Computes $\binom{G}{2} = \frac{G(G-1)}{2}$ comparisons.
   - For $G = 50$, this requires 1,225 pairwise statistical tests per feature, creating extreme multiple-testing penalties and quadratic compute costs.
2. **Source-vs-Reference ($O(G)$)**:
   - Compares each target source group $s_g$ against a certified, immutable reference source $s_{\text{ref}}$: $\mathcal{P}_{s_g}$ vs $\mathcal{P}_{s_{\text{ref}}}$.
   - Linear complexity ($G-1$ comparisons). Clean baseline semantics without circularity or reference contamination.
3. **Leave-One-Source-Out (LOSO) / Pooled-Complement ($O(G)$)**:
   - Compares source $s_g$ against the pooled aggregate of all remaining sources $\mathcal{S} \setminus \{s_g\}$.
   - *Hazards*: Vulnerable to group size dominance (a single large contributor comprising 90% of the dataset will define the "pooled" baseline for all smaller contributors), sample leakage, and circular dependencies.

**Decision for AIVARA v1**: Primary topology is **Source-vs-Reference ($O(G)$)** with explicit baseline selection. When an explicit reference source is not designated, the system supports **Source-vs-Baseline Population ($O(G)$)** comparing each source against a validated Reference Population (Phase 11.2).

---

## 3. Multiple Testing & Multiplicity Control

### 3.1 Family-Wise Error vs. False Discovery Rate
Evaluating $M$ features across $G$ source groups generates $M \times G$ hypothesis tests. Without multiplicity control, testing 10 features across 20 sources at $\alpha = 0.05$ produces an expected false discovery count of $200 \times 0.05 = 10$ false alarms under the global null.

AIVARA enforces Benjamini–Hochberg False Discovery Rate (FDR) control at nominal $q^* = 0.05$ (Benjamini & Hochberg, 1995).

### 3.2 Family Definition
To ensure rigorous statistical guarantees without over-conservative penalties:
- **Primary Source Family**: The set of all source comparisons for a specific feature or modality: $\{H_{0, g}^{(f)}: \mathcal{P}_{s_g}^{(f)} = \mathcal{P}_{\text{ref}}^{(f)}\}_{g=1}^G$.
- **Holm–Bonferroni Step-Down (FWER)**: Applied when evaluating a composite global dataset alert across features.
- Double-correction (e.g., applying BH over already BH-adjusted $p$-values) is strictly prohibited.

---

## 4. Dual-Gate Decision Policy (Statistical Significance + Practical Effect)

Statistical significance alone is insufficient for practical assurance. On large datasets ($N_g \ge 1,000$), two-sample tests (e.g., Kolmogorov-Smirnov) achieve astronomical statistical power ($p < 10^{-15}$) even for trivially imperceptible divergences ($\Delta \mu < 0.001\sigma$).

Therefore, Phase 11.8 reuses Phase 11.3 dual-gate decision logic:
$$\text{Shift}(s_g, f) = \text{TRUE} \iff (p_{\text{adj}} \le 0.05) \land (\text{EffectSize}(s_g, \text{ref}, f) \ge \theta_{\text{effect}})$$

### Approved Effect Metrics & Thresholds:
- **Continuous 1D Features**: Population Stability Index ($\text{PSI} \ge 0.10$) or 1D Wasserstein Distance ($W_1$).
- **Categorical / Label Features**: Total Variation Distance ($\text{TVD} \ge 0.05$) or Jensen-Shannon Divergence ($\text{JSD} \ge 0.05$).
- **High-Dimensional Embeddings**: Kernel Maximum Mean Discrepancy ($\text{MMD}^2 \ge 0.02$) or Energy Distance ($E \ge 1.0$).

---

## 5. Contributor vs. Source Disambiguation

| Attribute | Contributor (`contributor_id`) | Source (`source_id`) |
|---|---|---|
| **Definition** | The legal entity, human annotator, organization, or user account responsible for contributing or curating the data. | The physical, technical, or acquisition origin context (e.g., camera sensor serial, collection pipeline version, lab site, API ingestion endpoint). |
| **Cardinality** | A single contributor may operate multiple capture devices or sources ($1 \to N$). | A single source (e.g., shared lab microscope) may be utilized by multiple contributors ($N \to 1$). |
| **Trust Model** | Claimed identity (often external metadata subject to spoofing, aliasing, or privacy pseudonymization). | Technical context metadata (often recorded in hardware headers, EXIF tags, or ingestion logs). |
| **Privacy Sensitivity** | High (subject to GDPR/CCPA PII protections, requiring project-isolated pseudonymization/hashing). | Moderate-to-Low (hardware specifications, pipeline tags). |

AIVARA v1 establishes a unified, generic **Source Attribute Context** (`SourceContext`) that encapsulates both contributor identities and origin channels while maintaining strict project isolation and pseudonymization.

---

## 6. Privacy & Cross-Project Linkability Risks

### 6.1 Linkability Threat
If raw contributor IDs (e.g., email addresses, usernames, real names) are persisted directly into cryptographic hashes or audit profiles, an attacker with access to audit reports from Project A and Project B could link contributor activities across organizational boundaries, violating data protection regulations and confidentiality agreements.

### 6.2 Architectural Privacy Guarantees:
1. **Canonical Pseudonymization**: Contributor identifiers are canonicalized and deterministically pseudonymized within a project scope:
   $$\text{PseudonymID} = \text{SHA-256}(\text{project\_id} \mathbin{\Vert} \text{salt} \mathbin{\Vert} \text{canonical\_raw\_id})[:16]$$
2. **Strict Project Isolation**: A contributor active in Project A and Project B receives distinct, unlinkable pseudonymized identifiers in each project.
3. **Zero Raw Metadata Leakage**: Raw contributor PII is never serialized into persistent `FindingModel` descriptions, `EvidenceModel` payloads, or public-facing export profiles.

---

## 7. Adversarial Threats in Multi-Contributor Environments

Adversarial contributors or untrusted data vendors may attempt to evade quality controls or distort model training through metadata tampering:
1. **Source Fragmentation / Sybil Attacks**: An attacker splits 1,000 anomalous samples across 50 fake contributor accounts (20 samples each) to drop below the minimum group sample size ($N_{\text{min}} = 30$), evading statistical group testing.
2. **Source Spoofing / Camouflage**: An attacker tags poisoned or corrupted data with the identifier of a reputable, high-trust contributor.
3. **Dominance Manipulation**: A single large contributor submits 95% of total dataset volume, overwhelming pooled statistics and suppressing minority source signals.
4. **Metadata Stripping / Null Flooding**: Stripping provenance tags so samples fall into `MISSING` or `UNKNOWN` source bins.

### Mitigations:
- Strict **Source Accounting**: All observations must reconcile: $\text{Total} = \text{Eligible} + \text{Insufficient} + \text{Missing} + \text{Invalid} + \text{Unknown}$.
- Explicit **Fragmentation Warnings**: High volumes of small, unanalyzable groups ($N_g < 30$) trigger structural metadata warnings (`EXCESSIVE_SOURCE_FRAGMENTATION`).
- Non-conflation of claimed metadata with cryptographic proof.

---

## 8. Cross-Phase Architectural Composition

Phase 11.8 composes seamlessly with the existing frozen subsystem architecture:
- **Phase 11.2 (Boundary & Sampling)**: Reuses population boundaries, metadata validation, and deterministic seeded PRNG subsampling for groups with $N_g > N_{\text{max}}$.
- **Phase 11.3 (Statistical Drift Engine)**: Reuses all univariate, categorical, and multivariate two-sample hypothesis tests (Two-Sample KS, Chi-Square, Permutation MMD, Energy Distance). Zero duplicate statistical mathematics.
- **Phase 11.4 (Feature Drift)**: Reuses tabular feature extraction and PSI/TVD metrics.
- **Phase 11.5 (Image Drift)**: Reuses image feature descriptors (color histograms, sharpness, aspect ratio, luminance).
- **Phase 11.6 (Representation Drift)**: Reuses frozen 384-dimensional DINOv2 ViT-S/14 embeddings and multivariate MMD/Energy testing.
- **Phase 11.7 (Temporal Drift)**: Consumes source-specific temporal distributions as contextual cross-dimensional metadata without duplicate windowing calculations.

---

## 9. Key Conclusions & Next Steps

1. Phase 11.8 architecture must enforce strict separation between **observational source-associated distributional divergence** and **causal / malicious culpability**.
2. Group comparison topology must be linear $O(G)$ via explicit reference source or baseline population comparison.
3. Privacy must be preserved through project-scoped pseudonymization.
4. The architecture, threat model, formal requirements, and decision records are ready for formal specification.
