# AIVARA — Contributor Risk Architecture Specification
## Phase 6.1: Architecture Review & Design Freeze (Corrected)

**Version:** 1.1.0-frozen  
**Status:** DESIGN FROZEN (Implementation Target: Phase 6.2)  
**Security Classification:** Local / Air-Gapped AI Verification & Assurance  
**Target Subsystem:** Phase 6 — Contributor Risk Engine (CRE)  
**Evidence Layer:** `evidence_layer="detection"` for analytical indicators; `evidence_layer="proof"` for cryptographic provenance  
**Database Schema Changes:** NONE (Zero new tables, zero migrations)  
**Cryptographic Changes:** NONE (Phase 4 cryptographic engine preserved)  
**Phase 5 Impact:** NONE (Phase 5 dataset integrity engine frozen)  

---

## 1. Purpose & Core Philosophy

The **Contributor Risk subsystem (Phase 6)** provides a deterministic, mathematically rigorous, and evidence-traceable framework for evaluating **contributor-associated data reliability, consistency, anomaly concentration, and provenance integrity** across AI training and evaluation datasets.

```
       EVIDENCE  ──►  FINDING  ──►  CONFIDENCE  ──►  RISK  ──►  DECISION
          │              │              │              │            │
      (Phase 5)      (Phase 5)      (Phase 5/6)    (Phase 6/12)  (Phase 12)
```

### The Central Question
The Contributor Risk subsystem is designed exclusively to answer:
> *"What measurable, verifiable evidence exists regarding contributor-associated anomaly patterns, labeling consistency, distribution deviations, and provenance quality?"*

It is fundamentally forbidden from attempting to answer:
> *"Is this contributor malicious or deliberately attempting to sabotage the model?"*

### Foundational Semantic Invariants

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   INVARIANT 1:  ANOMALY ≠ MALICIOUSNESS                                     │
│   INVARIANT 2:  DETECTION EVIDENCE ≠ PROOF OF GUILT                         │
│   INVARIANT 3:  CONTRIBUTOR SPECIALIZATION ≠ DATASET POISONING              │
│   INVARIANT 4:  INTER-ANNOTATOR DISAGREEMENT ≠ FRAUD                        │
│   INVARIANT 5:  UNATTRIBUTED / MISSING PROVENANCE ≠ TAMPERING               │
│   INVARIANT 6:  MULTI-CONTRIBUTOR EXPOSURE MUST BE CONSERVED (1/K)          │
│   INVARIANT 7:  CORRELATED DETECTORS MUST NOT MULTIPLY RISK (NO OVERCOUNT)  │
│   INVARIANT 8:  NO OPAQUE BLACK-BOX SCALAR RISK SCORES                      │
│   INVARIANT 9:  PROOF-LAYER EVIDENCE MUST NOT BE NUMERICALLY POOLED        │
│                 WITH DETECTION-LAYER ANOMALY SCORES                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Scope & Target Subsystem

### 2.1 Scope (Phase 6 In-Scope)
1. **Separated Detection vs. Proof Profile:** Structured assessment separating probabilistic analytical metrics (`evidence_layer="detection"`) from deterministic cryptographic verification (`evidence_layer="proof"`).
2. **Contextual Leave-One-Out (LOO) & Subgroup Baselines:** Computing statistical differentials ($\Delta = R_{\text{contributor}} - R_{\text{baseline}}$) conditioned on class, domain, and sensor subgroups to eliminate Simpson's Paradox.
3. **Small-Sample Safety & Empirical Bayes Shrinkage:** Conservative prior-weighted shrinkage preventing small-batch annotators from generating spurious risk signals.
4. **Fractional Multi-Contributor Attribution:** Strict $1/K$ weight propagation ensuring that multi-contributor samples distribute exposure proportionally without artificial inflation.
5. **Dependency-Aware Evidence Families:** Partitioning detector evidence into structured families to prevent correlated detectors from compounding penalties.
6. **Immutable Execution & Traceability:** Deterministic RFC 8785 (JCS) canonical execution identities linked to Phase 4 cryptographic provenance via existing Phase 5.9 adapters.

### 2.2 Out-of-Scope (Strict Non-Goals)
1. **No Psychological / Intent Inference:** No assessment of contributor motives, honesty, or malice.
2. **No Opaque Universal "Threat Score":** No uncalibrated scalar (e.g., $87/100$) devoid of component-level traceability.
3. **No Temporal Behavioral Tracking (Phase 8):** Real-time burst dynamics, keystroke/mouse velocity, session fatigue, and user-agent forensics belong strictly to Phase 8 (Behavioral Analysis).
4. **No Cross-Domain Organizational Decision Support (Phase 12):** Global multi-dataset risk synthesis, automated policy quarantine, and cross-project executive dashboards belong strictly to Phase 12 (Universal Evidence + Risk Engine).
5. **No Model Retraining / Active Learning:** The subsystem never initiates training runs, fine-tuning, or active-learning loops (ADR-014).

---

## 3. Authoritative Terminology & Semantic Safety

### 3.1 Strict Invariant on Intent vs. Technical Terminology

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   TECHNICAL SECURITY TERMINOLOGY IS ALLOWED.                                │
│   UNSUPPORTED HUMAN INTENT / CULPABILITY INFERENCE IS NOT.                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

- **Prohibited:** Unsupported assertions of human intent, motive, guilt, culpability, maliciousness, deliberate human action, fraud, or sabotage.
- **Permitted Technical Terminology:** Standard technical, statistical, and security terminology is explicitly allowed where technically appropriate:
  - `adversarial example`
  - `adversarial perturbation`
  - `adversarial robustness`
  - `attack simulation`
  - `backdoor trigger`
  - `data poisoning experiment`
  - `poisoning attack`
  - `threat model`
  - `out-of-distribution anomaly`
  - `directional label transition`

### 3.2 Domain Terminology Mapping

| Forbidden Accusatory Human Assertion | Mandatory AIVARA Domain Term | Semantic Rationale |
| :--- | :--- | :--- |
| *Malicious contributor / Bad actor* | **High-Anomaly Association Contributor** | Focuses on observed data properties, not actor character. |
| *Sabotaged dataset / Malicious intent* | **Directional / Asymmetric Label Transition** | Reflects statistical transition asymmetry without asserting intent. |
| *Fraudulent Annotator / Cheater* | **Low Inter-Annotator Agreement / Low Consistency** | Distinguishes task difficulty/ambiguity from intentional cheating. |
| *Guilt score / Threat score* | **Contributor Risk Profile / Metric Differential ($\Delta$)** | Expresses deviation from baseline in measurable units. |
| *Culpable / Liable* | **Attributed Proportion ($w_{s,c} = 1/K$)** | Pure fractional mathematical attribution of sample observation. |

---

## 4. Subsystem Architecture & System Context

```
                      PHASE 5: DATASET INTEGRITY SUBSYSTEM
   ┌────────────────────────────────────────────────────────────────────────┐
   │ Phase 5.3: Multi-Tier Fingerprinting & Merkle Trees                   │
   │ Phase 5.4: Near-Duplicate Detection (pHash/dHash)                      │
   │ Phase 5.5: Label Anomalies & Confident Learning (y*_hat)               │
   │ Phase 5.6: Targeted Directional Label Flipping                         │
   │ Phase 5.7: Out-of-Distribution & Image Quality Degradation             │
   │ Phase 5.8: Contributor Aggregation Engine (Base Metrics)               │
   │ Phase 5.9: Canonical Evidence Identity & Provenance Ledger             │
   └───────────────────────────────────┬────────────────────────────────────┘
                                       │
                                       ▼ (Evidence Models & Aggregations)
   ┌────────────────────────────────────────────────────────────────────────┐
   │             PHASE 6: CONTRIBUTOR RISK ENGINE (CRE)                     │
   │                                                                        │
   │  ┌──────────────────────────────────────────────────────────────────┐  │
   │  │ 1. Attribution Normalizer & Multi-Contributor Expander (1/K)     │  │
   │  └────────────────────────────────┬─────────────────────────────────┘  │
   │                                   ▼                                    │
   │  ┌──────────────────────────────────────────────────────────────────┐  │
   │  │ 2. Contextual Baseline Engine (LOO + Class-Conditional)          │  │
   │  └────────────────────────────────┬─────────────────────────────────┘  │
   │                                   ▼                                    │
   │  ┌──────────────────────────────────────────────────────────────────┐  │
   │  │ 3. Small-Sample Guardrail & Empirical Bayes Shrinkage Estimator   │  │
   │  └────────────────────────────────┬─────────────────────────────────┘  │
   │                                   ▼                                    │
   │  ┌──────────────────────────────────────────────────────────────────┐  │
   │  │ 4. Dependency-Aware Evidence Family Evaluator                    │  │
   │  └────────────────────────────────┬─────────────────────────────────┘  │
   │                                   ▼                                    │
   │  ┌──────────────────────────────────────────────────────────────────┐  │
   │  │ 5. Structured Contributor Risk Profile Synthesizer               │  │
   │  │    ├── Detection Profile [Label, Transition, Quality, OOD]       │  │
   │  │    └── Proof Profile     [Provenance Integrity (Deterministic)]  │  │
   │  └────────────────────────────────┬─────────────────────────────────┘  │
   │                                   ▼                                    │
   │  ┌──────────────────────────────────────────────────────────────────┐  │
   │  │ 6. Traceable Risk Evidence Binder (RFC 8785 Canonical Bridge)    │  │
   │  └──────────────────────────────────────────────────────────────────┘  │
   └───────────────────────────────────┬────────────────────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
        Phase 5.9 / 4 Provenance Ledger       Phase 12 Universal Risk Engine
        (Ed25519 Sealed Record)             (Global Decision Support)
```

---

## 5. Mathematical Risk Formulation & Empirical Bayes Policy

### 5.1 Multi-Contributor Fractional Exposure
Let dataset $\mathcal{D} = \{s_1, s_2, \dots, s_N\}$ be a collection of $N$ samples. Each sample $s_i$ has a set of attributed contributors $\mathcal{C}(s_i) = \{c_{i,1}, \dots, c_{i, K_i}\}$.

The fractional weight of sample $s_i$ attributed to contributor $c$ is:
$$w_{i, c} = \begin{cases} \frac{1}{|\mathcal{C}(s_i)|} = \frac{1}{K_i} & \text{if } c \in \mathcal{C}(s_i) \\ 0 & \text{otherwise} \end{cases}$$

**Invariant (Conservation of Exposure):**
$$\sum_{c \in \mathcal{C}_{\text{total}}} w_{i, c} = 1.0 \quad \forall s_i \in \mathcal{D}$$

The effective exposure of contributor $c$ is:
$$N_c = \sum_{i=1}^N w_{i, c}$$

### 5.2 Contextual Leave-One-Out (LOO) Baseline
For any metric event $E$ (e.g., sample flagged for label anomaly), let $y_i(E) \in \{0, 1\}$ indicate presence of event $E$ on sample $s_i$.

1. **Contributor Empirical Rate:**
   $$\hat{p}_c(E) = \frac{\sum_{i=1}^N w_{i, c} \cdot y_i(E)}{N_c}$$

2. **Leave-One-Out (LOO) Dataset Baseline:**
   $$p_{\text{LOO}, c}(E) = \frac{\sum_{j \notin \mathcal{S}_c} y_j(E)}{N - |\mathcal{S}_c|}$$
   where $\mathcal{S}_c = \{s_i \in \mathcal{D} \mid c \in \mathcal{C}(s_i)\}$.

3. **Subgroup-Stratified Baseline (for stratum $g$, e.g., Class $k$):**
   $$p_{\text{sub}, g, c}(E) = \frac{\sum_{s_j \in \mathcal{D}_g \setminus \mathcal{S}_c} y_j(E)}{|\mathcal{D}_g \setminus \mathcal{S}_c|}$$

### 5.3 Frozen Empirical Bayes Prior-Selection Policy (v1)
To prevent small contributor sample counts ($N_c < 30$) from generating erratic, over-confident rate estimates, CRE uses a deterministic **Baseline-Derived Beta-Binomial Empirical Bayes Prior**:

1. **Prior Mean ($\mu_0$):**
   $$\mu_0 = p_{\text{LOO}, c}(E)$$
2. **Prior Sample Size Parameter ($M_0$):**
   $$M_0 = 20.0 \quad (\text{Deterministic v1 Policy})$$
   *Reasoning:* A prior weight of $M_0 = 20.0$ represents a conservative pseudo-count equivalent to 20 background samples. This ensures that an annotator with only 5 samples has their rate shrunk by $80\%$ toward the background rate, preventing spurious flags.
3. **Beta Prior Hyperparameters:**
   $$\alpha_0 = \mu_0 \cdot M_0 = 20.0 \cdot p_{\text{LOO}, c}$$
   $$\beta_0 = (1 - \mu_0) \cdot M_0 = 20.0 \cdot (1 - p_{\text{LOO}, c})$$
4. **Shrinkage Factor ($\lambda_c$):**
   $$\lambda_c = \frac{N_c}{N_c + M_0} = \frac{N_c}{N_c + 20.0}$$
5. **Posterior Shrunk Contributor Rate:**
   $$\tilde{p}_c(E) = \frac{k_c + \alpha_0}{N_c + M_0} = \lambda_c \hat{p}_c(E) + (1 - \lambda_c) p_{\text{LOO}, c}(E)$$
   where $k_c = \sum_{i=1}^N w_{i, c} y_i(E)$ is the effective anomaly count.

### 5.4 Support Tier Behavior Table

```
┌──────────────────┬──────────────────────┬─────────────────┬───────────────────────────────────────────────────────┐
│ Effective Count  │ Shrinkage Factor     │ Support Status  │ Operational Semantic Action                           │
├──────────────────┼──────────────────────┼─────────────────┼───────────────────────────────────────────────────────┤
│ $N_c < 3$        │ $\lambda_c < 0.13$   │ `UNVERIFIABLE`  │ Rate omitted; status UNVERIFIABLE; 0 risk indicators. │
│ $3 \le N_c < 10$ │ $0.13 \le \lambda < 0.33$│ `LOW_SUPPORT` │ Rate shrunk by $\ge 67\%$; informative notice only.   │
│ $10 \le N_c < 30$│ $0.33 \le \lambda < 0.60$│ `MODERATE`    │ Empirical Bayes shrinkage active; moderate confidence.│
│ $N_c \ge 30$     │ $\lambda_c \ge 0.60$ │ `ADEQUATE`      │ Converges toward empirical rate; full confidence.     │
└──────────────────┴──────────────────────┴─────────────────┴───────────────────────────────────────────────────────┘
```

### 5.5 Metric Differential & Standard Error
The calibrated differential is:
$$\Delta_c(E) = \tilde{p}_c(E) - p_{\text{LOO}, c}(E)$$
$$\text{SE}(\Delta_c) = \sqrt{\frac{\tilde{p}_c(1 - \tilde{p}_c)}{N_c + M_0} + \frac{p_{\text{LOO}}(1 - p_{\text{LOO}})}{N_{\text{LOO}}}}$$

---

## 6. Dependency-Aware Evidence Families & Anti-Double-Counting

### 6.1 Architectural Separation vs. Statistical Independence
Detector outputs across computer vision pipelines are frequently **statistically correlated**. For example, poor sensor focus creates blur (Phase 5.7), induces out-of-distribution feature distance (Phase 5.7), and degrades confident learning classification probability (Phase 5.5).

CRE explicitly acknowledges that detector outputs are not statistically independent. To prevent linear accumulation of correlated penalties, evidence is grouped into **Four Dependency-Aware Evidence Families**:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                 DEPENDENCY-AWARE EVIDENCE FAMILIES                          │
├─────────────────────────────────────────────────────────────────────────────┤
│ Family 1: Label Integrity (Detection Layer)                                 │
│   - Inputs: Confident Learning (5.5), Targeted Label Flipping TFS (5.6)     │
│   - Focus: Inconsistency between observed labels and model latent estimates │
│                                                                             │
│ Family 2: Physical Quality (Detection Layer)                                │
│   - Inputs: Luminance, Exposure, Sharpness/Blur, Noise, Blockiness (5.7)    │
│   - Focus: Physical image capture and compression artifacts                 │
│                                                                             │
│ Family 3: Distribution Shift (Detection Layer)                              │
│   - Inputs: Feature embeddings, Mahalanobis distance, OOD metrics (5.7)     │
│   - Focus: Feature-space drift relative to in-distribution reference       │
│                                                                             │
│ Family 4: Cryptographic Provenance (Proof Layer - STRICTLY ISOLATED)        │
│   - Inputs: Ed25519 Signatures, Hash Chains, Nonces, Key Validity (4.x/5.9) │
│   - Focus: Deterministic cryptographic integrity of contribution metadata   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Family-Level Aggregation & Anti-Double-Counting Rules
1. **No Cross-Family Numerical Pooling:** The system **NEVER** computes a single composite score across families. Each family retains its distinct differential and confidence.
2. **Family-Level Dominance Rule (Max Differential):** Within an evidence family $F$, the family's observed deviation is bounded by the *maximum validated differential* among its constituent detectors, rather than their sum:
   $$\Delta_{\text{family}}(F) = \max_{e \in F} \left( \Delta_c(e) \right)$$
   This guarantees that three correlated quality metrics (e.g., underexposure + blur + low contrast) cannot trigger a $3\times$ stacked penalty for the same physical issue.
3. **Strict Isolation of Proof-Layer Evidence:** Proof-layer evidence (cryptographic provenance) is **NEVER** numerically averaged, weighted, or pooled with detection-layer anomaly scores. Provenance status is reported as an independent cryptographic verification state (`VERIFIED`, `INVALID`, `MISSING`, `UNAVAILABLE`, `MISMATCHED`, `UNVERIFIABLE`).

---

## 7. Structure of the Contributor Risk Profile

In accordance with ADR-030, AIVARA outputs a strongly-typed, explainable **Contributor Risk Profile** partitioned cleanly into a **Detection Profile** and a **Proof Profile**:

```
Contributor Risk Profile
│
├── Metadata & Support Status
│   ├── Contributor ID & External References
│   ├── Effective Sample Count ($N_c$)
│   └── Support Tier (`ADEQUATE` | `MODERATE` | `LOW_SUPPORT` | `UNVERIFIABLE`)
│
├── Detection Profile (`evidence_layer="detection"`)
│   ├── Label Reliability Dimension
│   │   ├── Observed Rate, Baseline Rate, Differential ($\Delta$)
│   │   ├── Calibrated Confidence & Standard Error
│   │   └── Referenced Evidence IDs
│   ├── Transition Asymmetry Dimension
│   │   ├── Targeted Flip Score (TFS), Noise Concentration Index (NCI)
│   │   └── Directional Class Pairs
│   ├── Quality Divergence Dimension
│   │   ├── Metric Differentials (Luminance, Blur, Artifacts)
│   │   └── Physical Degradation Indicators
│   └── Distribution Shift Dimension
│       ├── Feature Distance Differential
│       └── Reference Dataset Identifiers
│
└── Proof Profile (`evidence_layer="proof"`)
    └── Provenance Integrity
        ├── Verification Status (`VERIFIED` | `INVALID` | `MISSING` | etc.)
        ├── Signer Key ID & Lifecycle State
        ├── Monotonic Chain Sequence & Nonce Verification
        └── Deterministic Confidence ($1.0$)
```

### Deterministic Profile Status Interpretation
If an executive overview status is requested, it is evaluated strictly as a deterministic rule-based mapping (not a numerical formula):

```
┌──────────────────────────────────────────────┬────────────────────────────────────────────────────────┐
│ Profile Condition                            │ Contributor Profile Status                             │
├──────────────────────────────────────────────┼────────────────────────────────────────────────────────┤
│ Proof Status == `INVALID`                    │ `PROVENANCE_INTEGRITY_VIOLATION`                       │
│ Proof Status == `MISSING`                    │ `UNVERIFIED_PROVENANCE`                                │
│ Support Tier == `UNVERIFIABLE`               │ `INSUFFICIENT_EVIDENCE`                                │
│ Any Detection Differential $\Delta > 0.20$   │ `ELEVATED_ANOMALY_CONCENTRATION`                       │
│ Any Detection Differential $\Delta \in [0.10, 0.20]$│ `MODERATE_DEVIATION`                              │
│ All Detection Differentials $\Delta < 0.10$  │ `BASELINE_CONGRUENT`                                   │
└──────────────────────────────────────────────┴────────────────────────────────────────────────────────┘
```

---

## 8. Provenance & Execution Identity Integration

Phase 6 does **NOT** invent a new cryptographic system or secondary provenance ledger. It integrates seamlessly with the existing Phase 5.9 and Phase 4 infrastructure:

```
  Phase 6: Contributor Risk Engine
                 │
                 ▼ (Produces deterministic profile payload)
  Phase 5.9: ExecutionIdentityPayload (RFC 8785 JCS Canonicalization)
                 │
                 ▼ (Synthesizes finding & evidence models)
  Phase 5.9: EvidenceProvenanceService.record_analytical_scan()
                 │
                 ▼ (Signs and chains record)
  Phase 4: ProvenanceChain & Ed25519 KeyManager
```

### Execution Identity Fields
The execution identity strictly binds all result-altering parameters using Phase 5.9's `ExecutionIdentityPayload`:
- `project_id`: Target project UUID
- `dataset_version_id`: Audited dataset version
- `dataset_fingerprint`: Cryptographic SHA-256 dataset hash
- `detector_id`: `"ContributorRiskEngine"`
- `detector_version`: `"1.0.0"`
- `engine_version`: `"1.0.0"`
- `policy_version`: Active policy version string (e.g., `"v1_conservative"`)
- `detector_config_hash`: SHA-256 of canonicalized configuration parameters ($M_0$, thresholds)
- `reference_dataset_fingerprint`: Optional baseline reference dataset hash
- `model_fingerprint`: Optional reference model weights hash

---

## 9. Phase Boundaries & Non-Overlapping Responsibilities

```
┌──────────────────────────────────────────────┬──────────────────────────────────────────────┐
│ PHASE 6: CONTRIBUTOR RISK (CRE)              │ PHASE 8: BEHAVIORAL ANALYSIS (CBA)           │
├──────────────────────────────────────────────┼──────────────────────────────────────────────┤
│ Static Dataset Artifact Focus                │ Temporal Interaction & Session Dynamics      │
│ Aggregated cross-sectional distribution      │ Time-series sequence and burst analysis      │
│ Label consistency & error differentials      │ Annotator velocity, cadence & jitter         │
│ Image quality & feature distributions        │ Session fatigue & circadian drift            │
│ Cryptographic provenance record state        │ Keystroke dynamics, UI telemetry & client IPs│
│ Inputs: Manifests, Annotations, Images       │ Inputs: Audit event logs, Session streams    │
└──────────────────────────────────────────────┴──────────────────────────────────────────────┘

┌──────────────────────────────────────────────┬──────────────────────────────────────────────┐
│ PHASE 6: CONTRIBUTOR RISK (CRE)              │ PHASE 12: UNIVERSAL RISK ENGINE (URE)        │
├──────────────────────────────────────────────┼──────────────────────────────────────────────┤
│ Domain-Specific Contributor Analytical Layer │ Cross-Domain Universal Synthesis Layer       │
│ Produces Contributor Profiles & Evidence     │ Consumes Contributor, Model & Pipeline Risks │
│ Evaluates individual contributors            │ Evaluates entire AI system deployment risk   │
│ Outputs `evidence_layer="detection"`         │ Computes organizational disposition decisions│
│ No automated quarantine decisions            │ Determines Accept / Review / Quarantine      │
└──────────────────────────────────────────────┴──────────────────────────────────────────────┘
```

---

## 10. Database Impact: ZERO Schema Changes

Phase 6 requires **ZERO** database schema changes or migrations:
- Contributor entities are stored in `contributors` (`ContributorModel`).
- Fractional sample links are stored in `sample_contributors` (`SampleContributorModel`).
- Contributor risk findings are stored in `findings` (`FindingModel`, `affected_asset_type="contributor"`).
- Profile metrics and differentials are stored in `evidence` (`EvidenceModel`).
- Scoped summaries are stored in `risk_assessments` (`RiskAssessmentModel`, `scope="contributor"`).
- Sealed provenance records are stored in `provenance_records` (`ProvenanceRecordModel`).

---

## 11. Architectural Decision Records (ADRs)

### ADR-030: Multi-Dimensional Contributor Risk Vector over Scalar Scoring
- **Status:** ACCEPTED
- **Context:** Collapsing multi-engine contributor signals into a single scalar score (e.g., $85/100$) destroys explainability and violates ADR-002.
- **Decision:** CRE will output a structured vector profile separating Detection from Proof. Scalar scores are prohibited.
- **Consequences:** Dashboards and APIs present component breakdowns; decisions remain fully auditable.

### ADR-031: Contextual Leave-One-Out (LOO) and Subgroup Baselines
- **Status:** ACCEPTED
- **Context:** Global dataset averages penalize annotators assigned to difficult classes (Simpson's Paradox).
- **Decision:** CRE will compute class-conditional Leave-One-Out baselines for all rate differentials.
- **Consequences:** Eliminates false accusations against specialized domain annotators.

### ADR-032: Empirical Bayes Prior-Derived Shrinkage for Small-Sample Safety
- **Status:** ACCEPTED
- **Context:** Small sample counts produce erratic rate estimates ($1/1 = 100\%$).
- **Decision:** Apply Beta-Binomial Empirical Bayes shrinkage with fixed prior strength $M_0 = 20.0$.
- **Consequences:** Eliminates small-sample false alarms; contributors with $N_c < 3$ evaluate to `UNVERIFIABLE`.

### ADR-033: Conservation of Fractional Attribution ($1/K$)
- **Status:** ACCEPTED
- **Context:** Multi-contributor samples must not count as full evidence against all annotators simultaneously.
- **Decision:** Strictly enforce $w_{s,c} = 1/K$ fractional weight conservation across all CRE calculations.
- **Consequences:** Sample counts and anomaly counts remain strictly conserved.

### ADR-034: Dependency-Aware Evidence Families and Proof-Layer Isolation
- **Status:** ACCEPTED
- **Context:** Detector outputs may be correlated; pooling cryptographic proof with statistical anomaly scores is invalid.
- **Decision:** Partition evidence into Dependency-Aware Families, use family-level dominance, and strictly isolate the Proof Profile.
- **Consequences:** Prevents correlated detector cascades from multiplying risk; preserves cryptographic integrity guarantees.

### ADR-035: Semantic Safety and Intent Invariant
- **Status:** ACCEPTED
- **Context:** Statistical anomalies must never be conflated with maliciousness or intentional sabotage, while legitimate technical security terminology must remain available.
- **Decision:** Prohibit unsupported assertions of human intent, motive, guilt, culpability, or maliciousness. Standard technical security terms (`adversarial perturbation`, `poisoning attack`, `backdoor trigger`) remain permitted.
- **Consequences:** Defensible, neutral, observation-based reporting aligned with Phase 5.9 vocabulary guards.

### ADR-036: Phase 8 (Behavioral) vs Phase 6 (Contributor Risk) Boundary
- **Status:** ACCEPTED
- **Context:** Potential overlap between contributor artifact analysis and behavioral interaction analysis.
- **Decision:** Phase 6 analyzes static dataset artifacts; Phase 8 analyzes temporal session dynamics and keystroke/UI interactions.
- **Consequences:** Clean separation of concerns; no duplicate subsystems.

### ADR-037: Phase 12 (Universal Risk) vs Phase 6 (Contributor Risk) Boundary
- **Status:** ACCEPTED
- **Context:** Contributor Risk must not attempt to become the universal organizational risk engine.
- **Decision:** Phase 6 produces contributor-level detection profiles; Phase 12 performs cross-domain risk synthesis and disposition decisions.
- **Consequences:** Preserves modularity and the two-layer assurance architecture.

### ADR-038: Zero Database Schema Changes for Phase 6
- **Status:** ACCEPTED
- **Context:** Phase 3 schema and Phase 4/5 models already provide adequate relational tables.
- **Decision:** Phase 6 will strictly reuse existing `ContributorModel`, `FindingModel`, `EvidenceModel`, `RiskAssessmentModel`.
- **Consequences:** Zero database migrations required; backward compatibility guaranteed.

### ADR-039: Canonical Execution Identity for Contributor Risk
- **Status:** ACCEPTED
- **Context:** Contributor Risk assessments must be verifiable and tamper-evident.
- **Decision:** Generate RFC 8785 canonical execution hashes binding all input hashes, policies, and detector configurations.
- **Consequences:** Full reproducibility and seamless integration with Phase 4 cryptographic provenance.

---

## 12. Freeze Checklist & Review Sign-Off

```
[x] Contributor Risk has a precise mathematical and semantic definition (§1, §5)
[x] Semantic safety rule distinguishes prohibited human intent from permitted technical terms (§3, ADR-035)
[x] No opaque black-box scalar risk scores (§7, ADR-030)
[x] Detection Profile and Proof Profile are strictly separated (§6, §7, ADR-034)
[x] Proof-layer evidence is never numerically pooled with anomaly scores (§6, ADR-034)
[x] Evidence families are explicitly defined as dependency-aware groupings (§6, ADR-034)
[x] Contextual Leave-One-Out and subgroup baselines defined (§5, ADR-031)
[x] Empirical Bayes policy frozen with M_0 = 20.0 and clear support tier behaviors (§5, ADR-032)
[x] Multi-contributor attribution strictly conserves 1/K weights (§5, ADR-033)
[x] Phase 5.9 / 4 provenance lifecycle reused without creating parallel systems (§8, ADR-039)
[x] Phase 8 boundary is explicit and non-overlapping (§9, ADR-036)
[x] Phase 12 boundary is explicit and non-overlapping (§9, ADR-037)
[x] Database impact is confirmed as ZERO schema changes (§10, ADR-038)
[x] Determinism and RFC 8785 execution identity guaranteed (§8, ADR-039)
[x] 100% offline air-gapped operation verified
[x] Phase 4 and Phase 5 remain completely frozen
[x] Full regression passed (750/750 tests)
```

---

*End of Architecture Specification — AIVARA Contributor Risk Engine (Phase 6.1 Corrected)*
