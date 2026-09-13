# Phase 11.9: Evidence, Findings & Multi-Modal Risk Integration Research Notes

**Project**: AIVARA — AI Verification & Assurance  
**Phase**: 11 — Distribution Shift / Data Drift Analysis  
**Subphase**: 11.9.1 — Evidence, Findings & Risk Integration Architecture & Requirements Freeze  
**Status**: ARCHITECTURE RESEARCH & FOUNDATIONAL AUDIT  
**Date**: September 2026  

---

## 1. Executive Summary & Problem Formulation

AIVARA generates heterogeneous verification, integrity, behavioral, and distribution-shift evidence across multiple independent assurance subsystems:
- **Phase 4**: Cryptographic Provenance & Ledger Chains (Proof Layer)
- **Phase 5**: Dataset Integrity & Sample Anomaly Detection (Detection & Proof Layers)
- **Phase 6**: Contributor Risk Profiling & Empirical Bayes Shrinkage (Risk Context Layer)
- **Phase 7**: AI Model Integrity & Weight Fingerprinting (Proof & Detection Layers)
- **Phase 8**: Behavioral Anomaly & Runtime Perturbation Analysis (Detection Layer)
- **Phase 9**: Backdoor Activation & Trigger Analysis (Detection Layer)
- **Phase 10**: Inference Input-Output Binding & Replay Verification (Proof Layer)
- **Phase 11.1–11.8**: Multi-Modal Distribution Shift Engine (Tabular Features, Image Descriptors, Latent Embeddings, Temporal Window Sequences, Contributor & Source Partitions) (Detection Layer)

### The Integration Challenge
Prior to Phase 11.9, each subsystem produced localized findings and evidence records independently. However, a robust AI assurance system requires an authoritative, unified framework to aggregate, calibrate, deduplicate, and synthesize multi-modal evidence into actionable risk signals and policy-driven decisions without:
1. Conflating statistical observation with malicious intent.
2. Inappropriately mixing deterministic cryptographic proofs with probabilistic detection metrics.
3. Artificially inflating risk through double-counting correlated evidence derived from shared raw artifacts.
4. Generating uncalibrated, black-box pseudo-probabilities of attacks.
5. Inverting negative results to claim unverified safety ("absence of evidence is not evidence of absence").

---

## 2. Theoretical Foundations of Evidence Aggregation

We evaluated multiple theoretical paradigms for aggregating heterogeneous assurance evidence:

### 2.1 Bayesian Evidence Synthesis vs. Dempster-Shafer Theory
- **Bayesian Updating**:
  - *Mechanism*: Computes posterior odds $P(H \mid E_1, \dots, E_k) \propto P(H) \prod \frac{P(E_i \mid H)}{P(E_i \mid \neg H)}$ under conditional independence assumptions.
  - *Limitations in Security Assurance*: Requires well-calibrated base rate priors $P(H)$ (e.g., prior probability that a dataset or model is compromised) and likelihood distributions under both benign and adversarial regimes. In real-world security assurance, adversarial attack distributions are non-stationary and non-ergodic. Arbitrary prior assignment yields ungrounded, illusory precision.
- **Dempster-Shafer (D-S) Theory of Evidence**:
  - *Mechanism*: Models belief functions $m: 2^\Theta \to [0, 1]$ allocating mass to subsets of propositions, directly representing epistemic uncertainty (ignorance) $\Theta$. Combines mass functions using Dempster's rule of combination:
    $$m_{1 \oplus 2}(A) = \frac{\sum_{B \cap C = A} m_1(B) m_2(C)}{1 - \sum_{B \cap C = \emptyset} m_1(B) m_2(C)}$$
  - *Strengths*: Naturally distinguishes between "contradictory evidence" and "insufficient evidence" (uncommitted mass $m(\Theta)$).
  - *Weaknesses*: Highly sensitive to conflicting evidence (Zadeh's paradox) where two high-confidence contradictory observations can produce catastrophic mass misallocations if conflict $\sum_{B \cap C = \emptyset} m_1(B) m_2(C) \to 1$.
- **Selected Paradigm**: **Hybrid Evidential Dependency Layer with Calibrated Risk Bounding (ADR-102)**.
  - Separates **Proof Evidence** ($\text{Confidence} = 1.0$, binary, non-compensable) from **Detection Evidence** ($\text{Confidence} \in [0.0, 1.0]$, observational).
  - Employs **Ancestry-Aware Evidential Clustering** to group correlated observations sharing raw data lineage.
  - Evaluates risk using **Conservative Multi-Dimensional Bounded Aggregation** with explicit uncommitted epistemic uncertainty bounds.

---

## 3. Evidence Taxonomy & Layer Separation

AIVARA strictly enforces a two-layer evidential hierarchy:

```
+-----------------------------------------------------------------------------------+
|                                 PROOF LAYER                                       |
|  - Confidence = 1.0 (Strictly enforced by schema validator)                       |
|  - Cryptographic hash mismatches, signature invalidity, provenance chain breaks   |
|  - Non-compensable: Cannot be diluted or overridden by statistical normality      |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                               DETECTION LAYER                                     |
|  - Confidence in [0.0, 1.0] representing statistical support strength             |
|  - Distributional shifts (KS, PSI, MMD), behavioral anomalies, outlier densities   |
|  - Observational: Indicates distributional non-stationarity, NOT malicious intent |
|  - Dependency-Aware: Grouped by shared artifact ancestry to prevent double count  |
+-----------------------------------------------------------------------------------+
```

---

## 4. Multi-Modal Correlation & Double-Counting Mitigation

### 4.1 The Correlated Drift Problem
Consider an image dataset that undergoes illumination and compression changes:
1. **Phase 11.4** detects tabular feature shift on pixel intensity stats ($p < 10^{-4}, \text{PSI} = 0.35$).
2. **Phase 11.5** detects image descriptor shift on brightness and contrast ($p < 10^{-4}, \text{KS} = 0.42$).
3. **Phase 11.6** detects latent representation shift on DINOv2 embeddings ($p < 10^{-4}, \text{MMD}^2 = 0.08$).
4. **Phase 11.7** detects temporal window shift ($p < 10^{-4}$).
5. **Phase 11.8** detects collection site shift ($p < 10^{-4}$).

If an engine naively sums or multiplies these 5 signals, the composite risk will be massively inflated by $5\times$, treating 5 mathematical lenses on the *same physical event* as 5 independent adversarial actions.

### 4.2 Ancestry-Based Evidence Clustering
Phase 11.9 establishes **Evidential Ancestry Trees**:
- Each evidence record binds its **Primary Asset Ancestor** (`dataset_version_id`, `model_fingerprint`, `source_group_id`, `window_id`).
- Detectors operating on the same underlying asset modality belong to the same **Modality Cluster** $\mathcal{C}_k$.
- **Cluster Aggregation Rule**:
  $$\text{Score}(\mathcal{C}_k) = \max_{e_i \in \mathcal{C}_k} \text{SeverityWeight}(e_i) \cdot \text{Confidence}(e_i) + \sum_{e_j \in \mathcal{C}_k \setminus \{e_{\max}\}} \lambda_{\text{corr}} \cdot \text{SeverityWeight}(e_j) \cdot \text{Confidence}(e_j)$$
  where $\lambda_{\text{corr}} \in [0.0, 0.15]$ represents a heavily damped diminishing-returns coefficient for redundant confirmations of the same physical shift.

---

## 5. Confidence vs. Probability vs. Risk

AIVARA mathematically and semantically distinguishes these terms:

| Term | Definition | Range | Permitted Semantic Interpretation | Forbidden Misinterpretations |
| :--- | :--- | :--- | :--- | :--- |
| **Statistical p-value ($p$)** | Probability of observing test statistic $\ge T$ under $H_0$. | $[0.0, 1.0]$ | Measure of statistical surprise relative to reference distribution. | "Probability that data is authentic." |
| **Evidence Confidence ($c_e$)** | Quantitative strength of evidence support. | $[0.0, 1.0]$ | $c_e = 1 - p_{\text{adj}}$ (for detection) or $1.0$ (for proof). | "Probability that contributor is malicious." |
| **Finding Severity ($s_f$)** | Operational impact / security consequence if finding is active. | Enum / $[0, 1]$ | Inherent operational consequence (CRITICAL, HIGH, MEDIUM, LOW, INFO). | "How certain the finding is." |
| **Risk Score ($R$)** | Calibrated operational exposure index under explicit policy. | $[0.0, 1.0]$ | Decision-relevant exposure score synthesized from non-redundant findings. | "Probability of an attack" or "Poisoning percentage". |

---

## 6. Decision Theory & Human-in-the-Loop Integration

### 6.1 Disposition Actions
Decisions mapped under a versioned policy $\mathcal{P}_{\text{dec}}$:
1. **`ACCEPT`**: All proof checks verified; detection risk within baseline operational tolerance ($R < \tau_{\text{review}}$).
2. **`REVIEW`**: Statistical anomalies or elevated dispersion detected ($\tau_{\text{review}} \le R < \tau_{\text{quarantine}}$). Non-blocking human review queue created.
3. **`QUARANTINE`**: Substantial distribution divergence or multi-modal corroboration ($\tau_{\text{quarantine}} \le R < \tau_{\text{reject}}$). Assets isolated from downstream training/inference pending audit.
4. **`REJECT`**: Critical proof violation (hash mismatch, signature break, replay failure) or extreme corroborated risk ($R \ge \tau_{\text{reject}}$). Immediate rejection.
5. **`INSUFFICIENT_EVIDENCE`**: Sample size $N < N_{\min}$ or missing critical metadata. Analysis fails closed to review; never defaults to `ACCEPT`.

---

## 7. Comparative Assessment of Alternative Approaches

| Candidate Approach | Mathematical Rigor | Interpretability | Double-Counting Resistance | Offline Feasibility | Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Naive Linear Weighted Sum** | Low | High | None (Severe inflation) | High | **REJECTED** |
| **Full Bayesian Network** | High (in theory) | Low (black-box priors) | Moderate | Low (uncalibrated priors) | **REJECTED** |
| **Pure Dempster-Shafer** | Moderate | Moderate | Moderate (Conflict collapse) | High | **REJECTED** |
| **Deep Neural Risk Classifier** | Low (Opaque) | Zero (Unexplainable) | Low | Low (Model weights required) | **REJECTED** |
| **Ancestry-Clustered Damped Risk Index (ADR-102)** | High | High (Fully deterministic) | High (Lineage clustering) | High (100% offline & fast) | **SELECTED** |

---

## 8. Summary of Research Decisions

1. **Strict Evidential Bipartition**: Proof Layer ($\text{Conf} = 1.0$) vs. Detection Layer ($\text{Conf} \le 1.0$).
2. **Ancestry Evidence Grouping**: Clustered by asset origin with $\lambda_{\text{corr}} = 0.10$ inter-modality damping.
3. **Deterministic RFC 8785 Cryptographic Grounding**: Canonical SHA-256 identity over all policy descriptors, evidence graphs, and assurance profiles.
4. **Non-Attribution Language**: Purely observational findings (`"Multi-modal distribution divergence observed"` vs. `"Malicious contributor detected"`).
5. **Safe Fail-Closed Handling**: Insufficient, conflicting, or stale evidence produces `REVIEW` / `INSUFFICIENT_EVIDENCE`, never silent `ACCEPT`.
