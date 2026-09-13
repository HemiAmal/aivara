# PHASE 11 — DISTRIBUTION SHIFT & DRIFT THREAT MODEL
## Security Boundaries, Detection Capabilities, Non-Attribution Principles, and Adversarial Limits

**Date:** 2026-09-13  
**Project:** AIVARA — AI Verification & Assurance  
**Phase:** 11.1 (Threat Model & Requirements Freeze)  
**Parent Phase:** Phase 11 — Distribution Shift / Data Drift Analysis  

---

## 1. FUNDAMENTAL AIVARA NON-ATTRIBUTION PRINCIPLE

$$\textbf{Distribution Shift} \neq \textbf{Malicious Attack}$$

A fundamental governing invariant of AIVARA is the strict separation between objective mathematical/statistical observations and subjective culpability or intent. 

Distribution shift is **statistical evidence of population divergence**. It does **NOT** automatically prove, nor should it ever be unilaterally labeled as:
- Data poisoning or dataset tampering
- Backdoor trigger insertion
- Contributor fraud, malice, or misconduct
- Model compromise or intellectual property theft

### Benign Operational Causes of Distribution Shift
In production computer vision and multi-contributor pipelines, the vast majority of observed distribution shifts arise from legitimate, benign real-world dynamics, including:
1. **Environmental & Meteorological Transitions:** Changes in daylight, weather (rain, snow, fog), seasonal foliage, or shadows.
2. **Hardware & Sensor Modifications:** Upgraded camera sensors, differing lens focal lengths, color profile calibrations, or compression codec changes.
3. **Geographic & Demographic Evolution:** Expansion into new operational territories, different road topographies, architectural styles, or user demographics.
4. **Acquisition Pipeline Changes:** Transitions in image harvesting scripts, bounding box annotation guidelines, or crowdsourcing platforms.
5. **Legitimate Market Trends:** Introduction of new vehicle models, seasonal fashion lines, or updated product packaging.

Labeling these legitimate operational variations as "attacks" or "malicious contributor activity" destroys system trust and produces crippling false positives. Phase 11 generates non-accusatory, descriptive findings (e.g. `PRACTICAL_COVARIATE_SHIFT_DETECTED`, `LABEL_PROPORTION_SHIFT_DETECTED`).

---

## 2. CAPABILITY MATRIX: WHAT PHASE 11 CAN AND CANNOT DETECT

### What Phase 11 CAN Detect
- **Photometric & Geometric Covariate Drift:** Systematic changes in resolution, aspect ratios, luminance, color saturation, and contrast between reference and target datasets.
- **Structural Feature Drift:** Divergence in image frequency distributions (sharpness, texture, edge density) and perceptual hash distance distributions.
- **Prior / Label Distribution Shift:** Statistically significant and materially relevant changes in class proportions ($P(Y)$) across dataset versions or batches.
- **Latent Representation Drift:** Statistical divergence in deep latent feature embeddings ($P(Z)$) extracted using verified local models.
- **Temporal & Version Trajectories:** Quantifiable shifts occurring across sequential dataset version releases ($V_1 \to V_2 \to \dots \to V_n$).
- **Contributor-Scoped Distribution Discrepancies:** Identifying when a specific contributor's submitted samples exhibit distributional profiles divergent from the broader population baseline.

### What Phase 11 CANNOT Prove Unilaterally
- **Attacker Intent:** Statistical tests cannot determine whether a shifted distribution was created accidentally by a broken sensor or deliberately by an adversary.
- **Targeted Backdoor Injections:** A clean-label backdoor targeting a fraction of a percent of a dataset may introduce near-zero aggregate distribution shift, bypassing global statistical tests. (Phase 9 dedicated backdoor trigger analysis addresses this).
- **Exact Data Manipulation / Provenance Tampering:** Statistical shift indicates that data differs, but cannot prove whether file bytes were edited in transit. (Phase 4 Provenance and Phase 5 Fingerprinting address this).
- **Model Downstream Failure:** Distribution shift indicates potential risk of model performance degradation, but does not measure accuracy loss without ground truth evaluation. (Phase 8 Behavioral Analysis addresses this).

---

## 3. ADVERSARIAL THREAT MODEL AGAINST DRIFT DETECTION

An adversary interacting with a dataset assurance pipeline may attempt the following evasion or manipulation strategies:

### 3.1 Distribution Mimicry / Stealth Injections
- **Threat:** An adversary injects poisoned samples specifically synthesized to match the first and second moments (mean, variance, color histograms) of the reference distribution.
- **Mitigation:** Phase 11 evaluates higher-order moments and non-parametric RKHS representations via Kernel MMD and Energy Distance, which are sensitive to complex multi-modal distributions beyond mean and variance.

### 3.2 Reference Poisoning / Baseline Contamination
- **Threat:** An attacker manipulates the reference baseline itself (e.g. submitting a corrupted baseline version) so that subsequent poisoned targets appear "consistent" with the baseline.
- **Mitigation:** Phase 11 strictly enforces **Explicit, Immutable Reference Selection**. Baselines must be bound to immutable dataset versions with verified cryptographic hashes (`dataset_hash`) and cannot be dynamically or silently chosen by untrusted inputs.

### 3.3 Sample Starvation / Small-Batch Evasion
- **Threat:** An adversary splits contaminated data into microscopic batches ($N = 5$) to exploit statistical power degradation and evade detection.
- **Mitigation:** Strict enforcement of the **`INSUFFICIENT_DATA`** state floor ($N_{\text{min}} = 30$). Batches below this floor explicitly raise warnings and cannot claim a clean `NO_SHIFT_DETECTED` disposition.

### 3.4 Resource Exhaustion / Algorithmic DoS
- **Threat:** An adversary submits datasets with millions of samples or thousands of synthetic dimensions to trigger $O(N^2)$ memory and CPU exhaustion during pairwise kernel evaluations.
- **Mitigation:** Strict upper bounds:
  - Subsampling budget: $N_{\text{subsample}} \le 5,000$ with deterministic hashing seeds.
  - Permutation budget: $B \le 1,000$.
  - Dimension limit: $D \le 4,096$.
  - Cooperative cancellation timeouts in `DistributionShiftTaskManager`.

---

## 4. SECURITY & AIR-GAP BOUNDARIES

1. **100% Offline & Local Execution:**
   - Zero outbound or inbound network connections.
   - Prohibition of external cloud APIs for embeddings, feature extraction, or telemetry.
2. **Prohibition of Dynamic Code Execution:**
   - Zero usage of `eval()`, `exec()`, `pickle.loads()`, `subprocess`, `os.system()`, or `shell=True`.
3. **Filesystem Sandbox & Path Traversal Defense:**
   - Strict resolution of file paths against project storage roots via `backend/aivara/dataset/path_security.py`.
4. **Tenant Isolation:**
   - Strict `project_id` scoping across all database queries, task tracking, and evidence synthesis.
