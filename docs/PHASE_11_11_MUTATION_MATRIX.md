# Phase 11.11 — Comprehensive Distribution Shift Verification
## Adversarial & Invariant Mutation Matrix

**Document ID:** `DOC-11-11-MUTATION-MATRIX`  
**Phase:** Phase 11.11 (Verification Planning & Architecture Only)  
**Total Formal Mutation Cases:** 20 Systematic Invariant & Payload Mutations  
**Status:** Permanent Freeze Baseline  

---

### 1. Mutation Methodology

Adversarial mutation testing systematically alters individual fields, payload contents, metadata values, cryptographic digests, random seeds, and policy thresholds to verify that:
1. Every semantic modification induces an appropriate, deterministic change in downstream findings, risk scores, or cryptographic digests.
2. Invariant properties (e.g. key order invariance, arrival order invariance) remain perfectly invariant under non-semantic permutations.
3. Malformed, corrupted, or out-of-bounds mutations fail closed cleanly with standardized errors without process crashing or database corruption.

---

### 2. Formal Mutation Verification Matrix

| Mutation ID | Target Parameter / Component | Original Value | Mutated Value | Expected Affected Component | Expected Hash Change | Expected Finding Change | Expected Risk / Decision Impact | Expected Detection & Validation Behavior | Verification Method |
|---|---|---|---|---|---|---|---|---|---|
| **MUT-001** | `dataset_id` in Population Contract | `"ds_alpha_01"` | `"ds_alpha_02"` | Population Boundary (11.2) | `contract_hash` $\Delta$, `population_hash` $\Delta$ | None (metadata change) | Recomputes assurance profile with new dataset identity | Detected at boundary contract calculation | Compare JCS SHA-256 digest before and after mutation |
| **MUT-002** | `dataset_version_id` in Target Dataset | `"v1.0.0"` | `"v1.0.1"` | Modality Ancestry Clustering (11.9) | `integrated_profile_hash` $\Delta$ | Asset ancestor tag updated | Creates separate modality cluster if reference ancestry diverges | Lineage isolation verified in risk engine | Check cluster keys in `RiskAssessmentModel` |
| **MUT-003** | Single Sample Removal in Reference Set | $N_{\text{ref}} = 1000$ | $N_{\text{ref}} = 999$ | Boundary & Statistical Engines (11.2, 11.3) | `population_hash` $\Delta$, all profile hashes $\Delta$ | Slight numerical shift in empirical quantiles | Marginal risk delta ($\Delta R < 0.01$) | Subsampling and quantile bin boundaries recomputed deterministically | Verify `population_hash` is completely different (Avalanche effect) |
| **MUT-004** | Sample Membership Swap in Target Set | Valid Target Sample A | Outlier / Perturbed Sample B | Feature & Statistical Engines (11.3, 11.4) | `population_hash` $\Delta$, `feature_drift_profile_hash` $\Delta$ | Feature KS/PSI scores increase | Risk score increases according to effect magnitude | Dual gate triggers drift flag if $p_{\text{adj}} \le 0.05$ AND $\text{PSI} \ge 0.10$ | Verify drift flag boolean transitions `False` $\to$ `True` |
| **MUT-005** | Random Seed in Subsampling | `seed = 42` | `seed = 99` | Population Subsampling (11.2) | `population_hash` $\Delta$ | Subsampled set members change; statistical metrics vary within sampling error | Risk score remains within confidence interval | Deterministic repeatability maintained per seed value | Compare outputs across seeds 42, 99, 42 |
| **MUT-006** | Continuous Feature Value Shift | $\mu_{\text{tgt}} = 0.0$ | $\mu_{\text{tgt}} = 3.5$ ($\sigma=1.0$) | Feature Engine (11.4) | `feature_drift_profile_hash` $\Delta$, `integrated_profile_hash` $\Delta$ | KS $D > 0.8$, $p < 10^{-6}$, $\text{PSI} > 0.50$; finding emitted | Risk score increases significantly ($\Delta R \ge 0.40$); disposition shifts to `QUARANTINE` or `REJECT` | High-confidence feature drift finding generated | Verify `FeatureDriftProfile.drift_detected == True` |
| **MUT-007** | Categorical Feature Value Skew | $P(A)=0.5, P(B)=0.5$ | $P(A)=0.95, P(B)=0.05$ | Feature & Statistical Engine (11.3, 11.4) | `feature_drift_profile_hash` $\Delta$ | $\chi^2$ $p < 10^{-5}$, $\text{TVD} = 0.45$; finding emitted | Incremental risk increase in feature modality cluster | Categorical drift finding generated with high TVD | Check `TVD` and categorical p-value |
| **MUT-008** | Target Label Proportion Flipping | $P(Y=1) = 0.50$ | $P(Y=1) = 0.10$ | Feature & Source Engines (11.4, 11.8) | `feature_drift_profile_hash` $\Delta$ | `target_label_shift` finding emitted; `label_confounding_advisory` triggered | Advisory flags confounding to prevent misattributing sensor shift | Simpson's paradox safeguard activates | Check `finding_type == "label_confounding_advisory"` |
| **MUT-009** | Image Pixel Inversion (Adversarial Tint) | Original Image RGB | Inverted Image Pixels ($255 - x$) | Image Drift Engine (11.5) | `image_drift_profile_hash` $\Delta$ | Image Pixel & Quality descriptor drift findings emitted | Image cluster score $S(\mathcal{C}_{\text{image}}) \to 0.95$; overall risk increases | Image descriptor drift detected across mean brightness and contrast | Check `ImageDriftProfile.drift_detected == True` |
| **MUT-010** | Corrupted Image Bytes (Truncated File) | Valid JPEG | Truncated byte stream | Image Boundary (11.5) | `image_drift_profile_hash` $\Delta$ | Zero crash; sample categorized as `corrupt_images` in accounting | Insufficient analyzable images may trigger `INSUFFICIENT_EVIDENCE` | Fail-closed graceful error handling; accounting total conserved | Verify `ImageDriftProfile.accounting.corrupt_count == 1` |
| **MUT-011** | Model Artifact Weight Byte Modification | Valid ONNX Model (SHA-256 A) | Modified Model Byte (SHA-256 B) | Representation Engine (11.6) | Analysis halts; 0 profile emitted | Zero partial profile emitted | Fails closed with execution error | Fails closed before inference; throws `ModelFingerprintMismatchError` | Verify exception raised and task status transitions to `FAILED` |
| **MUT-012** | Embedding Dimension Exceeding Bound | $D = 512$ | $D = 5000$ ($> D_{\max}=4096$) | Representation Boundary (11.6) | Analysis rejected | Zero finding emitted | Validation error (HTTP 422 / Exception) | Rejection at schema/boundary validation | Verify `DimensionalityExceededError` raised |
| **MUT-013** | Timestamp Scrambling / Arrival Permutation | Time-ordered $[t_0, t_1, \dots, t_N]$ | Randomly shuffled $[t_{\pi(0)}, \dots, t_{\pi(N)}]$ | Temporal Engine (11.7) | **NO HASH CHANGE** (Invariant) | **NO FINDING CHANGE** | **NO RISK CHANGE** | Deterministic UTC pre-sorting normalizes sequence identically | Compare output profiles of sorted vs shuffled streams |
| **MUT-014** | Contributor ID Whitespace & Case Perturbation | `"user_alpha"` | `"  USER_ALPHA \t"` | Source Engine (11.8) | **NO HASH CHANGE** (Invariant) | **NO FINDING CHANGE** | **NO RISK CHANGE** | 5-stage canonicalization maps to identical canonical ID and pseudonym | Compare pseudonym hashes between clean and dirty strings |
| **MUT-015** | Contributor Salt Modification | `salt = "salt_01"` | `salt = "salt_02"` | Source Engine (11.8) | `source_drift_profile_hash` $\Delta$ | Pseudonym strings change; statistical comparisons remain identical | Risk score unchanged (pseudonymization does not alter group memberships) | Privacy salt rotation supported cleanly | Verify pseudonym mapping changes while group sizes match |
| **MUT-016** | Insufficient Evidence Injection | Valid Target Dataset | Target with $N = 15$ ($< N_{\min}=30$) | Population Boundary (11.2, 11.9) | Analysis halts | Emits `INSUFFICIENT_EVIDENCE` finding | Disposition forced to $\mathbf{INSUFFICIENT\_EVIDENCE}$ | Rejects undersized populations; zero false `ACCEPT` emitted | Verify `RiskAssessmentModel.disposition == "INSUFFICIENT_EVIDENCE"` |
| **MUT-017** | Proof Layer Failure Injection | Detection Findings Only | Detection + Proof Failure finding | Multi-Modal Assurance Engine (11.9) | `integrated_profile_hash` $\Delta$ | Proof failure finding registered with $\text{confidence} = 1.0$ | **MANDATORY REJECT** ($R = 1.0$) overrides all detection scores | Proof Layer Non-Compensability Invariant enforced | Verify `RiskAssessmentModel.disposition == "REJECT"` |
| **MUT-018** | Risk Disposition Threshold Adjustment | `accept_threshold = 0.30` | `accept_threshold = 0.10` | Policy Engine (11.9) | `decision_policy_hash` $\Delta$, `integrated_profile_hash` $\Delta$ | Policy metadata updated | Risk score $R=0.20$ previously `ACCEPT` now becomes `REVIEW` | Tamper-evident policy hash attestation verified | Check `decision_policy_hash` matches canonical policy |
| **MUT-019** | JSON Key Order Permutation in API Request | `{"dataset_id": "A", "modality": "tabular"}` | `{"modality": "tabular", "dataset_id": "A"}` | API Fingerprinting (11.10) | **NO HASH CHANGE** (Invariant) | **NO TASK DUPLICATION** | **IDEMPOTENT MATCH** | RFC 8785 JCS canonicalization generates identical `request_fingerprint` | Assert `request_fingerprint_A == request_fingerprint_B` |
| **MUT-020** | Modified Payload under Existing Idempotency Key | Payload A with Key K | Payload B with Key K | API Router (11.10) | None | None | Request rejected with HTTP 409 Conflict | Idempotency conflict detector prevents corrupting existing task | Verify HTTP status 409 and code `IDEMPOTENCY_CONFLICT` |

---

### 3. Mutation Invariant Guarantees

1. **Deterministic Sensitivity:** Every semantic change to data or policy ($100\%$ of test cases MUT-001 through MUT-012, MUT-015 through MUT-018, MUT-020) alters downstream hashes, findings, or triggers expected fail-closed rejections.
2. **Canonical Invariance:** Every non-semantic transformation (key reordering MUT-019, timestamp arrival permutation MUT-013, contributor string formatting MUT-014) preserves exact bit-for-bit cryptographic and statistical invariance.
