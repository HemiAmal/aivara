# PHASE 11.6 — FUNCTIONAL & NON-FUNCTIONAL REQUIREMENTS
## REPRESENTATION & EMBEDDING DISTRIBUTION SHIFT

**Project**: AIVARA — AI Verification & Assurance  
**Phase**: 11.6 — Representation & Embedding Distribution Shift Analysis  
**Subphase**: 11.6.1 — Architecture & Requirements Freeze  
**Document**: Requirements & Specification Standards  
**Status**: ARCHITECTURAL SPECIFICATION (FREEZE CANDIDATE)  

---

## 1. Functional Requirements (FR)

### A. Boundary & Compatibility Requirements
- **FR-01 (Modality Validation)**: Representation shift evaluation must only operate on populations validated with `DataModality.IMAGE` or `DataModality.LATENT_EMBEDDING`. Non-compatible modalities must be rejected fail-closed with `IncompatiblePopulationError`.
- **FR-02 (Representation Space Equality)**: Two embedding populations are valid for comparison if and only if their `RepresentationContract` parameters match exactly: identical `model_id`, `model_artifact_hash`, `representation_layer`, `embedding_dimension`, `preprocessing_contract_hash`, and `normalization_policy`.
- **FR-03 (Dimension Matching)**: Embedding dimensions $D_{\text{ref}}$ and $D_{\text{target}}$ must be identical. Truncation, zero-padding, or unaligned dimensional matching is strictly prohibited.
- **FR-04 (Boundary Reuse)**: The representation analyzer must consume the immutable Phase 11.2 `ComparisonBoundaryResult` and preserve project, dataset, and population hashes.

### B. Model Identity & Artifact Security
- **FR-05 (Artifact Hash Binding)**: The representation model must be verified against its SHA-256 artifact hash prior to loading. Mismatched or corrupted model files must fail closed with `InvalidModelArtifactError`.
- **FR-06 (Phase 7 Model Integrity Integration)**: Where available, the representation engine must verify the Phase 7 `model_master_fingerprint` to ensure weight integrity.
- **FR-07 (Safe Format Enforcement)**: Only statically verifiable, non-executable model formats (`ONNX`, `SafeTensors`, or `TorchScript` with `weights_only=True`) are permitted. Python `pickle` deserialization is strictly prohibited.
- **FR-08 (Offline Air-Gapped Operation)**: Representation models must be loaded exclusively from local storage. Zero runtime network retrieval, Hugging Face Hub queries, or remote API calls are allowed.

### C. Preprocessing & Extraction Determinism
- **FR-09 (Preprocessing Contract Binding)**: Preprocessing operations (resize, crop, channel formatting, normalization) must be defined in a content-addressed Phase 10.4 `PreprocessingContract` bound into the `RepresentationContract`.
- **FR-10 (Evaluation Mode Enforcement)**: Model inference must be executed in strict evaluation mode (`eval()`, disabled dropout, frozen batchnorm statistics, no gradient computation).
- **FR-11 (Deterministic Reproducibility)**: Repeated representation extraction over identical image populations and identical representation contracts must produce bitwise identical embedding arrays.
- **FR-12 (Finite Value Assurance)**: Every extracted embedding tensor must be validated to ensure all elements are strictly finite floating-point numbers ($\text{NaN} = 0, \pm\infty = 0$).

### D. Multivariate Statistical Analysis
- **FR-13 (Phase 11.3 Engine Reuse)**: Embedding distribution shift must be computed using Phase 11.3's multivariate statistical functions (`compute_kernel_mmd`, `compute_energy_distance`, `compute_permutation_p_value`). Duplicate statistical code is prohibited.
- **FR-14 (Dual-Gate Decisioning)**: Global material shift requires satisfying both:
  1. Statistical significance: Permutation $p$-value $\le 0.05$.
  2. Practical effect size: $\text{MMD}^2 \ge 0.02$ OR $\text{Energy Distance} \ge 1.0$.
- **FR-15 (Adaptive Bandwidth Heuristic)**: The Gaussian RBF kernel bandwidth $\gamma$ must be deterministically computed via the median pairwise distance heuristic across pooled sample vectors.
- **FR-16 (Zero Target Leakage)**: No statistical transformation, normalization parameter, or dimensionality reduction matrix may be computed using target population data to transform reference data.
- **FR-17 (Single Global Hypothesis)**: Representation shift must be evaluated as a single global multivariate hypothesis without uncorrected per-coordinate false discovery inflation.

### E. Evidence, Findings & Cryptographic Identity
- **FR-18 (Detection-Layer Findings)**: Findings must be generated with `evidence_layer = "detection"` and `finding_type = "representation_distribution_shift"`.
- **FR-19 (Observational Semantics)**: Finding narratives and evidence records must report mathematical representation divergence and must **never** assert malicious intent, data poisoning, or model compromise.
- **FR-20 (Evidence Minimization)**: Evidence records must contain statistical summaries, bandwidths, sample counts, and cryptographic digests without persisting raw high-dimensional embedding matrices to disk.
- **FR-21 (Cryptographic Identity)**: The analysis result must compute `representation_drift_profile_hash = SHA256(RFC8785_JCS(canonical_descriptor))`.
- **FR-22 (Full Provenance Linkage)**: Complete lineage from reference/target populations through boundary, model artifact, preprocessing contract, statistical tests, and findings must be reconstructible.

---

## 2. Non-Functional Requirements (NFR)

- **NFR-01 (Security & Attack Surface)**: Zero use of `eval`, `exec`, `pickle`, `os.system`, `subprocess`, or `popen`. 100% compliant with AST security scanners.
- **NFR-02 (Offline Execution)**: Zero outbound network connections. Complete test suite and analytical engine must execute in fully disconnected/air-gapped environments.
- **NFR-03 (Resource Bounds)**:
  - Maximum population budget: $N \le 5000$.
  - Maximum embedding dimension: $D \le 4096$.
  - Maximum model file size: $500\text{ MB}$.
  - Maximum sample size for quadratic MMD permutation kernels: $N_{\text{eval}} \le 2000$.
- **NFR-04 (Memory Management)**: Image pixel buffers and intermediate feature maps must be discarded immediately after extraction. In-memory footprint must remain bounded ($< 2\text{ GB}$ RAM).
- **NFR-05 (Zero Database Schema Impact)**: Phase 11.6 must introduce 0 database migrations, 0 new tables, and 0 database schema modifications.
- **NFR-06 (Portability & CPU Feasibility)**: Primary reference execution must be fully functional and reproducible on standard x86_64 CPU hardware without requiring CUDA GPUs.
- **NFR-07 (Auditability & JCS Canonicalization)**: All hashes, descriptors, and contracts must follow RFC 8785 JSON Canonicalization Scheme (JCS) for deterministic cross-platform verification.

---

## 3. Failure States Specification

| Failure Condition | Handling Behavior | Resulting Status | Finding / Error |
| :--- | :--- | :--- | :--- |
| **Non-Image / Non-Embedding Modality** | Fail closed immediately | `INVALID` | Raises `IncompatiblePopulationError` |
| **Model Artifact File Missing** | Fail closed immediately | `INVALID` | Raises `ModelArtifactNotFoundError` |
| **Model Artifact Hash Mismatch** | Fail closed immediately | `INVALID` | Raises `InvalidModelArtifactError` |
| **Preprocessing Contract Mismatch** | Fail closed | `INCOMPATIBLE_REPRESENTATION` | Emits compatibility warning & invalid profile |
| **Representation Layer Mismatch** | Fail closed | `INCOMPATIBLE_REPRESENTATION` | Emits compatibility warning & invalid profile |
| **Embedding Dimension Mismatch** | Fail closed | `INCOMPATIBLE_DIMENSIONS` | Emits dimension warning & invalid profile |
| **Sample Count $< N_{\min} (30)$** | Fail closed | `INSUFFICIENT_DATA` | Returns profile with `INSUFFICIENT_DATA` |
| **NaN / Inf in Embedding Vectors** | Fail closed | `INVALID` | Rejects corrupted embeddings |
| **Resource Limit Exceeded ($N > 5000, D > 4096$)** | Fail closed | `RESOURCE_LIMIT_EXCEEDED` | Raises `ResourceLimitExceededError` |
| **Project ID Mismatch Across Boundary** | Fail closed immediately | `PROJECT_MISMATCH` | Raises `ProjectMismatchError` |

---

## 4. Future Test Plan (Phase 11.6.2 Implementation Test Suite)

When implementation commences in Phase 11.6.2, the following test categories must be developed:

1. **Representation Contract & Compatibility**:
   - Identical representation contracts yield `COMPATIBLE`.
   - Mismatched `model_id`, `model_artifact_hash`, `layer`, or `dimension` return `INCOMPATIBLE`.
   - Preprocessing contract hash divergence rejected.
2. **Deterministic Extraction**:
   - Repeated extraction over identical images produces bitwise identical embeddings on CPU.
   - Normalization policy (L2, standardized) correctly applied.
3. **Statistical Shift Scenarios**:
   - Identical embedding distributions yield `NO_SHIFT_DETECTED`.
   - Clearly shifted embedding distributions yield `MATERIAL_SHIFT`.
   - Subtly shifted distributions test dual-gate distinction.
4. **Failure State Trapping**:
   - Corrupt model weights, missing model files, dimension mismatches, NaNs in embeddings.
   - Insufficient sample counts ($N < 30$) fail closed.
5. **Security & Immutability**:
   - Input populations and comparison boundaries remain unmodified.
   - AST security scanner confirms 0 forbidden calls.
   - Cryptographic profile hash sensitivity and determinism verified.
