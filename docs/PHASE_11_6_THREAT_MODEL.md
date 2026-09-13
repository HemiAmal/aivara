# PHASE 11.6 — THREAT MODEL: REPRESENTATION & EMBEDDING DISTRIBUTION SHIFT

**Project**: AIVARA — AI Verification & Assurance  
**Phase**: 11.6 — Representation & Embedding Distribution Shift Analysis  
**Subphase**: 11.6.1 — Architecture & Requirements Freeze  
**Document**: Threat Model & Security Boundary Specification  
**Status**: ARCHITECTURAL SPECIFICATION (FREEZE CANDIDATE)  

---

## 1. Executive Summary & Security Philosophy

Phase 11.6 introduces learned latent representations and high-dimensional embeddings to distribution shift analysis. Unlike physical pixel descriptors (evaluated in Phase 11.5), learned representations require neural network feature extractors. Executing deep models introduces supply-chain risks, code execution vectors, GPU/CPU nondeterminism, preprocessing vulnerabilities, and statistical misattribution.

This threat model formalizes:
1. **Trust Boundaries** between untrusted image/model inputs and the trusted AIVARA deterministic evaluation core.
2. **Attacks on Representation Pipelines** (model substitution, weight tampering, layer swapping, preprocessing manipulation, embedding cache poisoning).
3. **Statistical & Inference Vulnerabilities** (adversarial perturbation, target leakage, curse of dimensionality, permutation test exhaustion).
4. **Semantic Misattribution** (confusing representation divergence with maliciousness or compromise).

---

## 2. Security Boundaries

```
┌────────────────────────────────────────────────────────────────────────┐
│                        UNTRUSTED BOUNDARY                              │
│  - Raw Image Populations (Reference & Target files)                   │
│  - User-Supplied Model Weights & Checkpoints                           │
│  - External Model Metadata / Configuration Files                       │
│  - Intermediate Cached Embedding Tensors                               │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                         Cryptographic Verification
                         (SHA-256 + Model Fingerprint)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         TRUSTED CORE                                   │
│  - Phase 7 Model Integrity Fingerprinting & Verification              │
│  - Content-Addressed Preprocessing Contracts (Phase 10.4)              │
│  - Isolated, Air-Gapped ONNX / TorchScript Runtime Environment         │
│  - Phase 11.2 Validated Comparison Boundary                            │
│  - Phase 11.3 Statistical Multivariate Engine (MMD, Energy, Perm)       │
│  - Canonical Representation Contract Hashing (RFC 8785 JCS)            │
│  - Deterministic PRNG Seed Control                                     │
│  - Detection-Layer Finding & Evidence Generation                       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Threat Analysis & Mitigation Matrix

### Threat 1: Model Substitution & Identity Spoofing
- **Description**: An adversary replaces the representation model (e.g., swapping a verified ResNet50/DINOv2 with a compromised or fine-tuned model) while keeping the declared model name.
- **Attack Surface**: Model file ingestion, model registry paths.
- **Consequence**: False negative distribution shift (attacker hides drift) or false positive shift (artificial alarms).
- **Mitigation**: Bind the representation contract to the **immutable model artifact hash** and Phase 7 **Master Model Fingerprint**. Verify artifact hash before loading weights.
- **Residual Risk**: Zero if SHA-256 hash collision resistance holds.

### Threat 2: Model Weight Modification / Backdoor Injection
- **Description**: Model weights are slightly modified to map specific target images into the reference cluster or to collapse latent variance.
- **Attack Surface**: Model checkpoint storage.
- **Consequence**: Masked distribution shift in the latent space.
- **Mitigation**: Enforce Phase 7 Model Integrity verification prior to representation extraction. Reject corrupted or modified weights fail-closed.
- **Residual Risk**: Negligible when weights are strictly content-addressed.

### Threat 3: Representation Layer & Node Substitution
- **Description**: Changing the extracted representation layer (e.g., from the penultimate pooling layer to an intermediate convolutional layer or classification head) between reference and target evaluations.
- **Attack Surface**: Inference configuration, layer index argument.
- **Consequence**: Comparing embeddings from completely different topological manifolds; invalid distribution shift.
- **Mitigation**: Bind `representation_layer` / output node name explicitly into the canonical `RepresentationContract`. Enforce strict equality in `validate_representation_compatibility()`.
- **Residual Risk**: Zero.

### Threat 4: Preprocessing Discrepancy (Preprocessing Version Drift)
- **Description**: Evaluating reference images with standard ImageNet normalization (`mean=[0.485, 0.456, 0.406]`) and target images with zero normalization (`mean=[0, 0, 0]`) or different crop policies.
- **Attack Surface**: Image resizing, cropping, color space conversion, channel ordering.
- **Consequence**: Embedding shift caused entirely by preprocessing pipeline divergence rather than dataset drift.
- **Mitigation**: Cryptographically bind the `PreprocessingContract` hash into the `RepresentationContract`. Reject comparisons where preprocessing contract hashes differ.
- **Residual Risk**: Zero.

### Threat 5: Embedding Dimension & Normalization Manipulation
- **Description**: Comparing unnormalized raw embeddings with L2-normalized embeddings, or comparing different dimensional embeddings ($D=512$ vs $D=768$).
- **Attack Surface**: Embedding post-processing, tensor shapes.
- **Consequence**: Metric distortion in Kernel MMD and Energy Distance calculations.
- **Mitigation**: Contract explicitly declares `embedding_dimension` and `normalization_policy` (`NONE`, `L2`, `STANDARDIZED`). Runtime verifies dimension and applies normalization deterministically.
- **Residual Risk**: Zero.

### Threat 6: Embedding Cache Poisoning
- **Description**: If precomputed embeddings are cached on disk, an attacker alters cached embeddings to hide target distribution shift.
- **Attack Surface**: Temporary tensor storage on disk.
- **Consequence**: Corrupted or bypassed statistical analysis.
- **Mitigation**: Embeddings must be generated in memory during analytical runs, or verified against input image identity hashes if cached temporarily. No persistent unauthenticated embedding cache in v1.
- **Residual Risk**: Low (in-memory execution).

### Threat 7: Target Population Leakage (Dimensionality Reduction Contamination)
- **Description**: Fitting dimensionality reduction (e.g., PCA or feature selection) on combined reference and target data, leaking target variance into the reference representation space.
- **Attack Surface**: High-dimensional transformation pipeline.
- **Consequence**: Contaminated null distribution, biased two-sample test statistics, invalid empirical $p$-values.
- **Mitigation**: Dimension reduction is prohibited in v1 default architecture (direct full-space Kernel MMD on $D \le 4096$). If dimension reduction is configured, projection matrices must be fitted **exclusively on the reference population** and applied out-of-sample to the target population.
- **Residual Risk**: Zero.

### Threat 8: Unsafe Model Deserialization (Pickle Vulnerabilities)
- **Description**: Loading PyTorch model weights serialized using Python `pickle`, enabling arbitrary code execution during `torch.load()`.
- **Attack Surface**: File parser / model loader.
- **Consequence**: Remote code execution (RCE) inside the evaluation environment.
- **Mitigation**: Enforce **ONNX** (`InspectionPolicy.SUPPORTED`) or SafeTensors/TorchScript in `weights_only=True` mode. Strictly prohibit raw `.pkl` model formats.
- **Residual Risk**: Low.

### Threat 9: Computational Resource Exhaustion (DoS)
- **Description**: Submitting massive populations ($N > 50,000$) or huge latent vectors ($D > 100,000$) to induce $O(N^2)$ Kernel MMD matrix allocation and $O(B \cdot N^2)$ permutation test memory exhaustion.
- **Attack Surface**: Population ingestion and statistical testing.
- **Consequence**: Host Out-Of-Memory (OOM) crash, analytical process termination.
- **Mitigation**: Enforce frozen limits: $N \le 5000$, $D \le 4096$. Subsample to $N_{\text{eval}} \le 2000$ for quadratic MMD permutation kernels with deterministic seeding. Limit permutation count $B \le 1000$.
- **Residual Risk**: Zero.

### Threat 10: Nondeterministic Inference Drift (GPU vs CPU Floating-Point Drift)
- **Description**: Numerical discrepancies between GPU CUDA kernels and CPU execution causing subtle embedding vector differences that trigger false positive drift alarms on identical populations.
- **Attack Surface**: Hardware execution environment, CUDA non-deterministic reductions.
- **Consequence**: Shift detection failure on identical datasets across different execution nodes.
- **Mitigation**: Enforce evaluation mode (`eval()`), disable gradients, use fixed deterministic PRNG seeds, and standardize v1 reference execution on **CPU** for bitwise reproducibility. If GPU is used, enable deterministic algorithms (`torch.use_deterministic_algorithms(True)`).
- **Residual Risk**: Minimal.

### Threat 11: Statistical False Positives on High-Dimensional Latent Spaces
- **Description**: In high dimensions ($D \ge 768$), distance concentration (the curse of dimensionality) can make pairwise distances collapse, causing Kernel MMD with fixed bandwidth to lose power or generate biased $p$-values.
- **Attack Surface**: Bandwidth selection in Gaussian RBF kernel.
- **Consequence**: False negative drift detection on genuine semantic shifts.
- **Mitigation**: Use the median heuristic across pooled sample distances to adaptively set kernel bandwidth $\gamma = \frac{1}{2 \sigma_{\text{med}}^2}$, combined with exact permutation testing ($B \ge 100$).
- **Residual Risk**: Low.

### Threat 12: Semantic Misattribution & Intent Hallucination
- **Description**: Interpreting detected representation divergence as evidence of malicious dataset poisoning, contributor fraud, or model backdoor attacks.
- **Attack Surface**: Finding generation and reporting narratives.
- **Consequence**: Wrongful attribution, unjustified security alerts, regulatory non-compliance.
- **Mitigation**: Enforce detection-layer semantics (`evidence_layer = "detection"`). Findings must strictly report mathematical representation divergence and include explicit disclaimer:
  $$\text{REPRESENTATION DRIFT} \ne \text{MALICIOUS INTENT}$$
- **Residual Risk**: Zero (enforced by schema and templates).

---

## 4. Verification & Testing Requirements for Threat Mitigations

| Threat ID | Test Verification Requirement |
| :--- | :--- |
| **T1 / T2** | Test model artifact hash mismatch triggers immediate rejection. |
| **T3** | Test representation layer mismatch returns `INCOMPATIBLE_REPRESENTATION`. |
| **T4** | Test preprocessing contract hash mismatch returns `INCOMPATIBLE_PREPROCESSING`. |
| **T5** | Test embedding dimension mismatch fails closed via `INCOMPATIBLE_DIMENSIONS`. |
| **T7** | Test that reference distribution is never transformed using target data statistics. |
| **T8** | Test AST security scanner verifies 0 unsafe pickle loads or dynamic imports. |
| **T9** | Test population and dimension bounds ($N \le 5000, D \le 4096$) reject out-of-budget inputs. |
| **T10** | Test repeated extraction over identical images produces bitwise identical embeddings. |
| **T12** | Test finding text strictly preserves detection layer semantics without malice claims. |
