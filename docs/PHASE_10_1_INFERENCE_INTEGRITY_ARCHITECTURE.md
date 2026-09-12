# AIVARA Phase 10 — Inference Integrity Architecture & Requirements Specification
**Authoritative Architecture, Data Flow, Verification Graph, and Invariant Specification**

---

## 1. Objective

Phase 10 provides the authoritative architecture and verification framework for **Inference Integrity** in AIVARA. It establishes whether an individual inference transaction is internally valid, structurally sound, numerically finite, traceable, consistent, and cryptographically sealed across the complete pipeline:

$$\text{Input} \longrightarrow \text{Preprocessing} \longrightarrow \text{Model Execution} \longrightarrow \text{Raw Output} \longrightarrow \text{Postprocessing} \longrightarrow \text{Final Output} \longrightarrow \text{Evidence} \longrightarrow \text{Provenance}$$

Phase 10 guarantees that every recorded inference transaction is tamper-evident, verifiable against declared contracts, reproducible under specified execution configurations, and auditable without reliance on cloud services, external queues, or unverified assumptions.

---

## 2. Scope

### In-Scope:
- **Transaction-Level Integrity**: Validation of individual inference transactions and controlled batches.
- **Input Identity & Validation**: Shape, dtype, layout, finite-value verification, and RFC 8785 canonical hashing.
- **Model Artifact Binding**: Cryptographic binding to exact model IDs, versions, weight digests, and Phase 7 structural fingerprints.
- **Preprocessing Contract Integrity**: Content-addressed preprocessing specifications and transformation verification without executing arbitrary unverified code.
- **Controlled Execution Binding**: In-memory execution tracking, runtime provider metadata, configuration binding, and resource bounds.
- **Output Schema & Numerical Integrity**: Task-aware structural schema validation (Classification, Detection, Segmentation, Embedding) and numerical sanity checks (NaN/Inf trapping, probability sum checks, bounding box constraints).
- **Postprocessing Contract Integrity**: Content-addressed postprocessing validation separating raw model logits/tensors from application outputs.
- **Cryptographic Input $\rightarrow$ Output Binding**: Deterministic composite integrity hash binding input, model, preprocessing, execution, raw output, and postprocessing.
- **Inference Record Integrity & Provenance**: Tamper-evident ledger logging reusing Phase 4 Ed25519 digital signatures and SHA-256 hash chains.
- **Replay & Consistency Verification**: Reproducibility verification distinguishing valid identical execution from drift, perturbation, or non-deterministic hardware divergence.

### Out-of-Scope:
- Detecting malicious model backdoors or synthetic triggers (permanently frozen in **Phase 9**).
- Population-level distribution drift, out-of-distribution (OOD) shift, or MMD/Energy Distance testing (**Phase 11**).
- Universal multi-asset risk aggregation, enterprise risk scoring, or final disposition decisions (**Phase 12**).
- OS-level kernel sandboxing, hardware virtualization, or external cloud model hosting.

---

## 3. Definitions

- **Inference Transaction**: An atomic evaluation unit comprising a specific input, preprocessing configuration, target model artifact, execution runtime configuration, raw model output, postprocessing transformation, and resulting final output.
- **Inference Integrity**: The verifiable property that an inference transaction was executed using the intended input, on the genuine model artifact, with the exact declared preprocessing and postprocessing policies, producing structurally and numerically valid outputs bound into a tamper-evident cryptographic ledger.
- **Input Identity**: The deterministic SHA-256 hash over the canonical tensor representation (dtype, shape, layout, contiguous C-order byte stream) or raw file payload.
- **Model Binding**: The cryptographic linkage between an inference transaction and the target model's SHA-256 artifact hash and Phase 7 structural/statistical fingerprint.
- **Preprocessing Identity**: The content-addressed hash of the deterministic preprocessing recipe (resize dimensions, normalization constants, interpolation method, channel conversions).
- **Execution Identity**: The deterministic hash capturing model fingerprint, input hash, preprocessing hash, execution provider, runtime version, and configuration flags.
- **Raw Output Identity**: The canonical hash over the direct, un-postprocessed model output tensors.
- **Postprocessing Identity**: The content-addressed hash of the decision and conversion parameters (e.g., argmax, softmax, confidence thresholds, NMS IoU thresholds, mask quantization).
- **Final Output Identity**: The canonical hash over the finalized structured inference result.
- **Composite Integrity Hash**: The cryptographic hash binding all constituent identities:
  $$\text{IntegrityHash} = \text{SHA-256}(\text{InputID} \parallel \text{ModelFingerprint} \parallel \text{PreprocID} \parallel \text{ExecID} \parallel \text{RawOutputID} \parallel \text{PostprocID} \parallel \text{FinalOutputID})$$
- **Replay Verification**: The deterministic re-execution and comparison of an inference transaction under matched runtime conditions to assess numerical reproducibility and state consistency.

---

## 4. Phase Boundaries

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                    AIVARA PIPELINE                                     │
├───────────────────┬──────────────────────────────────┬─────────────────────────────────┤
│ FROZEN PHASES     │ PHASE 10 (INFERENCE INTEGRITY)   │ FUTURE PHASES                   │
├───────────────────┼──────────────────────────────────┼─────────────────────────────────┤
│ Phase 4: Crypto   │ 10.1 Arch & Requirements Freeze  │ Phase 11: Distribution Shift    │
│ Phase 5: Dataset  │ 10.2 Safe Input Boundary         │   - Population Drift            │
│ Phase 6: Contrib  │ 10.3 Input / Model Binding       │   - Energy Distance / MMD       │
│ Phase 7: Model    │ 10.4 Preprocessing Integrity     │   - OOD Statistical Tests       │
│ Phase 8: Behav    │ 10.5 Execution Integrity         │ Phase 12: Evidence & Risk       │
│ Phase 9: Backdoor │ 10.6 Output Schema/Numerical     │   - Universal Risk Score        │
│                   │ 10.7 Input -> Output Binding     │   - Enterprise Aggregation      │
│                   │ 10.8 Inference Record Ledger     │   - Multi-Modal Disposition     │
│                   │ 10.9 Replay & Consistency        │                                 │
│                   │ 10.10 Evidence & Provenance      │                                 │
│                   │ 10.11 REST API & Task Runner     │                                 │
│                   │ 10.12 Comprehensive Verification │                                 │
│                   │ 10.13 Final Phase 10 Freeze      │                                 │
└───────────────────┴──────────────────────────────────┴─────────────────────────────────┘
```

---

## 5. Existing Frozen Interfaces Reused

Phase 10 interfaces directly with existing frozen subsystems via clean adapters without modifying upstream code:

1. **Phase 4 (Cryptographic Provenance)**:
   - Reuses `backend/aivara/crypto/signing.py` (`Ed25519SignatureEngine`), `chain.py` (`ProvenanceLedger`), and `canonical.py` (`RFC 8785 JCS`).
   - Reuses `ProvenanceRecordModel` and `InferenceRecordModel`.
2. **Phase 5 (Dataset Integrity)**:
   - Reuses canonical tensor hashing conventions (`hash_canonical_tensor`) and image validation protocols.
3. **Phase 7 (Model Integrity)**:
   - Reuses `ModelFingerprintModel`, `AIModelModel`, and `StructuralFingerprintExtractor` (`model_fingerprint_sha256`).
4. **Phase 8 (Controlled Behavioral Execution)**:
   - Reuses `InferenceContext`, `ControlledExecutionEngine`, and in-memory process boundary protections.
5. **Phase 9 (Evidence & REST Architecture)**:
   - Reuses content-addressed `EvidenceModel` and `FindingModel` binding adapters and the process-local `ThreadPoolExecutor` task manager.

---

## 6. Threat Model

### Threats Addressed by Phase 10:
1. **Model Substitution / Hijacking**: Inference executed against an unexpected or unauthorized model version, corrupted weights, or un-fingerprinted artifact.
2. **Input Corruption & Parameter Tampering**: Inputs modified in transit, corrupted during memory ingestion, or mismatching declared spatial/channel semantics.
3. **Silent Preprocessing Drift**: Undocumented changes in normalization, color space conversion, resizing algorithms, or channel transposition altering model behavior.
4. **Output Forgery & Fabrication**: Manually injected or forged model predictions, truncated tensors, or synthetic probabilities not originating from the declared model execution.
5. **Numerical Anomalies & Instabilities**: Uncaught NaN, $+\infty$, $-\infty$, numerical overflow, probability distributions not summing to 1.0, or degenerate bounding boxes.
6. **Postprocessing Discrepancies**: Inconsistent confidence thresholding, altered NMS IoU cutoffs, or misaligned class index mapping between raw model output and application display.
7. **Inference Ledger Mutation**: Retroactive alteration of historical inference records, timestamps, or execution statuses.
8. **Inconsistent Replay**: Discrepancies between historical recorded outputs and newly re-executed inferences under identical configurations.
9. **Cross-Tenant Contamination**: Associating inference records, models, or cryptographic keys across distinct tenant project boundaries.

### Threats NOT Addressed by Phase 10:
- Adversarial backdoor triggers embedded in training weights (handled in **Phase 9**).
- Population-level distribution shifts between training and inference domains (handled in **Phase 11**).
- Insider compromise of the local host operating system or kernel memory (outside AIVARA's user-space execution boundary).

---

## 7. Trust Model

| Component | Trust Level | Verification Mechanism |
|---|---|---|
| **Raw Input Data** | Untrusted | Validated against dimension bounds, finite values, and canonical hashing. |
| **Target Model Artifact** | Semi-Trusted | Verified against Phase 7 SHA-256 weight hash and structural fingerprint. |
| **Declared Preprocessing** | Untrusted | Verified against declarative content-addressed whitelist recipe; no arbitrary code execution. |
| **Execution Runtime** | Controlled | Monitored in-memory execution; provider and library versions captured. |
| **Raw Model Output** | Untrusted | Validated against schema types, finite value bounds, and shape constraints. |
| **Declared Postprocessing** | Untrusted | Verified against deterministic declarative algorithms (e.g. standard NMS, thresholding). |
| **Final Output** | Untrusted | Validated against domain schema and bound to composite integrity hash. |
| **Inference Record** | Cryptographically Verified | Sealed via Ed25519 digital signature and chained into the provenance ledger. |

---

## 8. End-to-End Inference Integrity Architecture

```
[ INCOMING INFERENCE REQUEST ]
             │
             ├──► 1. INPUT INGESTION & VALIDATION (§9)
             │      ├── Dimension, Dtype, Layout & Finite-Value Checks
             │      └── Compute Canonical Input Hash (SHA-256)
             │
             ├──► 2. MODEL BINDING (§10)
             │      ├── Resolve AIModelModel & ModelFingerprintModel
             │      └── Verify Artifact Hash & Structural Fingerprint
             │
             ├──► 3. PREPROCESSING CONTRACT (§11, §12)
             │      ├── Validate Input against Declarative Preprocessing Recipe
             │      ├── Execute Bounded Transformation (No eval/exec)
             │      └── Compute Preprocessing Identity Hash
             │
             ├──► 4. CONTROLLED EXECUTION (§13, §14)
             │      ├── Execute Model inside Controlled In-Memory Boundary
             │      ├── Capture Provider, Runtime Version & Configuration
             │      └── Compute Execution Identity Hash
             │
             ├──► 5. RAW OUTPUT STRUCTURAL & NUMERICAL VALIDATION (§15, §16)
             │      ├── Structural Schema Validation (Classification/Detection/Seg/Embed)
             │      ├── Numerical Sanity Check (NaN/Inf Trapping, Finite Checks)
             │      └── Compute Raw Output Hash
             │
             ├──► 6. POSTPROCESSING CONTRACT (§17)
             │      ├── Execute Declarative Postprocessing (NMS, Threshold, Argmax)
             │      ├── Validate Final Output Structure
             │      └── Compute Postprocessing & Final Output Hashes
             │
             ├──► 7. COMPOSITE INPUT-TO-OUTPUT BINDING (§18)
             │      └── Compute Deterministic Composite Integrity Hash
             │
             ├──► 8. INFERENCE LEDGER SEALING (§19, §20)
             │      ├── Populate InferenceRecordModel (0 Schema Changes)
             │      ├── Sign with Project Ed25519 Key Handle
             │      └── Append to Sequential Provenance Hash Chain
             │
             └──► 9. EVIDENCE & PROVENANCE ADAPTER (§21, §22)
                    ├── Create RFC 8785 JCS Content-Addressed EvidenceModel
                    └── Return Cryptographic Verification Assessment
```

---

## 9. Input Integrity & Validation

1. **Tensor Verification**:
   - Dtype: Explicit validation (`float32`, `float64`, `uint8`, `int32`, `int64`).
   - Dimensions: Rank 2 `(H, W)`, Rank 3 `(H, W, C)` or `(C, H, W)`, Rank 4 `(N, H, W, C)` or `(N, C, H, W)`.
   - Layout Semantics: Explicitly declared (`HWC`, `CHW`, `NHWC`, `NCHW`). Ambiguous layouts fail closed.
   - Finite State: Enforced via `np.all(np.isfinite(x))`. Inputs containing NaN or $\pm\infty$ are rejected immediately.
2. **Canonical Input Hash**:
   $$\text{InputHash} = \text{SHA-256}(\text{dtype\_str} \parallel \text{shape\_str} \parallel \text{layout\_str} \parallel \text{contiguous\_bytes})$$
3. **Raw File Ingestion**:
   - For file-based inputs (PNG, JPEG), both `raw_file_hash` and `decoded_tensor_hash` are captured and bound.

---

## 10. Model Binding Specification

1. **Required Binding Tuple**:
   $$\text{ModelBinding} = \langle \text{model\_id}, \text{model\_version}, \text{file\_hash\_sha256}, \text{structural\_fingerprint\_sha256} \rangle$$
2. **Verification Protocol**:
   - An inference record cannot reference a generic model name alone.
   - Target model must exist in `AIModelModel` within the active tenant `project_id`.
   - The stored model file hash and structural fingerprint from `ModelFingerprintModel` are verified prior to execution.
   - Any fingerprint or hash divergence yields `MODEL_BINDING_MISMATCH`.

---

## 11. Preprocessing Integrity & Content-Addressed Recipes

1. **Declarative Recipe Model**: Preprocessing steps must be declared as structured, parameter-validated dictionaries:
   ```json
   {
     "pipeline_version": "1.0",
     "steps": [
       {"op": "resize", "params": {"height": 224, "width": 224, "interpolation": "bilinear"}},
       {"op": "normalize", "params": {"mean": [0.485, 0.456, 0.406], "std": [0.229, 0.224, 0.225]}},
       {"op": "channel_transpose", "params": {"source": "HWC", "target": "CHW"}}
     ]
   }
   ```
2. **Prohibition of Dynamic Code Execution**:
   - Strictly **NO** `eval`, `exec`, `pickle.loads`, arbitrary Python lambda functions, or shell preprocessing commands.
   - All transformations are executed via deterministic, hardened native library primitives.
3. **Preprocessing Identity**:
   $$\text{PreprocID} = \text{SHA-256}(\text{RFC8785\_JCS}(\text{declarative\_recipe}))$$

---

## 12. Preprocessing Contract Validation

- **Contract Enforcement**: Before applying transformations, the input tensor is checked against declared input preconditions (expected channels, input resolution, value ranges).
- **No Silent Coercion**: If an input is single-channel grayscale but the recipe expects 3-channel RGB without a declared conversion step, the pipeline fails closed with `PREPROCESSING_CONTRACT_VIOLATION` rather than silently duplicating channels.

---

## 13. Execution Integrity & Runtime Metadata

1. **Execution Identity**:
   $$\text{ExecID} = \text{SHA-256}(\text{RFC8785\_JCS}(\{ \text{model\_fingerprint}, \text{provider}, \text{runtime\_version}, \text{device}, \text{batch\_size}, \text{deterministic\_mode} \}))$$
2. **Captured Runtime Context**:
   - Execution Provider: `ONNXRuntime-CPU`, `PyTorch-CPU`, `TorchScript-CPU`, etc.
   - Library and compiler version strings.
   - Execution configuration flags (threading count, optimization level, precision mode).

---

## 14. Controlled In-Memory Execution Boundary

- When local model execution is performed, AIVARA enforces the **Controlled In-Memory Execution Boundary** established in Phase 8:
  - Process-isolated worker execution preventing crashes from affecting the main application.
  - Hard timeout limits per inference call ($T_{\text{max}} = 30.0\text{s}$).
  - Memory allocation ceilings preventing out-of-memory exhaustion.
- **Architectural Boundary Statement**: This is a controlled application-level in-memory execution harness. It is **NOT** an operating system kernel sandbox, hypervisor, or secure enclave.

---

## 15. Output Structural Integrity by Task Type

| Task Type | Expected Structural Components | Validation Rules |
|---|---|---|
| **Classification** | Logits tensor, probability vector, predicted class index, confidence score. | Probability vector length equals class count; predicted class is valid index; confidence in $[0.0, 1.0]$. |
| **Object Detection** | Bounding boxes `[N, 4]`, class labels `[N]`, score vector `[N]`, detection count $N$. | Box coordinates satisfy $0 \le x_1 < x_2 \le W$ and $0 \le y_1 < y_2 \le H$; class labels $\in [0, C-1]$; scores $\in [0.0, 1.0]$. |
| **Semantic Segmentation** | Class map `[H, W]`, class probabilities `[C, H, W]`, mask dimensions. | Mask spatial dimensions match output specification; all pixel values $\in [0, C-1]$. |
| **Embeddings / Vectors** | Feature vector `[D]`, dimension $D$, dtype. | Rank 1 or 2 tensor; exact dimension $D$ matching model contract; finite numeric values. |

---

## 16. Output Numerical Integrity

1. **Non-Finite Value Trapping**:
   - Any raw or processed output tensor containing `NaN`, `+Inf`, or `-Inf` is immediately flagged as `OUTPUT_NUMERICAL_INSTABILITY`.
2. **Probability Distribution Validation**:
   - For models declaring probability outputs, the normalization constraint $|\sum_{c=1}^C p_c - 1.0| \le 10^{-4}$ is enforced.
   - Logits are explicitly distinguished from probabilities; softmax is **never** applied automatically unless specified in the postprocessing contract.
3. **Bounding Box Geometric Sanity**:
   - Coordinates with negative width/height, inverted corners ($x_2 \le x_1$), or coordinates exceeding image dimensions by $> 1\%$ fail closed.

---

## 17. Postprocessing Integrity & Final Output Derivation

1. **Separation of Raw vs. Final Output**:
   - Raw model tensor outputs (logits, raw anchor regressions, unquantized feature maps) are preserved and hashed separately from final application predictions.
2. **Postprocessing Recipe**:
   - Postprocessing transformations (e.g. Softmax, Argmax, Class Label Lookup, Bounding Box NMS, Score Thresholding) are declared as deterministic, content-addressed specifications.
3. **Postprocessing Identity**:
   $$\text{PostprocID} = \text{SHA-256}(\text{RFC8785\_JCS}(\text{postproc\_config}))$$
4. **Final Output Identity**:
   $$\text{FinalOutputID} = \text{SHA-256}(\text{RFC8785\_JCS}(\text{canonical\_final\_output}))$$

---

## 18. Cryptographic Input $\rightarrow$ Output Binding

The central integrity primitive of Phase 10 is the **Composite Input-to-Output Integrity Hash**:

$$\text{IntegrityIdentity} = \text{SHA-256}(\text{RFC8785\_JCS}(\{$$
$$\quad \text{"input\_hash"}: \text{InputHash},$$
$$\quad \text{"model\_fingerprint"}: \text{ModelFingerprint},$$
$$\quad \text{"preprocessing\_id"}: \text{PreprocID},$$
$$\quad \text{"execution\_id"}: \text{ExecID},$$
$$\quad \text{"raw\_output\_hash"}: \text{RawOutputHash},$$
$$\quad \text{"postprocessing\_id"}: \text{PostprocID},$$
$$\quad \text{"final\_output\_hash"}: \text{FinalOutputHash},$$
$$\quad \text{"project\_id"}: \text{ProjectID}$$
$$\}))$$

Any alteration in input pixels, model weights, preprocessing parameters, runtime configurations, raw logits, or postprocessing thresholds results in an immediate divergence of $\text{IntegrityIdentity}$.

---

## 19. Inference Record Integrity & Database Strategy

1. **Zero Database Schema Changes (`DATABASE SCHEMA CHANGES = 0`)**:
   - Phase 10 strictly reuses the existing `InferenceRecordModel` defined in `backend/aivara/database/models.py`.
2. **Field Mapping**:
   - `id`: Unique inference transaction UUID.
   - `project_id`: Multi-tenant project identifier.
   - `model_id`: Bound target model ID.
   - `input_hash`: Canonical input hash (`InputHash`).
   - `input_path`: Reference URI / storage path of input.
   - `preprocessing_hash`: Content-addressed preprocessing recipe hash (`PreprocID`).
   - `config_hash`: Execution configuration identity (`ExecID`).
   - `output_json`: Structured payload containing final predictions, raw output metadata, postprocessing recipe, and numerical integrity flags.
   - `output_hash`: Composite final output hash (`FinalOutputID`).
   - `sequence_number`: Monotonically increasing per-project sequence counter.
   - `nonce`: Cryptographically random 32-byte hex nonce.
   - `signature`: Ed25519 digital signature over the record hash.
   - `previous_record_hash`: Previous sequential record hash linking the audit chain.
   - `record_hash`: SHA-256 hash over the canonical record fields.
   - `verification_status`: Status enum string (`verified`, `invalid`, `unverified`).

---

## 20. Cryptographic Provenance Ledger Integration

1. **Signing Protocol (Phase 4 Reuse)**:
   - Each inference transaction is hashed and signed using the project's active Ed25519 private key handle managed by `KeyManager`.
2. **Audit Chain Linking**:
   $$\text{RecordHash}_k = \text{SHA-256}(\text{RFC8785\_JCS}(\{$$
   $$\quad \text{"sequence\_number"}: k,$$
   $$\quad \text{"previous\_record\_hash"}: \text{RecordHash}_{k-1},$$
   $$\quad \text{"integrity\_identity"}: \text{IntegrityIdentity}_k,$$
   $$\quad \text{"nonce"}: \text{Nonce}_k,$$
   $$\quad \text{"timestamp"}: \text{ISO8601\_UTC}$$
   $$\}))$$
3. **Tamper Evidence**: Single-bit modification of any recorded parameter invalidates the cryptographic signature and breaks downstream hash chain links.

---

## 21. Replay Semantics & Consistency Verification

1. **Distinguishing Valid Reproduction from Replay Attacks**:
   - **Valid Reproduction (Deterministic Verification)**: Re-executing an inference with identical inputs, model fingerprint, and execution configuration to verify numerical reproducibility.
   - **Stale / Replay Attack (Transaction Hijacking)**: Presenting an old signed inference record as a newly generated transaction, or reusing a signature on altered inputs.
2. **Replay Verification Protocol**:
   - Re-runs inference under matched execution provider settings.
   - Compares newly generated raw output $Y_{\text{new}}$ against recorded raw output $Y_{\text{orig}}$.
3. **Non-Deterministic Hardware Handling**:
   - Where exact bit-for-bit equality is not guaranteed due to floating-point non-associativity across different hardware architectures, tolerance-based numerical comparison is applied with explicit status reporting:
     - Exact Match: `REPLAY_EXACT_MATCH`
     - Within Policy Tolerance: `REPLAY_TOLERANCE_MATCH`
     - Beyond Tolerance: `REPLAY_NUMERICAL_DIVERGENCE`
     - Hardware Incomparable: `UNVERIFIABLE`

---

## 22. Numerical Comparison Policies by Task

| Task Modality | Comparison Metrics | Standard Policy Thresholds |
|---|---|---|
| **Classification** | Maximum absolute logit difference $\|L_1 - L_2\|_\infty$, Top-1 class agreement. | $\text{Class}_1 == \text{Class}_2 \land \|L_1 - L_2\|_\infty \le 10^{-5}$ |
| **Object Detection** | Bounding box mean IoU, label match rate, score delta $\|\mathbf{s}_1 - \mathbf{s}_2\|_\infty$. | $\text{mIoU} \ge 0.999 \land \Delta\text{labels} == 0 \land \Delta\text{score} \le 10^{-4}$ |
| **Semantic Segmentation** | Pixel-wise mask agreement ratio, class mIoU. | $\text{MaskAgreement} \ge 0.9999 \land \text{mIoU} \ge 0.9999$ |
| **Feature Embeddings** | Cosine similarity $\cos(\mathbf{e}_1, \mathbf{e}_2)$, L2 Euclidean distance. | $\cos(\mathbf{e}_1, \mathbf{e}_2) \ge 1.0 - 10^{-6} \land \|\mathbf{e}_1 - \mathbf{e}_2\|_2 \le 10^{-5}$ |

---

## 23. Evidence Architecture (Phase 5.9 / 9.9 Reuse)

- **Evidence Model Binding**:
  - `EvidenceModel.evidence_layer = EvidenceLayer.PROOF`
  - `EvidenceModel.confidence = 1.0` (for all cryptographic/integrity proofs)
  - `EvidenceModel.evidence_type = "INFERENCE_INTEGRITY_ASSESSMENT"`
  - `EvidenceModel.data_json`: Contains canonical representations of input hash, model fingerprint, preprocessing ID, execution ID, output hashes, composite integrity identity, and replay comparison metrics.
  - `EvidenceModel.evidence_hash`: Deterministic SHA-256 over `data_json` canonicalized via RFC 8785 JCS.

---

## 24. Status Taxonomy & Observational Vocabulary

### 1. Integrity Status Taxonomy:
- `VERIFIED`: Complete mathematical, structural, and cryptographic validation passed.
- `INVALID`: Structural schema violation, non-finite numerical output, or signature failure.
- `MISSING`: Required transaction components (e.g. model fingerprint, preprocessing recipe) not supplied.
- `UNAVAILABLE`: Execution runtime or model weights unresolvable on local host.
- `MISMATCHED`: Input, model, or preprocessing configuration diverges from declared specification.
- `UNVERIFIABLE`: Runtime non-determinism or missing baseline prevents conclusive verification.

### 2. Observational Finding Types:
- `OUTPUT_SCHEMA_MISMATCH`
- `OUTPUT_NONFINITE_VALUES`
- `PROBABILITY_SUM_INVALID`
- `GEOMETRIC_BOUNDS_VIOLATION`
- `INPUT_MODEL_BINDING_MISMATCH`
- `PREPROCESSING_CONTRACT_VIOLATION`
- `POSTPROCESSING_DISCREPANCY`
- `COMPOSITE_INTEGRITY_HASH_MISMATCH`
- `INFERENCE_RECORD_TAMPERED`
- `REPLAY_NUMERICAL_DIVERGENCE`
- `PROVENANCE_CHAIN_DISCONTINUITY`

### 3. Strictly Prohibited Accusatory Terms:
The analytical engine must **NEVER** output terms asserting intent or culpability such as `MALICIOUS_INFERENCE`, `ATTACKER_TAMPERING`, `INTENTIONAL_FRAUD`, or `BACKDOOR_INFERENCE`.

---

## 25. Failure and Absence Semantics

- **Fail-Closed Principle**: If any input, model fingerprint, preprocessing parameter, or output tensor is missing, malformed, or unresolvable, the engine immediately outputs `MISSING` or `INVALID`.
- **No Silent Zero-Filling**: Missing confidence values, failed bounding boxes, or absent logits are **never** fabricated or defaulted to zero; they are preserved as explicit `None` / missing states.

---

## 26. Security & Air-Gap Guarantees

1. **AST Security Invariants**:
   - Zero usage of `eval`, `exec`, `subprocess`, `os.system`, `pickle`, `__import__`, or `ctypes` in any inference integrity module.
2. **Air-Gap Compliance**:
   - 100% process-local execution. Zero network calls, cloud APIs, remote telemetry, or external database queries.
3. **Resource Bounds**:
   - Max Tensor Elements: $50 \times 10^6$ elements per tensor.
   - Max Image Dimensions: $8,192 \times 8,192$ pixels.
   - Max Batch Size: $N \le 32$.
   - Max Replay Iterations: $R \le 10$.
   - Max Execution Time: $30.0\text{s}$ hard timeout.

---

## 27. REST API Strategy (Planned for Phase 10.11)

All endpoints will be project-scoped and multi-tenant isolated:
- `POST /api/v1/projects/{project_id}/inference/verify`: Submit inference transaction for integrity verification.
- `POST /api/v1/projects/{project_id}/inference/replay`: Execute deterministic replay verification.
- `GET /api/v1/projects/{project_id}/inference/records/{record_id}`: Retrieve sealed inference record.
- `GET /api/v1/projects/{project_id}/inference/records/{record_id}/evidence`: Retrieve cryptographic evidence.
- `GET /api/v1/projects/{project_id}/inference/records/{record_id}/provenance`: Retrieve provenance verification status.

---

## 28. Architectural Decision Records (ADRs)

### ADR-092: Inference Transaction Identity & Content-Addressed Preprocessing/Postprocessing Contracts
- **Status**: ACCEPTED (Phase 10.1)
- **Decision**: Represent preprocessing and postprocessing configurations as declarative, content-addressed JSON recipes hashed via RFC 8785 JCS + SHA-256. Strictly forbid arbitrary Python code execution.
- **Consequences**: Deterministic, reproducible pipeline validation without code-injection security vulnerabilities.

### ADR-093: Cryptographic Input-to-Output Binding for End-to-End Inference Verification
- **Status**: ACCEPTED (Phase 10.1)
- **Decision**: Define a single composite `IntegrityIdentity` hash binding input, model fingerprint, preprocessing ID, execution ID, raw output, postprocessing ID, and final output into an atomic tamper-evident identity.
- **Consequences**: Any modification to any stage of the inference pipeline invalidates the complete transaction hash.

### ADR-094: Deterministic Replay vs. Reproduction Semantics & Non-Determinism Failure Modes
- **Status**: ACCEPTED (Phase 10.1)
- **Decision**: Distinguish valid deterministic re-execution from replay attacks. Apply task-aware tolerance metrics for floating-point comparisons across execution providers, falling back to explicit `UNVERIFIABLE` rather than asserting false equality or false violation.
- **Consequences**: Resilient, scientifically sound reproducibility verification across heterogeneous compute hardware.

### ADR-095: Task-Aware Output Schema and Numerical Integrity Verification Framework
- **Status**: ACCEPTED (Phase 10.1)
- **Decision**: Implement task-specialized structural validators for Classification, Object Detection, Semantic Segmentation, and Embeddings with mandatory non-finite value trapping (NaN/$\pm\infty$) and geometric sanity bounds.
- **Consequences**: Structural and numerical corruption is caught deterministically before downstream consumption.

---

## 29. Subphase Implementation Roadmap (Phase 10.1 – Phase 10.13)

| Subphase | Title | Core Objective | Key Deliverables |
|---|---|---|---|
| **10.1** | Architecture & Requirements Freeze | Freeze Phase 10 specification, data flow, and ADRs. | `docs/PHASE_10_1_INFERENCE_INTEGRITY_ARCHITECTURE.md` |
| **10.2** | Safe Inference Input Boundary | Implement input tensor validation, shape/layout checks, finite-value assertions, and canonical input hashing. | `backend/aivara/inference/input/`, tests |
| **10.3** | Input / Model Binding | Link inputs to Phase 7 model fingerprints, weight hashes, and tenant models. | `backend/aivara/inference/model_binding/`, tests |
| **10.4** | Preprocessing & Contract Integrity | Implement declarative, content-addressed preprocessing recipes and contract checks. | `backend/aivara/inference/preprocessing/`, tests |
| **10.5** | Inference Execution Integrity | Capture runtime provider context, deterministic execution flags, and controlled boundary isolation. | `backend/aivara/inference/execution/`, tests |
| **10.6** | Output Schema & Numerical Integrity | Validate task-specific output schemas (classification, detection, segmentation, embeddings) and trap NaN/Inf. | `backend/aivara/inference/output/`, tests |
| **10.7** | Input $\rightarrow$ Output Binding | Construct composite cryptographic integrity hash binding all pipeline stages. | `backend/aivara/inference/binding/`, tests |
| **10.8** | Inference Record Integrity | Populate, validate, and query `InferenceRecordModel` entities without database schema changes. | `backend/aivara/inference/records/`, tests |
| **10.9** | Replay & Consistency Verification | Implement deterministic replay verification and task-specific numerical tolerance comparisons. | `backend/aivara/inference/replay/`, tests |
| **10.10** | Evidence & Provenance Binding | Bind inference transactions into Phase 4 Ed25519 provenance chains and Phase 9.9 evidence models. | `backend/aivara/inference/evidence.py`, tests |
| **10.11** | REST API & Task Integration | Implement project-scoped REST endpoints and SSE progress streaming. | `backend/aivara/api/routers/inference.py`, tests |
| **10.12** | Comprehensive Verification | Build and run comprehensive integration, adversarial trapping, and regression test suites. | `tests/test_phase10_comprehensive.py` |
| **10.13** | Final Inference Integrity Freeze | Perform final verification, baseline recording, and permanent Phase 10 freeze. | `docs/PHASE_10_FREEZE.md` |

---

## 30. Phase 10 Acceptance Criteria

1. **Deterministic Identity**: Every inference transaction has a deterministic, content-addressed identity.
2. **Model Fingerprint Binding**: Target model artifact is bound by SHA-256 weight digest and Phase 7 fingerprint.
3. **Preprocessing Safety**: Preprocessing recipes are content-addressed and execute zero arbitrary code (`eval`/`exec`).
4. **Output Validation**: All output tensors are validated against task schemas and checked for non-finite values (NaN/Inf).
5. **Composite Binding**: Input, model, preprocessing, execution, raw output, and final output are bound via a single cryptographic hash.
6. **Tamper-Evident Ledger**: Inference records are signed via Ed25519 and chained sequentially in SQLite without database schema changes.
7. **Replay vs. Reproduction**: Replay verification accurately assesses reproducibility with task-specific numerical tolerances.
8. **No Silent Fabrication**: Missing or unverifiable data is explicitly represented as `MISSING` or `UNVERIFIABLE`.
9. **Multi-Tenant Isolation**: Project isolation is strictly maintained across all queries and ledger operations.
10. **Air-Gap Compliance**: Zero external network, cloud, or remote messaging broker dependencies.
11. **Subsystem Immutability**: Frozen Phase 0 through Phase 9 subsystems remain unmodified.
12. **Phase Boundaries Respected**: Phase 11 (Distribution Shift) and Phase 12 (Universal Risk) are strictly decoupled.

---

## 31. Phase 10.1 Architecture Sign-Off

**DECISION: ARCHITECTURE FROZEN & APPROVED**

Phase 10.1 establishes the implementation-ready foundation for AIVARA Inference Integrity.
Phase 10.2 (Safe Inference Input Boundary) is authorized as the next implementation step upon user approval.
