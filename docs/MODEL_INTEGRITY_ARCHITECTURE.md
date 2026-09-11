# Phase 7 — Model Integrity Architecture & Requirements Specification

**Subsystem:** AIVARA Model Integrity Engine (MIE)  
**Document Version:** 1.1.0  
**Phase Status:** Phase 7.1 — Architecture & Requirements Freeze  
**Author:** DeepMind / AIVARA Engineering Team  
**Date:** 2026-09-11  

---

## 1. Executive Summary & Purpose

The **Model Integrity Subsystem (Phase 7)** is the core assurance layer in AIVARA responsible for verifying the authenticity, structural validity, internal consistency, and operational contract compliance of Computer Vision and AI model artifacts.

### 1.1 Central Objective
> *"Establish deterministically whether an AI/CV model artifact is the expected model artifact and whether its structural, cryptographic, metadata, and input/output contract properties are internally consistent."*

### 1.2 Non-Inference of Human Intent (Foundational Invariant)
Phase 7 operates strictly under the foundational AIVARA invariant:
$$\text{MODEL INTEGRITY ANOMALY} \ne \text{MALICIOUSNESS}$$
$$\text{CONTRACT MISMATCH} \ne \text{ATTACK}$$
$$\text{PROOF OF MISMATCH} \ne \text{PROOF OF GUILT}$$

Phase 7 detects, quantifies, and isolates structural, cryptographic, and operational deviations. It **NEVER** asserts human motive, deliberate sabotage, intent, or fraud.

### 1.3 Subsystem Boundaries
Phase 7 is strictly scoped and decoupled from downstream phases:
- **Phase 7 (Model Integrity):** Static, structural, cryptographic, format, and contract verification of the model artifact itself.
- **Phase 8 (Model Behavioral Analysis):** Dynamic behavioral evaluation, invariance testing, and red-teaming (OUT OF SCOPE for Phase 7).
- **Phase 9 (Backdoor & Trigger Analysis):** Specialized trigger inversion, latent space clean-label backdoor detection (OUT OF SCOPE for Phase 7).
- **Phase 10 (Inference Integrity):** Execution-time verification, hardware drift, replay protection (OUT OF SCOPE for Phase 7).
- **Phase 11 (Distribution Shift):** Dataset-to-model latent domain shift (OUT OF SCOPE for Phase 7).
- **Phase 12 (Universal Risk Engine):** Cross-subsystem multi-entity synthesis (OUT OF SCOPE for Phase 7).
- **Phase 13 (Attack Simulation Lab):** Automated red-team perturbations and attack simulations (OUT OF SCOPE for Phase 7).

---

## 2. Threat & Anomaly Surface

The Model Integrity Engine identifies 17 distinct classes of model integrity anomalies across 4 operational domains:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MODEL INTEGRITY THREAT & ANOMALY SURFACE                 │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Cryptographic & Byte-Level Domain                                       │
│    - Raw Artifact Tampering (SHA-256 mismatch)                              │
│    - Truncated / Corrupted Binary Streams                                   │
│    - Unsigned / Unknown Signer Provenance                                   │
│                                                                             │
│ 2. Weight & Tensor Domain                                                   │
│    - Weight Value Modification (Parameter Perturbation)                     │
│    - Missing Tensors / Pruned Layer Weights                                 │
│    - Unexpected / Injected Auxiliary Tensors                                │
│    - Tensor Shape & Rank Discrepancies                                      │
│    - Tensor Precision / DType Mismatch (e.g. float32 -> float16)            │
│                                                                             │
│ 3. Architecture & Topology Domain                                           │
│    - Layer Sequence Alteration / Node Reordering                            │
│    - Operator Type Substitution                                             │
│    - Graph Topology & Connectivity Mutation                                 │
│    - Framework / OpSet Version Incompatibility                              │
│                                                                             │
│ 4. Operational Contract & Metadata Domain                                   │
│    - Input Dimensions & Channel Order (NCHW vs NHWC)                        │
│    - Normalization / Preprocessing Discrepancies (Mean, Std, Color Space)   │
│    - Output Dimensionality & Activation Function (Logits vs Softmax)        │
│    - Class Vocabulary & Category Count Mismatch ($K_{\text{ref}} \ne K$)    │
│    - Metadata Header Tampering & Version Drift                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Anomaly Taxonomy & Evidence Classification

| Anomaly Identifier | Domain | Observable Indicator | Assurance Layer | Confidence |
| :--- | :--- | :--- | :--- | :--- |
| `ANOM_ARTIFACT_TAMPERED` | Cryptographic | $H_{\text{artifact}} \ne H_{\text{ref}}$ | **Proof** | $1.0$ |
| `ANOM_PROVENANCE_INVALID` | Cryptographic | Invalid Ed25519 signature / broken chain | **Proof** | $1.0$ |
| `ANOM_WEIGHT_DIGEST_MISMATCH`| Weight | Weight Merkle root diverges from reference | **Detection** | $[0.95, 1.0]$ |
| `ANOM_TENSOR_SCHEMA_MUTATION`| Weight | Missing, unexpected, or renamed tensor keys | **Detection** | $1.0$ |
| `ANOM_TENSOR_DTYPE_MISMATCH` | Weight | Precision reduced or altered (e.g., FP32 $\to$ INT8) | **Detection** | $1.0$ |
| `ANOM_TENSOR_SHAPE_MISMATCH` | Weight | Tensor dimension counts or ranks altered | **Detection** | $1.0$ |
| `ANOM_ARCH_TOPOLOGY_MUTATION`| Architecture | Graph edge connectivity or node list altered | **Detection** | $[0.90, 1.0]$ |
| `ANOM_OPERATOR_SUBSTITUTION` | Architecture | Layer operator replaced (e.g. GeLU $\to$ ReLU) | **Detection** | $1.0$ |
| `ANOM_INPUT_SHAPE_MISMATCH`  | Contract | Expected $[B, 3, 224, 224]$ observed $[B, 1, 128, 128]$ | **Detection** | $1.0$ |
| `ANOM_INPUT_DTYPE_MISMATCH`  | Contract | Expected `float32` observed `uint8` | **Detection** | $1.0$ |
| `ANOM_NORM_PARAM_MISMATCH`   | Contract | Dataset normalization mean/std $\ne$ model spec | **Detection** | $[0.85, 1.0]$ |
| `ANOM_CLASS_COUNT_MISMATCH`  | Contract | $K_{\text{model}} \ne K_{\text{dataset}}$ (e.g. 10 classes vs 1000) | **Detection** | $1.0$ |
| `ANOM_CLASS_VOCAB_MISMATCH`  | Contract | Class label mapping disjoint or permuted | **Detection** | $[0.90, 1.0]$ |
| `ANOM_METADATA_DISCREPANCY`  | Metadata | Author, license, or training hyperparams altered | **Detection** | $[0.80, 1.0]$ |
| `ANOM_FORMAT_CORRUPTED`      | Loader | Corrupted protobuf, malformed zip container | **Detection** | $1.0$ |
| `ANOM_FORMAT_UNSUPPORTED`    | Loader | Unrecognized file format or unsupported OpSet | **Detection** | $1.0$ |
| `ANOM_SECURITY_POLICY_VIOL`  | Security | Arbitrary code in pickle, path traversal in zip | **Detection** | $1.0$ |

---

## 3. Deterministic Multi-Tier Model Identity

To provide granular, explainable identity tracking, AIVARA decomposes model identity into three distinct hierarchical tiers bound through an explicit canonical structured representation (ADR-040):

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       MULTI-TIER MODEL IDENTITY                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  [ Tier 1: Artifact Identity ]                                              │
│    H_artifact = SHA-256( raw_file_bytes )                                   │
│    -> Byte-for-byte physical immutability                                   │
│                                                                             │
│  [ Tier 2: Structural Identity ]                                            │
│    H_structural = SHA-256( RFC_8785_JCS( Structural_Descriptor_Dict ) )     │
│    -> Format-agnostic architecture & parameter structure                    │
│                                                                             │
│  [ Tier 3: Operational Contract Identity ]                                  │
│    H_contract = SHA-256( RFC_8785_JCS( Contract_Specification_Dict ) )      │
│    -> Compatibility with pipelines, datasets, and inference engines         │
│                                                                             │
│  [ Master Model Fingerprint ]                                               │
│    H_model = SHA-256( RFC_8785_JCS( {                                       │
│                "schema_version": "1.0",                                     │
│                "artifact_hash": H_artifact,                                 │
│                "structural_hash": H_structural,                             │
│                "contract_hash": H_contract                                  │
│              } ) )                                                          │
│    -> Canonical, structured, extensible master model fingerprint            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Tier 1: Artifact Identity ($H_{\text{artifact}}$)
- **Definition:** Standard SHA-256 cryptographic digest of the raw model file stream on disk.
- **Purpose:** Fast byte-level tamper detection. Any bit alteration on disk changes $H_{\text{artifact}}$.
- **Limitation:** Sensitive to non-semantic file formatting differences (e.g., zip compression level, protobuf field ordering, metadata timestamps).

### 3.2 Tier 2: Structural Identity ($H_{\text{structural}}$)
- **Definition:** Canonical JSON serialization (RFC 8785 JCS) of sorted tensor descriptors and graph topology:
  $$H_{\text{structural}} = \text{SHA-256}(\text{JCS}(\mathcal{S}_{\text{model}}))$$
  where $\mathcal{S}_{\text{model}}$ contains:
  - `schema_version`: `"1.0"`
  - `tensor_count`: Total number of parameter tensors (integer).
  - `parameter_count`: Total parameter count (integer).
  - `tensors`: Deterministically sorted array (lexicographical by tensor name) of `[name, shape, dtype, sha256_bytes]`.
  - `graph_hash`: SHA-256 of canonical layer sequence and operator connectivity (where available).
- **Purpose:** Verifies whether the mathematical weights and architecture are identical even if container metadata differs.

### 3.3 Tier 3: Operational Contract Identity ($H_{\text{contract}}$)
- **Definition:** Canonical JSON serialization (RFC 8785 JCS) of I/O contracts and preprocessing schemas:
  $$H_{\text{contract}} = \text{SHA-256}(\text{JCS}(\mathcal{C}_{\text{model}}))$$
  where $\mathcal{C}_{\text{model}}$ contains:
  - `schema_version`: `"1.0"`
  - `input_spec`: Input tensor shapes, dtypes, channel orders (`NCHW` vs `NHWC`).
  - `preprocessing_config`: Normalization mean, standard deviation, color space, resize/crop resolution.
  - `output_spec`: Output tensor shape, activation type (`logits`, `softmax`, `sigmoid`).
  - `class_vocabulary`: Sorted list or mapping of class IDs to label strings.
- **Purpose:** Verifies whether the model can safely interoperate with a given dataset or downstream inference pipeline without silent dimension or normalization failures.

### 3.4 Master Model Fingerprint ($H_{\text{model}}$) & Structured Binding
- **Canonical Formulation (ADR-040):**
  The master model fingerprint binds the three tier hashes through an explicit RFC 8785 canonical JSON schema:
  ```json
  {
    "schema_version": "1.0",
    "artifact_hash": "a1b2c3d4e5...",
    "structural_hash": "f6e5d4c3b2...",
    "contract_hash": "9876543210..."
  }
  ```
  $$H_{\text{model}} = \text{SHA-256}(\text{JCS}(\text{MasterFingerprintPayload}))$$
- **Why Structured Binding is Preferable over Raw Concatenation:**
  1. *Unambiguous Field Boundaries:* Eliminates delimiter sliding and length-extension ambiguities inherent in raw binary concatenation.
  2. *Schema Versioning:* The explicit `"schema_version": "1.0"` field enables forward and backward compatibility when future revisions introduce additional metadata (e.g. quantization parameters or hardware profiles).
  3. *Engine Reuse:* Directly reuses Phase 4 canonical serialization (`backend/aivara/crypto/canonical.py`) without introducing secondary serialization logic.

---

## 4. Safe Model Inspection Boundary & Format Policy

Inspecting untrusted AI model artifacts is a critical security boundary. Arbitrary deserialization (e.g. `pickle.load()`) executes arbitrary Python bytecode embedded within serialized payloads (`__reduce__` exploit vectors).

### 4.1 Inspection Level Definitions
To prevent ambiguity, Phase 7 establishes three distinct operational inspection levels:
1. **Safe Static Parsing:** Reading file headers, zip container central directories, and static protobuf schemas without invoking language runtime interpreters, dynamic libraries, or unpicklers.
2. **Safe Deserialization:** Controlled loading of scalar and tensor numeric arrays strictly restricted to safe primitive numeric types via whitelisted AST parsers (`weights_only=True` or Safetensors zero-copy buffers), with zero execution of arbitrary classes or functions.
3. **Model Execution:** Instantiating live runtime execution graphs or executing operator kernels (strictly **PROHIBITED** in Phase 7).

### 4.2 Model Format Policy Table

```
┌────────────────────────────────┬──────────────────────────────────────────┬────────────────────────────────────────────┬────────────────────────┬───────────────────┬─────────────────────────────────────────────────────────────┐
│ FORMAT                         │ DEFAULT POLICY                           │ INSPECTION METHOD                          │ DESERIALIZATION RISK   │ EXECUTION ALLOWED?│ RATIONALE                                                   │
├────────────────────────────────┼──────────────────────────────────────────┼────────────────────────────────────────────┼────────────────────────┼───────────────────┼─────────────────────────────────────────────────────────────┤
│ **Safetensors**                │ **SUPPORTED**                            │ Safe Static Parsing & Safe Deserialization │ ZERO                   │ **NO**            │ Header is pure JSON; tensor buffers are raw byte arrays.   │
│ (`.safetensors`)               │ (Safe-Inspection)                        │ (Zero-copy header + memory-mapped hashes)  │                        │                   │ No executable bytecode possible.                            │
├────────────────────────────────┼──────────────────────────────────────────┼────────────────────────────────────────────┼────────────────────────┼───────────────────┼─────────────────────────────────────────────────────────────┤
│ **ONNX**                       │ **SUPPORTED**                            │ Safe Static Parsing                        │ ZERO (Static Protobuf) │ **NO**            │ Static protobuf schema; inspects graph topology & initial- │
│ (`.onnx`)                      │ (Safe-Static-Inspection)                 │ (Protobuf schema traversal)                │                        │                   │ izers without invoking ONNX Runtime or operator kernels.    │
├────────────────────────────────┼──────────────────────────────────────────┼────────────────────────────────────────────┼────────────────────────┼───────────────────┼─────────────────────────────────────────────────────────────┤
│ **PyTorch State Dict**         │ **RESTRICTED**                           │ Safe Deserialization                       │ MEDIUM (Controlled)    │ **NO**            │ Whitelists only tensor storage classes (`weights_only=True`│
│ (`.pt`, `.pth`, `.bin`)        │ (Safe-Loading Only)                      │ (`weights_only=True` / Restricted AST)     │                        │                   │ or custom Unpickler AST). Rejects any arbitrary callable.   │
├────────────────────────────────┼──────────────────────────────────────────┼────────────────────────────────────────────┼────────────────────────┼───────────────────┼─────────────────────────────────────────────────────────────┤
│ **TorchScript**                │ **RESTRICTED**                           │ Safe Static Archive Parsing                │ HIGH (if executed)     │ **NO**            │ Inspected strictly as a Zip archive (reading code/constants│
│ (`.pt`, `.pt2`)                │ (Safe-Static-Archive-Inspection Only)    │ (Zip member traversal & byte hashing)      │ LOW (static archive)   │                   │ metadata); `torch.jit.load()` is strictly FORBIDDEN.        │
├────────────────────────────────┼──────────────────────────────────────────┼────────────────────────────────────────────┼────────────────────────┼───────────────────┼─────────────────────────────────────────────────────────────┤
│ **Arbitrary Pickle Checkpoint**│ **PROHIBITED**                           │ REJECT IMMEDIATELY                         │ CRITICAL               │ **FORBIDDEN**     │ `pickle.load()` on unconstrained objects allows remote code │
│ (`.pkl`, full model objects)   │ (Forbidden)                              │ (Zero loading permitted)                   │ (Arbitrary Code Exec)  │                   │ execution via `__reduce__`. Hard policy rejection.          │
└────────────────────────────────┴──────────────────────────────────────────┴────────────────────────────────────────────┴────────────────────────┴───────────────────┴─────────────────────────────────────────────────────────────┘
```

### 4.3 Security Defenses & Sandboxing Guardrails

1. **Unrestricted `pickle.load()` Prohibition (ADR-041):** Calling `pickle.load()` without strict whitelist constraints is globally prohibited across the entire AIVARA codebase.
2. **Decompression Bomb Defense (Zip Bomb Protection):**
   - Maximum uncompressed size limit: $10\text{ GB}$ (configurable).
   - Maximum compression expansion ratio: $100:1$.
   - Maximum file entry count inside archive: $10,000$.
3. **Zip Slip / Path Traversal Defense:** All archive member paths are sanitized; any path containing `..`, leading slashes, or non-printable control characters is immediately rejected with `SecurityViolationError`.
4. **Memory Allocation Caps:** Tensor allocations during inspection stream raw chunks to cryptographic hash functions without loading multi-gigabyte arrays into RAM.

---

## 5. Reference Model Comparison & Explanatory State Taxonomy

AIVARA verifies model integrity by evaluating an **Observed Model Artifact** against an optional **Declared Reference Model Specification**.

### 5.1 Clean State Taxonomy

1. `MODEL_AVAILABLE`: The model artifact exists, passed all security checks, and was successfully parsed.
2. `MODEL_UNAVAILABLE`: The model file does not exist on disk or is inaccessible.
3. `MODEL_CORRUPTED`: The file is structurally malformed (truncated zip, corrupted protobuf).
4. `MODEL_INCOMPATIBLE`: Unsupported model format, unsupported OpSet version, or unparseable custom layer.
5. `SECURITY_POLICY_VIOLATION`: Malicious pickle payload, zip slip traversal, or decompression bomb detected.
6. `REFERENCE_UNAVAILABLE`: Model inspected successfully, but no reference fingerprint was registered for comparison.
7. `REFERENCE_MATCH`: Observed model fingerprint matches reference specification across all requested tiers.
8. `REFERENCE_MISMATCH`: Discrepancy observed between observed model properties and reference specification.

---

## 6. Input / Output Contract Integrity

A model may have intact weights but fail catastrophically in deployment due to operational contract divergence against its target dataset. Phase 7 verifies operational compatibility:

### 6.1 Input Contract Specification
- **Tensor Rank & Shape:** Expected input tensor rank ($4$ for 2D images: $[B, C, H, W]$ or $[B, H, W, C]$).
- **Dimension Constraints:** Fixed resolution (e.g. $224 \times 224$) vs Dynamic resolution.
- **Channel Format & Ordering:** RGB vs BGR vs Grayscale ($C \in \{1, 3, 4\}$).
- **Data Type & Range:** `float32` normalized in $[0, 1]$ or $[-1, 1]$ vs `uint8` in $[0, 255]$.
- **Preprocessing Transforms:** Expected mean $\mu = [\mu_R, \mu_G, \mu_B]$ and standard deviation $\sigma = [\sigma_R, \sigma_G, \sigma_B]$.

### 6.2 Output Contract Specification
- **Output Tensor Shape:** Number of output dimensions and batch handling.
- **Class Cardinality ($K$):** Number of output classes $K_{\text{model}}$ must match target dataset $K_{\text{dataset}}$.
- **Activation Semantics:** Raw logits ($z \in (-\infty, +\infty)$) vs Softmax probabilities ($p \in [0, 1], \sum p = 1$) vs Multi-label sigmoid.
- **Vocabulary Mapping:** Explicit class ID to label name dictionary (`{0: "cat", 1: "dog"}`).

---

## 7. Architecture Decisions (ADR-040 through ADR-047)

### ADR-040: Multi-Tier Model Identity with Canonical Structured Binding
- **Decision:** Decompose model identity into three independent hierarchical tiers ($H_{\text{artifact}}$, $H_{\text{structural}}$, $H_{\text{contract}}$) bound into a master fingerprint $H_{\text{model}}$ via an explicit RFC 8785 (JCS) canonical dictionary with schema versioning.
- **Rationale:** Byte-level hashes alone fail when container formats repack identical weights; structural hashes alone fail when preprocessing contracts mutate. Structured JCS binding eliminates delimiter sliding ambiguities and provides deterministic extensibility.
- **Consequences:** Unambiguous, granular, and forward-compatible identity tracking.

### ADR-041: Safe Model Inspection Boundary & Unsafe Pickle Prohibition
- **Decision:** Strictly forbid unrestricted `pickle.load()` execution. Implement safe static inspection for ONNX, Safetensors, and safe AST/weights-only PyTorch unpickling. Prohibit dynamic model execution in Phase 7.
- **Rationale:** Untrusted model files must never achieve arbitrary remote code execution on the verification host.
- **Consequences:** Eliminates supply chain code-injection vulnerabilities.

### ADR-042: Format Tiering & ONNX-First Architecture Inspection
- **Decision:** Establish ONNX and Safetensors as primary open formats for safe inspection, permit PyTorch state dicts strictly under `weights_only=True`, and restrict TorchScript to static archive member inspection without runtime execution.
- **Rationale:** Lightweight, air-gapped, framework-agnostic inspection without runtime framework dependencies.
- **Consequences:** Robust offline parsing across diverse CV formats.

### ADR-043: Input/Output Contract Verification
- **Decision:** Mandate formal verification of input shapes, dtypes, channel layouts, preprocessing parameters, output activations, and class vocabularies.
- **Rationale:** A majority of silent CV pipeline failures stem from preprocessing or channel ordering mismatches rather than corrupted weights.
- **Consequences:** Early detection of integration failures before dynamic execution.

### ADR-044: Reference Model Comparison Semantics
- **Decision:** Formally distinguish between exploratory baseline inspection (`REFERENCE_UNAVAILABLE`) and active compliance comparison (`REFERENCE_MATCH` vs `REFERENCE_MISMATCH`).
- **Rationale:** Models are often registered before an authoritative reference is declared. The engine must support baseline generation without false compliance failure alarms.
- **Consequences:** Clean separation between inspection and compliance verification.

### ADR-045: Two-Layer Model Assurance & Proof/Detection Decoupling
- **Decision:** Enforce ADR-028 two-layer separation: Cryptographic artifact hashes and Ed25519 signatures belong to `evidence_layer="proof"` ($\text{confidence} = 1.0$), while structural, weight, and contract comparisons belong to `evidence_layer="detection"`.
- **Rationale:** Cryptographic facts must never be blurred or numerically averaged with heuristic or structural differentials.
- **Consequences:** Maintains uncompromised cryptographic rigor across the system.

### ADR-046: Database Schema Preservation & Entity Reuse
- **Decision:** Reuse existing frozen database entities (`AIModelModel`, `ModelFingerprintModel`, `FindingModel`, `EvidenceModel`, `ProvenanceRecordModel`, `RiskAssessmentModel`) with **ZERO schema migrations**.
- **Rationale:** The established database schema already provides comprehensive model, fingerprint, finding, and evidence tables.
- **Consequences:** Zero migration friction, 100% backward compatibility.

### ADR-047: Semantic Safety & Intent Prohibition for Model Integrity
- **Decision:** Enforce ADR-035 vocabulary restrictions across all Model Integrity findings, evidence summaries, and API payloads. Technical security terms (`adversarial robustness`, `poisoning vulnerability`, `threat model`) are allowed; accusatory terms (`malicious`, `sabotage`, `guilty`, `fraudulent`, `collusion`) are strictly prohibited.
- **Rationale:** Scientific assurance requires neutral, observable descriptions of model properties rather than speculation about developer motives.
- **Consequences:** Objective, defensible compliance artifacts.

---

## 8. Requirements Specification

### 8.1 Functional Requirements (FR)

- **FR-MI-001 (Model Registration):** The system SHALL register AI model artifacts with metadata, framework format, declared architecture, and file path.
- **FR-MI-002 (Artifact Hashing):** The system SHALL compute deterministic SHA-256 cryptographic digests of raw model files streamingly without excessive RAM buffering.
- **FR-MI-003 (Safe Inspection):** The system SHALL parse model files using safe deserializers without executing untrusted bytecode or arbitrary scripts.
- **FR-MI-004 (Weight Merkle Digest):** The system SHALL extract tensor descriptors (name, shape, dtype) and compute a deterministic Merkle root over sorted tensor hashes.
- **FR-MI-005 (Graph Extraction):** The system SHALL extract layer sequence, operator types, and graph connectivity for supported formats (ONNX, TorchScript).
- **FR-MI-006 (Contract Extraction):** The system SHALL extract or parse declared input/output tensor contracts, channel configurations, and class mappings.
- **FR-MI-007 (Reference Comparison):** The system SHALL compare observed model fingerprints against declared reference model specifications across all 3 tiers.
- **FR-MI-008 (Evidence Generation):** The system SHALL generate structured, traceable Phase 5.9 evidence items for all observed integrity matches and mismatches.
- **FR-MI-009 (Finding Synthesis):** The system SHALL synthesize standardized findings with severity, confidence, and asset references according to ADR-028.
- **FR-MI-010 (Provenance Sealing):** The system SHALL optionally seal model integrity assessments into the Phase 4 cryptographic provenance ledger.
- **FR-MI-011 (REST API):** The system SHALL expose model registration, inspection, verification, and graph retrieval endpoints complying with standard `ApiResponse` envelopes.
- **FR-MI-012 (Semantic Safety):** The system SHALL reject all prohibited human-intent vocabulary across all generated findings and API responses.

### 8.2 Non-Functional Requirements (NFR)

- **NFR-MI-001 (Offline & Air-Gapped):** The subsystem SHALL operate 100% locally with zero network, cloud AI, or remote registry dependencies.
- **NFR-MI-002 (Security & Sandboxing):** Safe parsers SHALL enforce limits on uncompressed archive size ($10\text{ GB}$), compression ratios ($100:1$), and reject path traversal attempts.
- **NFR-MI-003 (Determinism):** Identical model artifacts evaluated under identical reference specifications SHALL produce bit-for-bit identical canonical JSON payloads.
- **NFR-MI-004 (Zero Schema Changes):** The subsystem SHALL operate with zero database schema migrations, reusing existing tables and models.
- **NFR-MI-005 (Performance Benchmark Policy):**
  - The system SHALL target $\le 5\text{ seconds}$ total inspection time for representative $\le 500\text{ MB}$ reference fixtures on defined benchmark hardware, with actual execution times measured and recorded across model size and complexity tiers.
  - *Benchmark Hardware Specification:* Quad-core x86_64 or ARM64 CPU $\ge 2.5\text{ GHz}$, $16\text{ GB}$ RAM, local NVMe/SSD storage.
  - *Representative Fixtures:* Standard CV models including ResNet-50 ($\sim 100\text{ MB}$), EfficientNet-B0 ($\sim 20\text{ MB}$), ViT-Base ($\sim 350\text{ MB}$), ConvNeXt-Large ($\sim 750\text{ MB}$).
  - *Measurement Instrumentation:* Inspection engines SHALL measure and record granular sub-operation times:
    1. $t_{\text{artifact}}$: Raw file stream SHA-256 computation time.
    2. $t_{\text{structural}}$: Safe header/protobuf parsing & graph extraction time.
    3. $t_{\text{weights}}$: Tensor-level Merkle hashing time.
    4. $t_{\text{contract}}$: I/O contract & vocabulary extraction time.
    5. $t_{\text{total}}$: End-to-end inspection and fingerprinting time.
  - *Cache Policy:* Benchmark testing SHALL evaluate both cold-cache (first load from disk) and warm-cache execution.
- **NFR-MI-006 (Multi-Tenant Isolation):** Model artifacts, fingerprints, findings, and evidence SHALL be strictly partitioned by `project_id`.
- **NFR-MI-007 (Explainability):** Every model mismatch SHALL provide exact structural root-cause details (e.g., exact tensor name, observed shape vs expected shape).
- **NFR-MI-008 (Cryptographic Integrity):** Proof-layer findings SHALL enforce confidence $= 1.0$ and utilize Ed25519 digital signatures.

---

## 9. Risk Register

| Risk ID | Description | Likelihood | Impact | Mitigation Strategy | Residual Risk |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **RSK-MI-01** | Arbitrary code execution via malicious pickle checkpoint | High | Critical | Enforce `weights_only=True` and safe custom Unpickler; reject unconstrained pickle formats (ADR-041). | Low |
| **RSK-MI-02** | Denial of Service via Decompression Bomb (Zip Bomb) | Medium | High | Enforce pre-extraction byte limits, compression ratio bounds, and entry count limits (NFR-MI-002). | Low |
| **RSK-MI-03** | Out of Memory (OOM) on multi-gigabyte foundation models | Medium | Medium | Stream tensor chunks directly to cryptographic hash functions without accumulating full arrays in RAM. | Low |
| **RSK-MI-04** | Accidental network call to remote model hub (e.g. HuggingFace) | Medium | High | Strict air-gapped design; unit tests run under socket interception guardrails. | Zero |
| **RSK-MI-05** | Flaky fingerprinting due to floating-point formatting | Low | Medium | Standardize floating-point tensor serialization via raw IEEE 754 byte streams and RFC 8785 JCS for metadata. | Low |
| **RSK-MI-06** | Accidental scalar risk scoring calculation | Low | High | Enforce multi-dimensional profile representation; forbid scalar score aggregation in Phase 7 (ADR-040). | Zero |

---

## 10. Proposed Phase 7 Subphases

To ensure clean, modular, test-driven implementation, Phase 7 is decomposed into 8 logical subphases:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PHASE 7 SUBPHASE ROADMAP                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Phase 7.1  Architecture & Requirements Freeze (Current)                    │
│             -> Freeze ADR-040 to ADR-047, Threat Surface, & Taxonomy        │
│                                                                             │
│  Phase 7.2  Safe Model Ingestion & Format Parsers                           │
│             -> ONNX, Safetensors, & Safe PyTorch StateDict parsers          │
│                                                                             │
│  Phase 7.3  Multi-Tier Model Fingerprinting Engine                          │
│             -> Artifact hash, Tensor Merkle digest, & Structural hash       │
│                                                                             │
│  Phase 7.4  Input / Output Contract & Preprocessing Verification            │
│             -> Shape, dtype, normalization, & vocabulary extraction         │
│                                                                             │
│  Phase 7.5  Reference Model Comparison Engine                               │
│             -> Multi-tier diffing, mismatch analysis, & load states         │
│                                                                             │
│  Phase 7.6  Evidence Generation & Provenance Binding                        │
│             -> Phase 5.9 evidence synthesis & Phase 4 cryptographic seal    │
│                                                                             │
│  Phase 7.7  REST API & Integration Services                                 │
│             -> Model registration, verification endpoints, & envelopes      │
│                                                                             │
│  Phase 7.8  Comprehensive Verification & Final Freeze                       │
│             -> Exhaustive end-to-end security, regression, & air-gap tests  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 11. Freeze Declaration & Compliance Summary

- **Architecture Status:** Phase 7.1 is complete and ready for formal review.
- **Production Code Status:** **ZERO production code implemented** in this architectural phase.
- **Database Status:** **ZERO schema migrations or alterations**.
- **Cryptographic Status:** Phase 4 and Phase 5.9 remain the sole authoritative cryptographic and provenance foundations.
- **Phase Boundaries:** Phase 8, 9, 10, 11, 12, and 13 remain strictly excluded.
