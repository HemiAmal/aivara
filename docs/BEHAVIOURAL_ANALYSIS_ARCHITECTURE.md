# Phase 8 — Behavioral Analysis Architecture & Requirements Specification

**Subsystem:** AIVARA Behavioral Analysis Engine (BAE)  
**Document Version:** 1.1.0  
**Phase Status:** Phase 8.1 — Architecture & Requirements Freeze  
**Author:** DeepMind / AIVARA Engineering Team  
**Date:** 2026-09-11  

---

## 1. Executive Summary & Objective

The **Behavioral Analysis Subsystem (Phase 8)** is the controlled observation, runtime execution, and dynamic behavioral measurement engine of AIVARA. It evaluates how an AI/Computer Vision model artifact responds to controlled, deterministically defined inputs, repeatable executions, environmental variations, input perturbations, and baseline comparisons.

### 1.1 Central Objective
> *"Establish deterministically and quantitatively how an AI/CV model artifact behaves under controlled, isolated observations, whether its behavioral outputs are repeatable, stable, and reference-consistent, and whether it exhibits statistically significant behavioral anomalies relative to defined baselines."*

### 1.2 Non-Inference of Human Intent (Foundational Invariant)
Phase 8 operates under the core AIVARA semantic separation invariant:
$$\text{BEHAVIORAL DEVIATION} \ne \text{MALICIOUSNESS}$$
$$\text{PERTURBATION SENSITIVITY} \ne \text{ATTACK SUCCESS}$$
$$\text{NUMERICAL INSTABILITY} \ne \text{DELIBERATE SABOTAGE}$$
$$\text{UNAVAILABLE BASELINE} \ne \text{BEHAVIORAL ANOMALY}$$

Phase 8 observes, measures, normalizes, and compares model responses. It **NEVER** asserts human motive, maliciousness, attacker presence, compromise, or culpability.

---

## 2. Scope and Non-Goals

### 2.1 In Scope (Phase 8)
1. **Controlled Local Model Execution Boundary:** Resource-bounded, offline, isolated model execution (via ONNX Runtime with default `CPUExecutionProvider` and safe local execution adapters).
2. **Deterministic Input Management:** Ingestion and tracking of reference dataset samples, synthetic test inputs, and controlled perturbations.
3. **Canonical Behavioral Observations:** Structured, deterministic schemas capturing model outputs, logits/probabilities, bounding boxes, latencies, and execution telemetry.
4. **Task-Specific Output Normalization:** Standardized extractors and mathematical transforms for Classification, Object Detection, and Segmentation (with strict ground-truth vs. reference model metric separation).
5. **Repeatability & Numerical Stability:** Multi-run identical input evaluation to quantify floating-point variance, seed dependency, and determinism.
6. **Controlled Perturbation Framework:** Parameterized, deterministic input modifications (noise, blur, contrast, geometric shift) to measure sensitivity gradients.
7. **Behavioral Metrics & Divergence:** Information-theoretic, geometric, and rank-based metrics (KL divergence, JS divergence, Wasserstein distance, IoU overlap, Top-k agreement, Reference Mask Agreement).
8. **Reference & Baseline Comparison:** Multi-dimensional deviation analysis against reference models, golden execution profiles, or historical baselines.
9. **Empirical Anomaly Detection:** Non-parametric, robust statistical thresholding (MAD, robust z-score, empirical quantiles) with sample-size shrinkage.
10. **Assurance Evidence & Provenance Binding:** Integration with Phase 4 cryptographic signatures and Phase 5.9 canonical evidence synthesis.

### 2.2 Non-Goals & Strict Phase Boundaries
- **Phase 7 (Model Integrity):** Static file, structural, weight Merkle, and I/O contract inspection (FROZEN in Phase 7).
- **Phase 9 (Backdoor & Trigger Analysis):** Latent-space trigger inversion, poisoned subnet scanning, Trojan backdoor search (OUT OF SCOPE for Phase 8).
- **Phase 10 (Inference Integrity):** Production pipeline runtime execution, hardware timing side-channels, live serving replay verification (OUT OF SCOPE for Phase 8).
- **Phase 11 (Distribution Shift):** Population-level dataset covariate shift, concept drift modeling (OUT OF SCOPE for Phase 8).
- **Phase 12 (Universal Risk Engine):** Cross-subsystem multi-entity synthesis, global risk quantification (OUT OF SCOPE for Phase 8).
- **Phase 13 (Attack Simulation Lab):** Active adversarial exploitation, evasion attack generation (OUT OF SCOPE for Phase 8).
- **Phases 14–16 (Frontend, Reports, Blockchain):** UI components, PDF generation, blockchain anchoring (OUT OF SCOPE for Phase 8).

---

## 3. Separation of Detection and Proof Layers (ADR-028 Alignment)

Phase 8 strictly maintains the architectural two-layer model defined in ADR-028:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                          AIVARA TWO-LAYER ARCHITECTURE                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. PROOF LAYER (evidence_layer = "proof", confidence = 1.0)                 │
│    - Input artifact SHA-256 digests                                         │
│    - Model Master Fingerprint (H_master) binding                            │
│    - Ed25519 digital signatures over canonical observation ledgers          │
│    - Nonce uniqueness and hash-linked provenance chains                     │
│                                                                             │
│ 2. DETECTION LAYER (evidence_layer = "detection", confidence in [0.0, 1.0]) │
│    - Measured output distributions and probabilities                        │
│    - Repeatability delta and floating-point stability metrics               │
│    - Perturbation sensitivity scores                                        │
│    - Reference behavioral divergence and distance metrics                   │
│    - Behavioral anomaly classifications and empirical p-values              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Invariant:** A behavioral anomaly is a statistical detection, not a mathematical proof. Proof layer guarantees that an observation was genuinely recorded and signed; detection layer quantifies the behavior observed.

---

## 4. Controlled Local Model Execution Boundary

Unlike Phase 7 static analysis, Phase 8 executes model forward passes under a strict, isolated **Controlled Local Model Execution Boundary**:

```text
               +----------------------------------------------------+
               |             UNTRUSTED CANDIDATE MODEL              |
               +----------------------------------------------------+
                                         |
                                         v
               +----------------------------------------------------+
               |               SAFE EXECUTION GATEWAY               |
               | - Verify Phase 7 Master Fingerprint & Policy       |
               | - Set Execution Provider = CPUExecutionProvider    |
               | - Enforce Timeout, Batch Limits, and Memory Bounds |
               +----------------------------------------------------+
                                         |
                                         v
               +----------------------------------------------------+
               |       CONTROLLED LOCAL MODEL EXECUTION BOUNDARY    |
               | - ONNX Runtime / Safe Static Framework Wrapper    |
               | - Default Backend: CPUExecutionProvider            |
               | - Explicit Opt-In: CUDAExecutionProvider           |
               | - Air-Gapped Network Isolation (Socket Blocked)    |
               | - Memory Bound (e.g. <= 4GB RAM)                   |
               | - Timeout (e.g. <= 10s / batch) with Cancellation  |
               | - Restricted Temp Directory & Environment Scrub    |
               | - Deterministic Seed (Torch/Numpy PRNG)            |
               +----------------------------------------------------+
                                         |
                                         v
               +----------------------------------------------------+
               |             STANDARDIZED TENSOR OUTPUTS            |
               | (Classification / Detection / Segmentation)        |
               +----------------------------------------------------+
```

### 4.1 Boundary Distinction & Security Guarantees
**Important Clarification:** ONNX Runtime is a high-performance execution engine; it does **not** by itself constitute an OS-level or hypervisor-level security sandbox. Phase 8 therefore establishes a **Controlled Local Model Execution Boundary** enforcing the following 11 concrete containment guarantees:
1. **Controlled Execution Process:** Inference is isolated within structured worker execution wrappers.
2. **Hard Execution Timeout:** Per-inference and per-batch wall-clock timeout (default: 10,000 ms) with immediate cancellation on expiry.
3. **Resource Limits:** Hard caps on batch size ($B \le 64$), tensor element counts, and memory allocations.
4. **Restricted Filesystem Access:** Read-only access to model and input files; temporary writes restricted strictly to designated, isolated scratch directories.
5. **Air-Gapped Network Isolation:** All network sockets and outbound DNS/HTTP calls are actively disabled and blocked.
6. **Subprocess Execution Prohibition:** No arbitrary subprocess or shell spawning is permitted during model execution.
7. **Controlled Environment Variables:** Environment variables are sanitized to prevent dynamic library injection or unauthorized execution path overrides.
8. **Controlled Temporary Directory:** All temporary working files are placed in dedicated sandbox directories and wiped post-execution.
9. **Output-Size & Allocation Limits:** Extracted tensor dimensions and response payloads are strictly bounded to prevent memory bombs.
10. **Cancellation & Termination Handling:** Clean handling of cancellation signals and worker thread termination.
11. **Fail-Closed Behavior:** Any unhandled execution exception, runtime crash, or invariant breach terminates inference immediately with `EXECUTION_ERROR` or `RESOURCE_LIMIT`.

### 4.2 Execution Provider Policy (CPU by Default, CUDA Opt-In)
- **DEFAULT:** `CPUExecutionProvider` (CPU execution).
- **OPTIONAL:** `CUDAExecutionProvider` (CUDA GPU execution), strictly as an **EXPLICIT OPT-IN**.
- **Rationale:**
  1. CPU execution provides the most conservative, predictable baseline.
  2. Ensures high reproducibility across heterogeneous environments.
  3. Avoids non-deterministic floating-point reduction variations inherent to GPU parallelism.
  4. Hardware availability must not silently change behavioral results without explicit user direction.
  5. Security-sensitive analysis should maintain an auditable, stable execution backend.
- **Execution Telemetry:** Every execution record must explicitly capture:
  - `execution_provider` (e.g. `"CPUExecutionProvider"`, `"CUDAExecutionProvider"`)
  - `device` (e.g. `"cpu"`, `"cuda:0"`)
  - `runtime_version` (e.g. `"onnxruntime 1.17.0"`)
  - `precision` (e.g. `"float32"`, `"float16"`)

### 4.3 Safe Format Execution Policies
1. **ONNX Models:** Executed via `onnxruntime.InferenceSession` under the configured provider.
2. **Safetensors / PyTorch State Dicts:** Executed ONLY when paired with an explicitly configured, trusted, pre-verified architectural wrapper. Arbitrary model class instantiation is prohibited.
3. **Prohibited Formats:** Arbitrary pickled checkpoints, unconstrained `torch.load()`, and raw script executions are immediately rejected with `EXECUTION_UNAVAILABLE` or `UNSUPPORTED_EXECUTION_FORMAT`.

---

## 5. Supported Task Types & Canonical Normalization

Phase 8 supports three primary computer vision and machine learning tasks:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SUPPORTED CV TASK TYPES                           │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. CLASSIFICATION                                                           │
│    - Top-1 Predicted Class Index and Label                                  │
│    - Top-K Class Indices and Probabilities/Logits                           │
│    - Output Shannon Entropy: H(p) = - \sum p_i \ln(p_i)                     │
│    - Prediction Margin: \Delta p = p_{(1)} - p_{(2)}                        │
│    - Softmax Temperature Normalization                                      │
│                                                                             │
│ 2. OBJECT DETECTION                                                         │
│    - Detection Count N_det                                                  │
│    - Bounding Box Coordinates: [x_min, y_min, x_max, y_max]                 │
│    - Per-box Class Predictions and Confidence Scores                        │
│    - Spatial Distribution (Centroid Centering, Area Spread)                 │
│    - Non-Maximum Suppression (NMS) Parameter Tracking                       │
│                                                                             │
│ 3. SEGMENTATION                                                             │
│    - Per-pixel Class Categorization & Histogram                             │
│    - Class Area Proportions (Pixel Counts / Total Pixels)                   │
│    - Strict Distinction: Ground-Truth mIoU vs. Reference Mask Agreement     │
│    - Spatial Boundary Sharpness & Entropy Map                               │
│                                                                             │
│ 4. UNSUPPORTED / CUSTOM TASKS                                               │
│    - Unrecognized output shape or missing contract                          │
│    - Returns STATUS = UNSUPPORTED or UNVERIFIABLE                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Controlled Perturbation Framework

Phase 8 implements a deterministic, parameterized perturbation generator to evaluate behavioral sensitivity and local stability:

$$\tilde{x} = \mathcal{T}(x; \theta, s)$$
where $\theta$ is the perturbation intensity parameter and $s$ is the deterministic PRNG seed.

### 6.1 Standard Perturbation Operators

| Perturbation Type | Parameters ($\theta$) | Formula / Operation | Deterministic Invariant |
| :--- | :--- | :--- | :--- |
| **Gaussian Noise** | $\sigma \in [0.01, 0.20]$ | $x' = \text{clip}(x + \mathcal{N}(0, \sigma^2), 0, 1)$ | Seeded PRNG |
| **Uniform Noise** | $\epsilon \in [0.01, 0.15]$ | $x' = \text{clip}(x + \mathcal{U}(-\epsilon, \epsilon), 0, 1)$ | Seeded PRNG |
| **Brightness Shift** | $\beta \in [-0.3, +0.3]$ | $x' = \text{clip}(x + \beta, 0, 1)$ | Deterministic scalar |
| **Contrast Scaling** | $\gamma \in [0.5, 1.5]$ | $x' = \text{clip}((x - \mu)\gamma + \mu, 0, 1)$ | Deterministic scalar |
| **Gaussian Blur** | $k \in \{3, 5, 7\}, \sigma \in [0.5, 2.0]$ | $x' = x * G_{k, \sigma}$ | Fixed convolution kernel |
| **JPEG Compression** | $Q \in \{30, 50, 70, 90\}$ | $x' = \text{JPEG\_Encode\_Decode}(x, Q)$ | Canonical codec |
| **Spatial Translation** | $(\Delta x, \Delta y) \in [-4, +4]\text{px}$ | Affine coordinate shift with zero-padding | Exact grid interpolation |

**Rule:** Every perturbation execution records `source_input_hash`, `perturbed_input_hash`, `perturbation_type`, `perturbation_params`, and `seed`.

---

## 7. Mathematical Behavioral Metrics & Segmentation Semantics

Phase 8 defines explicit, mathematically bounded metrics for comparative and stability analysis:

### 7.1 Classification Metrics
1. **Top-1 Agreement:**
   $$\text{Agreement}(y_1, y_2) = \mathbb{I}(y_1 = y_2) \in \{0, 1\}$$
2. **Kullback-Leibler (KL) Divergence (Probabilities only):**
   $$D_{\text{KL}}(P \parallel Q) = \sum_{i=1}^{K} P(i) \ln\left(\frac{P(i)}{Q(i) + \epsilon}\right)$$
3. **Jensen-Shannon (JS) Divergence (Symmetric, bounded $[0, \ln 2]$):**
   $$M = \frac{1}{2}(P + Q), \quad D_{\text{JS}}(P \parallel Q) = \frac{1}{2} D_{\text{KL}}(P \parallel M) + \frac{1}{2} D_{\text{KL}}(Q \parallel M)$$
4. **Total Variation Distance ($L_1$ norm on simplex):**
   $$\delta_{\text{TV}}(P, Q) = \frac{1}{2} \sum_{i=1}^K |P(i) - Q(i)| \in [0, 1]$$
5. **Prediction Margin Delta:**
   $$\Delta_{\text{margin}} = |(P_{(1)} - P_{(2)}) - (Q_{(1)} - Q_{(2)})|$$

### 7.2 Detection Metrics
1. **Detection Count Delta:**
   $$\Delta N = |N_{\text{cand}} - N_{\text{ref}}|$$
2. **Bipartite Matching IoU (Hungarian Assignment):**
   $$\text{mIoU}_{\text{det}} = \frac{1}{|M|} \sum_{(i, j) \in M} \text{IoU}(B_i^{\text{cand}}, B_j^{\text{ref}})$$
3. **Class Distribution Wasserstein Distance:**
   $$\mathcal{W}_1(P_{\text{class}}, Q_{\text{class}})$$

### 7.3 Segmentation Metrics & Ground-Truth Semantics
The architecture strictly enforces three distinct segmentation evaluation cases:

- **CASE A: Dense Ground-Truth Segmentation Masks Available**
  - **Allowed Metric:** `mIoU` (Mean Intersection-over-Union).
  - **Definition:** Candidate prediction mask $M_{\text{cand}}$ compared against authoritative ground-truth mask $M_{\text{gt}}$:
    $$\text{mIoU} = \frac{1}{C} \sum_{c=1}^C \frac{|M_{\text{cand}}^{(c)} \cap M_{\text{gt}}^{(c)}|}{|M_{\text{cand}}^{(c)} \cup M_{\text{gt}}^{(c)}|}$$

- **CASE B: No Ground-Truth Masks, Reference Model Output Available**
  - **Allowed Metric:** `REFERENCE_MASK_AGREEMENT` (or `reference_mask_agreement`).
  - **Definition:** Pairwise spatial overlap and label agreement between candidate model mask $M_{\text{cand}}$ and reference model mask $M_{\text{ref}}$:
    $$\text{Agreement}_{\text{mask}} = \frac{1}{C} \sum_{c=1}^C \frac{|M_{\text{cand}}^{(c)} \cap M_{\text{ref}}^{(c)}|}{|M_{\text{cand}}^{(c)} \cup M_{\text{ref}}^{(c)}|}$$
  - **Strict Semantic Rule:** This is explicitly model-to-model agreement. It is **NOT** ground-truth mIoU and must never be labeled as mIoU.

- **CASE C: Neither Ground Truth nor Reference Output Available**
  - **Result:** Return status `UNAVAILABLE` or `UNVERIFIABLE`.
  - **Strict Rule:** Do **NOT** calculate mIoU or invent synthetic ground truth.

### 7.4 General Numerical Stability Metrics
1. **Maximum Absolute Logit Error:**
   $$\epsilon_{\infty} = \max_i |z_i^{(1)} - z_i^{(2)}|$$
2. **Root Mean Square Error (RMSE):**
   $$\text{RMSE} = \sqrt{\frac{1}{K} \sum_{i=1}^K (z_i^{(1)} - z_i^{(2)})^2}$$
3. **Cosine Similarity:**
   $$S_{\cos}(z^{(1)}, z^{(2)}) = \frac{z^{(1)} \cdot z^{(2)}}{\|z^{(1)}\|_2 \|z^{(2)}\|_2}$$

---

## 8. Repeatability and Numerical Stability Analysis

Given $N_{\text{runs}}$ repeated executions with identical input $x$, identical seed $s$, and identical preprocessing:

$$\Delta_{\text{rep}} = \max_{j > 1} \|f_j(x) - f_1(x)\|_{\infty}$$

### Classification of Repeatability:
- **DETERMINISTIC:** $\Delta_{\text{rep}} = 0.0$ (Bit-for-bit exact identical outputs).
- **NUMERICALLY_STABLE:** $\Delta_{\text{rep}} \le \tau_{\text{float}}$ (e.g. $\tau = 10^{-5}$ for FP32, $10^{-3}$ for FP16/CUDA).
- **NONDETERMINISTIC:** $\Delta_{\text{rep}} > \tau_{\text{float}}$ or Top-1 prediction changes across identical runs.
- **UNVERIFIABLE:** Environment does not support repeat execution measurement.

---

## 9. Baseline Management & Reference Comparison

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                          BEHAVIORAL BASELINE TIERS                          │
├─────────────────────────────────────────────────────────────────────────────┤
│ Tier 1: REFERENCE MODEL (Gold Standard)                                     │
│   Candidate model f_cand is compared directly against reference f_ref on   │
│   identical test set inputs.                                                │
│                                                                             │
│ Tier 2: HISTORICAL EXECUTION PROFILE                                        │
│   Candidate model is compared against pre-recorded, signed execution logs.  │
│                                                                             │
│ Tier 3: SYNTHETIC / CONTRACTUAL SPECIFICATION                               │
│   Candidate model is evaluated against formal invariant rules (e.g.        │
│   invariance to brightness shift, Lipschitz bounds).                        │
│                                                                             │
│ Tier 4: SELF-BASELINE (Internal Perturbation Response)                      │
│   Candidate model's clean output f_cand(x) is compared against its own      │
│   perturbed output f_cand(\tilde{x}).                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 9.1 Reference Comparison Outcomes:
1. `BEHAVIOR_MATCH`: Measured divergence below established empirical threshold $\tau_{\text{match}}$.
2. `BEHAVIOR_DEVIATION`: Statistically significant divergence exceeding $\tau_{\text{dev}}$.
3. `PARTIAL_COMPARISON`: Output schemas only partially overlap (e.g. subset of classes matched).
4. `REFERENCE_UNAVAILABLE`: No reference model or historical baseline provided.
5. `INCOMPATIBLE_REFERENCE`: Reference model operates on different task, shapes, or incompatible label space.
6. `UNVERIFIABLE`: Inference execution failure on candidate or reference.

---

## 10. Behavioral Anomaly Detection & Empirical Thresholding

Behavioral anomalies are detected using robust, distribution-free statistical estimators over evaluation sets $\mathcal{D}_{\text{eval}}$:

### 10.1 Median Absolute Deviation (MAD) Estimator
For metric sequence $M = \{m_1, m_2, \dots, m_N\}$:
$$\text{Median}(M) = \tilde{m}$$
$$\text{MAD}(M) = \text{Median}(|m_i - \tilde{m}|)$$
$$\text{Robust } Z\text{-Score: } z_i^* = \frac{0.6745 \cdot (m_i - \tilde{m})}{\text{MAD}(M) + \epsilon}$$

An observation is flagged as an empirical anomaly if $|z_i^*| > \tau_{\text{anomaly}}$ (typically $\tau = 3.5$).

### 10.2 Small-Sample Protection (Shrinkage)
When evaluation sample size $N < 30$:
- Confidence is shrunk toward zero via empirical shrinkage: $c_{\text{adj}} = c \cdot \frac{N}{N + N_0}$ with prior pseudo-count $N_0 = 10.0$.
- If $N < 5$, anomaly status defaults to `INSUFFICIENT_SUPPORT`.

---

## 11. Confidence Semantics (ADR-028 Compliance)

The `confidence` field in Phase 8 findings and evidence represents **confidence in the observation and metric fidelity**, defined as:

$$c = f(N_{\text{samples}}, \text{SNR}, \text{RepeatabilityScore}) \in [0.0, 1.0]$$

- $c = 0.95$: *"We have 95% statistical confidence that the observed 18.2% drop in Top-1 agreement under Gaussian noise is an accurate behavioral measurement."*
- **PROHIBITED INTERPRETATION:** *"There is a 95% probability that the model has been backdoored or attacked."*

---

## 12. Complete Status & Reason Code Taxonomy

### 12.1 Execution Status (`ExecutionStatus`)
- `SUCCESS`: Inference executed cleanly, outputs parsed and validated.
- `EXECUTION_UNAVAILABLE`: Execution backend or runtime dependencies missing.
- `UNSUPPORTED_FORMAT`: Container cannot be safely executed.
- `TIMEOUT`: Model forward pass exceeded allocated wall-clock time limit.
- `RESOURCE_LIMIT`: Execution exceeded memory or batch bounds.
- `EXECUTION_ERROR`: Runtime framework threw an unhandled internal exception.
- `INVALID_INPUT`: Input tensor shape, dtype, or value range violated contract.
- `INVALID_OUTPUT`: Model produced NaN, Inf, or malformed tensor dimensions.

### 12.2 Behavioral Assessment Status (`BehavioralStatus`)
- `NORMAL`: Behavior conforms to baseline expectations and thresholds.
- `ANOMALOUS`: Measured metric exhibits statistically significant deviation.
- `INSUFFICIENT_SUPPORT`: Sample count too small to draw statistically reliable conclusions.
- `UNVERIFIABLE`: Runtime execution failed or contract unverified.
- `REFERENCE_UNAVAILABLE`: Evaluation requires baseline reference which was not supplied.
- `INCOMPATIBLE_REFERENCE`: Baseline model has disjoint task or output contract.

---

## 13. Evidence Synthesis & Provenance Binding

Phase 8 creates standardized evidence objects conforming to Phase 5.9 schemas:

### 13.1 Phase 8 Evidence Types
1. `behavioral_repeatability_evidence`: Multi-run stability, numerical divergence, floating-point delta.
2. `behavioral_perturbation_evidence`: Sensitivity gradients across noise, blur, compression, contrast.
3. `behavioral_reference_comparison_evidence`: Pairwise candidate-vs-reference divergence metrics.
4. `behavioral_task_performance_evidence`: Top-k distributions, entropy profiles, confidence histograms.
5. `behavioral_anomaly_summary_evidence`: Aggregate anomaly assessment, statistical support, and confidence.

### 13.2 Deterministic Execution Identity Binding
Every behavioral evaluation produces an immutable `execution_identity_hash` binding:
$$\text{ExecutionIdentity} = \text{SHA-256}(\text{RFC 8785 JCS}(\mathcal{P}))$$
where $\mathcal{P}$ binds:
- `project_id`
- `model_id` & `model_fingerprint` ($H_{\text{master}}$)
- `reference_model_id` & `reference_fingerprint`
- `test_dataset_id` & `test_dataset_fingerprint`
- `perturbation_config_hash`
- `detector_id` (`"behavioral_analysis_engine"`) & `detector_version` (`"1.0.0"`)
- `policy_version` (`"1.0"`)
- `execution_provider` & `device`
- `execution_seed`

---

## 14. Database Compatibility & Zero Schema Changes

Phase 8 introduces **ZERO new database tables** and **ZERO schema migrations**. All domain objects map directly to the frozen Phase 3–6 ORM entities:

| Behavioral Concept | Physical Database Entity | Field Mapping Strategy |
| :--- | :--- | :--- |
| Model under evaluation | `AIModelModel` / `ModelFingerprintModel` | Foreign key `model_id`, verified against `model_fingerprints` |
| Test inputs / dataset | `DatasetModel` / `SampleModel` | Source test sample tracking |
| Raw execution result | `InferenceRecordModel` | Stores input hash, output summary, latency, backend |
| Behavioral Evidence | `EvidenceModel` | `evidence_type = "behavioral_*"`, `evidence_layer = "detection"` |
| Behavioral Finding | `FindingModel` | Neutral finding codes (`BEHAVIOR_DEVIATION_*`, `SEVERITY = INFO/LOW/MED/HIGH`) |
| Signed Assessment | `ProvenanceRecordModel` | Signed canonical record hash via Phase 4 Ed25519 engine |
| Audit Trail | `AuditEventModel` | Immutable lifecycle event logging |

---

## 15. Hardware Backend Policy (CPU by Default, CUDA Opt-In)

1. **CPU Execution (Default):** `CPUExecutionProvider` is the mandatory default execution provider for all Phase 8 operations to maximize reproducibility and audit stability.
2. **CUDA / GPU Execution (Explicit Opt-In):** `CUDAExecutionProvider` is enabled ONLY when explicitly configured by user request. The system never silently switches to CUDA based on hardware presence.
3. **Execution Metadata Logging:** Every observation records `execution_provider`, `device`, `runtime_version`, and `precision`.
4. **Cross-Hardware Numerical Tolerance:** Comparisons across executions on different providers account for precision differences (FP32 vs FP16/BF16).

---

## 16. Security Threat Model & Mitigations

| Threat ID | Threat Description | Severity | Mitigation Strategy in Phase 8 |
| :--- | :--- | :--- | :--- |
| **THREAT-BA-01** | Arbitrary code execution via malicious custom model class | **CRITICAL** | Prohibit raw pickle / unpickling; enforce ONNX / safe weights-only wrappers. |
| **THREAT-BA-02** | Resource exhaustion / Memory Bomb (OOM Denial of Service) | **HIGH** | Strict batch size caps ($B \le 64$), memory monitoring, controlled worker limits. |
| **THREAT-BA-03** | CPU Hang / Infinite Loop Forward Pass | **HIGH** | Synchronous execution timeouts (10s max per batch) with cancellation. |
| **THREAT-BA-04** | Adversarial Tensor Dimension Explosion | **MEDIUM** | Input dimension validation against Phase 7 verified input contract. |
| **THREAT-BA-05** | NaN / Inf Numerical Poisoning in Output | **MEDIUM** | Comprehensive finite-check validation on all extracted output tensors. |
| **THREAT-BA-06** | Data Exfiltration / Network Channel | **CRITICAL** | Air-gapped socket blocking; zero external HTTP/DNS dependencies. |
| **THREAT-BA-07** | Nonce Replay / Finding Spoofing | **HIGH** | Replay detection cache, Ed25519 signatures, CSPRNG nonces (Phase 4). |

---

## 17. Architecture Decision Records (ADR-048 to ADR-060)

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PHASE 8 ARCHITECTURE DECISION RECORDS                    │
├─────────────────────────────────────────────────────────────────────────────┤
│ ADR-048 — Behavioral Analysis Scope and Strict Phase Boundary               │
│ ADR-049 — Controlled Local Model Execution Boundary and Provider Policy     │
│ ADR-050 — Behavioral Observation Canonical Schema & Representation          │
│ ADR-051 — Task-Specific Output Normalization & Segmentation Semantics       │
│ ADR-052 — Repeatability, Numerical Stability & Tolerance Thresholds        │
│ ADR-053 — Deterministic Controlled Perturbation Framework                  │
│ ADR-054 — Behavioral Baseline Taxonomy & Reference Comparison Protocol     │
│ ADR-055 — Distribution-Free Empirical Anomaly Detection Semantics          │
│ ADR-056 — Strict Behavioral Confidence Semantics (Observation != Guilt)     │
│ ADR-057 — Universal Evidence and Provenance Ledger Reuse                   │
│ ADR-058 — Permanent Database Schema Preservation (Zero Migrations)          │
│ ADR-059 — Air-Gapped / Offline Local Execution Guarantee                   │
│ ADR-060 — Semantic Safety & Non-Culpable Finding Vocabulary                │
└─────────────────────────────────────────────────────────────────────────────┘
```

### ADR-048: Behavioral Analysis Scope and Strict Phase Boundary
- **Context:** Phase 8 introduces dynamic execution to observe model behavioral responses.
- **Decision:** Restrict Phase 8 strictly to behavioral observation, stability measurement, perturbation sensitivity, and reference comparison. Trigger inversion (Phase 9), live serving integrity (Phase 10), and population shift (Phase 11) are strictly prohibited in Phase 8.

### ADR-049: Controlled Local Model Execution Boundary and Provider Policy
- **Context:** Model forward passes require executing runtime graph computations safely without claiming false OS-level sandbox guarantees.
- **Decision:**
  1. Standardize on a **Controlled Local Model Execution Boundary** with 11 concrete containment controls (timeout, batch limits, memory caps, network disablement, process isolation, env sanitization, fail-closed handlers).
  2. Acknowledge explicitly that ONNX Runtime is an execution engine, not an OS-level sandbox.
  3. Enforce **`CPUExecutionProvider` (CPU)** as the mandatory default. CUDA execution is strictly **EXPLICIT OPT-IN** and never auto-selected merely because hardware is present.

### ADR-050: Behavioral Observation Canonical Schema
- **Context:** Observations must be comparable, immutable, and auditable across evaluations.
- **Decision:** Define structured Pydantic schemas for observations canonicalized with RFC 8785 JCS and SHA-256 digests.

### ADR-051: Task-Specific Output Normalization and Segmentation Semantics
- **Context:** Models output tensors of varying ranks, logits, bounding boxes, or segmentation masks.
- **Decision:**
  1. Implement dedicated extractors for Classification (logits, top-k, entropy) and Object Detection (boxes, class scores, NMS counts).
  2. For Segmentation, enforce strict 3-way distinction:
     - Case A: Dense ground truth available $\implies$ Allowed metric: `mIoU`.
     - Case B: No ground truth, reference model available $\implies$ Allowed metric: `REFERENCE_MASK_AGREEMENT`. (Never label as mIoU).
     - Case C: Neither available $\implies$ Return `UNAVAILABLE` or `UNVERIFIABLE`. Never invent ground truth.

### ADR-052: Repeatability and Numerical Stability
- **Context:** Repeated inference runs can exhibit floating-point divergence due to non-deterministic operations or multi-threading.
- **Decision:** Quantify repeatability over identical inputs with distinct categories (`DETERMINISTIC`, `NUMERICALLY_STABLE`, `NONDETERMINISTIC`, `UNVERIFIABLE`). Floating-point variations are classified as stability characteristics, never as malicious behavior.

### ADR-053: Deterministic Controlled Perturbation Framework
- **Context:** Model robustness requires testing under controlled noise and image transforms.
- **Decision:** All perturbations must be seeded, deterministic, and parameterized with explicit records of source input hash, perturbed input hash, and transform parameters.

### ADR-054: Behavioral Baseline Taxonomy
- **Context:** Evaluating whether a behavior is anomalous requires an objective reference.
- **Decision:** Support 4 baseline tiers (Reference Model, Historical Profile, Contract Invariant, Self-Baseline). If a reference is missing, report `REFERENCE_UNAVAILABLE` rather than generating an anomaly.

### ADR-055: Empirical Anomaly Detection Semantics
- **Context:** Detecting abnormal behavior requires statistical decision boundaries.
- **Decision:** Utilize Median Absolute Deviation (MAD) and robust z-scores with sample-size shrinkage. Small sample sizes ($N < 5$) must output `INSUFFICIENT_SUPPORT`.

### ADR-056: Strict Behavioral Confidence Semantics
- **Context:** Risk of users misinterpreting detection confidence as proof of attack.
- **Decision:** Enforce ADR-028: `confidence` reflects measurement statistical reliability $[0.0, 1.0]$ in the detection layer. Findings must never express probability of malicious intent.

### ADR-057: Evidence and Provenance Ledger Reuse
- **Context:** Assurance findings must be bound to immutable ledgers.
- **Decision:** Reuse existing Phase 4 Ed25519 signing engine and Phase 5.9 canonical evidence synthesis without creating redundant cryptographic subsystems.

### ADR-058: Permanent Database Schema Preservation
- **Context:** System architecture must maintain immutable relational storage.
- **Decision:** Reuse existing 15 database tables (`ai_models`, `inference_records`, `evidence`, `findings`, `provenance_records`, `audit_events`). Zero schema migrations are permitted.

### ADR-059: Air-Gapped / Offline Local Execution Guarantee
- **Context:** AIVARA workstations operate in air-gapped security enclaves.
- **Decision:** Behavioral analysis must run 100% locally with zero external network, DNS, cloud AI, or telemetry calls.

### ADR-060: Semantic Safety & Non-Culpable Finding Vocabulary
- **Context:** Assurance reports must remain strictly scientific, neutral, and objective.
- **Decision:** Prohibit words asserting intent, culpability, or compromise (`malicious`, `attacker`, `culpable`, `collusion`, `sabotage`, `backdoor`). All finding codes use neutral technical descriptors (`BEHAVIOR_DEVIATION_*`, `SENSITIVITY_ANOMALY_*`).

---

## 18. Self-Review & Integrity Checklist

| Review Question | Verification Status | Rationale / Reference |
| :--- | :---: | :--- |
| **1. Does Phase 8 duplicate Phase 7?** | **NO** | Phase 7 verifies static files, weights, and contracts. Phase 8 executes forward passes to observe dynamic behavioral outputs. |
| **2. Does Phase 8 implement Phase 9?** | **NO** | Trigger inversion and backdoor detection are strictly deferred to Phase 9. Phase 8 only applies general perturbations. |
| **3. Does Phase 8 implement Phase 10?** | **NO** | Production serving integrity and live replay protection are deferred to Phase 10. |
| **4. Does Phase 8 implement Phase 11?** | **NO** | Population-level dataset distribution shift is deferred to Phase 11. |
| **5. Does Phase 8 implement Phase 12?** | **NO** | Universal risk synthesis across all subsystems is deferred to Phase 12. |
| **6. Does runtime execution permit arbitrary code?** | **NO** | Controlled local execution boundary and safe static wrappers only. Pickle execution prohibited (ADR-049). |
| **7. Is CPU the default execution provider?** | **YES** | CPUExecutionProvider is the mandatory default; CUDA is explicit opt-in only (ADR-049). |
| **8. Are segmentation metric semantics strict?** | **YES** | mIoU requires dense ground truth; reference model comparisons use `REFERENCE_MASK_AGREEMENT` (ADR-051). |
| **9. Is runtime security terminology accurate?** | **YES** | Uses "Controlled Local Model Execution Boundary"; no false OS-level sandbox claims (ADR-049). |
| **10. Are confidence semantics correct?** | **YES** | Confidence reflects metric statistical support $[0.0, 1.0]$, not malicious probability (ADR-056). |
| **11. Is anomaly separated from maliciousness?** | **YES** | Absolute decoupling enforced mathematically and semantically (ADR-060). |
| **12. Is evidence separated from proof?** | **YES** | Two-layer ADR-028 separation maintained across all schemas. |
| **13. Is provenance reused rather than duplicated?** | **YES** | Phase 4 Ed25519 ledger signing engine is reused directly (ADR-057). |
| **14. Is the database schema unchanged?** | **YES** | 15 Phase 3 foundational tables reused with zero migrations (ADR-058). |
| **15. Is offline operation guaranteed?** | **YES** | Zero network dependencies; air-gap verified (ADR-059). |

---

## 19. Phase 8 Subphase Roadmap

```text
Phase 8.1 — Architecture & Requirements Freeze [CURRENT GATE]
Phase 8.2 — Safe Runtime Execution Gateway & Controlled Boundary
Phase 8.3 — Deterministic Perturbation & Input Generator
Phase 8.4 — Task-Specific Output Normalizers (Classification/Detection/Segmentation)
Phase 8.5 — Repeatability & Numerical Stability Engine
Phase 8.6 — Reference Comparison & Divergence Engine
Phase 8.7 — Empirical Anomaly Detection & Statistical Evidence Synthesis
Phase 8.8 — REST API & Service Integration
Phase 8.9 — Comprehensive Behavioral Verification & Final Freeze
```
