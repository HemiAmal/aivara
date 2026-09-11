# PHASE 8.2 — SAFE RUNTIME OBSERVATION BOUNDARY

**Project:** AIVARA — AI Verification & Assurance  
**Subsystem:** Behavioral Analysis Engine (BAE) — Safe Runtime Boundary  
**Status:** **COMPLETE**  
**Date:** 2026-09-11  
**Authoritative References:** ADR-048, ADR-049, ADR-050, ADR-059  

---

## 1. Executive Summary & Architecture

Phase 8.2 implements the **Controlled Local Model Execution Boundary** within the AIVARA Behavioral Analysis subsystem. This layer isolates model forward-pass execution from the core AIVARA control plane, ensuring that untrusted AI/CV model artifacts are loaded and executed with strict containment, deterministic provider selection, hard timeouts, bounded resources, sanitized environments, and air-gapped network guards.

```text
+-------------------------------------------------------------------------------+
|                             AIVARA CONTROL PLANE                              |
| (Database, Cryptographic Keys, Provenance Ledger, Git Repo, Audit Log)        |
+-------------------------------------------------------------------------------+
                                        |
                            ExecutionRequest (Typed)
                                        |
                                        v
+-------------------------------------------------------------------------------+
|                  CONTROLLED LOCAL MODEL EXECUTION BOUNDARY                    |
|                                                                               |
|  1. Policy & Format Validation:                                               |
|     - CPUExecutionProvider (Default) / CUDAExecutionProvider (Opt-in only)    |
|     - Hard Timeouts (<= 10.0s) & Max Batch Size (<= 64)                       |
|     - Prohibit raw pickle / scripts / unpicklers                              |
|                                                                               |
|  2. Process & Workspace Containment:                                          |
|     - Isolated scratch workspace per execution (aivara_exec_*)                |
|     - Sanitized environment (AWS, Azure, Git, API keys stripped)              |
|     - Air-gapped socket blocking (Zero outbound HTTP/DNS)                     |
|                                                                               |
|  3. Controlled Model Ingestion:                                               |
|     - ONNX Runtime InferenceSession                                           |
|                                                                               |
|  4. Strict Tensor Validation:                                                 |
|     - Input rank, batch, element count, finite checks (no unallowed NaN/Inf)  |
|     - Output rank, dimension, finite checks, byte caps                        |
|                                                                               |
|  5. Deterministic Output Hashing:                                             |
|     - RFC 8785 JCS Canonicalization + SHA-256 Digest                          |
+-------------------------------------------------------------------------------+
                                        |
                            ExecutionResult (Sealed)
                                        |
                                        v
+-------------------------------------------------------------------------------+
|                  BEHAVIORAL ANALYSIS & PROVENANCE SUBSYSTEM                   |
+-------------------------------------------------------------------------------+
```

---

## 2. Execution Lifecycle

Every model execution traverses a deterministic 8-step lifecycle:
1. **Request Intake & Policy Validation:** Validates `ExecutionRequest`, checks that `timeout_seconds <= 10.0s`, `max_batch_size <= 64`, and validates provider availability.
2. **Path & Security Sanitization:** Validates `model_path` against UNC paths, traversal sequences, and sensitive system assets (`.git`, `keys`, `aivara.db`).
3. **Workspace Initialization:** Generates an ephemeral scratch directory `aivara_exec_<uuid>_` with automatic context manager cleanup.
4. **Input Tensor Sanitization:** Validates input dictionary keys, tensor ranks ($\le 8$), batch size ($\le 64$), element totals ($\le 100,000,000$), and finite values.
5. **Session Initialization:** Creates an isolated `onnxruntime.InferenceSession` under explicit provider settings.
6. **Forward Pass Execution:** Executes inference within a worker thread bounded by a strict wall-clock timeout and cooperative cancellation tokens.
7. **Output Validation & Telemetry:** Validates output tensors, traps NaN/Inf anomalies, checks memory ceilings, and computes execution telemetry.
8. **Canonical Output Hashing & Sealed Result:** Formulates a deterministic SHA-256 output digest over canonical tensor metadata and contiguous bytes, cleans up scratch storage, and returns `ExecutionResult`.

---

## 3. Execution Provider Policy (ADR-049 Alignment)

- **Default Execution Provider:** `CPUExecutionProvider` (CPU).
- **CUDA Execution Provider:** `CUDAExecutionProvider` is strictly **EXPLICIT OPT-IN ONLY**.
- **Fail-Closed Invariant:** If `CUDAExecutionProvider` is requested but CUDA is unavailable on the host, execution fails immediately with `ExecutionStatus.PROVIDER_UNAVAILABLE`. Silent fallback to CPU is strictly prohibited.
- **Provider Telemetry:** Every execution record documents `provider`, `device`, `runtime_version`, and `precision`.

---

## 4. Runtime Limits & Ceilings

| Limit Name | Default Setting | Hard Ceiling | Violation Status |
| :--- | :--- | :--- | :--- |
| **Max Batch Size** | 64 | 64 samples | `RESOURCE_LIMIT` |
| **Max Execution Time** | 10.0 s | 10.0 s | `TIMEOUT` / `RESOURCE_LIMIT` |
| **Max Input Dimensions** | 8 dimensions | 16 dimensions | `RESOURCE_LIMIT` |
| **Max Tensor Elements** | 100,000,000 | 100,000,000 | `RESOURCE_LIMIT` |
| **Max Output Payload** | 500 MB | 500 MB | `RESOURCE_LIMIT` |
| **Max Memory Ceiling** | 4 GB | 4 GB | `RESOURCE_LIMIT` |
| **Max Temporary Storage** | 1 GB | 1 GB | `RESOURCE_LIMIT` |

---

## 5. Security & Isolation Boundaries

### 5.1 Process & Execution Boundary
- Inference runs via standardized ONNX Runtime engines without executing user-supplied Python constructors or arbitrary scripts.

### 5.2 Network Boundary (Air-Gapped)
- Air-gapped socket blocking is active; no outbound HTTP, HTTPS, raw socket, or DNS calls are permitted.

### 5.3 Environment Sanitization
- All sensitive environment variables (`AWS_*`, `AZURE_*`, `OPENAI_*`, `TOKEN`, `SECRET`, `PASSWORD`, `DATABASE_*`, `GIT_*`, `GITHUB_*`) are stripped before worker execution.

### 5.4 Filesystem Boundary
- Paths are validated against traversal (`..`), UNC paths (`\\server\share`), symlink escapes, and sensitive files (`.git`, `keys/`, `aivara.db`).
- Ephemeral workspaces (`aivara_exec_*`) are automatically scrubbed on success, timeout, or failure.

---

## 6. Input & Output Validation

- **Input Validation:** Requires non-empty input dictionary, verifies rank $\ge 1$ and $\le 8$, batch size $\le 64$, dimension positivity, and finite float values.
- **Output Validation:** Validates output tensor types, element counts, byte sizes, and traps non-finite floats (NaN/Inf) -> marked as `INVALID_OUTPUT`.
- **Deterministic Hashing:** Computes SHA-256 over RFC 8785 JCS canonical representation:
  $$\text{OutputHash} = \text{SHA-256}(\text{JCS}(\{\text{"schema\_version"}: \text{"1.0"}, \text{"tensors"}: [\{\text{name}, \text{shape}, \text{dtype}, \text{element\_count}, \text{content\_hash}\}]\}))$$

---

## 7. Status Taxonomy

| Status Code | Meaning |
| :--- | :--- |
| `SUCCESS` | Forward pass completed cleanly; outputs validated and hashed. |
| `EXECUTION_UNAVAILABLE` | Runtime execution dependencies missing or disabled. |
| `UNSUPPORTED` | Model format unsupported for safe execution (e.g. `.pkl`). |
| `TIMEOUT` | Forward pass exceeded wall-clock timeout limit ($\le 10.0$s). |
| `RESOURCE_LIMIT` | Batch size, memory, or tensor element limits exceeded. |
| `EXECUTION_ERROR` | Internal runtime exception trapped and sanitized. |
| `INVALID_INPUT` | Input shape, rank, dtype, or non-finite values violated contract. |
| `INVALID_OUTPUT` | Output produced NaN, Inf, or exceeded memory bounds. |
| `PROVIDER_UNAVAILABLE` | Explicitly requested provider (e.g. CUDA) not available. |
| `MODEL_LOAD_ERROR` | ONNX session loading or protobuf parsing failed. |
| `CANCELLED` | Cooperative cancellation requested prior to or during execution. |

---

## 8. Platform Limitations & Security Distinctions

1. **Controlled Execution Boundary vs. OS Sandbox:** ONNX Runtime provides safe computational graph execution but is not an OS-level hypervisor or container sandbox. In-process isolation is enforced via Python timeouts, thread pooling, resource validation, sanitized environments, and filesystem boundaries.
2. **Hardware Concurrency:** CPU inference utilizes bounded sequential execution threads (`intra_op_num_threads=4`, `inter_op_num_threads=1`).

---

## 9. Dependency Additions

- Added `onnxruntime` (v1.30.0) — Safe runtime inference engine.
- Added `onnx` (v1.22.0) — Protobuf model serialization helper for testing.
- Added `ml_dtypes` (v0.6.0) — Supported dtypes dependency.

---

## 10. Test & Verification Results

```text
tests/test_behavioral_runtime.py ....................... [ 23/23 PASSED ]

=========================== Full Regression Baseline ===========================
Phase 0–7 Test Suites: 1072 PASSED
Phase 8.2 Targeted Suite: 23 PASSED
Total Repository Tests: 1095 PASSED
Failures / Errors: 0
Regressions: 0
=========================== 1095 passed in 100% ===========================
```
