# AIVARA Phase 10.5 — Inference Execution Integrity Specification

## Status: FROZEN & VERIFIED

---

### 1. Objective

Phase 10.5 establishes the authoritative **Inference Execution Integrity** subsystem of the AIVARA Inference Integrity pipeline (`backend/aivara/inference/execution/`).

The purpose of Phase 10.5 is to execute a validated inference transaction within the approved controlled observation boundary, establishing:
- **What model was executed** (verified Phase 7 master fingerprint & model ID).
- **What input was executed** (validated Phase 10.2 `input_id` and Phase 10.3 `binding_hash`).
- **What preprocessing identity was used** (Phase 10.4 `preprocessing_contract_hash` and `transformed_input_hash`).
- **Under which execution policy it ran** (deterministic provider, timeout, and resource bounds).
- **Whether execution completed correctly** (lifecycle state and numerical sanity).
- **What raw output artifact was produced** (deterministic canonical `raw_output_hash` preserving declared model graph order).

---

### 2. Controlled Local Execution Boundary

Reusing the established Phase 8 execution architecture:
- **Default Execution Provider**: `CPUExecutionProvider` is the strictly enforced default.
- **Explicit CUDA Opt-In**: `CUDAExecutionProvider` requires explicit request and fails closed if unavailable (`EXECUTION_PROVIDER_UNAVAILABLE`), prohibiting silent CPU fallback.
- **Hard Timeout Ceiling**: Execution timeout is explicitly bounded ($\le 30.0\text{s}$).
- **Resource Limits**: Input elements ($\le 50\text{M}$), batch size ($\le 32$), output byte size ($\le 100\text{MB}$), memory ($\le 1\text{GB}$).
- **Cooperative Cancellation**: Handlers verify cancellation state prior to expensive model forward passes.
- **Air-Gap Guarantee**: 100% process-local, zero network sockets or external telemetry.

---

### 3. Execution Transaction Schema

#### Immutable Schema: `InferenceExecution`
| Field | Type | Description |
|---|---|---|
| `schema_version` | `str` | Specification schema version (`"1.0"`, max 16 chars) |
| `execution_version` | `str` | Execution engine version (`"1.0"`, max 16 chars) |
| `execution_id` | `str` | Deterministic transaction identifier (64-char hex) |
| `project_id` | `str` | Multi-tenant project identifier (max 255 chars) |
| `input_id` | `str` | Validated Phase 10.2 input identifier (64-char hex) |
| `binding_hash` | `str` | Verified Phase 10.3 binding hash (64-char hex) |
| `preprocessing_contract_hash` | `str` | Verified Phase 10.4 preprocessing contract hash (64-char hex) |
| `transformed_input_hash` | `str` | Verified Phase 10.4 preprocessed input byte hash (64-char hex) |
| `model_id` | `str` | Model identifier (max 255 chars) |
| `model_master_fingerprint` | `str` | Phase 7 composite model master fingerprint (64-char hex) |
| `execution_provider` | `str` | Execution provider utilized (e.g. `CPUExecutionProvider`) |
| `execution_policy` | `ExecutionPolicy` | Bounded execution safety policy |
| `lifecycle` | `ExecutionLifecycle` | Lifecycle state (`SUCCEEDED`, `FAILED`, `TIMED_OUT`, `CANCELLED`, etc.) |
| `status` | `InferenceIntegrityStatus` | Integrity status (`VERIFIED`, `INVALID`, `UNAVAILABLE`) |
| `execution_identity_hash` | `str` | SHA-256 digest of canonical RFC 8785 execution descriptor |
| `raw_output` | `Optional[RawExecutionOutput]` | Container for raw output tensors |
| `raw_output_hash` | `Optional[str]` | Deterministic canonical SHA-256 hash of output tensors |
| `findings` | `List[InputFinding]` | Observational findings |
| `details` | `Dict[str, Any]` | Execution telemetry |

---

### 4. Deterministic Identity Formulas

#### Execution Identity Hash:
$$\text{execution\_identity\_hash} = \text{SHA256}(\text{RFC8785\_JCS}(\mathcal{D}_{\text{execution}}))$$

where $\mathcal{D}_{\text{execution}}$ is the canonical descriptor:
```json
{
  "binding_hash": "<64-hex>",
  "execution_policy": {
    "deterministic": true,
    "max_batch_size": 32,
    "max_output_bytes": 100000000,
    "max_tensor_elements": 50000000,
    "memory_limit_bytes": 1000000000,
    "provider": "CPUExecutionProvider",
    "timeout_seconds": 10.0
  },
  "execution_provider": "CPUExecutionProvider",
  "execution_version": "1.0",
  "input_id": "<64-hex>",
  "model_id": "resnet50-v1",
  "model_master_fingerprint": "<64-hex>",
  "preprocessing_contract_hash": "<64-hex>",
  "project_id": "<project_id>",
  "schema_version": "1.0",
  "transformed_input_hash": "<64-hex>"
}
```

#### Raw Output Hash:
$$\text{raw\_output\_hash} = \text{SHA256}(\text{RFC8785\_JCS}(\mathcal{D}_{\text{raw\_output}}))$$

where $\mathcal{D}_{\text{raw\_output}}$ preserves model-declared output sequence:
```json
{
  "outputs": [
    {
      "byte_hash": "<64-hex>",
      "byte_size": 4000,
      "dtype": "float32",
      "element_count": 1000,
      "index": 0,
      "is_finite": true,
      "name": "logits",
      "shape": [1, 1000]
    }
  ],
  "schema_version": "1.0"
}
```

---

### 5. Phase Boundaries
- **No Semantic Validation**: Phase 10.5 captures raw arrays and checks numerical finiteness only (`FINITE` vs `NONFINITE`).
- **No Postprocessing / Logit Analysis**: Reserved for Phase 10.6.
- **No Composite Binding**: Reserved for Phase 10.7.
- **No Database Persistence**: Reserved for Phase 10.8 (`DATABASE SCHEMA CHANGES = 0`).
