# Phase 10.7 — Cryptographic Input → Output Binding Subsystem

**Document Version:** 1.1 (Consistency Corrected)  
**Phase:** 10.7 (FROZEN & VERIFIED)  
**Security Level:** CRITICAL / CANONICAL REPLAY & TAMPER RESISTANCE  

---

## 1. Overview & Purpose

The **Phase 10.7 Input → Output Binding** subsystem provides end-to-end cryptographic closure across an entire AI inference transaction. It deterministically combines the outputs and identities of all preceding phases:

1. **Safe Input Identity** (Phase 10.2: `input_id`, `input_canonical_hash`, `input_raw_hash`)
2. **Model Integrity & Input-Model Binding** (Phase 7 / Phase 10.3: `model_id`, `model_master_fingerprint`, `model_artifact_hash`, `model_structural_hash`, `model_contract_hash`, `input_model_binding_hash`)
3. **Preprocessing Contract & Transformed Tensor Identity** (Phase 10.4: `preprocessing_contract_hash`, `transformed_input_hash`)
4. **Controlled Inference Execution & Raw Output** (Phase 10.5: `execution_identity_hash`, `raw_output_hash`)
5. **Output Schema & Numerical Integrity** (Phase 10.6: `validated_output_identity`, `output_contract_hash`)

Together with the tenant boundary (`project_id`), binding algorithm version (`binding_version="1.0"`), and schema specification version (`schema_version="1.0"`), these constitute the **exactly 18 atomic committed components** of the canonical RFC 8785 JSON Canonicalization Scheme (JCS) descriptor.

The computed SHA-256 digest over this canonical descriptor produces the **`inference_binding_hash`** (ADR-093).

---

## 2. Architecture & Subsystem Structure

The subsystem is implemented under `backend/aivara/inference/composite_binding/`:

```
backend/aivara/inference/composite_binding/
├── __init__.py           # Public exports (models, engine functions, enums)
├── enums.py              # InferenceBindingStatus (VERIFIED, MISMATCHED, INVALID)
├── models.py             # InferenceBinding, InferenceBindingVerificationResult
└── engine.py             # Pure functional descriptor construction, hashing, creation, verification
```

### Module Roles & Responsibilities

- **`enums.py`**:
  - `InferenceBindingStatus`: Status representation (`VERIFIED`, `MISMATCHED`, `INVALID`).

- **`models.py`**:
  - `InferenceBinding`: Immutable (Pydantic `frozen=True`, `extra="forbid"`) model holding the 18 committed fields, computed `inference_binding_hash`, status, and observational findings.
  - `InferenceBindingVerificationResult`: Verification assessment carrying boolean `is_valid`, status, recomputed hash, recorded hash, observational findings, and audit details.

- **`engine.py`**:
  - `build_canonical_inference_binding_descriptor()`: Formats strictly typed, canonical dictionary with alphanumeric sorted keys per RFC 8785 JCS containing exactly the 18 committed fields.
  - `compute_inference_binding_hash()`: Computes deterministic SHA-256 over `canonicalize(descriptor)`.
  - `create_inference_binding()`: Validates project isolation, cross-stage references, hash formats, computes identity, and constructs `InferenceBinding`.
  - `verify_inference_binding()`: Offline, zero-evaluation pure observational cryptographic verification of existing bindings against reconstructed components or descriptors. Validates each internal component identity directly.
  - `validate_sha256_hex_format()`: Enforces lowercase 64-character hex regex (`^[0-9a-f]{64}$`).

---

## 3. The 18 Committed Descriptor Fields

The canonical descriptor dictionary committed to `inference_binding_hash` contains **exactly 18 fields**:

| # | Field Name | Source Stage | Description |
|---|---|---|---|
| 1 | `binding_version` | Constant / Protocol | Semantic version of the composite binding format (`"1.0"`) |
| 2 | `execution_identity_hash` | Phase 10.5 | SHA-256 hash of the execution context descriptor |
| 3 | `input_canonical_hash` | Phase 10.2 | SHA-256 hash of canonicalized input data |
| 4 | `input_id` | Phase 10.2 | Unique identifier of input payload |
| 5 | `input_model_binding_hash` | Phase 10.3 | Cryptographic binding hash linking input to model |
| 6 | `input_raw_hash` | Phase 10.2 | SHA-256 hash of raw input file/bytes |
| 7 | `model_artifact_hash` | Phase 7 | SHA-256 hash of model weights artifact |
| 8 | `model_contract_hash` | Phase 7 | SHA-256 hash of model I/O tensor contract |
| 9 | `model_id` | Phase 7 | Target model identifier |
| 10 | `model_master_fingerprint` | Phase 7 | Master fingerprint of verified model |
| 11 | `model_structural_hash` | Phase 7 | SHA-256 hash of model computational graph structure |
| 12 | `output_contract_hash` | Phase 10.6 | SHA-256 hash of expected model output contract |
| 13 | `preprocessing_contract_hash`| Phase 10.4 | SHA-256 hash of preprocessing contract |
| 14 | `project_id` | Tenant Boundary | Project isolation boundary identifier |
| 15 | `raw_output_hash` | Phase 10.5 | SHA-256 hash of raw execution output tensors |
| 16 | `schema_version` | Constant / Protocol | Schema version of descriptor (`"1.0"`) |
| 17 | `transformed_input_hash` | Phase 10.4 | SHA-256 hash of transformed tensor bytes |
| 18 | `validated_output_identity` | Phase 10.6 | SHA-256 canonical identity of validated output assessment |

*Note: All SHA-256 fields are strictly validated against `^[0-9a-f]{64}$` before descriptor construction and hashing.*

---

## 4. Cryptographic Mutation Sensitivity

Altering even a single bit in any of the 18 atomic fields changes the resulting `inference_binding_hash` completely.

```mermaid
graph TD
    BV[1. binding_version] --> BIND[RFC 8785 Canonical JCS Descriptor (18 Fields)]
    P[2. project_id] --> BIND
    IID[3. input_id] --> BIND
    ICH[4. input_canonical_hash] --> BIND
    IRH[5. input_raw_hash] --> BIND
    MID[6. model_id] --> BIND
    MMF[7. model_master_fingerprint] --> BIND
    MAH[8. model_artifact_hash] --> BIND
    MSH[9. model_structural_hash] --> BIND
    MCH[10. model_contract_hash] --> BIND
    IMB[11. input_model_binding_hash] --> BIND
    PCH[12. preprocessing_contract_hash] --> BIND
    TIH[13. transformed_input_hash] --> BIND
    EIH[14. execution_identity_hash] --> BIND
    ROH[15. raw_output_hash] --> BIND
    VOI[16. validated_output_identity] --> BIND
    OCH[17. output_contract_hash] --> BIND
    SV[18. schema_version] --> BIND

    BIND -->|SHA-256 Digest| HASH[inference_binding_hash]
    HASH --> RECORD[Immutable InferenceBinding]
```

---

## 5. Security & Isolation Invariants

1. **Non-Executable / Zero-Evaluation**: Phase 10.7 performs zero model inference, zero preprocessing transforms, and zero tensor computations. It strictly hashes and validates existing cryptographic identities.
2. **Deterministic & Nonce-less**: Identical component hashes produce identical `inference_binding_hash` values at any point in time.
3. **Tenant Boundary Enforcement**: Any cross-project component reference triggers `InferenceBindingProjectMismatchError`.
4. **Cross-Stage Identity Consistency**: Input ID and component cross-references are validated across Phase 10.2, 10.3, 10.4, 10.5, and 10.6.
5. **Separation of Raw vs Validated Outputs**: Maintains strict distinction between `raw_output_hash` (physical tensor bytes) and `validated_output_identity` (contract & numerical assessment identity).
6. **Zero Database Alterations**: `DATABASE SCHEMA CHANGES = 0`. No tables, columns, or migration files created or modified.
7. **Zero External / Network Dependencies**: Completely offline, self-contained implementation.
