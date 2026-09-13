# Phase 10.7 — Input → Output Binding Specification

## 1. Overview & Architectural Role

Phase 10.7 establishes the authoritative, deterministic cryptographic binding connecting every artifact, contract, configuration, and result produced across the AIVARA Phase 10 inference verification pipeline.

```
+---------------------------------------------------------------------------------------------------+
|                                  PHASE 10.7 INFERENCE BINDING PIPELINE                            |
+---------------------------------------------------------------------------------------------------+
| Phase 10.2: Validated Input (raw_hash, canonical_hash, input_id)                                  |
| Phase 7 / 10.3: Model (model_id, structural_hash, artifact_hash, contract_hash, master_fp)        |
| Phase 10.4: Preprocessing Contract & Transformed Input (contract_hash, transformed_canonical_hash)|
| Phase 10.5: Execution Identity & Raw Output (execution_hash, raw_output_hash)                      |
| Phase 10.6: Output Contract & Validated Output (output_contract_hash, validated_output_identity)  |
+---------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
             [Canonical JCS Serialized Descriptor (16 committed fields)]
                                                  │
                                                  ▼
                          SHA-256(canonical_json_bytes)
                                                  │
                                                  ▼
                              `inference_binding_hash` (ADR-093)
```

Phase 10.7 guarantees:
- **No Phase Skip:** An inference cannot be bound without validated output from Phase 10.6, execution from Phase 10.5, preprocessing from Phase 10.4, model identity from Phase 10.3, and input identity from Phase 10.2.
- **Cross-Component Consistency:** Project ID, Input ID, Model ID, and Raw Output Hash consistency are strictly enforced across component boundaries.
- **Cryptographic Tamper-Evidence:** Altering any single bit across any of the 16 committed fields produces an entirely different `inference_binding_hash`.

---

## 2. Canonical Descriptor Specification

The canonical descriptor is a RFC 8785 (JCS) JSON dictionary with sorted keys and no extraneous whitespace:

| Field Key | Type | Description | Origin Subsystem |
|:---|:---|:---|:---|
| `binding_version` | `str` | Fixed schema version (`"1.0.0"`) | Phase 10.7 |
| `execution_identity_hash` | `str` | SHA-256 of execution identity | Phase 10.5 |
| `input_canonical_hash` | `str` | SHA-256 of canonical input payload | Phase 10.2 |
| `input_id` | `str` | Unique Input UUID | Phase 10.2 |
| `input_model_binding_hash`| `str` | SHA-256 of Input-Model Binding | Phase 10.3 |
| `input_raw_hash` | `str` | SHA-256 of raw unnormalized input bytes | Phase 10.2 |
| `model_artifact_hash` | `str` | SHA-256 of ONNX model artifact | Phase 7 / 10.3 |
| `model_contract_hash` | `str` | SHA-256 of Model Input Contract | Phase 10.3 |
| `model_id` | `str` | Unique Model UUID | Phase 7 / 10.3 |
| `model_master_fingerprint`| `str` | Master fingerprint hex | Phase 7 / 10.3 |
| `model_structural_hash` | `str` | SHA-256 of model graph topology | Phase 7 / 10.3 |
| `output_contract_hash` | `str` | SHA-256 of Output Contract | Phase 10.6 |
| `preprocessing_contract_hash` | `str` | SHA-256 of Preprocessing Contract | Phase 10.4 |
| `project_id` | `str` | Unique Project UUID | Common Context |
| `raw_output_hash` | `str` | SHA-256 of Raw Output Envelope | Phase 10.5 |
| `schema_version` | `str` | Fixed schema version (`"1.0.0"`) | Phase 10.7 |
| `transformed_input_hash` | `str` | SHA-256 of Transformed Input Identity | Phase 10.4 |
| `validated_output_identity`| `dict` | Canonical Validated Output Identity Descriptor | Phase 10.6 |

---

## 3. Verification Subsystem

Verification (`verify_inference_binding`) reconstructs the canonical descriptor from components or an existing binding, recomputes the SHA-256 hash using JCS, and performs comprehensive cross-validation:

1. Recomputed hash match (`INFERENCE_BINDING_HASH_MISMATCH`).
2. Project ID consistency (`INFERENCE_BINDING_PROJECT_MISMATCH`).
3. Cross-component consistency (`INFERENCE_BINDING_COMPONENT_MISMATCH`):
   - Input ID across InputIdentity, InputModelBinding, TransformedInputIdentity.
   - Model ID across ModelIdentity, InputModelBinding, ExecutionIdentity.
   - Raw output hash across ExecutionResult and ValidatedOutput.
4. Completeness checks (`INFERENCE_BINDING_*_MISSING`).
5. SHA-256 hex format validation (lowercase, 64 hex characters).

---

## 4. API Reference

```python
from aivara.inference.composite_binding import (
    InferenceBinding,
    InferenceBindingStatus,
    InferenceBindingVerificationResult,
    build_canonical_inference_binding_descriptor,
    compute_inference_binding_hash,
    create_inference_binding,
    verify_inference_binding,
)

binding = create_inference_binding(
    project_id=project_id,
    input_identity=input_identity,
    model_identity=model_identity,
    input_model_binding=input_model_binding,
    preprocessing_contract=preprocessing_contract,
    transformed_input=transformed_input,
    execution_identity=execution_identity,
    execution_result=execution_result,
    output_contract=output_contract,
    validated_output=validated_output,
)

verification = verify_inference_binding(
    binding=binding,
    project_id=project_id,
    input_identity=input_identity,
    model_identity=model_identity,
    input_model_binding=input_model_binding,
    preprocessing_contract=preprocessing_contract,
    transformed_input=transformed_input,
    execution_identity=execution_identity,
    execution_result=execution_result,
    output_contract=output_contract,
    validated_output=validated_output,
)
assert verification.is_valid
```
