# Phase 10.3: Input / Model Binding Specification

**AIVARA — AI Verification & Assurance**  
**Subsystem:** Phase 10 — Inference Integrity  
**Phase:** 10.3 — Input / Model Binding  
**Status:** IMPLEMENTED & VERIFIED  

---

## 1. Objective

Phase 10.3 implements the **Input / Model Binding Subsystem** as specified by the permanently frozen Phase 10.1 architecture, [ADR-092](file:///d:/Downloads/Projects/AiVara/docs/DECISIONS.md#adr-092), and [ADR-093](file:///d:/Downloads/Projects/AiVara/docs/DECISIONS.md#adr-093).

The purpose of Phase 10.3 is to establish a deterministic, cryptographically verifiable relationship between:

$$\text{Validated Input Identity (Phase 10.2)} + \text{Verified Model Identity (Phase 7)} \Longrightarrow \text{Input-Model Binding Identity}$$

It definitively answers:
> *"Which exact validated input transaction was bound to which specific model artifact for this inference execution?"*

---

## 2. Architectural Boundary & Prohibitions

Phase 10.3 is strictly an **identity binding phase**:
- **Consumes Phase 10.2 InputIdentity**: References `input_id`, `canonical_hash`, `input_kind`, and validation status without re-hashing or mutating caller data.
- **Consumes Phase 7 Model Identity**: References `master_fingerprint` (ADR-040), `artifact_hash`, `structural_hash`, `contract_hash`, and model metadata without reloading model weights or executing bytecode.
- **Zero Model Execution**: Strictly prohibited from running ONNX, PyTorch, TorchScript, or CUDA inference (owned by Phase 10.5).
- **Zero Preprocessing**: Strictly prohibited from resizing, cropping, normalizing, or transforming inputs (owned by Phase 10.4).
- **Zero Database Changes**: `DATABASE SCHEMA CHANGES = 0`. Operates as an immutable domain envelope.
- **Zero Unsafe Constructs**: Strictly avoids `eval`, `exec`, `pickle`, `subprocess`, `os.system`, dynamic imports, or remote API calls.

---

## 3. Cryptographic Identity Graph

```
Phase 10.2 Validated Input               Phase 7 Verified Model
        │                                         │
  [ InputIdentity ]                      [ ModelIdentityEnvelope ]
        │                                         │
        ├── input_id                              ├── model_id
        ├── input_kind                            ├── model_master_fingerprint
        ├── input_canonical_hash                  ├── model_artifact_hash
        └── input_raw_hash                        ├── model_structural_hash
        │                                         └── model_contract_hash
        │                                         │
        └───────────────────┬─────────────────────┘
                            │
                            ▼
               [ Canonical Binding Descriptor ]
                            │
                            ▼ RFC 8785 (JCS)
                 [ Canonical UTF-8 Bytes ]
                            │
                            ▼ SHA-256
                     [ binding_hash ]
                            │
                            ▼
                 [ InputModelBinding ]
```

---

## 4. Canonical Descriptor & Hash Formula

The canonical descriptor commits to all essential identity parameters with strict field sorting via RFC 8785 (JSON Canonicalization Scheme - JCS):

$$\begin{aligned}
\mathcal{D}_{\text{binding}} = \{ & \\
  &\text{"binding\_version"}: \text{"1.0"}, \\
  &\text{"input\_canonical\_hash"}: \text{input\_canonical\_hash}, \\
  &\text{"input\_id"}: \text{input\_id}, \\
  &\text{"input\_kind"}: \text{input\_kind}, \\
  &\text{"model\_artifact\_hash"}: \text{model\_artifact\_hash}, \\
  &\text{"model\_contract\_hash"}: \text{model\_contract\_hash}, \\
  &\text{"model\_id"}: \text{model\_id}, \\
  &\text{"model\_master\_fingerprint"}: \text{model\_master\_fingerprint}, \\
  &\text{"model\_structural\_hash"}: \text{model\_structural\_hash}, \\
  &\text{"project\_id"}: \text{project\_id}, \\
  &\text{"schema\_version"}: \text{"1.0"} \\
\}
\end{aligned}$$

$$\text{binding\_hash} = \text{SHA-256}(\text{JCS}(\mathcal{D}_{\text{binding}}))$$

Any alteration to the input identity, model identifier, master fingerprint, artifact digest, structural representation, contract representation, or project scope produces an entirely distinct `binding_hash`.

---

## 5. Project / Tenant Isolation

Binding is strictly project-scoped. Attempts to bind a model belonging to Project A with an input transaction for Project B fail closed immediately:
- **Raising Mode:** Raises [`ProjectMismatchError`](file:///d:/Downloads/Projects/AiVara/backend/aivara/inference/exceptions.py#L143).
- **Non-Raising Mode:** Returns `InputModelBinding` with `binding_status = INVALID` and observational finding code `BINDING_PROJECT_MISMATCH`.

---

## 6. Status Taxonomy & Failure Semantics

| Condition | Status | Finding Code | Behavior |
|---|---|---|---|
| Input & Model verified, hashes consistent | `VERIFIED` | *(none)* | Successfully bound |
| Model project differs from binding project | `INVALID` | `BINDING_PROJECT_MISMATCH` | Fail closed |
| Input status is not `VERIFIED` | `INVALID` / `MISMATCHED` | `BINDING_INPUT_NOT_VERIFIED` | Fail closed |
| Model status is unverified or partial | `INVALID` | `BINDING_MODEL_NOT_VERIFIED` | Fail closed |
| Master fingerprint inconsistent with components | `INVALID` | `BINDING_INCONSISTENT_IDENTITY` | Fail closed |
| Hash string not 64-char lowercase hex | `INVALID` | `BINDING_MALFORMED_HASH` | Fail closed |
| Recomputed descriptor hash does not match | `INVALID` | `BINDING_HASH_MISMATCH` | Fail closed |

---

## 7. Public API Interface

Phase 10.3 exposes:
- [`create_input_model_binding()`](file:///d:/Downloads/Projects/AiVara/backend/aivara/inference/binding/engine.py#L125): Constructs and verifies a bound transaction.
- [`verify_input_model_binding()`](file:///d:/Downloads/Projects/AiVara/backend/aivara/inference/binding/engine.py#L225): Pure cryptographic verification of an existing binding.
- [`compute_binding_hash()`](file:///d:/Downloads/Projects/AiVara/backend/aivara/inference/binding/engine.py#L67): Deterministic JCS + SHA-256 calculation.
- [`InputModelBinding`](file:///d:/Downloads/Projects/AiVara/backend/aivara/inference/binding/models.py#L38): Immutable domain model.
- [`ModelIdentityEnvelope`](file:///d:/Downloads/Projects/AiVara/backend/aivara/inference/binding/models.py#L12): Normalized model identity container.

---

## 8. Interface to Phase 10.4

Phase 10.4 (Preprocessing & Contract Integrity) consumes `InputModelBinding` and verifies whether the bound model's input contract (`InputContractDescriptor`) matches the declared preprocessing pipeline and validated input shape.
