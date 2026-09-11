# PHASE 7 FINAL FREEZE: MODEL INTEGRITY SUBSYSTEM

**Project:** AIVARA — AI Verification & Assurance  
**Subsystem:** Model Integrity Engine (Phase 7)  
**Status:** **FROZEN**  
**Date:** 2026-09-11  
**Authoritative Reference:** ADR-039 through ADR-043  

---

## 1. Phase 7 Objective

Phase 7 establishes an air-gapped, zero-execution, deterministic verification and assurance subsystem for AI and computer vision model artifacts. The engine validates that an untrusted candidate model file matches its structural, weight, and interface contract expectations without executing code or executing forward inference passes.

---

## 2. Product & Technical Scope

Phase 7 is strictly bounded to the following capabilities:
1. **Expected Artifact Identity:** Deterministic streaming SHA-256 computation over raw artifact bytes.
2. **Structural Topology Integrity:** Safe static extraction and canonical normalization of graph nodes, tensor shapes, dtypes, parameters, and operator metadata.
3. **Weight Merkle Tree Integrity:** Canonical ordering, domain-separated leaf hashing, RFC 6962 tree construction, and cryptographic inclusion proofs for tensor weights.
4. **I/O & Preprocessing Contract Verification:** Static validation of operational input ranks, tensor layouts, value ranges, normalization parameters, and output contracts.
5. **Reference Model Comparison:** 8-state multidimensional drift classification and per-tensor attribution between reference and candidate models.
6. **Assurance Evidence Generation:** Generation of canonical, immutable evidence payloads bound to a deterministic execution identity.
7. **Cryptographic Provenance:** Ed25519 digital signatures and audit ledger binding with formal status taxonomies.
8. **REST Integration:** Complete API endpoints delegating to service layers under multi-tenant project isolation.

Phase 7 **MUST NOT** assert:
- Malicious intent, attacker identity, collusion, or compromise.
- Backdoor / trigger activation (deferred to Phase 9).
- Runtime behavioral drift (deferred to Phase 8).
- Execution-based inference integrity (deferred to Phase 10).

---

## 3. Authoritative Pipeline Architecture

```text
               +-----------------------------------+
               |       UNTRUSTED MODEL FILE        |
               +-----------------------------------+
                                 |
                                 v
               +-----------------------------------+
               |          SAFE INGESTION           |
               | (Path, Limits, Policy, Headers)   |
               +-----------------------------------+
                                 |
        +------------------------+------------------------+
        |                                                 |
        v                                                 v
+-------------------------------+             +-------------------------------+
|      STREAMING SHA-256        |             |      STATIC PARSING &         |
|      (Artifact Hash)          |             |   METADATA NORMALIZATION      |
+-------------------------------+             +-------------------------------+
        |                                                 |
        |               +---------------------------------+
        |               |                 |               |
        |               v                 v               v
        |     +-------------------+ +------------+ +-----------------+
        |     |  STRUCTURAL GRAPH | | WEIGHTS    | |  I/O & PREPROC  |
        |     |  (Structural Hash)| | (Merkle    | |  (Contract Hash)|
        |     |                   | |  Tree Root)| |                 |
        |     +-------------------+ +------------+ +-----------------+
        |               |                                 |
        +---------------+----------------+----------------+
                                         |
                                         v
               +-----------------------------------+
               |         MASTER FINGERPRINT        |
               |   RFC 8785 JCS Canonical Binding  |
               +-----------------------------------+
                                 |
                                 v
               +-----------------------------------+
               |     REFERENCE COMPARISON &        |
               |    8-STATE DRIFT CLASSIFICATION   |
               +-----------------------------------+
                                 |
                                 v
               +-----------------------------------+
               |        EVIDENCE SYNTHESIS         |
               |    & NEUTRAL FINDING GENERATION   |
               +-----------------------------------+
                                 |
                                 v
               +-----------------------------------+
               |     CRYPTOGRAPHIC PROVENANCE      |
               | (Ed25519 Signing & Ledger Record) |
               +-----------------------------------+
                                 |
                                 v
               +-----------------------------------+
               |          REST API LAYER           |
               | (Multi-Tenant Project Isolation)  |
               +-----------------------------------+
```

---

## 4. Frozen Subphases (7.1 – 7.9)

- **Phase 7.1 — Architecture & Requirements:** Domain models, ADR-039 through ADR-043, threat vectors, formal requirements. [FROZEN]
- **Phase 7.2 — Safe Ingestion & Metadata Normalization:** Content detection, resource bounding, traversal prevention, static parsers for Safetensors, ONNX, PyTorch state_dict, TorchScript. [FROZEN]
- **Phase 7.3 — Hierarchical Fingerprinting & Weight Merkle Engine:** Streaming artifact hash, structural hash, contract hash, Weight Merkle tree, inclusion proofs, master fingerprint binding. [FROZEN]
- **Phase 7.4 — Contract & Preprocessing Verification:** Static shape checking, dtype normalization, preprocessing consistency, 7-state contract status taxonomy. [FROZEN]
- **Phase 7.5 — Reference Model Comparison & Drift Attribution:** 8-state drift matrix, per-tensor change attribution, master match detection. [FROZEN]
- **Phase 7.6 — Evidence Synthesis & Cryptographic Provenance:** 7 model evidence types, deterministic execution identity, neutral technical findings, Ed25519 provenance ledger signing. [FROZEN]
- **Phase 7.7 — REST API & Integration Services:** 8 REST routes, Pydantic schemas, service orchestration, project multi-tenancy. [FROZEN]
- **Phase 7.8 — Comprehensive Verification:** Exhaustive 19-category verification suite across all layers with zero regressions. [FROZEN]
- **Phase 7.9 — Final Freeze:** Authoritative release gate and permanent boundary freeze. [FROZEN]

---

## 5. Frozen Architectural Decisions (ADRs)

### ADR-039: Zero-Execution Policy
All model inspection must be static. Arbitrary Python deserialization (`pickle.load`, `torch.load(weights_only=False)`), TorchScript execution (`torch.jit.load`), ONNX runtime execution, subprocess execution, and network access are strictly forbidden.

### ADR-040: Master Fingerprint Canonical Binding
The Master Model Fingerprint $H_{\text{master}}$ is computed as:
$$\text{MasterBinding} = \{\text{"schema\_version"}: \text{"1.0"}, \text{"artifact\_hash"}: H_{\text{artifact}}, \text{"structural\_hash"}: H_{\text{structural}}, \text{"contract\_hash"}: H_{\text{contract}}\}$$
$$H_{\text{master}} = \text{SHA-256}(\text{RFC 8785 JCS}(\text{MasterBinding}))$$
The Weight Merkle Root remains an independent verification dimension.

### ADR-041: Deterministic Weight Merkle Engine
Weights are organized into leaves sorted canonically by tensor name. Leaves are hashed with domain separator `0x00` over `RFC 8785 JCS(TensorLeafDescriptor)`. Internal nodes are hashed with domain separator `0x01`. Inclusion proofs provide tamper-evident verification.

### ADR-042: Neutral Finding Taxonomy & Semantic Separation
Findings generated by Model Integrity use strictly objective, non-culpable technical vocabulary (`MODEL_CRYPTOGRAPHIC_IDENTITY_SEALED`, `MODEL_EXACT_INTEGRITY_MATCH`, `MODEL_DRIFT_*`). Terms asserting malice, intent, attacker control, or compromise are forbidden.

### ADR-043: Multi-Tenant Ledger Compatibility Abstraction
Provenance records are signed with Ed25519. The physical ledger records `target_type="dataset_version"` and `target_id=model_id` to maintain compatibility with the immutable Phase 3 schema, while the REST API surface presents `target_type_logical="model"` and `target_type_recorded="dataset_version"`.

---

## 6. Security & Air-Gap Guarantees

1. **Air-Gapped Operation:** All operations execute 100% locally. Socket creation is blocked during air-gap testing.
2. **Safe Ingestion Guardrails:** Path traversal (`../`, UNC, drive paths), symlink escaping, oversized headers (>100MB), archive bombs, and corrupt tensor offsets are intercepted and rejected cleanly with standard `InspectionStatus` codes.
3. **Cryptographic Protection:** Ed25519 signatures, SHA-256 streaming hashing, CSPRNG nonces, and sequence tracking protect audit trails against forgery and replay attacks.

---

## 7. Determinism & Idempotency Guarantees

1. **Bit-for-Bit Determinism:** Identical model files evaluated under the same configuration produce identical artifact hashes, structural hashes, contract hashes, Merkle roots, master fingerprints, execution identities, and evidence digests.
2. **Idempotent Reuse:** Re-running an integrity assessment for an already evaluated model returns `assessment_status = "IDEMPOTENT_HIT"` with zero duplicate rows inserted into findings, evidence, or provenance tables.

---

## 8. Database Schema Compatibility

- **Baseline Schema:** Phase 3 foundational schema with 15 tables (`projects`, `contributors`, `datasets`, `dataset_versions`, `samples`, `sample_contributors`, `ai_models`, `model_fingerprints`, `inference_records`, `findings`, `evidence`, `risk_assessments`, `audit_events`, `provenance_records`, `reports`).
- **Phase 7 Schema Migrations:** **ZERO (0)**.
- **Added Tables / Columns / Constraints:** **ZERO (0)**.

---

## 9. Test & Verification Baseline

| Test Suite | Total Tests | Passed | Failed |
|:---|:---:|:---:|:---:|
| `tests/test_model_integrity_comprehensive.py` | 24 | 24 | 0 |
| `tests/test_model_integrity_api.py` | 31 | 31 | 0 |
| `tests/test_model_integrity_evidence.py` | 31 | 31 | 0 |
| `tests/test_model_integrity_comparison.py` | 27 | 27 | 0 |
| `tests/test_model_integrity_contracts.py` | 28 | 28 | 0 |
| `tests/test_model_integrity_fingerprinting.py` | 31 | 31 | 0 |
| `tests/test_model_integrity_ingestion.py` | 30 | 30 | 0 |
| Phase 0–6 Regression Suites | 870 | 870 | 0 |
| **Total Full Repository Suite** | **1072** | **1072** | **0** |

---

## 10. Known Limitations

1. **Provenance Target Ledger Mapping:** In accordance with ADR-043, model provenance records are stored physically in `provenance_records` with `target_type = "dataset_version"` (to preserve the frozen Phase 3 database constraint) and mapped at the service/API boundary to `target_type_logical = "model"`.
2. **Static I/O Metadata for Weight-Only Formats:** Weight-only container formats (e.g. raw Safetensors or PyTorch state_dict) do not embed computational graph contracts; their contract status is classified as `UNAVAILABLE` unless an explicit preprocessing declaration is supplied.

---

## 11. Final Freeze Gate Decision

Phase 7 is officially **FROZEN**. No further modifications to Phase 7 code, schemas, or tests are permitted without an approved formal change control process.

Subsequent development proceeds to **PHASE 8 — BEHAVIOURAL ANALYSIS**.
