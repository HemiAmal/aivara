# Phase 10.7 — Input → Output Binding Specification

## 1. Overview & Purpose
Phase 10.7 establishes an authoritative, deterministic cryptographic binding subsystem (`backend/aivara/inference/composite_binding/`) that binds the complete inference transaction from validated input (Phase 10.2) through verified model (Phase 7 / Phase 10.3), preprocessing contract & transformed input (Phase 10.4), controlled execution & raw output (Phase 10.5), to validated output (Phase 10.6).

The binding computes the canonical `inference_binding_hash` (ADR-093) ensuring end-to-end cryptographic traceability and tamper-evidence.

---

## 2. Architecture & 16 Canonical Descriptor Fields
The canonical descriptor commits to exactly 16 atomic fields formatted per RFC-8785 (JCS) and hashed with SHA-256:

1. `binding_version`: Schema version string (default: `"1.0"`).
2. `execution_identity_hash`: SHA-256 hash representing Phase 10.5 execution container/environment.
3. `input_canonical_hash`: SHA-256 canonical hash of input payload (Phase 10.2).
4. `input_id`: UUID of the input transaction.
5. `input_model_binding_hash`: SHA-256 input-to-model binding hash (Phase 10.3).
6. `input_raw_hash`: SHA-256 raw hash of input payload.
7. `model_artifact_hash`: SHA-256 artifact hash of the model (Phase 7).
8. `model_contract_hash`: SHA-256 model contract definition hash.
9. `model_id`: UUID of the model entity.
10. `model_master_fingerprint`: SHA-256 master fingerprint of the model (Phase 7).
11. `model_structural_hash`: SHA-256 structural architecture hash.
12. `output_contract_hash`: SHA-256 output schema contract hash (Phase 10.6).
13. `preprocessing_contract_hash`: SHA-256 preprocessing contract hash (Phase 10.4).
14. `project_id`: UUID of the tenancy project.
15. `raw_output_hash`: SHA-256 raw output tensor hash (Phase 10.5).
16. `schema_version`: String schema version identifier (default: `"1.0"`).
17. `transformed_input_hash`: SHA-256 transformed tensor payload hash (Phase 10.4).
18. `validated_output_identity`: Canonical dictionary identity of validated output tensors (Phase 10.6).

---

## 3. Core Cryptographic Invariants
- **Deterministic Canonicalization**: Serialized exclusively with RFC-8785 JSON Canonicalization Scheme (JCS).
- **Zero Evaluation / Pure Observational Binding**: Cryptographic computation only; zero model inference or state mutation.
- **Fail-Closed Verification**: Any hash mismatch, project mismatch, or missing component immediately returns `InferenceBindingStatus.INVALID` or raises appropriate domain exception.
- **Tenancy Isolation**: Strict validation that all components share the identical `project_id`.
- **Database Schema Changes**: 0 (zero migrations, zero table alters).
