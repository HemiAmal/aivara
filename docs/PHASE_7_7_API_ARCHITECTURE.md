# Phase 7.7 — Model Integrity REST API & Integration Services Architecture

## 1. Executive Summary

Phase 7.7 exposes the complete static Model Integrity analysis capabilities of AIVARA through the established FastAPI architecture. The API serves purely as an orchestration and interface layer, delegating all cryptographic computations, hierarchical fingerprinting, contract verification, reference model comparison, evidence binding, and provenance sealing to the frozen Phase 7.2–7.6 engines and Phase 4 cryptographic services.

**Authoritative Status:** COMPLETED (NOT FROZEN)  
**Regression Baseline:** 1042 / 1042 PASS (100%)

---

## 2. Architecture & Request Flow

```
                      +-----------------------------+
                      |         REST Client         |
                      +-----------------------------+
                                     |
                                     | HTTP / JSON
                                     v
                 +---------------------------------------+
                 |    FastAPI Router Layer               |
                 |  (api/routers/model_integrity.py)     |
                 +---------------------------------------+
                                     |
                                     | Validated DTOs & Sessions
                                     v
                 +---------------------------------------+
                 |     ModelIntegrityService             |
                 |  (services/model_integrity_service.py)|
                 +---------------------------------------+
                                     |
         +---------------------------+---------------------------+
         |                           |                           |
         v                           v                           v
+------------------+       +-------------------+       +--------------------+
|  Phase 7.2 Safe  |       |   Phase 7.3 Merkle|       |   Phase 7.4        |
|  Ingestion &     |       |   Fingerprinting  |       |   Contract         |
|  Parsers Engine  |       |   Engine          |       |   Verification     |
+------------------+       +-------------------+       +--------------------+
         |                           |                           |
         +---------------------------+---------------------------+
                                     |
                                     v
                 +---------------------------------------+
                 | Phase 7.5 Reference Comparison        |
                 +---------------------------------------+
                                     |
                                     v
                 +---------------------------------------+
                 | Phase 7.6 Evidence Binding Service    |
                 +---------------------------------------+
                                     |
                                     v
                 +---------------------------------------+
                 | Phase 4 Cryptographic Provenance      |
                 | & Ledger Verification                 |
                 +---------------------------------------+
```

---

## 3. Endpoint Inventory & API Contracts

All endpoints are project-scoped under the base path `/api/v1/projects/{project_id}/models/{model_id}`.

### 3.1 Model Safe Inspection
- **Method:** `POST`
- **Path:** `/api/v1/projects/{project_id}/models/{model_id}/inspect`
- **Purpose:** Performs deterministic static header parsing and validation of model artifacts without executing model bytecode.
- **Request Body:** None (relies on registered model artifact reference)
- **Response Model:** `ModelInspectResponse`
- **Status Codes:** `200 OK`, `400 Bad Request`, `404 Not Found`, `500 Server Error`

### 3.2 Hierarchical Fingerprinting
- **Method:** `POST`
- **Path:** `/api/v1/projects/{project_id}/models/{model_id}/fingerprint`
- **Purpose:** Generates canonical 4-tier cryptographic fingerprints: Artifact SHA-256, Structural Hash, Weight Merkle Root, and Master Model Fingerprint. Supports idempotent cached reuse from database.
- **Request Body:** `ModelFingerprintRequest`
- **Response Model:** `ModelFingerprintResponse`
- **Status Codes:** `200 OK`, `400 Bad Request`, `404 Not Found`

### 3.3 Contract Verification
- **Method:** `POST`
- **Path:** `/api/v1/projects/{project_id}/models/{model_id}/contract/verify`
- **Purpose:** Verifies operational input, output, and preprocessing contracts against static metadata or explicit declarations.
- **Request Body:** `ModelContractVerifyRequest`
- **Response Model:** `ModelContractVerifyResponse`
- **Status Codes:** `200 OK`, `400 Bad Request`, `404 Not Found`

### 3.4 Reference Model Comparison
- **Method:** `POST`
- **Path:** `/api/v1/projects/{project_id}/models/{model_id}/compare`
- **Purpose:** Performs multi-tier cryptographic and structural diffing between candidate and trusted reference models, classifying drift into the frozen 8-state matrix.
- **Request Body:** `ModelCompareRequest`
- **Response Model:** `ModelCompareResponse`
- **Status Codes:** `200 OK`, `400 Bad Request`, `404 Not Found`

### 3.5 Integrated Model Integrity Assessment
- **Method:** `POST`
- **Path:** `/api/v1/projects/{project_id}/models/{model_id}/integrity-assessment`
- **Purpose:** End-to-end orchestration endpoint: safe inspection -> fingerprinting -> contract verification -> optional reference comparison -> evidence synthesis -> provenance sealing.
- **Request Body:** `ModelIntegrityAssessmentRequest`
- **Response Model:** `ModelIntegrityAssessmentResponse`
- **Status Codes:** `200 OK`, `400 Bad Request`, `404 Not Found`

### 3.6 Evidence Retrieval
- **Method:** `GET`
- **Path:** `/api/v1/projects/{project_id}/models/{model_id}/evidence`
- **Purpose:** Retrieves immutable cryptographic evidence records associated with model integrity findings.
- **Response Model:** `List[EvidenceItemRead]`
- **Status Codes:** `200 OK`, `404 Not Found`

### 3.7 Finding Retrieval
- **Method:** `GET`
- **Path:** `/api/v1/projects/{project_id}/models/{model_id}/findings`
- **Purpose:** Retrieves technical integrity findings bound to the model asset.
- **Response Model:** `List[FindingDetailRead]`
- **Status Codes:** `200 OK`, `404 Not Found`

### 3.8 Provenance Verification
- **Method:** `GET`
- **Path:** `/api/v1/projects/{project_id}/models/{model_id}/provenance`
- **Purpose:** Verifies digital signature, canonical payload, and hash chain integrity for the model's cryptographic provenance record.
- **Response Model:** `ModelProvenanceVerificationResponse`
- **Status Codes:** `200 OK`, `404 Not Found`

---

## 4. Integration Services & Reused Engines

The API directly integrates with and reuses:
1. `ModelIngestionService` (Phase 7.2): Safe static parsing for Safetensors, ONNX, and PyTorch (weights-only).
2. `ModelFingerprintingService` (Phase 7.3): Merkle tree construction and hierarchical digest derivation.
3. `ModelContractVerificationService` (Phase 7.4): Input/output shape/dtype verification and preprocessing validation.
4. `ModelComparisonService` (Phase 7.5): Deterministic diffing across artifact, structural, weight, and contract identities.
5. `ModelIntegrityEvidenceService` (Phase 7.6): Evidence synthesis, finding persistence, and provenance sealing.
6. `KeyManager` & `ProvenanceVerifier` (Phase 4): Ed25519 signing and hash-chained ledger verification.

---

## 5. Idempotency & Project Isolation

### Idempotency
- Uses the frozen Phase 7.6 deterministic `compute_execution_identity_hash` algorithm based on RFC 8785 JSON Canonicalization Scheme (JCS).
- Repeated identical assessments return `assessment_status: "IDEMPOTENT_HIT"` with `idempotent: true` and reuse the existing evidence and provenance records without creating duplicate database rows.

### Project Isolation
- All endpoints enforce strict project boundary checks:
  - Both candidate and reference models must belong to the requested `project_id`.
  - Evidence, findings, and provenance queries are strictly scoped to the model and project.
  - Cross-project model references return `404 Not Found` (or `400 Bad Request` on cross-project reference models).

---

## 6. Provenance Target Representation & Compatibility Abstraction

Phase 7.6 maintained backward compatibility with the frozen Phase 5.9 adapter by recording:
- `target_type`: `"dataset_version"`
- `target_id`: `model_id`

The Phase 7.7 REST API abstracts this compatibility detail for clients:
- Exposes `target_type_logical: "model"` indicating the domain entity.
- Exposes `target_type_recorded: "dataset_version"` documenting the underlying ledger representation.
- Includes a clear `compatibility_note` detailing the mapping.

---

## 7. Security Boundaries & Invariants

1. **Zero Execution:** Models are never loaded into execution runtimes (no ONNX Runtime, no PyTorch eval, no TorchScript execution, no pickle loading).
2. **Path Traversal Protection:** All file paths are strictly validated to prevent directory traversal and access outside authorized project storage.
3. **No Secret Leakage:** Private keys, passphrases, and raw exception tracebacks are never exposed in API responses or HTTP error bodies.
4. **Offline Capability:** Zero external network calls, cloud LLM APIs, or remote registries are accessed.
5. **No Scalar Risk Scoring:** No artificial risk percentages, threat multipliers, or subjective intent labels are generated.
