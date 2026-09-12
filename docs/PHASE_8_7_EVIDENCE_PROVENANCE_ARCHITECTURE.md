# PHASE 8.7 — BEHAVIORAL EVIDENCE & PROVENANCE BINDING ARCHITECTURE

**Status:** IMPLEMENTATION ARCHITECTURE  
**Target:** AIVARA — AI Verification & Assurance  
**Phase:** 8.7 (Evidence & Provenance Binding)  
**Security Model:** Read-Only Analysis, Deterministic Canonical Evidence, Project-Scoped Hash-Linked Provenance, Ed25519 Signing, Multi-Tenant Isolation, 100% Offline Air-Gapped Execution.

---

## 1. Executive Summary & Core Principle

Phase 8.7 establishes the cryptographic evidence and provenance binding pipeline for all behavioral verification outputs produced by Phases 8.3 through 8.6 (Behavioral Baselines, Controlled Perturbations, Output Consistency & Stability, and Behavioral Anomaly Detection).

The architectural pipeline follows AIVARA's universal core assurance chain:
```
MEASUREMENT (Phases 8.3–8.5)
      ↓
FINDING (Phase 8.6)
      ↓
CANONICAL EVIDENCE CONTENT (Phase 8.7)
      ↓
CRYPTOGRAPHIC IDENTITY (RFC 8785 JCS + SHA-256)
      ↓
PROVENANCE RECORD (Phase 4 Hash-Linked Ledger + Ed25519)
      ↓
VERIFIABLE AUDIT TRAIL
```

### Essential Invariants
1. **Detection ≠ Proof & Anomaly ≠ Maliciousness:** Cryptographic verification of behavioral evidence asserts the authenticity and integrity of the analysis, NOT compromise or malicious intent. Statistical extremeness relative to a reference population is purely analytical.
2. **Zero Cryptographic Duplication:** Strictly reuse Phase 4 cryptographic primitives (RFC 8785 JCS canonicalization, SHA-256, Ed25519 digital signatures, cryptographically secure nonces, sequence numbers, hash-linked provenance records).
3. **Zero Database Schema Changes:** Store all behavioral evidence and provenance within existing `EvidenceModel`, `FindingModel`, `ProvenanceRecordModel`, and `AuditEventModel` tables.
4. **Deterministic & Content-Addressed Identity:** Evidence identity is derived deterministically from canonical semantic content, completely independent of database UUIDs or wall-clock timestamps.
5. **Project Isolation:** All evidence, findings, baselines, and provenance records must belong to the exact same `project_id`. Cross-project bindings are rejected.

---

## 2. Inventory of Reusable Architectural Components

| Component | Origin | Purpose in Phase 8.7 |
| :--- | :--- | :--- |
| `aivara.crypto.canonical.canonicalize` | Phase 4 | RFC 8785 JSON Canonicalization Scheme (JCS) deterministic serialization. |
| `aivara.crypto.hashing.hash_canonical_data` | Phase 4 | Canonical SHA-256 content hashing. |
| `aivara.crypto.hashing.is_valid_sha256` | Phase 4 | 64-hex SHA-256 format verification. |
| `aivara.crypto.signing.sign_hash` | Phase 4 | Ed25519 signing of canonical provenance record payloads. |
| `aivara.crypto.signing.verify_signature` | Phase 4 | Ed25519 cryptographic signature verification. |
| `aivara.crypto.chain.generate_nonce` | Phase 4 | Cryptographically secure 256-bit random nonce generation (`secrets.token_hex(32)`). |
| `aivara.crypto.keys.KeyManager` | Phase 4 | Local Ed25519 key lifecycle and status management (`ACTIVE`, `ROTATED`, `REVOKED`, `EXPIRED`). |
| `aivara.crypto.verification.verify_record` | Phase 4 | Provenance record verification engine (signature, hash, sequence, nonce, previous hash). |
| `aivara.services.provenance_service.ProvenanceService` | Phase 4 | Ledger persistence and hash chain state manager. |
| `aivara.services.audit_service.AuditService` | Phase 4 | Tamper-evident append-only audit event logger. |
| `aivara.evidence.identity.compute_execution_identity_hash`| Phase 5.9 | Analytical execution context hash for idempotency. |
| `aivara.evidence.binding.EvidenceFindingBinder` | Phase 5.9 | Persistence bridge for Findings and Evidence rows. |
| `aivara.evidence.provenance.ProvenanceBindingAdapter` | Phase 5.9 | Finding-to-Provenance ledger sealing adapter. |
| `EvidenceModel`, `FindingModel`, `ProvenanceRecordModel` | Phase 1–5.9 | Existing relational models reused with zero migrations. |

---

## 3. Behavioral Evidence Taxonomy

Phase 8.7 introduces explicit behavioral evidence types within the established evidence taxonomy:

1. `BEHAVIORAL_BASELINE`: Deterministic profile of expected model behavior across reference populations (Phase 8.3).
2. `BEHAVIORAL_COMPARISON`: Comparative evaluation between candidate model and trusted reference model.
3. `BEHAVIORAL_REPEATABILITY`: Measurement of output determinism and numerical stability under identical inputs (Phase 8.5).
4. `BEHAVIORAL_PERTURBATION`: Systematic sensitivity measurements under controlled input transformations (Phase 8.4 & 8.5).
5. `BEHAVIORAL_STABILITY`: Comprehensive multi-family stability assessment vector (Phase 8.5).
6. `BEHAVIORAL_ANOMALY`: Multi-family statistical deviation analysis against reference baseline (Phase 8.6).

---

## 4. Evidence Content vs. Provenance Metadata Separation

A strict boundary is maintained between what was analyzed and how it is cryptographically sealed:

### Evidence Content (Deterministic, Immutable Payload)
- `evidence_type`: Controlled behavioral evidence type.
- `project_id`: Multi-tenant project boundary.
- `model_id` & `model_fingerprint`: Candidate model identity and Phase 7 cryptographic master fingerprint.
- `observation_id`: Execution observation identifier.
- `baseline_id` & `baseline_type`: Baseline reference context.
- `task_type`: Task domain (classification, detection, segmentation, generic).
- `metrics`: Alphabetically sorted deterministic metrics, baseline statistics, robust z-scores, and validity flags.
- `families`: Behavioral family aggregation summaries.
- `policy_version` & `engine_version`: Applied analytical policies.
- `support_status` & `comparability_status`: Analytical completeness flags.
- `limitations`: Canonical list of documented limitations.

### Provenance Metadata (Ledger Context)
- `record_type`: Ledger record classification (e.g. `BEHAVIORAL_ASSURANCE_SEAL`).
- `actor`: System identity (e.g. `system:behavioral_orchestrator`).
- `signer_key_id`: Ed25519 public key identifier.
- `nonce`: Cryptographically secure 256-bit random nonce.
- `sequence_number`: Project-scoped monotonic sequence number.
- `previous_record_hash`: SHA-256 hash of previous record in project ledger.
- `record_hash`: SHA-256 digest of canonical record payload.
- `signature`: Ed25519 digital signature.
- `timestamp`: Canonical ISO-8601 UTC timestamp.

---

## 5. Idempotency & Lifecycle

- **Draft State:** Evidence payload constructed during analysis before final sealing.
- **Sealed State:** Canonical JCS serialization, SHA-256 hash computed (`evidence_hash`), committed to database with read-only immutability.
- **Idempotency Strategy:** Repeated execution of identical analytical inputs with identical policies resolves to the existing finding and provenance record without appending duplicate ledger blocks.

---

## 6. Verification Vector & Tamper Detection

Behavioral verification evaluates the complete cryptographic vector:
- `evidence_identity_valid`: Recomputed canonical evidence hash matches stored hash.
- `analysis_identity_valid`: Anomaly analysis digest matches bound evidence.
- `observation_identity_valid`: Observation ID matches bound evidence.
- `baseline_identity_valid`: Baseline ID matches bound evidence.
- `model_identity_valid`: Model ID and master fingerprint match candidate model.
- `provenance_hash_valid`: Provenance record payload matches `record_hash`.
- `signature_valid`: Ed25519 signature verifies against signer public key.
- `chain_valid`: `previous_record_hash` correctly links to the preceding project record.
- `sequence_valid`: Sequence number is strictly monotonic.
- `nonce_valid`: Nonce is unique within the project (no replay).
- `project_isolation_valid`: All components share identical `project_id`.
- `signer_status`: `ACTIVE`, `ROTATED`, `REVOKED`, `EXPIRED`, or `UNKNOWN_SIGNER`.
- `overall_status`: `VERIFIED`, `INVALID`, `MISSING`, `UNAVAILABLE`, `MISMATCHED`, or `UNVERIFIABLE`.

---

## 7. Security Invariants & Neutrality
- **No Maliciousness Inferences:** The engine reports statistical deviations. Terms such as "malicious", "compromised", "backdoor", or "attack" are strictly forbidden in findings, evidence, audit logs, and exceptions.
- **Floating-Point Canonicalization:** Non-finite floats (`NaN`, `+Inf`, `-Inf`) are rejected or represented via explicit string statuses (`UNDEFINED`, `NON_FINITE_DENOMINATOR`).
- **Offline Assurance:** Zero external calls or cloud services. Key management and cryptographic verification run 100% locally.
