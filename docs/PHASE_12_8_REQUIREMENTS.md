# Phase 12.8 — Proof & Provenance Integration Requirements Specification

**Status:** Authoritative Requirement Baseline  
**Authority:** Phase 12.1 Universal Risk Architecture Freeze  

---

## 1. Requirement Inventory

| Requirement ID | Category | Description | Verification Method |
|---|---|---|---|
| `REQ-12-PROOF-001` | Phase 4 Reuse | System must reuse existing Phase 4 cryptographic verification primitives without reimplementing algorithms. | Architectural / Code Review |
| `REQ-12-PROOF-002` | Proof Schema | Proof verification results must be immutable Pydantic V2 models with proof_status, evidence binding, checks, confidence, and proof_result_hash. | Unit / Contract Test |
| `REQ-12-PROOF-003` | Status Taxonomy | Engine must distinguish VERIFIED, INVALID, MISSING, UNAVAILABLE, TAMPERED, and REPLAY_DETECTED without generic failure collapsing. | Status Distinction Test |
| `REQ-12-PROOF-004` | Proof Confidence Invariant | Cryptographically verified proof evidence receives confidence = 1.0; non-verified evidence must never claim 1.0 proof confidence. | Confidence Invariant Test |
| `REQ-12-PROOF-005` | Detection Confidence Preservation | Proof verification must not overwrite or mutate underlying statistical detection confidence. | Detection Segregation Test |
| `REQ-12-PROOF-006` | Proof Non-Compensability | Strong detection cannot manufacture proof; valid proof cannot erase detection anomalies; proof failure on proof layer triggers REJECT override. | Non-Compensability Test |
| `REQ-12-PROOF-007` | Inviolable Proof Attenuation | Cryptographically verified proof evidence is not correlation-attenuated (attenuation factor = 1.0). | Integration Test |
| `REQ-12-PROOF-008` | Record Hash Integrity | Recomputed SHA-256 over RFC 8785 JCS canonical payload must match stored record_hash; mismatches flag TAMPERED. | Mutation / Tamper Test |
| `REQ-12-PROOF-009` | Hash Chain Continuity | Engine must verify previous_record_hash continuity and monotonic sequence ordering across provenance chains. | Chain Integrity Test |
| `REQ-12-PROOF-010` | Signature Verification | Ed25519 digital signatures over canonical payload must be verified using active signer public keys. | Signature Mutation Test |
| `REQ-12-PROOF-011` | Replay Protection | Nonce collisions and sequence rollbacks must be detected and classified as REPLAY_DETECTED. | Replay Attack Test |
| `REQ-12-PROOF-012` | Evidence Payload Binding | Provenance record entity/payload must match evidence_id and payload hash; mismatches flag INVALID. | Evidence Binding Test |
| `REQ-12-PROOF-013` | Ancestry Path Binding | 5-tuple ancestry path (<sample_id, dataset_version_id, model_fingerprint, window_id, source_id>) must match signed provenance. | Ancestry Mutation Test |
| `REQ-12-PROOF-014` | Project Scope Isolation | Provenance records referencing Project A cannot be bound to Project B evidence (cross-project protection). | Scope Isolation Test |
| `REQ-12-PROOF-015` | Asset Scope Isolation | Proof failure on Asset A does not invalidate unrelated Asset B without explicit DAG lineage. | Scope Isolation Test |
| `REQ-12-PROOF-016` | Deterministic Content Addressing | proof_result_hash and assessment_hash must be computed via RFC 8785 JCS + SHA-256 over deterministic fields only. | Determinism Test |
| `REQ-12-PROOF-017` | Universal Proof Assessment | Aggregated assessment must compute overall status, status counts, and proof_override_required flags. | Assessment Schema Test |
| `REQ-12-PROOF-018` | Fail-Closed Error Handling | Malformed cryptographic payloads or corrupted keys must fail closed with typed exceptions. | Fail-Closed Test |
| `REQ-12-PROOF-019` | Resource Ceilings | Enforce hard ceilings of max 5,000 evidence items and max 5,000 provenance records in linear O(P + E) time. | Resource Ceilings Test |
| `REQ-12-PROOF-020` | 100% Offline Air-Gap | Policy verification must execute 100% offline with zero network calls, remote lookups, or telemetry. | AST / Air-Gap Test |
