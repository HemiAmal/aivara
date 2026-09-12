# PHASE 8.7 — BEHAVIORAL EVIDENCE & PROVENANCE BINDING SPECIFICATION

**Status:** APPROVED / IMPLEMENTED  
**Target:** AIVARA — AI Verification & Assurance  
**Phase:** 8.7 (Evidence & Provenance Binding)  
**Security Model:** Read-Only Verification, Deterministic Canonical Evidence, Project-Scoped Hash-Linked Provenance Ledger, Ed25519 Cryptographic Signing, Multi-Tenant Project Isolation, 100% Offline Air-Gapped Execution.

---

## 1. Overview & Core Architecture

Phase 8.7 integrates the analytical behavioral outputs produced by Phases 8.3–8.6 (Baselines, Perturbations, Stability & Consistency, and Anomaly Detection) into AIVARA's established cryptographic evidence and provenance ledger architecture.

### The Universal Assurance Pipeline:
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

---

## 2. Core Security & Semantic Invariants

1. **Detection ≠ Proof & Anomaly ≠ Maliciousness:**
   - A cryptographically verified behavioral anomaly confirms that the analytical observation is authentic, complete, and un-tampered relative to the declared reference baseline.
   - It does **NOT** prove or imply malicious intent, model compromise, adversarial backdoors, or vulnerability.
2. **Zero Cryptographic Duplication:**
   - Strictly reuses Phase 4 cryptographic implementations: RFC 8785 JCS canonicalization, SHA-256 hashing, Ed25519 digital signatures, cryptographically secure nonces (`secrets.token_hex(32)`), monotonic sequence numbering, and hash-linked chain structures.
3. **Zero Database Schema Alterations:**
   - Zero database migrations. Reuses `EvidenceModel`, `FindingModel`, `ProvenanceRecordModel`, and `AuditEventModel`.
4. **Deterministic Content-Addressed Evidence Identity:**
   - The `evidence_id` is derived deterministically from the canonicalized semantic content, independent of database primary keys or wall-clock timestamps.
5. **Multi-Tenant Project Isolation:**
   - Rejects any binding or verification where `project_id` does not match across evidence, findings, models, observations, baselines, and provenance records.
6. **Floating-Point Determinism & Safety:**
   - Canonical evidence strictly sanitizes and rejects non-finite floating point values (`NaN`, `+Inf`, `-Inf`) to ensure JSON Canonicalization Scheme compliance.

---

## 3. Behavioral Evidence Taxonomy

| Evidence Type | Layer | Description |
| :--- | :--- | :--- |
| `BEHAVIORAL_BASELINE` | `DETECTION` | Reference profile capturing expected behavior distribution across trust-filtered populations. |
| `BEHAVIORAL_COMPARISON` | `DETECTION` | Comparative evaluation between candidate model and trusted reference baseline model. |
| `BEHAVIORAL_REPEATABILITY`| `PROOF` | Exact output determinism and numerical tolerance measurement on identical inputs. |
| `BEHAVIORAL_PERTURBATION` | `DETECTION` | Output sensitivity and drift measurements under controlled geometric and photometric transformations. |
| `BEHAVIORAL_STABILITY` | `DETECTION` | Multi-family stability assessment vector (classification, detection, segmentation, generic). |
| `BEHAVIORAL_ANOMALY` | `DETECTION` | Statistical outlier analysis evaluating robust z-scores and empirical extremeness against baseline. |

---

## 4. Verification Vector & Verification Flow

The `BehavioralProvenanceVerifier` performs deep multi-dimensional cryptographic verification:

```
                  +--------------------------------+
                  |  Retrieve Behavioral Evidence  |
                  +---------------+----------------+
                                  |
                                  v
                  +--------------------------------+
                  |  Recompute Canonical JCS Hash  |
                  +---------------+----------------+
                                  |
                                  v
                  +--------------------------------+
                  | Compare stored evidence_id     |
                  +---------------+----------------+
                                  |
                                  v
                  +--------------------------------+
                  | Validate Observation/Baseline/ |
                  | Model Identity & Fingerprints  |
                  +---------------+----------------+
                                  |
                                  v
                  +--------------------------------+
                  | Retrieve Provenance Record     |
                  | Verify Ed25519 Signature       |
                  | Verify Hash-Linkage & Nonce    |
                  +---------------+----------------+
                                  |
                                  v
                  +--------------------------------+
                  | Emit Immutable Verification    |
                  | Result & Audit Event Log       |
                  +--------------------------------+
```

### Verification Vector Fields
- `evidence_identity_valid`: Boolean flag indicating whether recomputed JCS SHA-256 matches `evidence_id`.
- `analysis_identity_valid`: Anomaly analysis digest matches evidence content.
- `observation_identity_valid`: Observation ID matches evidence content.
- `baseline_identity_valid`: Baseline ID matches evidence content.
- `model_identity_valid`: Model ID and master fingerprint match evidence content.
- `provenance_hash_valid`: Provenance record payload matches `record_hash`.
- `signature_valid`: Ed25519 signature is valid against public key.
- `chain_valid`: Previous record hash correctly links to project chain.
- `sequence_valid`: Sequence number is strictly monotonic.
- `nonce_valid`: Nonce is unique (replay protection).
- `project_isolation_valid`: Multi-tenant project boundary is strictly respected.
- `signer_status`: `ACTIVE`, `ROTATED`, `REVOKED`, `EXPIRED`, `UNKNOWN_SIGNER`, or `NONE`.
- `overall_status`: `VERIFIED`, `INVALID`, `MISSING`, `UNAVAILABLE`, `MISMATCHED`, or `UNVERIFIABLE`.

---

## 5. End-to-End Walkthrough Example

### Scenario:
A candidate object detection model exhibits an unusually low prediction agreement rate relative to historical reference executions.

1. **Analytical Observation & Anomaly Detection (Phases 8.3–8.6):**
   - Candidate model `model-yolo-v8-01` evaluated on dataset observation `obs-9812`.
   - Baseline `base-det-prod-v1` has median agreement = `0.94`, MAD = `0.02`.
   - Candidate observed agreement = `0.81`, resulting in `robust_z = -4.33` (`LOWER_IS_EXTREME`).
   - Phase 8.6 classifies metric as `ANOMALOUS`.

2. **Evidence Construction & Identity Sealing (Phase 8.7):**
   - `build_anomaly_evidence_content` packages observations, baseline metadata, metrics, and families into `BehavioralEvidenceContent`.
   - JCS canonicalization and SHA-256 produce deterministic `evidence_id`:
     `e4f9b8c2d10398471a5c6d3e8b7a1f2940283c7491823746a819283746501928`.
   - Evidence is marked `SEALED` and becomes read-only.

3. **Cryptographic Provenance Sealing (Phase 4 & 5.9):**
   - A `FindingModel` is synthesized and stored in the database.
   - A Phase 4 `ProvenanceRecordModel` is constructed:
     - `sequence_number = 42`
     - `previous_record_hash = "7a8b9c..."`
     - `nonce = "9f8e7d..."`
     - Canonical payload signed with Ed25519 private key.
     - Append-only audit event `BEHAVIORAL_PROVENANCE_BOUND` recorded.

4. **Independent Verification:**
   - Third-party auditor retrieves evidence and provenance record.
   - `BehavioralProvenanceVerifier.verify_behavioral_provenance(...)` executes.
   - Recomputes hash, verifies Ed25519 signature, checks previous hash linkage.
   - Returns `overall_status = ProvenanceStatus.VERIFIED`.
   - **Assurance Conclusion:** The statistical anomaly was authentic, un-tampered, and cryptographically verified. No maliciousness is inferred or asserted.

---

## 6. Offline Execution & Security Boundaries

Phase 8.7 executes 100% locally and offline:
- Zero HTTP/HTTPS external requests.
- Zero reliance on external KMS or timestamp authorities.
- Key management is fully local using Phase 4 `KeyManager`.
