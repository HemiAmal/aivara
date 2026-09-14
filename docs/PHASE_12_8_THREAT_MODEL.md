# Phase 12.8 — Proof & Provenance Integration Threat Model

**Status:** Authoritative Threat Analysis  
**Authority:** Phase 12.1 Universal Risk Architecture Freeze  

---

## 1. Threat Inventory & Mitigations

| Threat ID | Threat Description | Attack Vector | Severity | Mitigation in Phase 12.8 |
|---|---|---|---|---|
| `THREAT-12-PROOF-001` | Provenance Payload Tampering | Altering telemetry or metadata inside a provenance record. | CRITICAL | Canonical JCS SHA-256 `RECORD_HASH` validation flags `TAMPERED`. |
| `THREAT-12-PROOF-002` | Hash Chain Linkage Severing | Breaking `previous_record_hash` or inserting an unauthorized intermediate record. | CRITICAL | Full hash chain continuity verification detects breakage and flags `TAMPERED`. |
| `THREAT-12-PROOF-003` | Digital Signature Forgery | Attaching forged Ed25519 signature to modified payload. | CRITICAL | Ed25519 public key verification verifies cryptographic signature over canonical payload. |
| `THREAT-12-PROOF-004` | Signer Key Impersonation | Signing with an unauthorized or revoked private key. | HIGH | Signer key resolution via `KeyManager` enforces `ACTIVE` key lifecycle status. |
| `THREAT-12-PROOF-005` | Nonce / Record Replay | Replaying an old valid signed provenance record in a new session. | HIGH | Nonce uniqueness tracking and sequence monotonicity check flag `REPLAY_DETECTED`. |
| `THREAT-12-PROOF-006` | Evidence Hash Substitution | Binding a valid provenance record to a different evidence item. | HIGH | `EVIDENCE_BINDING` check verifies matching `evidence_id` and `normalized_payload_hash`. |
| `THREAT-12-PROOF-007` | Cross-Project Proof Contamination | Reusing signed provenance from Project A to validate evidence in Project B. | HIGH | `SCOPE_CONSISTENCY` check verifies project ID alignment. |
| `THREAT-12-PROOF-008` | Cross-Asset Proof Leakage | Using an asset-specific signature on Asset 1 to prove claims on Asset 2. | HIGH | Asset scope isolation restricts verification effect to the targeted asset. |
| `THREAT-12-PROOF-009` | Ancestry Path Spoofing | Binding provenance from Sample X to a different sample lineage. | HIGH | `ANCESTRY_BINDING` check validates all 5 ancestry tuple fields. |
| `THREAT-12-PROOF-010` | Proof-Confidence Inflation | Elevating unverified or detection evidence to confidence 1.0. | HIGH | Invariant: `proof_confidence == 1.0` if and only if status is `VERIFIED`. |
| `THREAT-12-PROOF-011` | Detection / Proof Compensation | Attempting to use high detection confidence to mask a failed proof. | HIGH | Proof non-compensability triggers explicit `REJECT` override on proof failure. |
| `THREAT-12-PROOF-012` | Correlation Attenuation of Proof | Diluting proof severity using Phase 12.5 correlation damping factors. | MEDIUM | Proof inviolability enforces attenuation factor $att_{\text{proof}} = 1.0$. |
| `THREAT-12-PROOF-013` | Denial of Service via Record Flooding | Submitting 500,000 chained records to exhaust memory/CPU. | MEDIUM | Hard resource ceiling of max 5,000 evidence items / 5,000 provenance records. |
| `THREAT-12-PROOF-014` | Non-Deterministic Result Hashing | Serializing dictionaries with random order or timestamps in hash descriptor. | MEDIUM | Canonical RFC 8785 JCS serialization over deterministic descriptor fields. |
| `THREAT-12-PROOF-015` | Arbitrary Code Execution | Malicious payloads attempting dynamic `eval()` or shell calls. | CRITICAL | AST static verification confirms zero dynamic execution, eval, or exec. |
| `THREAT-12-PROOF-016` | Network Data Exfiltration | Attempting remote key lookups or telemetry transmission. | HIGH | 100% offline air-gap design with zero socket or network dependencies. |
