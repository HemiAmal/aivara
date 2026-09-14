# Phase 12.11 Requirements Specification: Universal Audit & Compliance Reporting

**Document Status:** Approved & Frozen  
**Scope:** Phase 12.11 Requirements (`REQ-12-AUDIT-001` to `REQ-12-AUDIT-030`)  

---

## Requirements Catalog

### 1. Architectural & Behavioral Invariants
- **`REQ-12-AUDIT-001` (Authoritative Consumption Boundary):** The audit reporting engine shall consume authoritative assurance artifacts (Phases 12.2–12.10) without recalculating risk scores, correlation attenuations, policy decisions, proof statuses, or project aggregation formulas.
- **`REQ-12-AUDIT-002` (Deterministic Generation):** For identical input assurance artifacts, control catalogs, and report configurations, report generator shall produce bitwise-identical canonical descriptors.
- **`REQ-12-AUDIT-003` (Canonical Content Addressing):** Every audit report shall be uniquely and immutably identified by a 64-character SHA-256 hash computed over its RFC 8785 JCS canonical content descriptor.
- **`REQ-12-AUDIT-004` (Separation of Presentation Metadata):** Wall-clock generation timestamps, hostnames, thread IDs, and process IDs shall be segregated from the canonical descriptor to maintain hash invariance across environments.
- **`REQ-12-AUDIT-005` (Air-Gapped & Offline Execution):** Report generation, compliance evaluation, and integrity verification shall operate strictly offline with zero external network or telemetry calls.

### 2. Traceability & Claim Grounding
- **`REQ-12-AUDIT-006` (Material Claim Grounding):** Every material assurance conclusion in the report shall resolve to an explicit chain of authoritative source objects (`project_id`, `asset_id`, `evidence_id`, `finding_id`, `risk_hash`, `decision_hash`, `proof_hash`, `hierarchical_hash`).
- **`REQ-12-AUDIT-007` (Prohibition of Unsupported Narrative Claims):** The engine shall reject or omit ungrounded narrative text that claims unverified risk levels, finding categories, or proof statuses.
- **`REQ-12-AUDIT-008` (Bi-Directional Traceability Index):** The report shall include an index mapping findings to their supporting evidence envelopes, and mapping policy decisions to their triggering risk contribution rules.

### 3. Compliance Control Evaluation
- **`REQ-12-AUDIT-009` (Multi-Framework Control Support):** The system shall provide structured control definitions for NIST AI RMF, EU AI Act, ISO/IEC 42001, and OWASP Top 10 for LLMs.
- **`REQ-12-AUDIT-010` (Six-State Compliance Status):** Compliance statuses shall be strictly limited to `COMPLIANT`, `NON_COMPLIANT`, `PARTIALLY_COMPLIANT`, `NOT_ASSESSED`, `NOT_APPLICABLE`, and `UNAVAILABLE`.
- **`REQ-12-AUDIT-011` (No False Compliance on Absence of Findings):** Absence of findings shall not infer `COMPLIANT` unless the control specifically defines negative evidence criteria; otherwise status shall be `NOT_ASSESSED` or `UNAVAILABLE`.
- **`REQ-12-AUDIT-012` (Immutable Control Versioning):** Compliance control definitions shall have immutable IDs, version strings, and canonical definition hashes.

### 4. Report Structure & Generation
- **`REQ-12-AUDIT-013` (Mandatory 20-Section Canonical Schema):** Generated audit reports shall adhere to the canonical schema covering scope, assets, evidence, findings, confidence, risk, correlation, policy, proof, aggregation, compliance, limitations, and traceability.
- **`REQ-12-AUDIT-014` (Limitations & Unavailable Evidence Disclosure):** The report shall explicitly document all incomplete ancestry paths, missing proofs, and unassessed domains as formal limitations.
- **`REQ-12-AUDIT-015` (Multi-Asset Project Aggregation Reporting):** The report shall document Tier-2 cross-asset lineage chains, Tier-3 peak asset dominance, and proof-aware disposition escalations.

### 5. Cryptographic Integrity & Verification
- **`REQ-12-AUDIT-016` (Report Hash Verification):** The engine shall provide an independent verification function that recomputes the RFC 8785 JCS SHA-256 digest and returns `VERIFIED`, `TAMPERED`, `INVALID`, `INCOMPLETE`, or `UNAVAILABLE`.
- **`REQ-12-AUDIT-017` (Signature Verification):** Where an Ed25519 digital signature is attached to the report, the verification engine shall validate it using the public key from the key manager.
- **`REQ-12-AUDIT-018` (Fail-Closed Integrity):** Any mutation of referenced hashes, scores, decisions, or finding lists shall cause verification to fail closed with `TAMPERED` or `INVALID`.

### 6. Versioning & Change Tracking
- **`REQ-12-AUDIT-019` (Schema vs Instance Versioning):** The engine shall enforce semantic versioning for the report schema while treating report instances as immutable snapshots.
- **`REQ-12-AUDIT-020` (Deterministic Semantic Diff):** The engine shall provide an instance comparison function identifying added/removed assets, risk score deltas, decision changes, proof status transitions, and compliance status updates.
- **`REQ-12-AUDIT-021` (Permutation Invariance in Diff):** Reordering of items in lists or dict keys shall not produce false-positive diff entries.

### 7. REST API & Export Integration
- **`REQ-12-AUDIT-022` (Report Creation Endpoint):** `POST /api/v1/projects/{project_id}/universal/audit/reports` shall generate and register an audit report.
- **`REQ-12-AUDIT-023` (Report Query & Verification Endpoints):** `GET .../reports/{report_id}` and `POST .../reports/{report_id}/verify` shall return the report and verification status.
- **`REQ-12-AUDIT-024` (Report Comparison Endpoint):** `POST .../reports/compare` shall return a deterministic diff between two report IDs.
- **`REQ-12-AUDIT-025` (Deterministic Export Formats):** `GET .../reports/{report_id}/export` shall support JSON, Markdown dossier, and Plaintext tabular representations.

### 8. Security, Privacy & Resource Governance
- **`REQ-12-AUDIT-026` (Strict Broken Object-Level Authorization):** All audit endpoints shall enforce project tenancy matching between URL parameters, request bodies, and internal report scopes.
- **`REQ-12-AUDIT-027` (Sensitive Data Redaction):** Secret tokens, private keys, passwords, and internal tracebacks shall be automatically redacted from report content.
- **`REQ-12-AUDIT-028` (Safe Export Path Containment):** Export operations shall prevent directory traversal attacks.
- **`REQ-12-AUDIT-029` (Resource Governance Limits):** Report generation and diffing shall strictly enforce resource limits (max 100 assets, max 1000 evidence items, max 500 findings).
- **`REQ-12-AUDIT-030` (Zero Dynamic Execution):** The audit reporting subsystem shall contain zero calls to `eval`, `exec`, `__import__`, or arbitrary dynamic code execution.
