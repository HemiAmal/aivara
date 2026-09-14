# Phase 12.11 Architecture Specification: Universal Audit & Compliance Reporting

**Document Status:** Approved & Frozen  
**Subsystem:** Universal Audit & Compliance (`backend/aivara/universal/audit`)  
**Scope:** Phase 12.11 Only  
**Execution Invariant:** 100% Offline Air-Gapped & Deterministic  

---

## 1. Architectural Role & Boundary Principle

Phase 12.11 introduces the **Audit & Compliance Reporting Layer** for AIVARA. The reporting layer functions as a pure synthesis, traceability, compliance-mapping, integrity verification, and export boundary.

### Invariant: Pure Consumption Boundary
The reporting layer **MUST NOT** recalculate, re-estimate, or modify authoritative assurance results computed in upstream phases.

```
Authoritative Assurance Chain:
Evidence Envelopes (Phase 12.2)
       ↓
Finding-Evidence DAG (Phase 12.3)
       ↓
Cross-Subsystem Ingestion (Phase 12.4)
       ↓
Cross-Domain Correlation (Phase 12.5)
       ↓
Universal Risk Assessment (Phase 12.6)
       ↓
Policy Decision (Phase 12.7)
       ↓
Proof / Provenance Verification (Phase 12.8)
       ↓
Project & Multi-Asset Risk Aggregation (Phase 12.9)
       ↓
Universal Assurance API & Task Engine (Phase 12.10)
       ↓
[Phase 12.11] Audit & Compliance Reporting Layer
       ↓
Deterministic Report / Compliance Dossier / Export (JSON, Markdown, Text)
```

---

## 2. Core Architectural Components

### 2.1 Traceability Model (`backend/aivara/universal/audit/traceability.py`)
- Maps every material claim in an audit report to its authoritative backing objects:
  `Project -> Assets -> Evidence -> Findings -> Risk Contributions -> Risk Assessments -> Policy Decisions -> Proof Assessments -> Hierarchical Aggregation`.
- Disallows arbitrary free-form narrative claims.

### 2.2 Compliance Control & Mapping Layer (`backend/aivara/universal/audit/compliance.py`)
- Standard control catalogs: NIST AI RMF, EU AI Act, ISO/IEC 42001, OWASP Top 10 for LLMs.
- Strict 6-state compliance evaluation:
  `COMPLIANT`, `NON_COMPLIANT`, `PARTIALLY_COMPLIANT`, `NOT_ASSESSED`, `NOT_APPLICABLE`, `UNAVAILABLE`.
- Strict semantic rule: Absence of findings is NEVER treated as positive compliance unless the control definition explicitly specifies negative verification semantics. Incomplete evidence results in `NOT_ASSESSED` or `UNAVAILABLE`.

### 2.3 Deterministic Report Generator (`backend/aivara/universal/audit/generator.py`)
- Formulates the 20-section canonical audit report:
  1. Report Identity (`report_id`)
  2. Schema Version (`schema_version`)
  3. Instance Version (`instance_version`)
  4. Generation Metadata
  5. Project Tenancy (`project_id`)
  6. Scope & Asset Inventory
  7. Evidence Summary (by Domain & Layer)
  8. Findings Inventory (by Severity & Category)
  9. Confidence & Sufficiency Metrics
  10. Operational Risk Summary (Tier-1 Asset Scores)
  11. Cross-Domain Correlation Analysis (7x7 Matrix Attenuation)
  12. Policy Decision Evaluation (Rule Traceability)
  13. Cryptographic Proof & Provenance Verification
  14. Tier-2 Chain & Tier-3 Project Aggregation
  15. Compliance Control Results
  16. Unavailable Evidence & Limitations
  17. Material Traceability Index
  18. Cryptographic Content Hashes & Merkle Roots
  19. Verification & Integrity Attestation
  20. Sanitized / Redacted Artifact Reference
- Segregates non-deterministic presentation metadata (wall-clock time, process ID, thread ID) from canonical content descriptors.

### 2.4 Cryptographic Report Integrity (`backend/aivara/universal/audit/integrity.py`)
- Canonical report hashing:
  $$\text{report\_hash} = \text{SHA256}(\text{RFC8785\_JCS}(\text{canonical\_report\_descriptor}))$$
- Integrity states: `VERIFIED`, `TAMPERED`, `INVALID`, `INCOMPLETE`, `UNAVAILABLE`.
- Integrates with Phase 4 cryptographic verification engine for Ed25519 digital signatures if present.

### 2.5 Report Versioning & Semantic Diff (`backend/aivara/universal/audit/diff.py`)
- Distinguishes schema version from immutable instance version.
- Generates canonical semantic diffs between two report instances without false positives caused by dict key ordering or list permutations.

### 2.6 Security, Privacy & Redaction (`backend/aivara/universal/audit/redaction.py`)
- Automatic redaction of private keys, authentication tokens, API secrets, filesystem passwords, and internal tracebacks.
- Strict Broken Object-Level Authorization (BOLA) project scoping.
- Bounded file export path containment (no directory traversal).

### 2.7 RESTful API & Export (`backend/aivara/universal/audit/router.py` & `export.py`)
- REST endpoints mounted under `/api/v1/projects/{project_id}/universal/audit/`:
  - `POST /reports` (Generate report)
  - `GET /reports/{report_id}` (Retrieve report)
  - `POST /reports/{report_id}/verify` (Verify report integrity)
  - `POST /reports/compare` (Compare report instances)
  - `GET /reports/{report_id}/export` (Export report to JSON, Markdown, Text)
  - `GET /compliance/controls` (List available compliance controls)
