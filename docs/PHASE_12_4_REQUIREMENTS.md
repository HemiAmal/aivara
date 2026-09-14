# Phase 12.4 — Requirements Specification

**Phase:** Phase 12.4 Cross-Subsystem Evidence Ingestion  
**Status:** Requirements Baseline  

---

## 1. Functional Requirements

- **REQ-12.4-01 (Domain Coverage):** Ingestion pipeline must support all 7 canonical assurance domains: `DATASET_INTEGRITY`, `CONTRIBUTOR_RISK`, `MODEL_INTEGRITY`, `BEHAVIORAL_ANALYSIS`, `BACKDOOR_TRIGGER`, `INFERENCE_INTEGRITY`, and `DISTRIBUTION_SHIFT`.
- **REQ-12.4-02 (Boundary Isolation):** The ingestion service must reject any evidence item whose `project_id` does not match the active project context (`ProjectBoundaryIngestionError`).
- **REQ-12.4-03 (Payload Integrity):** When supplied, `source_payload_hash` must match the SHA-256 digest of canonical RFC 8785 JCS bytes of the raw payload (`SourceHashMismatchIngestionError`).
- **REQ-12.4-04 (Normalization Integration):** All accepted evidence must be normalized into `UniversalEvidenceEnvelope` via Phase 12.2 normalizer.
- **REQ-12.4-05 (Graph Integration):** Non-duplicate envelopes and N:M finding relationships must be bound to `UniversalEvidenceGraphBuilder` (Phase 12.3).
- **REQ-12.4-06 (Idempotency):** Ingesting identical items must result in `DUPLICATE_SKIPPED` status without error or mutation of existing graph state.
- **REQ-12.4-07 (Ancestry Preservation):** Ancestry self-loops ($E \in \text{parents}(E)$) must be rejected (`AncestryConflictIngestionError`). Missing ancestry must be marked `UNVERIFIED` without fabricating synthetic parent nodes.
- **REQ-12.4-08 (Confidence Invariants):** Proof-layer evidence confidence must be strictly $1.0$. Detection-layer evidence confidence must be preserved within $[0.0, 1.0]$.
- **REQ-12.4-09 (Resource Ceilings):** Hard resource limits ($E \le 5,000$, $F \le 1,000$, $A \le 250$) must be enforced during single and batch ingestion (`IngestionResourceLimitError`).
- **REQ-12.4-10 (Deterministic Ingestion Report):** Batch execution must generate an immutable `IngestionReport` with canonical SHA-256 `ingestion_report_hash`.

---

## 2. Non-Functional & Security Requirements

- **SEC-12.4-01 (100% Offline Air-Gap):** Zero network sockets, zero external API calls, zero cloud dependencies.
- **SEC-12.4-02 (Immutability):** All Pydantic data contracts must be frozen (`ConfigDict(frozen=True)`).
- **SEC-12.4-03 (Non-Breaking Integration):** Zero modifications to frozen Phase 0–11 and Phase 12.1–12.3 code.
- **SEC-12.4-04 (Boundary Segregation):** Zero risk calculation math, zero correlation damping, and zero policy decisions within Phase 12.4.
