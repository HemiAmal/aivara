# Phase 12.4 — Threat Model & Security Analysis

**Phase:** Phase 12.4 Cross-Subsystem Evidence Ingestion  
**Status:** Complete Threat Assessment  

---

## 1. Threat Vectors and Mitigations

| Threat ID | Threat Description | Attack Vector | Mitigation in Phase 12.4 |
|---|---|---|---|
| **T-12.4-01** | Cross-Tenant Evidence Injection | Malicious actor submits evidence with Tenant B project ID into Tenant A session | Strict project boundary assertion; immediate `ProjectBoundaryIngestionError` before normalization |
| **T-12.4-02** | Payload Tampering & Hash Collision | Adversary alters metrics payload while keeping original hash | Recomputed RFC 8785 JCS SHA-256 validation; raises `SourceHashMismatchIngestionError` |
| **T-12.4-03** | Ancestry Graph Poisoning / Cycles | Submitting self-referencing or cyclic parent evidence chains | Upstream self-loop rejection + Phase 12.3 DFS 3-color cycle detection |
| **T-12.4-04** | Resource Exhaustion (DoS) | Submitting massive batches (> 5000 items) or deep trees | Hard ceiling enforcement on batch size, evidence nodes, and DAG depth |
| **T-12.4-05** | Confidence Manipulation | Forcing detection evidence to confidence > 1.0 or non-finite floats | Pydantic finite float validation + domain adapter bounds checks |
| **T-12.4-06** | State Mutation via Duplicate Flooding | Flooding identical items to distort finding weight or risk | Canonical hash deduplication; marked `DUPLICATE_SKIPPED` with zero graph side-effects |
| **T-12.4-07** | Scope Creep / Decision Hijacking | Executing unauthorized risk aggregation or policy decisions | Static AST audit proving zero risk math or policy disposition assignments |
