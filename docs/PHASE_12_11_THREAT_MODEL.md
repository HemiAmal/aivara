# Phase 12.11 Threat Model: Universal Audit & Compliance Reporting

**Document Status:** Approved & Frozen  
**Scope:** Threat Analysis (`THREAT-12-AUDIT-001` to `THREAT-12-AUDIT-030`)  

---

## Threat Catalog & Mitigation Matrix

| Threat ID | Threat Name | Severity | Attack Vector / Description | Mitigation Strategy |
|---|---|---|---|---|
| `THREAT-12-AUDIT-001` | Report Content Tampering | CRITICAL | Malicious alteration of risk scores, findings, or decisions in a generated report. | RFC 8785 JCS canonicalization with SHA-256 `report_hash` verification. |
| `THREAT-12-AUDIT-002` | Traceability Reference Substitution | HIGH | Attacker replaces backing evidence/finding hash with unrelated benign artifact. | Bi-directional reference resolution and content-hash validation against graph nodes. |
| `THREAT-12-AUDIT-003` | Cross-Project Report Access (BOLA) | CRITICAL | User from Project A queries or modifies audit reports belonging to Project B. | Mandatory tenancy validation on URL `project_id` matching report `project_id`. |
| `THREAT-12-AUDIT-004` | False Compliance Attribution | HIGH | Reporting engine marks unassessed controls as `COMPLIANT` when no findings exist. | Strict 6-state logic enforcing `NOT_ASSESSED` or `UNAVAILABLE` on absence of positive evidence. |
| `THREAT-12-AUDIT-005` | Risk Score / Level Substitution | CRITICAL | Alteration of Tier-1 or Tier-3 risk scores to bypass regulatory audits. | Pure consumption of immutable upstream `UniversalRiskAssessment` hashes. |
| `THREAT-12-AUDIT-006` | Policy Decision Substitution | CRITICAL | Changing `REJECT` or `QUARANTINE` decision to `ACCEPT` in report summary. | Direct reference to frozen `UniversalPolicyDecision` and rule execution traces. |
| `THREAT-12-AUDIT-007` | Proof Status Whitewashing | CRITICAL | Concealing cryptographic proof failure (`TAMPERED` / `INVALID`) in the report. | Non-compensability invariant: proof status directly propagated into report findings. |
| `THREAT-12-AUDIT-008` | Aggregation Lineage Manipulation | HIGH | Fabricating or omitting multi-asset dependency edges to dilute peak risk. | Graph snapshot hash validation and explicit lineage chain reporting. |
| `THREAT-12-AUDIT-009` | Evidence Omission / Cherry-Picking | HIGH | Selectively excluding high-severity evidence from the report summary. | Canonical Merkle root reconciliation against Phase 12.3 Evidence Graph. |
| `THREAT-12-AUDIT-010` | Evidence Injection | HIGH | Injecting synthetic evidence items not present in the original evaluation. | Hash integrity check against graph snapshot nodes. |
| `THREAT-12-AUDIT-011` | Report Version Confusion / Downgrade | MEDIUM | Presenting an outdated report instance as the current compliance state. | Explicit `instance_version` incrementing and semantic diff tracking. |
| `THREAT-12-AUDIT-012` | Non-Deterministic Content Hash Instability | HIGH | Timestamps, process IDs, or dict permutations altering `report_hash`. | Strict segregation of non-deterministic presentation metadata from canonical descriptor. |
| `THREAT-12-AUDIT-013` | Sensitive Secret Disclosure | HIGH | Inclusion of private keys, API tokens, or DB passwords in audit report body. | Automated redaction engine scrubbing credentials before report rendering. |
| `THREAT-12-AUDIT-014` | Internal Stack Trace Leakage | LOW | Raw Python tracebacks exposed in report limitations or error envelopes. | Sanitized error codes and high-level descriptions. |
| `THREAT-12-AUDIT-015` | Export Directory Traversal | HIGH | Path traversal in export output (`../../etc/passwd`) allowing arbitrary writes. | Strictly contained, application-controlled memory/path exports. |
| `THREAT-12-AUDIT-016` | Export Overwrite Denial of Service | MEDIUM | Overwriting existing report exports or system files via export API. | Unique filename hashing with write collision guards. |
| `THREAT-12-AUDIT-017` | Resource Exhaustion via Asset Flooding | HIGH | Generating report for project with thousands of assets causing memory exhaustion. | Ceiling enforcement: max 100 assets per report. |
| `THREAT-12-AUDIT-018` | Resource Exhaustion via Evidence Flooding | HIGH | Generating report with tens of thousands of evidence envelopes. | Ceiling enforcement: max 1,000 evidence items per report. |
| `THREAT-12-AUDIT-019` | Infinite Recursion in Traceability Traversal | HIGH | Cyclic references in finding-evidence DAG causing infinite loops during report generation. | Visited set guards and DAG acyclicity verification. |
| `THREAT-12-AUDIT-020` | Dynamic Code Execution / `eval` | CRITICAL | Template injection or `eval` during markdown/text export rendering. | Pure deterministic string formatting; AST prohibition of `eval`/`exec`. |
| `THREAT-12-AUDIT-021` | Outbound Telemetry / Network Exfiltration | CRITICAL | Report exporter making external HTTP calls to remote reporting services. | Air-gap invariant: zero network libraries or sockets permitted. |
| `THREAT-12-AUDIT-022` | Cross-Project Report Diff Comparison Injection | HIGH | Comparing Report A (Project 1) with Report B (Project 2) leaking cross-tenant data. | Multi-report tenancy validation requiring matching `project_id`. |
| `THREAT-12-AUDIT-023` | False Verification Status Claim | HIGH | Returning `VERIFIED` when hash check or signature check was skipped. | Strict fail-closed verification pipeline returning explicit status enum. |
| `THREAT-12-AUDIT-024` | Stale Artifact Hash Linkage | MEDIUM | Report referencing an artifact whose underlying hash has evolved. | Snapshot pinning: reports reference specific immutable hashes. |
| `THREAT-12-AUDIT-025` | Schema Mutation & Extra Field Injection | MEDIUM | Client submits malformed or unauthorized fields in report request. | Pydantic `extra="forbid"` on all request schemas. |
| `THREAT-12-AUDIT-026` | Control Version Tampering | MEDIUM | Mutating compliance control definitions after report generation. | Cryptographic control definition hashing (`control_hash`). |
| `THREAT-12-AUDIT-027` | Replay of Old Verification Results | HIGH | Replaying a cached `VERIFIED` response for a mutated report. | Verification dynamically recomputes hash on request. |
| `THREAT-12-AUDIT-028` | Cross-Tenant Compliance Leakage | HIGH | Querying global compliance controls revealing tenant-specific policies. | Separation of generic framework catalogs from project-scoped results. |
| `THREAT-12-AUDIT-029` | Large Payload Diff Denial of Service | MEDIUM | Requesting semantic diff between extremely divergent large reports. | Max diff element bounding. |
| `THREAT-12-AUDIT-030` | Frozen Phase Regression Injection | CRITICAL | Modifying Phase 0–11 or 12.1–12.10 files during audit implementation. | Repository-wide regression tests and `git status` isolation checks. |
