# Phase 12.10 — Universal Risk API & Task Integration Threat Model

**Author:** DeepMind Antigravity Pair Programmer  
**Phase:** 12.10 — Universal Risk API & Task Integration  
**Date:** 2026-09-14  
**Status:** Frozen Threat Model Specification  

---

## 1. Threat Enumeration Matrix (THREAT-12-API-001 through THREAT-12-API-030)

| Threat ID | Threat Name | STRIDE Category | Attack Vector / Description | Mitigating Control |
| :--- | :--- | :--- | :--- | :--- |
| **THREAT-12-API-001** | Broken Object-Level Authorization (BOLA) | Elevation of Privilege | Attacker accesses task or risk assessment belonging to another project by guessing UUID | Strict `project_id` matching on every resource retrieval; returns 404 on mismatch |
| **THREAT-12-API-002** | Cross-Project Asset Injection | Tampering | Injecting asset IDs belonging to project $P_B$ into a project $P_A$ assurance request | Cross-project asset validation; fails closed with `ScopeMismatchError` (HTTP 400/404) |
| **THREAT-12-API-003** | Task ID Enumeration | Information Disclosure | Attacker sequentially enumerates task IDs to scrape assurance results | High-entropy UUID v4 identifiers combined with mandatory project tenant verification |
| **THREAT-12-API-004** | Risk ID Enumeration | Information Disclosure | Probing `/universal/risk/{id}` to access unassigned risk evaluations | Enforced project tenant ownership check on all risk lookups |
| **THREAT-12-API-005** | Decision ID Enumeration | Information Disclosure | Probing `/universal/decisions/{id}` to discover sensitive policy outcomes | Enforced project tenant ownership check on all decision lookups |
| **THREAT-12-API-006** | Proof ID Enumeration | Information Disclosure | Probing `/universal/proof/{id}` to harvest cryptographic verification records | Enforced project tenant ownership check on all proof lookups |
| **THREAT-12-API-007** | Path Traversal via Artifact URI | Tampering | Passing `../../etc/passwd` in artifact path references | Input regex sanitization `^[a-zA-Z0-9_\-\.]{1,128}$`; absolute path rejection |
| **THREAT-12-API-008** | Payload Exhaustion DoS | Denial of Service | Sending multi-gigabyte JSON payloads to exhaust server memory | Strict 10MB payload size limit enforced at middleware/Pydantic layer |
| **THREAT-12-API-009** | Task Flooding DoS | Denial of Service | Submitting thousands of rapid task requests to monopolize worker threads | Idempotency key fingerprinting and bounded worker pool capacity |
| **THREAT-12-API-010** | Concurrent Worker Exhaustion | Denial of Service | Long-running analysis tasks starvation of thread pool | Bounded `ThreadPoolExecutor(max_workers=4)` with cooperative cancellation sentinels |
| **THREAT-12-API-011** | SSE Subscription Resource Exhaustion | Denial of Service | Opening thousands of dangling SSE connections to exhaust server sockets | Connection limits, queue cleanup on client disconnect, and heartbeat timeouts |
| **THREAT-12-API-012** | Pagination Abuse | Denial of Service | Requesting `page_size=1000000` to trigger heavy database scans | Hard ceiling `max_page_size=50` enforced in query validators |
| **THREAT-12-API-013** | Schema Confusion Attack | Tampering | Supplying malformed payload fields to induce undefined type coercion | Strict Pydantic V2 schemas with `extra="forbid"` and explicit type validation |
| **THREAT-12-API-014** | API Version Confusion | Tampering | Calling deprecated or legacy API versions with altered semantics | Explicit route versioning `/api/v1/` with unsupported version 404 rejection |
| **THREAT-12-API-015** | Stack Trace Information Leakage | Information Disclosure | Inducing unhandled 500 errors to leak Python stack traces and filesystem paths | Centralized error handler sanitizing exceptions into structured `ErrorDetail` |
| **THREAT-12-API-016** | Database Schema Leakage | Information Disclosure | Malformed SQL queries leaking table/column metadata | ORM query parameterization and sanitized domain error responses |
| **THREAT-12-API-017** | Secret / Private Key Leakage | Information Disclosure | Returning key material or passphrases in API response JSON | Explicit omission of secret fields; Pydantic `exclude=True` on cryptographic secrets |
| **THREAT-12-API-018** | Result Hash Substitution | Tampering | Manually injecting fabricated risk or proof hashes into API responses | Hash re-verification during serialization via RFC 8785 JCS + SHA-256 |
| **THREAT-12-API-019** | Stale Result Retrieval | Integrity Violation | Returning outdated cached result after project evidence changes | Task fingerprinting incorporating evidence Merkle root and policy hashes |
| **THREAT-12-API-020** | Unauthorized Task Cancellation | Denial of Service | Malicious actor cancelling a legitimate user's running task | Project tenant authorization verification before processing cancellation |
| **THREAT-12-API-021** | Unauthorized Task Creation | Tampering | Creating assurance tasks for inactive or locked projects | Project existence and active status validation before task enqueue |
| **THREAT-12-API-022** | Cross-Project Task Access | Information Disclosure | Reading task status or logs across tenant boundaries | Strict tenant filtering on all task lookups |
| **THREAT-12-API-023** | Partial-Result Publication | Integrity Violation | Serving incomplete intermediate results before pipeline finishes | `GET /result` returns HTTP 409 Conflict until status is `COMPLETED` |
| **THREAT-12-API-024** | Replayed Task Submission | Replay Attack | Replaying identical request to waste computing resources | Idempotent task reuse matching canonical request hash |
| **THREAT-12-API-025** | Idempotency Key Collision Abuse | Tampering | Using duplicate idempotency key with conflicting request body | Hash comparison of request body; returns HTTP 409 Conflict on payload mismatch |
| **THREAT-12-API-026** | Permissive CORS Exploitation | Security Misconfiguration | Wildcard CORS allowing arbitrary malicious origins to read responses | CORS restricted strictly to localhost origins (`127.0.0.1:5173`, `localhost:8000`) |
| **THREAT-12-API-027** | Oversized Graph Injection | Denial of Service | Injecting 10,000 nodes/edges via API to crash graph algorithms | Hard API limits: $\le 500$ assets, $\le 2000$ edges |
| **THREAT-12-API-028** | Recursive Payload Abuse | Denial of Service | Deeply nested JSON payloads designed to cause stack overflow | Pydantic JSON parser depth bounding |
| **THREAT-12-API-029** | Resource Limit Bypass | Tampering | Setting custom config overrides to bypass safety limits | Validation of config bounds in Pydantic models (e.g. `max_depth <= 10`) |
| **THREAT-12-API-030** | API/Domain Semantic Mismatch | Integrity Violation | API recalculating risk using different formula than domain engine | API acts strictly as orchestration boundary, calling frozen domain engines |
