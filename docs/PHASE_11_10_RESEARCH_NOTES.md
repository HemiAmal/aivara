# Phase 11.10: API & Task Integration — Research Notes

## 1. Executive Summary
Phase 11.10 establishes the API and task orchestration layer for AIVARA's distribution shift subsystem (Phases 11.2–11.9). This document synthesizes key architectural research across asynchronous job processing, Server-Sent Events (SSE) reconnect mechanics, HTTP idempotency, state machine safety, denial-of-service protections, and non-attribution semantic preservation.

---

## 2. Research Topics & Architectural Findings

### Topic 1: FastAPI Long-Running Task Patterns & In-Process Concurrency
- **Source**: FastAPI Architectural Patterns, ASGI Specification, Python `concurrent.futures.ThreadPoolExecutor`
- **Finding**: Running CPU-bound or I/O-bound statistical and analytical engines directly within FastAPI async event loops causes event loop starvation, degrading health checks and SSE streaming responsiveness. In-process task execution requires dedicated worker thread pools with bounded concurrency.
- **AIVARA Implication**: The distribution shift service must employ a dedicated `ThreadPoolExecutor(max_workers=4, thread_name_prefix="aivara-drift-worker")`. Async route handlers submit jobs to the thread pool and stream progress over thread-safe `asyncio.Queue` structures.
- **Architectural Decision**: Implement `DriftTaskManager` as a thread-safe singleton managing task lifecycle, thread pool submission, and SSE subscriber broadcast queues.

### Topic 2: Asynchronous Job API Design & HTTP Status Semantics
- **Source**: RFC 7231 (HTTP/1.1 Semantics), RFC 9110 (HTTP Semantics), RESTful Asynchronous Task Pattern
- **Finding**: Submitting a long-running analytical task must not block the HTTP client. The initial `POST` request must return `202 Accepted` with a `task_id` and location headers, clearly distinguishing job acceptance from job completion. Polling or SSE endpoints provide live state updates.
- **AIVARA Implication**: `POST /api/v1/projects/{project_id}/drift/analyses` returns `202 Accepted` with an envelope containing `task_id`, `status: "QUEUED"`, and `links`. Once completed, `GET .../result` returns `200 OK` with the canonical result.
- **Architectural Decision**: Adopt `202 Accepted` for asynchronous analysis submission, `200 OK` for status and completed result retrieval, `404 Not Found` for non-existent or cross-project tasks, and `409 Conflict` for state machine or idempotency conflicts.

### Topic 3: Server-Sent Events (SSE) Semantics & Reconnect Resilience
- **Source**: W3C Server-Sent Events Specification, WHATWG HTML Living Standard
- **Finding**: SSE streams over HTTP are vulnerable to intermittent network disconnects. Standard clients automatically reconnect using the `Last-Event-ID` HTTP header. If events are ephemeral without sequence tracking, clients miss critical state transitions.
- **AIVARA Implication**: Drift progress events must include monotonically increasing `sequence_number`, unique `event_id`, authoritative `stage`, `progress_percent`, and sanitized `message`. The task maintains a bounded event history (e.g. 50 events) to replay missed events upon client reconnection with `Last-Event-ID`.
- **Architectural Decision**: Define `DriftProgressEvent` with explicit sequence numbers, keepalive ping intervals (30s), and terminal disconnect detection (`COMPLETED`, `FAILED`, `CANCELLED`).

### Topic 4: Idempotency Key Semantics in Distributed & Multi-Tenant APIs
- **Source**: IETF Draft `draft-ietf-httpapi-idempotency-key-header`, Stripe Idempotency Architecture
- **Finding**: Client retries after network timeouts can trigger duplicate background executions. An idempotency key must bind to the cryptographic fingerprint of the canonical request. If a subsequent request reuses the key with identical parameters, return the existing task; if parameters differ, reject with `409 Conflict` (`IDEMPOTENCY_CONFLICT`).
- **AIVARA Implication**: The API request contract computes a deterministic RFC 8785 JCS + SHA-256 `request_fingerprint`. The task registry stores `(project_id, idempotency_key) -> (task_id, request_fingerprint)`.
- **Architectural Decision**: Guarantee strict idempotency: identical key + identical fingerprint $\to$ return existing task; identical key + mismatched fingerprint $\to$ raise `409 Conflict`.

### Topic 5: Cooperative Cancellation in Air-Gapped Local Runtimes
- **Source**: POSIX Threading Safety, Python Asyncio Cancellation Guidelines
- **Finding**: Forcibly terminating threads in Python via C-extensions or signals risks memory corruption, abandoned locks, and incomplete SQLite transactions. Cancellation must be cooperative.
- **AIVARA Implication**: When `POST .../cancel` is called, the task transitions to `CANCEL_REQUESTED`. Analytical engines (Phases 11.2–11.9) check the cancellation sentinel at safe loop boundaries (between feature tests, window iterations, or source groups). Upon encountering the sentinel, the engine gracefully rolls back partial state and transitions the task to `CANCELLED`.
- **Architectural Decision**: Implement cooperative cancellation with state transitions `RUNNING` $\to$ `CANCEL_REQUESTED` $\to$ `CANCELLED`. If the task has already reached `COMPLETED` or `FAILED`, cancellation returns `409 Conflict`.

### Topic 6: OWASP API Security & Object-Level Authorization (BOLA)
- **Source**: OWASP API Security Top 10 (2023) — API1:2023 Broken Object Level Authorization, API4:2023 Unrestricted Resource Consumption
- **Finding**: Multi-tenant systems must enforce authorization checks before disclosing any task metadata or error details. Returning "Task exists but unauthorized" leaks operational intelligence.
- **AIVARA Implication**: If `task.project_id != request.project_id`, the API returns a generic `404 Not Found` (`ANALYSIS_NOT_FOUND` / `TASK_NOT_FOUND`), completely masking the existence of cross-project tasks.
- **Architectural Decision**: Enforce strict project boundary checks at the router layer before invoking service routines.

### Topic 7: Non-Attribution Semantic Preservation at the API Boundary
- **Source**: AIVARA Core Invariants (ADR-028, ADR-101, ADR-102)
- **Finding**: Upstream consumers (UI, CI/CD, downstream orchestrators) frequently mistake statistical drift metrics for active cyberattacks or malicious tampering.
- **AIVARA Implication**: The API must never expose fields named `is_attack`, `malicious_probability`, or `attacker_id`. All response fields must use descriptive terminology: `drift_impact_level`, `normalized_operational_exposure_index`, `disposition`, and `shift_detected`.
- **Architectural Decision**: The API layer strictly preserves the invariant $\text{Detection} \ne \text{Proof} \ne \text{Malicious Intent}$.

---

## 3. Comparative Matrix: Analytical Engine vs. API Orchestration Layer

| Property | Analytical Engines (Phases 11.2–11.9) | API & Task Layer (Phase 11.10) |
|:---|:---|:---|
| **Primary Responsibility** | Hypothesis testing, FDR control, change-point detection, source partitioning, risk synthesis | Request validation, concurrency control, task lifecycle, SSE broadcasting, HTTP formatting |
| **Statistical Calculations** | Authoritative (KS, PSI, MMD, Energy, Chi-Square, Damping, Sub-additive Risk) | **Zero (Strictly Prohibited)** |
| **Cryptographic Hashing** | Content addresses descriptors and profiles (`RFC 8785 JCS + SHA-256`) | Tracks operational identity (`task_id`, `request_id`) and binds analytical hashes |
| **State Persistence** | Pure functional / in-memory or sealed provenance | In-memory task state registry + SQLite finding/evidence/risk storage |
| **Error Handling** | Mathematical and statistical exceptions | Normalized `ApiResponse[T]` and `ApiErrorResponse` |
