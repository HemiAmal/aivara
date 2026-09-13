# Phase 11.10: API & Task Integration — Functional & Non-Functional Requirements

## 1. Specification Framework
This document defines the formal, testable requirements for Phase 11.10 API & Task Orchestration. Requirements are grouped by functional domain and tagged with explicit verification criteria.

---

## 2. Requirements Matrix (55 Formal Requirements)

### 2.1 API Surface & Router Architecture
- **REQ-11.10-001**: The system MUST expose a dedicated FastAPI APIRouter under prefix `/api/v1/projects/{project_id}/drift`.
- **REQ-11.10-002**: All API endpoints MUST wrap responses in the canonical `ApiResponse[T]` envelope with metadata (`request_id`, `timestamp`, `version`).
- **REQ-11.10-003**: The API layer MUST act strictly as an orchestration boundary and MUST NOT perform any independent statistical, risk, or proof calculations.
- **REQ-11.10-004**: The system MUST support `POST /api/v1/projects/{project_id}/drift/analyses` to initiate asynchronous distribution shift analysis, returning HTTP `202 Accepted`.
- **REQ-11.10-005**: The system MUST support `GET /api/v1/projects/{project_id}/drift/analyses/{analysis_id}` to retrieve current task execution status and progress, returning HTTP `200 OK`.
- **REQ-11.10-006**: The system MUST support `GET /api/v1/projects/{project_id}/drift/analyses/{analysis_id}/result` to retrieve the complete analytical findings and assurance profile once completed, returning HTTP `200 OK`.
- **REQ-11.10-007**: Attempting to retrieve results for a task that is not in `COMPLETED` state MUST return HTTP `409 Conflict` with error code `ANALYSIS_NOT_COMPLETED`.
- **REQ-11.10-008**: The system MUST support `POST /api/v1/projects/{project_id}/drift/analyses/{analysis_id}/cancel` to trigger cooperative task cancellation.
- **REQ-11.10-009**: The system MUST support `GET /api/v1/projects/{project_id}/drift/analyses/{analysis_id}/events` via Server-Sent Events (`text/event-stream`).
- **REQ-11.10-010**: The system MUST expose `GET /api/v1/projects/{project_id}/drift/capabilities` detailing supported analysis types, statistical methods, resource ceilings, and schema versions.

### 2.2 Analysis Types & Modality Dispatch
- **REQ-11.10-011**: The API MUST accept an explicit `analysis_type` enum spanning: `DATASET`, `FEATURE`, `IMAGE`, `REPRESENTATION`, `TEMPORAL`, `SOURCE`, and `MULTIMODAL`.
- **REQ-11.10-012**: When `analysis_type="DATASET"`, the task MUST delegate to Phase 11.4 `FeatureDatasetDriftAnalyzer` evaluating dataset-wide multivariate and categorical shift.
- **REQ-11.10-013**: When `analysis_type="FEATURE"`, the task MUST delegate to Phase 11.4 `FeatureDatasetDriftAnalyzer` with explicit univariate feature filtering.
- **REQ-11.10-014**: When `analysis_type="IMAGE"`, the task MUST delegate to Phase 11.5 `ImageDistributionShiftAnalyzer` over image descriptors (brightness, contrast, sharpness, color balance).
- **REQ-11.10-015**: When `analysis_type="REPRESENTATION"`, the task MUST delegate to Phase 11.6 `RepresentationDistributionShiftAnalyzer` with L2-normalized embeddings and MMD/Energy tests.
- **REQ-11.10-016**: When `analysis_type="TEMPORAL"`, the task MUST delegate to Phase 11.7 `TemporalDriftEngine` evaluating baseline-to-window and adjacent-window trajectories.
- **REQ-11.10-017**: When `analysis_type="SOURCE"`, the task MUST delegate to Phase 11.8 `SourceDriftEngine` evaluating $O(G)$ source-versus-reference population shifts.
- **REQ-11.10-018**: When `analysis_type="MULTIMODAL"`, the task MUST orchestrate the required sub-analyzers and synthesize evidence via Phase 11.9 `MultiModalRiskIntegrationEngine`.

### 2.3 Task State Machine & Concurrency
- **REQ-11.10-019**: The task state machine MUST implement the exact lifecycle states: `QUEUED`, `RUNNING`, `CANCEL_REQUESTED`, `CANCELLED`, `COMPLETED`, and `FAILED`.
- **REQ-11.10-020**: State transitions MUST be thread-safe and guarded by reentrant synchronization locks.
- **REQ-11.10-021**: Direct transitions from terminal states (`COMPLETED`, `FAILED`, `CANCELLED`) to any other state MUST be strictly prohibited.
- **REQ-11.10-022**: The task runner MUST execute analytical jobs in a dedicated `ThreadPoolExecutor` with a default concurrency cap of 4 worker threads.
- **REQ-11.10-023**: When cooperative cancellation is requested (`CANCEL_REQUESTED`), the executing engine MUST check the cancellation sentinel at loop boundaries and gracefully transition to `CANCELLED`.
- **REQ-11.10-024**: Cancellation MUST NOT leave uncommitted partial findings or corrupted records in SQLite.
- **REQ-11.10-025**: An execution error in an underlying engine MUST transition the task to `FAILED` with sanitized error details, without crashing the worker thread or event loop.

### 2.4 Server-Sent Events (SSE) & Progress Streaming
- **REQ-11.10-026**: SSE progress events MUST format messages as `event: progress\ndata: {JSON}\n\n`.
- **REQ-11.10-027**: Every progress event MUST include a strictly monotonic integer `sequence_number` (1, 2, 3, ...).
- **REQ-11.10-028**: Progress events MUST emit standard lifecycle stages: `POPULATION_BOUNDARY`, `STATISTICAL_ANALYSIS`, `PROFILE_SYNTHESIS`, `RISK_INTEGRATION`, `FINALIZATION`.
- **REQ-11.10-029**: SSE streams MUST emit periodic keepalive comments (`: ping\n\n`) every 30 seconds of inactivity.
- **REQ-11.10-030**: When the task reaches a terminal state (`COMPLETED`, `FAILED`, `CANCELLED`), the SSE stream MUST emit the terminal event and cleanly close the connection.
- **REQ-11.10-031**: In-memory task instances MUST buffer the last 50 progress events to support replay upon client reconnection via `Last-Event-ID`.

### 2.5 Request Contracts & Deterministic Fingerprinting
- **REQ-11.10-032**: All request payloads MUST validate via Pydantic V2 models with `extra="forbid"`.
- **REQ-11.10-033**: Numerical request parameters MUST reject `NaN` and `Inf` values and enforce finite bounds ($[0.0, 1.0]$ for confidence/significance, $[30, 5000]$ for sample budgets).
- **REQ-11.10-034**: The system MUST compute a deterministic `request_fingerprint` over the canonical request dictionary using RFC 8785 JCS + SHA-256.
- **REQ-11.10-035**: The `request_fingerprint` MUST exclude nondeterministic operational metadata (such as timestamps, request IDs, and client IP addresses).

### 2.6 Idempotency Semantics
- **REQ-11.10-036**: The API MUST accept an optional `Idempotency-Key` HTTP header (or request body field).
- **REQ-11.10-037**: Submitting a request with an existing `(project_id, idempotency_key)` and identical `request_fingerprint` MUST return the existing task with HTTP `200 OK` or `202 Accepted`.
- **REQ-11.10-038**: Submitting a request with an existing `(project_id, idempotency_key)` but a mismatched `request_fingerprint` MUST return HTTP `409 Conflict` with error code `IDEMPOTENCY_CONFLICT`.

### 2.7 Project & Object-Level Authorization
- **REQ-11.10-039**: Every API request MUST enforce strict project isolation (`project_id` matching).
- **REQ-11.10-040**: If a requested `analysis_id` does not belong to the route's `project_id`, the API MUST return HTTP `404 Not Found` without disclosing the task's existence.
- **REQ-11.10-041**: Cross-project dataset references in request payloads MUST be rejected with HTTP `404 Not Found` or `400 Bad Request`.

### 2.8 Error Handling & Canonical Error Envelopes
- **REQ-11.10-042**: All API error responses MUST follow the standard `ApiErrorResponse` model with `status: "error"`, `error.code`, `error.message`, and `error.details`.
- **REQ-11.10-043**: Error responses MUST NOT expose internal stack traces, SQLite database paths, filesystem paths, or memory addresses.
- **REQ-11.10-044**: Known analytical domain exceptions (`IncompatiblePopulationError`, `InsufficientDataError`, `ProjectMismatchError`, `ResourceLimitExceededError`) MUST map to specific HTTP status codes (400, 422, 403, 429).

### 2.9 Non-Attribution & Assurance Semantics
- **REQ-11.10-045**: The API response models MUST preserve the distinction between `EvidenceLayer.PROOF` and `EvidenceLayer.DETECTION`.
- **REQ-11.10-046**: API responses MUST NOT use accusatory language, claims of malicious contributor intent, or uncalibrated attack probabilities.
- **REQ-11.10-047**: An `ACCEPT` disposition returned in the API MUST be documented strictly as operational baseline tolerance under the active policy, never as proof of absolute safety.
- **REQ-11.10-048**: Insufficient evidence coverage MUST be explicitly indicated via `evaluation_status="INSUFFICIENT_DATA"` and routed to `disposition="REVIEW"`.

### 2.10 Security, Privacy, Offline, & Zero-Migration Governance
- **REQ-11.10-049**: The API and task infrastructure MUST run 100% offline without external network or DNS calls.
- **REQ-11.10-050**: The implementation MUST NOT introduce any new third-party package dependencies.
- **REQ-11.10-051**: The implementation MUST NOT introduce any database schema migrations or modify existing SQLite tables.
- **REQ-11.10-052**: Source-aware distribution shift responses MUST only expose project-scoped pseudonymized identifiers (`source_group_id`), never raw PII.
- **REQ-11.10-053**: AST security scans across Phase 11.10 code MUST report 0 forbidden constructs (`eval`, `exec`, `pickle`, `subprocess`, `os.system`).
- **REQ-11.10-054**: Phase 11.10 MUST NOT modify or regress any frozen Phase 0–10 or Phase 11.1–11.9 implementations.
- **REQ-11.10-055**: The complete repository test suite MUST maintain 100% pass rate upon Phase 11.10 completion.
