# Phase 12.10 — Universal Risk API & Task Integration Requirements

**Author:** DeepMind Antigravity Pair Programmer  
**Phase:** 12.10 — Universal Risk API & Task Integration  
**Date:** 2026-09-14  
**Status:** Frozen Requirements Specification  

---

## 1. Functional Requirements (REQ-12-API-001 through REQ-12-API-015)

- **REQ-12-API-001 (Task Creation Endpoint):** The API MUST expose `POST /projects/{project_id}/universal/assurance/tasks` returning HTTP `202 Accepted` with initial status `QUEUED` and a unique `task_id`.
- **REQ-12-API-002 (Task Status Endpoint):** The API MUST expose `GET /projects/{project_id}/universal/assurance/tasks/{task_id}` returning HTTP `200 OK` with status, progress percentage, current stage, created timestamp, and started/completed timestamps.
- **REQ-12-API-003 (Task Result Endpoint):** The API MUST expose `GET /projects/{project_id}/universal/assurance/tasks/{task_id}/result` returning the completed `UniversalAssuranceResultResponse`, or HTTP `409 Conflict` if the task is not in `COMPLETED` state.
- **REQ-12-API-004 (Task Cancellation Endpoint):** The API MUST expose `POST /projects/{project_id}/universal/assurance/tasks/{task_id}/cancel` allowing cooperative cancellation of queued or running tasks.
- **REQ-12-API-005 (SSE Progress Streaming):** The API MUST expose `GET /projects/{project_id}/universal/assurance/tasks/{task_id}/events` streaming Server-Sent Events with discrete stage transitions and progress updates.
- **REQ-12-API-006 (Risk Retrieval Endpoint):** The API MUST expose `GET /projects/{project_id}/universal/risk/{risk_id}` returning the stored Phase 12.6 `UniversalRiskAssessment` or `AssetRiskAssessment` without recomputing risk.
- **REQ-12-API-007 (Decision Retrieval Endpoint):** The API MUST expose `GET /projects/{project_id}/universal/decisions/{decision_id}` returning the stored Phase 12.7 `UniversalDecisionAssessment` without re-evaluating policy.
- **REQ-12-API-008 (Proof Retrieval Endpoint):** The API MUST expose `GET /projects/{project_id}/universal/proof/{proof_id}` returning the stored Phase 12.8 `UniversalProofAssessment` without re-running cryptographic verification.
- **REQ-12-API-009 (Project Aggregation Endpoint):** The API MUST expose `GET /projects/{project_id}/universal/aggregation` returning the stored Phase 12.9 `HierarchicalRiskAssessment` without re-running DAG aggregation.
- **REQ-12-API-010 (Capabilities Endpoint):** The API MUST expose `GET /projects/{project_id}/universal/capabilities` returning supported analysis types, subsystems, and governance ceilings.
- **REQ-12-API-011 (Orchestration Integrity):** The API layer MUST orchestrate underlying domain services (Phases 12.2–12.9) and MUST NOT duplicate or re-implement domain mathematics or algorithms.
- **REQ-12-API-012 (No-Recomputation Guarantee):** HTTP GET operations MUST strictly return stored/cached results and NEVER execute the analytical pipeline.
- **REQ-12-API-013 (Idempotency Fingerprinting):** The service MUST compute deterministic RFC 8785 JCS + SHA-256 request fingerprints to prevent duplicate redundant task execution on identical inputs.
- **REQ-12-API-014 (Task State Machine):** The task runner MUST strictly enforce valid state transitions: `QUEUED` $\to$ `RUNNING` $\to$ `COMPLETED` / `FAILED` / `CANCELLED`.
- **REQ-12-API-015 (Standardized API Envelope):** All API responses MUST be wrapped in the standard `ApiResponse[T]` envelope containing `status`, `data`, and `meta` (ISO timestamp and request ID).

---

## 2. Security & Governance Requirements (REQ-12-API-016 through REQ-12-API-025)

- **REQ-12-API-016 (BOLA / Project Tenant Isolation):** The API MUST verify project tenancy on every request. Querying a resource belonging to project $P_B$ from project $P_A$ context MUST return HTTP `404 Not Found`.
- **REQ-12-API-017 (Safe Input Boundaries):** All path parameters, asset IDs, and artifact references MUST be sanitized against path traversal (`..`, absolute paths) and illegal characters.
- **REQ-12-API-018 (Deterministic Error Mapping):** Domain exceptions (`ScopeMismatchError`, `DependencyCycleError`, `InvalidAssetRiskError`, etc.) MUST map to sanitized HTTP status codes (`400`, `404`, `409`, `422`) without leaking internal stack traces.
- **REQ-12-API-019 (Secret Material Protection):** API responses MUST NEVER expose private keys, cryptographic secrets, or database connection strings.
- **REQ-12-API-020 (Cryptographic Content Addressing):** API responses MUST preserve authoritative content hashes (`risk_hash`, `decision_hash`, `proof_result_hash`, `aggregation_hash`) without alteration.
- **REQ-12-API-021 (Resource Ceilings):** The API MUST enforce hard resource limits: $\le 500$ assets, $\le 2,000$ dependency edges, $\le 10\text{MB}$ payload size, $\le 4$ concurrent workers.
- **REQ-12-API-022 (Offline Air-Gap Invariant):** The API and task runner MUST execute 100% offline with zero cloud, network, or external telemetry dependencies.
- **REQ-12-API-023 (Pydantic V2 Schema Validation):** All request and response schemas MUST be implemented as frozen/validated Pydantic V2 models.
- **REQ-12-API-024 (Zero Frozen Phase Modifications):** Phase 12.10 MUST NOT modify any production files from Phases 0–11 or Phases 12.1–12.9.
- **REQ-12-API-025 (Full Non-Regression):** The complete repository test suite MUST maintain a 100% pass rate with zero errors or regressions.
