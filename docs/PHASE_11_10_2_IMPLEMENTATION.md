# Phase 11.10.2: API & Task Integration — Implementation Specification

## 1. Executive Summary

Phase 11.10.2 delivers the complete production implementation of the API and Task Orchestration layer for the AIVARA distribution shift subsystem (Phases 11.2–11.9).

The architecture adheres strictly to the frozen specifications in `docs/PHASE_11_10_API_ARCHITECTURE.md`, `docs/PHASE_11_10_TASK_STATE_MACHINE.md`, `docs/PHASE_11_10_API_CONTRACTS.md`, `docs/PHASE_11_10_REQUIREMENTS.md`, `docs/PHASE_11_10_THREAT_MODEL.md`, and `ADR-103`.

---

## 2. Implemented Components

### 2.1 Pydantic V2 Request & Response Contracts (`backend/aivara/api/schemas/drift.py`)
- **`DriftAnalysisTypeEnum`**: `DATASET`, `FEATURE`, `IMAGE`, `REPRESENTATION`, `TEMPORAL`, `SOURCE`, `MULTIMODAL`.
- **`DriftTaskStatusEnum`**: `QUEUED`, `RUNNING`, `CANCEL_REQUESTED`, `CANCELLED`, `COMPLETED`, `FAILED`.
- **`DriftAnalysisCreateRequest`**: Strict validation with `extra="forbid"`, finite float checks (rejection of `NaN`/`Inf`), bounded sample sizes ($[30, 5000]$), bounded significance levels ($[0.001, 0.20]$), and deterministic RFC 8785 JCS request fingerprinting via SHA-256.
- **`TemporalAnalysisConfig`**, **`SourceAnalysisConfig`**, **`RepresentationAnalysisConfig`**, **`MultiModalAssuranceConfig`**: Strongly typed sub-configurations with finite bound validation.
- **`DriftTaskResponse`**: Task status container with execution timestamps, stage descriptors, and request fingerprints.
- **`DriftProgressEvent`**: SSE event payload model featuring strictly monotonic `sequence_number`, unique `event_id`, lifecycle `stage`, and `progress_percent`.
- **`DriftAnalysisResultResponse`**: Full analytical result envelope providing dataset and analysis identities, feature-level summaries, synthesized findings, assurance profile, risk metrics, and non-attribution observational rationale.
- **`DriftCapabilitiesResponse`**: Informational static discovery endpoint model (`GET /api/v1/projects/{project_id}/drift/capabilities`).

### 2.2 FastAPI Router (`backend/aivara/api/routers/drift.py`)
- **`POST /api/v1/projects/{project_id}/drift/analyses`**: Initiates asynchronous analysis, returns HTTP `202 Accepted` (or HTTP `200 OK` on idempotent cache hit).
- **`GET /api/v1/projects/{project_id}/drift/analyses/{analysis_id}`**: Retrieves task execution state, returning HTTP `200 OK`. Enforces object-level authorization (BOLA) and returns HTTP `404 Not Found` if the project ID does not match.
- **`GET /api/v1/projects/{project_id}/drift/analyses/{analysis_id}/result`**: Retrieves full analytical results and assurance profiles once completed. Returns HTTP `409 Conflict` (`ANALYSIS_NOT_COMPLETED` or `ANALYSIS_FAILED` or `ANALYSIS_CANCELLED`) if requested prematurely.
- **`POST /api/v1/projects/{project_id}/drift/analyses/{analysis_id}/cancel`**: Initiates cooperative task cancellation. Rejects redundant cancellation requests on terminal tasks with HTTP `409 Conflict`.
- **`GET /api/v1/projects/{project_id}/drift/analyses/{analysis_id}/events`**: Real-time Server-Sent Events (SSE) stream (`text/event-stream`). Supports historical replay via the `Last-Event-ID` header and automatic connection teardown upon reaching terminal lifecycle states.
- **`GET /api/v1/projects/{project_id}/drift/capabilities`**: Static capabilities discovery endpoint returning supported analysis types, statistical methods, and resource limits.

### 2.3 Task State Machine & Orchestrator (`backend/aivara/services/drift_service.py`)
- **`DriftTask`**: Thread-safe in-memory task container with reentrant locking, lifecycle stage tracking, cooperative cancellation sentinel (`_is_cancelled`), rolling 50-event history buffer for SSE reconnect replay, and real-time subscriber queue distribution.
- **`DriftTaskManager`**: Singleton task registry managing concurrent task lifecycle states, idempotency key indexation with conflict detection, and background dispatch via a dedicated 4-worker `ThreadPoolExecutor`.
- **`DriftService`**: Authoritative domain orchestrator coordinating population boundary validation (Phase 11.2), statistical hypothesis testing (Phases 11.3–11.8), multi-modal assurance and risk synthesis (Phase 11.9), and non-attribution rationale generation.

---

## 3. Strict Compliance & Invariants

1. **No Calculation at the API Boundary**: The router and service perform zero statistical testing, FDR corrections, or risk computations; all mathematical authority is delegated to the frozen domain engines.
2. **Deterministic Request Fingerprinting**: Request fingerprints are computed strictly via RFC 8785 JCS canonicalization over request parameters, excluding operational timestamps and tenant identifiers.
3. **Multi-Tenant Isolation (BOLA Masking)**: Cross-project access attempts return uniform HTTP `404 Not Found` errors without disclosing whether the resource exists in another project.
4. **Cooperative Cancellation**: Tasks periodically check the cancellation sentinel and gracefully transition through `CANCEL_REQUESTED` to `CANCELLED` without leaving corrupt records.
5. **Zero Migrations & Air-Gapped Execution**: 0 database schema changes, 0 external network requests, and 0 new dependencies.
