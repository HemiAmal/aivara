# Phase 8.8 — REST API & Integration Architecture

## 1. Executive Summary

Phase 8.8 exposes AIVARA's frozen Behavioral Analysis pipeline (Phases 8.2–8.7) via a secure, typed, project-isolated, offline FastAPI REST API. The design maintains a strict separation of concerns:
- **Routers remain thin**: HTTP validation, project boundary checks, dependency injection, and typed envelope serialization.
- **Service Layer**: `BehavioralService` and `BehavioralTaskManager` coordinate the underlying domain engines without modifying them.
- **Domain Logic**: 100% frozen execution (Phases 8.2–8.7).
- **Zero Database Schema Changes**: Leverages existing `ProjectModel`, `AIModelModel`, `FindingModel`, `EvidenceModel`, `ProvenanceRecordModel`, and `AuditEventModel`.
- **Offline & Safe**: Local in-memory task runner, SSE progress streaming, cooperative cancellation, and RFC 8785 JCS + SHA-256 idempotency.

---

## 2. API Architecture & Layering

```
               [ HTTP / Client Request ]
                          │
                          ▼
            [ FastAPI Router (Thin Layer) ]
            - Endpoint routing & tags
            - Request / Header validation
            - Dependency injection (db, key_manager, behavioral_service)
                          │
                          ▼
            [ BehavioralService / Task Manager ]
            - Multi-tenant Project Isolation check
            - Idempotency key caching / resolution
            - Task orchestration (Sync / Async via ThreadPoolExecutor)
            - Real-time SSE event queuing
                          │
     ┌────────────────────┼────────────────────┬────────────────────┐
     ▼                    ▼                    ▼                    ▼
[ Phase 8.2 ]        [ Phase 8.3 ]        [ Phase 8.4 ]        [ Phase 8.5 ]
Controlled Exec      Baseline Engine     Perturbations        Output Stability
     │                    │                    │                    │
     └────────────────────┴─────────┬──────────┴────────────────────┘
                                    ▼
                             [ Phase 8.6 ]
                         Anomaly Detection
                                    │
                                    ▼
                             [ Phase 8.7 ]
                       Evidence & Provenance
                                    │
                                    ▼
                   [ Phase 4 Cryptographic Ledger ]
                   - RFC 8785 Canonical JCS
                   - SHA-256 Hashing
                   - Ed25519 Detached Signatures
                   - Monotonic Hash Chain & Audit Log
```

---

## 3. Resource Model & Endpoint Mapping

All behavioral endpoints are strictly project-scoped under `/api/v1/projects/{project_id}/behavioral/...`.

| HTTP Method | Route Path | Purpose | Service Method | Sync / Async |
|---|---|---|---|---|
| `POST` | `/projects/{project_id}/behavioral/baselines` | Create / compute behavioral baseline profile | `service.create_baseline(...)` | Sync |
| `GET` | `/projects/{project_id}/behavioral/baselines/{baseline_id}` | Retrieve stored behavioral baseline | `service.get_baseline(...)` | Sync |
| `POST` | `/projects/{project_id}/behavioral/baselines/{baseline_id}/compare` | Compare observation against baseline | `service.compare_baseline(...)` | Sync |
| `POST` | `/projects/{project_id}/behavioral/perturbations/experiment` | Execute deterministic perturbation experiment | `service.run_perturbation_experiment(...)` | Sync |
| `POST` | `/projects/{project_id}/behavioral/stability/repeatability` | Measure repeatability across identical executions | `service.analyze_repeatability(...)` | Sync |
| `POST` | `/projects/{project_id}/behavioral/stability/sensitivity` | Measure input perturbation sensitivity ratio | `service.analyze_sensitivity(...)` | Sync |
| `POST` | `/projects/{project_id}/behavioral/stability/compare` | Evaluate output consistency against reference model | `service.compare_stability(...)` | Sync |
| `POST` | `/projects/{project_id}/behavioral/anomalies/detect` | Execute statistical anomaly detection against baseline | `service.detect_anomalies(...)` | Sync |
| `GET` | `/projects/{project_id}/behavioral/anomalies/{analysis_id}` | Retrieve stored anomaly analysis | `service.get_anomaly_analysis(...)` | Sync |
| `POST` | `/projects/{project_id}/behavioral/evidence/bind` | Synthesize findings and bind sealed cryptographic evidence | `service.bind_evidence(...)` | Sync |
| `GET` | `/projects/{project_id}/behavioral/evidence/{evidence_id}` | Retrieve sealed evidence item | `service.get_evidence(...)` | Sync |
| `GET` | `/projects/{project_id}/behavioral/provenance/{target_id}` | Verify cryptographic provenance of behavioral commitments | `service.verify_provenance(...)` | Sync |
| `POST` | `/projects/{project_id}/behavioral/assessments` | Submit integrated behavioral assessment workflow | `service.create_and_start_assessment(...)` | Sync / Async |
| `GET` | `/projects/{project_id}/behavioral/tasks/{task_id}` | Retrieve task execution status and summary | `service.get_task(...)` | Sync |
| `GET` | `/projects/{project_id}/behavioral/tasks` | List active/recent tasks for project | `service.list_tasks(...)` | Sync |
| `POST` | `/projects/{project_id}/behavioral/tasks/{task_id}/cancel` | Request cooperative task cancellation | `service.cancel_task(...)` | Sync |
| `GET` | `/projects/{project_id}/behavioral/tasks/{task_id}/events` | Stream real-time SSE progress events | `service.stream_task_events(...)` | SSE (Async) |

---

## 4. Schemas & Contract Design

New Pydantic schemas in `backend/aivara/api/schemas/behavioral.py`:
- **Baselines**: `BaselineCreateRequest`, `BaselineReadResponse`, `BaselineCompareRequest`, `BaselineCompareResponse`
- **Perturbations**: `PerturbationExperimentRequest`, `PerturbationExperimentResponse`
- **Stability**: `RepeatabilityAnalysisRequest`, `RepeatabilityAnalysisResponse`, `SensitivityAnalysisRequest`, `SensitivityAnalysisResponse`, `StabilityCompareRequest`, `StabilityCompareResponse`
- **Anomalies**: `AnomalyDetectionRequest`, `AnomalyDetectionResponse`
- **Evidence & Findings**: `BehavioralEvidenceBindRequest`, `BehavioralEvidenceBindResponse`, `BehavioralEvidenceReadResponse`
- **Provenance Verification**: `BehavioralProvenanceVerificationResponse`
- **Integrated Assessment & Tasks**: `BehavioralAssessmentRequest`, `BehavioralAssessmentResponse`, `BehavioralTaskReadResponse`, `BehavioralProgressEvent`

All response bodies are wrapped in `ApiResponse[T]` to conform to the platform API standard.

---

## 5. Security & Isolation Boundaries

1. **Multi-Tenant Project Isolation**:
   - Every route path contains `{project_id}`.
   - The service layer retrieves models and assets within the project and rejects foreign resources with `CrossProjectContaminationError` (mapped to HTTP 422/403).
2. **Filesystem Sandbox**:
   - Model artifact paths must be validated via `validate_secure_model_path()` against allowed root directories.
   - Directory traversal (`..`), UNC paths, and symlink escapes are strictly prohibited.
3. **No Code Execution / Subprocess Execution**:
   - Model inference executes strictly within the controlled in-process ONNX Runtime boundary.
   - No dynamic `eval()`, `exec()`, pickle loading, or arbitrary shell calls.
4. **Offline & Air-Gapped**:
   - Zero external HTTP calls or telemetry.
   - All cryptographic keys and signatures managed locally via `KeyManager`.
5. **Semantic Safety Invariant**:
   - `ANOMALOUS ≠ MALICIOUS`.
   - The API will never generate, infer, or output terms like `MALICIOUS`, `BACKDOOR`, `COMPROMISED`, or `ATTACK`.

---

## 6. Task Management, SSE, and Cancellation

- **In-Memory Task Manager**: `BehavioralTaskManager` singleton manages threads via `ThreadPoolExecutor(max_workers=4)`.
- **Task Lifecycle**: `QUEUED` → `RUNNING` → `COMPLETED` / `FAILED` / `CANCELLED` / `IDEMPOTENT_HIT`.
- **SSE Streaming**: Clients connect to `/tasks/{task_id}/events` with `Accept: text/event-stream`. Periodic keep-alive comments prevent proxy timeouts.
- **Cooperative Cancellation**: Tasks periodically inspect `task.is_cancelled` between pipeline stages to abort gracefully without process corruption.
