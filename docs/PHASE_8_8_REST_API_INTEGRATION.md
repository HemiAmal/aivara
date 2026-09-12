# Phase 8.8 — REST API & Integration Specification

**Phase**: 8.8 (Behavioral Analysis REST API & Pipeline Integration)  
**Status**: COMPLETE & FROZEN  
**Test Suite**: `tests/test_behavioral_api.py` (51/51 tests passing, 100% pass rate)  
**Phase 8 Behavioral Tests**: 256/256 passing across Phases 8.2–8.8  
**Full Repository Regression**: 1,328/1,328 tests passing repository-wide  

---

## 1. Overview & Objectives

Phase 8.8 is the final phase of Phase 8 in the AIVARA (AI Verification & Assurance) platform. It exposes the frozen behavioral analysis domain pipeline (Phases 8.2 through 8.7) via a secure, typed, project-isolated, 100% offline FastAPI REST interface.

### Architectural Principles
1. **Thin Router Layer**: HTTP endpoints perform parameter extraction, header handling, schema validation, and envelope wrapping (`ApiResponse[T]`), delegating all business logic to `BehavioralService`.
2. **Zero Domain Modifications**: Phases 8.2–8.7 domain engines (Runtime, Baselines, Perturbations, Stability, Anomaly Detection, Evidence & Provenance) are strictly preserved and untouched.
3. **Zero Database Schema Migrations**: Operates completely within existing Phase 1–5 tables (`ProjectModel`, `AIModelModel`, `FindingModel`, `EvidenceModel`, `ProvenanceRecordModel`, `AuditEventModel`).
4. **Project Isolation**: Every endpoint enforces strict project boundaries under `/api/v1/projects/{project_id}/behavioral/...`. Access across projects immediately yields HTTP 403 / 404 / 422 with `CrossProjectContaminationError` / `NotFoundException`.
5. **Deterministic Idempotency**: Tasks and assessments accept optional `Idempotency-Key` headers. Cached tasks are matched on `(project_id, idempotency_key)` to avoid redundant computations; conflicting payloads consistently return HTTP 409 (`IDEMPOTENCY_CONFLICT_ERROR`).
6. **100% Offline Task Orchestration**: In-process thread pool task manager (`BehavioralTaskManager`), cooperative cancellation tokens, and SSE progress broadcasting (`text/event-stream`).
7. **Strict Semantic Neutrality**: Enforces `ANOMALOUS ≠ MALICIOUS`. Analysis findings, descriptions, and audit logs never generate malicious intent assertions.

---

## 2. Implemented REST Endpoints

All behavioral endpoints are mounted under the prefix:
`/api/v1/projects/{project_id}/behavioral`

| # | Method | Path | Summary | Schema |
|---|--------|------|---------|--------|
| 1 | `POST` | `/baselines` | Create behavioral baseline profile | `BaselineCreateRequest` -> `BaselineReadResponse` |
| 2 | `GET` | `/baselines/{baseline_id}` | Retrieve stored baseline profile | `BaselineReadResponse` |
| 3 | `POST` | `/baselines/{baseline_id}/compare` | Compare observation against baseline | `BaselineCompareRequest` -> `BaselineCompareResponse` |
| 4 | `POST` | `/perturbations/experiment` | Run controlled perturbation experiment | `PerturbationExperimentRequest` -> `PerturbationExperimentResponse` |
| 5 | `POST` | `/stability/repeatability` | Evaluate repeatability / determinism | `RepeatabilityAnalysisRequest` -> `RepeatabilityAnalysisResponse` |
| 6 | `POST` | `/stability/sensitivity` | Compute input-output sensitivity ratio | `SensitivityAnalysisRequest` -> `SensitivityAnalysisResponse` |
| 7 | `POST` | `/stability/compare` | Compare candidate vs reference model | `StabilityCompareRequest` -> `StabilityCompareResponse` |
| 8 | `POST` | `/anomalies/detect` | Run statistical anomaly detection | `AnomalyDetectionRequest` -> `AnomalyDetectionResponse` |
| 9 | `GET` | `/anomalies/{analysis_id}` | Retrieve anomaly detection analysis | `AnomalyDetectionResponse` |
| 10 | `POST` | `/evidence/bind` | Synthesize finding & seal provenance | `BehavioralEvidenceBindRequest` -> `BehavioralEvidenceBindResponse` |
| 11 | `GET` | `/evidence/{evidence_id}` | Retrieve immutable evidence item | `BehavioralEvidenceReadResponse` |
| 12 | `GET` | `/provenance/{target_id}` | Verify cryptographic provenance ledger | `BehavioralProvenanceVerificationResponse` |
| 13 | `POST` | `/assessments` | Run end-to-end integrated assessment | `BehavioralAssessmentRequest` -> `BehavioralAssessmentResponse` or `BehavioralTaskReadResponse` |
| 14 | `GET` | `/tasks/{task_id}` | Get async task status and progress | `BehavioralTaskReadResponse` |
| 15 | `GET` | `/tasks` | List in-memory tasks for project | `List[BehavioralTaskReadResponse]` |
| 16 | `POST` | `/tasks/{task_id}/cancel` | Cooperatively cancel queued/running task | `BehavioralTaskReadResponse` |
| 17 | `GET` | `/tasks/{task_id}/events` | Real-time SSE progress stream | `text/event-stream` (`BehavioralProgressEvent`) |

---

## 3. Component Reference

### 3.1 Pydantic Schemas (`backend/aivara/api/schemas/behavioral.py`)
- `BaselineCreateRequest`, `BaselineReadResponse`, `BaselineCompareRequest`, `BaselineCompareResponse`
- `PerturbationExperimentRequest`, `PerturbationExperimentResponse`
- `RepeatabilityAnalysisRequest`, `RepeatabilityAnalysisResponse`, `SensitivityAnalysisRequest`, `SensitivityAnalysisResponse`, `StabilityCompareRequest`, `StabilityCompareResponse`
- `AnomalyDetectionRequest`, `AnomalyDetectionResponse`
- `BehavioralEvidenceBindRequest`, `BehavioralEvidenceBindResponse`, `BehavioralEvidenceReadResponse`
- `BehavioralProvenanceVerificationResponse`, `BehavioralAssessmentRequest`, `BehavioralAssessmentResponse`, `BehavioralTaskReadResponse`
- Non-finite float validators rejecting `NaN`, `+Infinity`, `-Infinity` with structured HTTP 422 responses.

### 3.2 Service Layer (`backend/aivara/services/behavioral_service.py`)
- `BehavioralService`: Orchestrates domain calls, checks project isolation, translates observation formats into domain tensors/results, builds RFC 8785 evidence, signs provenance records via `KeyManager`, and records audit logs via `AuditService`.
- `BehavioralTaskManager`: Thread-safe, process-level task registry with worker thread pool, cooperative cancellation tokens, idempotency lookup, and subscriber event queues for SSE broadcasting.
- `BehavioralTask`: In-memory task model tracking stage progression (`0% QUEUED`, `15% MODEL_EXECUTION`, `40% STABILITY_ANALYSIS`, `60% ANOMALY_DETECTION`, `85% EVIDENCE_BINDING`, `100% COMPLETED`).

### 3.3 Router (`backend/aivara/api/routers/behavioral.py`)
- Thin router functions registered under `/projects/{project_id}/behavioral`.
- Standardized `ApiResponse[T]` envelope formatting.
- Query param `?async=true` / `?async=false` and `Idempotency-Key` header handling.

### 3.4 Exception Handling (`backend/aivara/api/errors.py`)
- Global registration of behavioral domain errors: `BehavioralError`, `NonFiniteValueError`, `IdempotencyConflictError`, `EvidenceTamperedError`, `InsufficientSupportError`, `CrossProjectBindingError`, `CrossProjectAnalysisError`, `InvalidMetricDataError`.
- Automatic recursive sanitization of non-finite floats and exceptions in `RequestValidationError` handlers.

---

## 4. Verification & Testing

### Test Suite Execution
- **Behavioral API Tests**: `tests/test_behavioral_api.py` (51 test cases, 100% pass)
- **Phase 8 Regression Tests**: `tests/test_behavioral_*.py` (256 test cases, 100% pass)
- **Complete Repository Tests**: `pytest -q` (1,328 test cases, 100% pass, runtime 3m 29s)

### Semantic Safety Verification
- Checked in tests `test_detect_anomalies_normal_result`, `test_detect_anomalies_anomalous_result`, and `test_bind_evidence_and_retrieve`.
- All outputs, explanations, and audit descriptions strictly exclude `MALICIOUS`, `COMPROMISED`, `ATTACK`, `BACKDOOR`.
