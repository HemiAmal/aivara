# Phase 11.10: API & Task Integration — Architecture Specification

## 1. Architectural Role & Boundary
Phase 11.10 provides the unified FastAPI orchestration and asynchronous task management layer for the frozen Distribution Shift subsystem (Phases 11.2–11.9). 

```
+-------------------------------------------------------------------------+
|                         HTTP / REST & SSE CLIENT                        |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  FASTAPI ROUTER: /api/v1/projects/{id}/drift            |
| - Request validation (Pydantic V2)                                      |
| - Project isolation & Object-level authorization (BOLA)                 |
| - Idempotency key evaluation (RFC 8785 request fingerprint)             |
| - Consistent ApiResponse[T] & ApiErrorResponse wrapping                 |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                    SERVICE LAYER: DriftService                          |
| - Coordinates DriftTaskManager lifecycle                                |
| - Resolves datasets, versions, and populations via Phase 11.2           |
| - Dispatches to specialized Phase 11 analytical engines                 |
| - Persists findings, evidence, risk, and audit events to SQLite         |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  TASK RUNNER: DriftTaskManager                          |
| - Thread-safe in-memory task registry (singleton)                       |
| - Dedicated ThreadPoolExecutor(max_workers=4)                           |
| - State Machine: QUEUED -> RUNNING -> COMPLETED / FAILED / CANCELLED    |
| - Real-time SSE progress broadcast queues & 50-event replay ring buffer |
+-------------------------------------------------------------------------+
                                    |
       +----------------------------+----------------------------+
       |                            |                            |
       v                            v                            v
+--------------+             +--------------+             +--------------+
|  Phase 11.4  |             |  Phase 11.5  |             |  Phase 11.6  |
| Feature/Data |             |  Image Drift |             |  Embedding   |
+--------------+             +--------------+             +--------------+
       |                            |                            |
       +----------------------------+----------------------------+
                                    |
       +----------------------------+----------------------------+
       |                            |                            |
       v                            v                            v
+--------------+             +--------------+             +--------------+
|  Phase 11.7  |             |  Phase 11.8  |             |  Phase 11.9  |
|   Temporal   |             |    Source    |             | Assurance    |
+--------------+             +--------------+             +--------------+
```

---

## 2. API Endpoints Specification

### 2.1 Initiate Drift Analysis
- **Method / Path**: `POST /api/v1/projects/{project_id}/drift/analyses`
- **Description**: Submits an asynchronous distribution shift analysis task.
- **Headers**:
  - `Idempotency-Key` (Optional): String (UUID or alphanumeric token up to 64 chars).
- **Request Body**: `DriftAnalysisCreateRequest`
- **Response**: `202 Accepted` $\to$ `ApiResponse[DriftTaskResponse]`
- **Error Codes**: `INVALID_REQUEST` (400), `INVALID_PROJECT` (404), `INVALID_DATASET` (404), `INCOMPATIBLE_POPULATIONS` (422), `IDEMPOTENCY_CONFLICT` (409), `RESOURCE_LIMIT_EXCEEDED` (429).

### 2.2 Get Analysis Task Status
- **Method / Path**: `GET /api/v1/projects/{project_id}/drift/analyses/{analysis_id}`
- **Description**: Polls the execution status, current stage, and progress percentage of an analysis task.
- **Response**: `200 OK` $\to$ `ApiResponse[DriftTaskResponse]`
- **Error Codes**: `ANALYSIS_NOT_FOUND` (404).

### 2.3 Get Analysis Full Result
- **Method / Path**: `GET /api/v1/projects/{project_id}/drift/analyses/{analysis_id}/result`
- **Description**: Retrieves the completed analytical result, including statistical summaries, synthesized findings, evidence items, and integrated assurance profile.
- **Response**: `200 OK` $\to$ `ApiResponse[DriftAnalysisResultResponse]`
- **Error Codes**: `ANALYSIS_NOT_FOUND` (404), `ANALYSIS_NOT_COMPLETED` (409), `ANALYSIS_FAILED` (409).

### 2.4 Cancel Analysis Task
- **Method / Path**: `POST /api/v1/projects/{project_id}/drift/analyses/{analysis_id}/cancel`
- **Description**: Requests cooperative cancellation of an in-flight analysis.
- **Response**: `200 OK` $\to$ `ApiResponse[DriftTaskResponse]`
- **Error Codes**: `ANALYSIS_NOT_FOUND` (404), `CANCELLATION_CONFLICT` (409 if already completed or cancelled).

### 2.5 Subscribe to Real-Time Progress Events (SSE)
- **Method / Path**: `GET /api/v1/projects/{project_id}/drift/analyses/{analysis_id}/events`
- **Description**: Opens an HTTP `text/event-stream` connection streaming real-time progress events.
- **Headers**:
  - `Last-Event-ID` (Optional): Replays missed events starting after this sequence ID.
- **Response**: `200 OK` with `media_type="text/event-stream"`.

### 2.6 Get Drift Subsystem Capabilities
- **Method / Path**: `GET /api/v1/projects/{project_id}/drift/capabilities`
- **Description**: Returns static, informational capability descriptors for the distribution shift subsystem.
- **Response**: `200 OK` $\to$ `ApiResponse[DriftCapabilitiesResponse]`.

---

## 3. Idempotency & Cryptographic Request Fingerprinting

1. **Fingerprint Computation**:
   ```python
   canonical_payload = {
       "analysis_type": request.analysis_type.value,
       "feature_names": sorted(request.feature_names or []),
       "method_overrides": {k: str(v) for k, v in sorted((request.method_overrides or {}).items())},
       "multimodal_config": request.multimodal_config.to_canonical_dict() if request.multimodal_config else None,
       "project_id": project_id,
       "reference_dataset_id": request.reference_dataset_id,
       "reference_dataset_version_id": request.reference_dataset_version_id,
       "representation_config": request.representation_config.to_canonical_dict() if request.representation_config else None,
       "source_config": request.source_config.to_canonical_dict() if request.source_config else None,
       "target_dataset_id": request.target_dataset_id,
       "target_dataset_version_id": request.target_dataset_version_id,
       "temporal_config": request.temporal_config.to_canonical_dict() if request.temporal_config else None,
   }
   request_fingerprint = hashlib.sha256(canonicalize(canonical_payload)).hexdigest()
   ```
2. **Registry Mapping**:
   The task manager stores a mapping of `f"{project_id}:{idempotency_key}"` to `(task_id, request_fingerprint)`.
   - If key exists and `stored_fingerprint == request_fingerprint` $\implies$ return existing task (`200 OK` / `202 Accepted`).
   - If key exists and `stored_fingerprint != request_fingerprint` $\implies$ raise `IdempotencyConflictError` (`409 Conflict`).

---

## 4. Provenance & Persistence Integration

When a task transitions to `COMPLETED`:
1. Synthesized findings are mapped to `FindingModel` records linked to `project_id`.
2. Supporting evidence references are persisted to `EvidenceModel` records.
3. The integrated assurance profile is saved to `RiskAssessmentModel` (`overall_risk_score`, `disposition`, `rationale`).
4. An `AuditEvent` is created with action `DRIFT_ANALYSIS_COMPLETED` containing `integrated_profile_hash` and `evidence_set_hash`.
5. An immutable `ProvenanceRecordModel` is appended to the project's cryptographic hash chain.
