# Phase 9.10 — REST API & Background Task Integration

## 1. Executive Summary & Objective
Phase 9.10 implements the enterprise-grade REST API and asynchronous background task orchestration layer for AIVARA's completed Backdoor and Trigger Analysis engine. This layer closes **GAP-09-02** by exposing the analytical engines (Phase 9.2–9.8) and cryptographic provenance binding (Phase 9.9) via robust HTTP endpoints, real-time Server-Sent Events (SSE) diagnostic progress streaming, and strict multi-tenant project isolation.

The implementation strictly satisfies all project architectural mandates:
- Zero database schema modifications (`DATABASE SCHEMA CHANGES = 0`).
- Fully offline, process-local task execution without cloud dependencies or external broker infrastructure.
- Hard inference budget ceiling enforcement ($\le 16,000$ total inferences).
- Strict non-speculative, observational taxonomy adherence (no speculative intent or maliciousness claims).

---

## 2. Architecture & Service Topology

```
+-----------------------------------------------------------------------------------+
| FastAPI Client (HTTP Request / EventSource SSE Stream)                           |
+-----------------------------------------------------------------------------------+
                                        |
                                        v
+-----------------------------------------------------------------------------------+
| FastAPI Router: backend/aivara/api/routers/backdoor.py                            |
| Prefix: /api/v1/projects/{project_id}/backdoor                                    |
|  - POST   /tasks                                 - Dispatch async / sync task     |
|  - GET    /tasks                                 - List tasks for tenant          |
|  - GET    /tasks/{task_id}                       - Get task status / stage        |
|  - POST   /tasks/{task_id}/cancel                - Cooperatively cancel task      |
|  - GET    /tasks/{task_id}/events                - SSE real-time event stream     |
|  - GET    /analyses/{analysis_id}                - Comprehensive analysis summary |
|  - GET    /analyses/{analysis_id}/candidates     - Evaluated candidates table     |
|  - GET    /analyses/{analysis_id}/activation     - Activation & TAR/TSR metrics   |
|  - GET    /analyses/{analysis_id}/output-shift   - Targeted output shift metrics  |
|  - GET    /analyses/{analysis_id}/localization   - Spatial localization heatmaps  |
|  - GET    /analyses/{analysis_id}/statistics     - Permutation & FDR statistics   |
|  - GET    /analyses/{analysis_id}/evidence       - Bound evidence payloads        |
|  - GET    /analyses/{analysis_id}/provenance     - Cryptographic signature record |
+-----------------------------------------------------------------------------------+
                                        |
                                        v
+-----------------------------------------------------------------------------------+
| Domain Service: backend/aivara/services/backdoor_service.py                       |
|  - BackdoorTaskManager: Thread-safe in-memory task registry and worker pool       |
|  - BackdoorTask: Lifecycle states, stage transitions, event subscription queues   |
|  - Multi-stage pipeline executor: Orchestrates 9.2 -> 9.3 -> 9.4 -> 9.5-9.8 -> 9.9 |
|  - Database binding: Scoped to tenant project using existing Finding/Evidence/    |
|    ProvenanceRecord tables                                                        |
+-----------------------------------------------------------------------------------+
```

---

## 3. Endpoints Specification

### Task Orchestration Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/projects/{project_id}/backdoor/tasks` | Create and start backdoor analysis (`?async=true\|false`, optional `Idempotency-Key` header). |
| `GET` | `/projects/{project_id}/backdoor/tasks` | List all tasks scoped to project (optional `?model_id=...` filter). |
| `GET` | `/projects/{project_id}/backdoor/tasks/{task_id}` | Get status, stage, progress %, and execution identity hash. |
| `POST` | `/projects/{project_id}/backdoor/tasks/{task_id}/cancel` | Cooperatively cancel an active task without database corruption. |
| `GET` | `/projects/{project_id}/backdoor/tasks/{task_id}/events` | Connect SSE event stream (`text/event-stream`) for progress updates. |

### Analysis Query Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/projects/{project_id}/backdoor/analyses/{analysis_id}` | Retrieve overall analysis summary with primary taxonomy and FDR metrics. |
| `GET` | `/projects/{project_id}/backdoor/analyses/{analysis_id}/candidates` | Retrieve candidate statistical summaries and confidence intervals. |
| `GET` | `/projects/{project_id}/backdoor/analyses/{analysis_id}/activation` | Retrieve candidate activation metrics (TAR, TSR vs clean). |
| `GET` | `/projects/{project_id}/backdoor/analyses/{analysis_id}/output-shift` | Retrieve targeted misclassification metrics and shift distributions. |
| `GET` | `/projects/{project_id}/backdoor/analyses/{analysis_id}/localization` | Retrieve $8\times 8$ spatial localization heatmaps and peak coordinates. |
| `GET` | `/projects/{project_id}/backdoor/analyses/{analysis_id}/statistics` | Retrieve paired permutation test metrics, $p$-values, and FDR ranks. |
| `GET` | `/projects/{project_id}/backdoor/analyses/{analysis_id}/evidence` | Retrieve canonical evidence records bound to the analysis findings. |
| `GET` | `/projects/{project_id}/backdoor/analyses/{analysis_id}/provenance` | Retrieve Ed25519 cryptographic signatures and hash-chain records. |

---

## 4. Multi-Tenant Project Isolation & Security
All endpoints strictly enforce tenant isolation:
1. URL path `project_id` must match payload `project_id`. Mismatches immediately trigger `CrossProjectContaminationError` / HTTP 422.
2. Query operations verify that requested tasks, findings, evidence, and provenance records belong to the requested project. Cross-project queries fail-closed with HTTP 404 / 422.
3. Database workers inherit engine bindings, maintaining session isolation during test and production runs.

---

## 5. Verification & Testing
The test suite in [`tests/test_backdoor_api.py`](file:///d:/Downloads/Projects/AiVara/tests/test_backdoor_api.py) exercises:
- Route registration and OpenAPI schema presence.
- Strict input validation and hard budget ceiling trapping (> 16,000 inferences rejected).
- Multi-tenant cross-project isolation rejections.
- Synchronous and asynchronous end-to-end task execution and cryptographic sealing.
- Cooperative task cancellation.
- Request deduplication and idempotency key handling.
- Observational semantic neutrality verification.
