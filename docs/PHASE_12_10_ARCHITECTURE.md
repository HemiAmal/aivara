# Phase 12.10 — Universal Risk API & Task Integration Architecture

**Author:** DeepMind Antigravity Pair Programmer  
**Phase:** 12.10 — Universal Risk API & Task Integration  
**Date:** 2026-09-14  
**Status:** Authoritative Architectural Design  

---

## 1. Architectural Mission & Scope

Phase 12.10 exposes the complete Phase 12 Universal Assurance framework (Phases 12.2 through 12.9) through a hardened, deterministic, project-scoped REST API and asynchronous task orchestration subsystem.

### Key Architectural Invariants:
1. **Orchestration Boundary, Not Computation Engine:** The API layer validates requests, manages task lifecycles, and coordinates domain services (Phases 12.2–12.9). It **NEVER** re-implements, recalculates, or mutates domain risk mathematics, correlation factors, policy thresholds, cryptographic proofs, or aggregation algorithms.
2. **Broken Object-Level Authorization (BOLA) & Project Enclosure:** Every task, risk assessment, policy decision, proof verification, and project aggregation is strictly bound to a tenant `project_id`. Cross-project access fails closed with HTTP 404/403.
3. **No-Recomputation on Retrieval:** HTTP `GET` operations strictly fetch cached in-memory or persisted database results. `GET` requests never trigger analytical pipeline execution.
4. **Asynchronous Task State Machine:** Execution is dispatched to a bounded local `ThreadPoolExecutor(max_workers=4)` with cooperative cancellation and real-time Server-Sent Events (SSE) stage broadcasting.
5. **Deterministic Idempotency:** Requests are fingerprinted using RFC 8785 JSON Canonicalization Scheme (JCS) and SHA-256 (`hash_canonical_data`). Duplicate concurrent or sequential identical requests reuse task state without spawning redundant executions.
6. **100% Offline Air-Gap:** Zero outbound network dependencies, cloud APIs, telemetry, or remote services.

---

## 2. Universal Assurance Pipeline Architecture

```
HTTP Client / Frontend Dashboard
               │
               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       FastAPI Universal Router (/api/v1)                    │
│                                                                             │
│  - Request Validation & Schema Sanitization (Pydantic V2)                   │
│  - Project Tenancy & BOLA Scope Verification                                │
│  - Request Idempotency Fingerprinting (RFC 8785 JCS + SHA-256)              │
│  - Rate Limiting & Resource Ceiling Checks                                  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    UniversalAssuranceService & Task Manager                 │
│                                                                             │
│  - In-Memory Thread-Safe Task Store (DriftTask-pattern)                     │
│  - Bounded ThreadPoolExecutor (max_workers=4)                               │
│  - Stage Progression & SSE Real-time Broadcasting                           │
│  - Cooperative Cancellation Checkpoints                                     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼ Dispatch to Authoritative Domain Engines
┌─────────────────────────────────────────────────────────────────────────────┐
│ Phase 12.2: UniversalEvidenceNormalizer     (Envelope Normalization)        │
│ Phase 12.3: UniversalEvidenceGraph          (Finding-Evidence N:M DAG)      │
│ Phase 12.4: CrossSubsystemIngestionEngine   (Cross-Subsystem Ingestion)     │
│ Phase 12.5: CrossDomainCorrelationEngine    (7x7 Correlation Damping)       │
│ Phase 12.6: UniversalRiskComputationEngine  (Tier-1 Asset Risk R(A))        │
│ Phase 12.7: UniversalPolicyEngine           (Universal Decision Engine)     │
│ Phase 12.8: UniversalProofIntegrationEngine (Ed25519 & Chain Proofs)        │
│ Phase 12.9: UniversalProjectAggregator      (3-Tier Project Aggregator)     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Authoritative Route Surface

All routes are mounted under `/api/v1/projects/{project_id}/universal` and `/api/v1/universal`:

| HTTP Method | Route Path | Status Code | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/projects/{project_id}/universal/assurance/tasks` | `202 Accepted` | Submit bounded asynchronous universal assurance analysis task |
| `GET` | `/projects/{project_id}/universal/assurance/tasks/{task_id}` | `200 OK` | Query task lifecycle state, current stage, and progress percentage |
| `GET` | `/projects/{project_id}/universal/assurance/tasks/{task_id}/result` | `200 OK` | Retrieve completed universal assurance result (`409 Conflict` if in-flight) |
| `POST` | `/projects/{project_id}/universal/assurance/tasks/{task_id}/cancel` | `200 OK` | Cooperatively cancel queued or running assurance task |
| `GET` | `/projects/{project_id}/universal/assurance/tasks/{task_id}/events` | `200 OK (SSE)` | Stream real-time stage progress Server-Sent Events |
| `GET` | `/projects/{project_id}/universal/risk/{risk_id}` | `200 OK` | Retrieve stored Phase 12.6 Risk Assessment by ID |
| `GET` | `/projects/{project_id}/universal/decisions/{decision_id}` | `200 OK` | Retrieve stored Phase 12.7 Policy Decision by ID |
| `GET` | `/projects/{project_id}/universal/proof/{proof_id}` | `200 OK` | Retrieve stored Phase 12.8 Proof Assessment by ID |
| `GET` | `/projects/{project_id}/universal/aggregation` | `200 OK` | Retrieve stored Phase 12.9 Project Hierarchical Risk Aggregation |
| `GET` | `/projects/{project_id}/universal/capabilities` | `200 OK` | Query supported subsystems, algorithms, and governance ceilings |

---

## 4. Task State Machine & Stage Progression

```
                   ┌──────────────┐
                   │    QUEUED    │
                   └──────┬───────┘
                          │ (Worker Pickup)
                          ▼
                   ┌──────────────┐
     ┌────────────►│   RUNNING    ├────────────┐
     │             └──────┬───────┘            │
     │                    │                    │
 (Cancellation)           │ (Completion)       │ (Error / Exception)
     │                    ▼                    │
┌────┴───────┐     ┌──────────────┐      ┌─────┴──────┐
│ CANCELLED  │     │  COMPLETED   │      │   FAILED   │
└────────────┘     └──────────────┘      └────────────┘
```

### Discrete Pipeline Stages:
1. `QUEUED`: Enqueued in worker task queue.
2. `NORMALIZING_EVIDENCE`: Normalizing raw evidence items into `UniversalEvidenceEnvelope` (Phase 12.2).
3. `BUILDING_GRAPH`: Constructing in-memory finding-evidence DAG and Merkle root (Phase 12.3).
4. `INGESTING`: Ingesting and validating cross-subsystem records (Phase 12.4).
5. `CORRELATING`: Applying $7 \times 7$ correlation matrix and ancestry clustering (Phase 12.5).
6. `COMPUTING_RISK`: Computing Tier-1 asset-level operational risk $R(A)$ (Phase 12.6).
7. `EVALUATING_POLICY`: Evaluating versioned risk and decision policies (Phase 12.7).
8. `VERIFYING_PROOF`: Verifying Ed25519 signatures, hash chains, and nonces (Phase 12.8).
9. `AGGREGATING_PROJECT`: Computing Tier-2 chain risk and Tier-3 peak-dominant project risk (Phase 12.9).
10. `COMPLETED`: Assessment results serialized and cached.

---

## 5. Security Architecture & BOLA Protection

1. **Strict Project Scoping:** Every request parameter `project_id` must match the URL route path and task tenant context. Attempting to query an object belonging to project $P_B$ from project $P_A$ context raises `NotFoundException` (fail-closed).
2. **Safe Input Boundary:** All incoming artifact references and asset IDs are validated against regex `^[a-zA-Z0-9_\-\.]{1,128}$` to prevent path traversal (`..`, absolute drive traversal).
3. **Payload Sanitization:** Error messages are stripped of stack traces, memory addresses, SQL schemas, and private keys.
4. **Resource Governance:** Max 500 assets, max 2,000 edges, max request payload 10MB, max 4 concurrent tasks, max 50 items per page.
