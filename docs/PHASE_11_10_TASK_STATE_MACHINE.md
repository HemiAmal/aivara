# Phase 11.10: Task State Machine & Lifecycle Specification

## 1. Formal State Definitions

The `DriftTask` lifecycle is governed by a deterministic, thread-safe state machine:

```
                  +------------+
                  |   QUEUED   |
                  +------------+
                        |
                        | (Worker thread acquires task)
                        v
                  +------------+
        +-------->|  RUNNING   |---------+
        |         +------------+         |
        |               |                |
(Cancel |               | (Analysis      | (Fatal error
Request)|               |  succeeds)     |  raised)
        v               v                v
+---------------+ +------------+ +------------+
|CANCEL_REQUEST | | COMPLETED  | |   FAILED   |
+---------------+ +------------+ +------------+
        |          [TERMINAL]     [TERMINAL]
        |
        | (Engine sentinel checks)
        v
+---------------+
|   CANCELLED   |
+---------------+
   [TERMINAL]
```

---

## 2. State Transition Matrix

| Current State | Permitted Next States | Trigger / Condition | Rejection / Conflict Behavior |
|:---|:---|:---|:---|
| **`QUEUED`** | `RUNNING`, `CANCELLED` | Worker thread starts execution OR immediate cancellation before pickup | Transition to `COMPLETED` or `FAILED` without `RUNNING` is prohibited. |
| **`RUNNING`** | `COMPLETED`, `FAILED`, `CANCEL_REQUESTED` | All analysis stages finish successfully, unhandled exception occurs, or client requests cancellation | Re-queuing or repeated `RUNNING` is prohibited. |
| **`CANCEL_REQUESTED`**| `CANCELLED`, `FAILED` | Engine encounters cancellation sentinel at loop boundary and halts cleanly, or engine crashes before halting | Transition to `COMPLETED` is rejected; cancellation takes precedence. |
| **`COMPLETED`** | *None (Terminal)* | None | Immutable. Further transitions raise `InvalidStateTransitionError`. |
| **`FAILED`** | *None (Terminal)* | None | Immutable. Further transitions raise `InvalidStateTransitionError`. |
| **`CANCELLED`** | *None (Terminal)* | None | Immutable. Further transitions raise `InvalidStateTransitionError`. |

---

## 3. Cooperative Cancellation Mechanism

Because AIVARA operates within local, in-process runtime constraints without isolated sub-processes, hard process killing is unsafe. Phase 11.10 implements cooperative cancellation:

1. **Client Cancellation Request**:
   - Client sends `POST .../cancel`.
   - `DriftTaskManager.cancel_task(task_id)` sets the task's atomic boolean flag `is_cancelled = True` and updates status to `CANCEL_REQUESTED`.
2. **Engine Sentinel Checkpoints**:
   - All Phase 11 engines (`FeatureDatasetDriftAnalyzer`, `ImageDistributionShiftAnalyzer`, `RepresentationDistributionShiftAnalyzer`, `TemporalDriftEngine`, `SourceDriftEngine`) receive a cancellation callback callable `should_cancel() -> bool`.
   - Sentinel checkpoints occur:
     - Between feature iterations in tabular drift.
     - Between image descriptor extraction batches in image drift.
     - Between permutation test iterations in MMD / Energy tests.
     - Between time-window evaluations in temporal drift.
     - Between source-group evaluations in source drift.
3. **Graceful Halting**:
   - When `should_cancel()` returns `True`, the engine immediately terminates the loop, discards partial uncommitted findings, and returns an aborted status.
   - The task manager sets task status to `CANCELLED` and broadcasts the `task.cancelled` event.

---

## 4. Analytical Progress Stages

Progress percentage and stage descriptors during `RUNNING` state:

| Stage Identifier | Typical Progress % | Operational Description |
|:---|:---|:---|
| `POPULATION_BOUNDARY` | 5.0% – 15.0% | Ingesting populations, validating compatibility, and applying deterministic subsampling (Phase 11.2). |
| `STATISTICAL_ANALYSIS` | 15.0% – 70.0% | Executing hypothesis tests (KS, Chi-Square, MMD, Energy, BH FDR) across feature/window dimensions (Phases 11.3–11.8). |
| `PROFILE_SYNTHESIS` | 70.0% – 85.0% | Formatting analytical profiles, evaluating change points, persistence, and Simpson's confounding. |
| `RISK_INTEGRATION` | 85.0% – 95.0% | Modality clustering, correlation damping ($\lambda_{\text{corr}}$), and sub-additive risk aggregation (Phase 11.9). |
| `FINALIZATION` | 95.0% – 100.0% | Computing cryptographic digests, creating audit/provenance records, and persisting to SQLite. |

---

## 5. Concurrency & Thread-Safety Guarantees

1. **Manager Synchronization**:
   - All internal task dictionaries (`_tasks`, `_idempotency_map`, `_event_queues`) are guarded by `threading.Lock()`.
2. **Single-Submission Invariant**:
   - A task is submitted to `ThreadPoolExecutor` exactly once upon creation.
3. **Memory Ceilings**:
   - The in-memory registry retains up to 1,000 active/completed tasks per project. Old completed/failed tasks exceeding this budget are evicted in LRU order (their results remain safely persisted in SQLite).
