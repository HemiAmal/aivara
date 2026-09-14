# Phase 12.10 — Universal Risk API & Task Integration Verification Plan

**Author:** DeepMind Antigravity Pair Programmer  
**Phase:** 12.10 — Universal Risk API & Task Integration  
**Date:** 2026-09-14  
**Status:** Verification Plan  

---

## 1. Test Strategy & Structure

The Phase 12.10 verification suite is partitioned into dedicated test modules located in `tests/phase_12_10/`:

1. **`test_route_registration.py`**:
   - Verify all universal assurance endpoints are mounted under FastAPI app `/api/v1/`.
   - Verify OpenAPI schema generation and tags.
   - Verify capabilities endpoint returns valid subsystem metadata.
2. **`test_task_lifecycle.py`**:
   - Verify async task creation: `QUEUED` $\to$ `RUNNING` $\to$ `COMPLETED`.
   - Verify task cooperative cancellation: `QUEUED`/`RUNNING` $\to$ `CANCELLED`.
   - Verify task failure state handling: error details, timestamps, and stage records.
3. **`test_request_validation.py`**:
   - Test rejection of malformed JSON, missing fields, and extra fields (`extra="forbid"`).
   - Test rejection of invalid project IDs and asset IDs.
   - Test payload boundary constraints.
4. **`test_bola_authorization.py`**:
   - Test project tenant scoping on every endpoint.
   - Verify cross-project task querying returns HTTP `404 Not Found`.
   - Verify cross-project risk, decision, proof, and aggregation queries fail closed.
5. **`test_no_recomputation.py`**:
   - Verify `GET /result` returns stored results without calling the underlying domain engines again.
   - Verify `GET /risk`, `GET /decisions`, `GET /proof`, `GET /aggregation` are read-only.
6. **`test_error_mapping.py`**:
   - Verify domain exceptions (`ScopeMismatchError`, `DependencyCycleError`, `InvalidAssetRiskError`, etc.) map to appropriate HTTP status codes (`400`, `404`, `409`, `422`).
   - Verify error responses contain standard `ApiErrorResponse` envelope without Python stack traces.
7. **`test_resource_governance.py`**:
   - Verify maximum asset and edge ceilings are enforced.
   - Verify pagination parameter limits (`max_page_size=50`).
8. **`test_sse_streaming.py`**:
   - Verify Server-Sent Events stream emits discrete stage events in correct chronological order.
   - Verify reconnect and replay handling.
9. **`test_hash_integrity.py`**:
   - Verify `risk_hash`, `decision_hash`, `proof_result_hash`, `aggregation_hash` match RFC 8785 JCS + SHA-256 canonical values.
10. **`test_security_ast.py`**:
    - Perform static AST analysis verifying zero dynamic `eval`, `exec`, or unauthorized network calls in `backend/aivara/universal/api/`.
11. **`test_end_to_end_pipeline.py`**:
    - Complete integration test executing full universal assurance pipeline from API task submission to hierarchical aggregation result.

---

## 2. Regression & Compilation Commands

```powershell
# 1. Run Phase 12.10 Dedicated Test Suite
.venv\Scripts\pytest.exe tests/phase_12_10 -v

# 2. Run Phase 12 Regression Suite (Phases 12.2 to 12.10)
.venv\Scripts\pytest.exe tests/phase_12_2 tests/phase_12_3 tests/phase_12_4 tests/phase_12_5 tests/phase_12_6 tests/phase_12_7 tests/phase_12_8 tests/phase_12_9 tests/phase_12_10 -v

# 3. Run Full Repository Test Suite
.venv\Scripts\pytest.exe

# 4. Bytecode Compilation
.venv\Scripts\python.exe -m compileall backend/aivara/universal/api tests/phase_12_10
```
