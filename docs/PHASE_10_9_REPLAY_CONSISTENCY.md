# Phase 10.9 — Replay & Consistency Verification Subsystem

## 1. Overview & Purpose

The **Phase 10.9 Replay & Consistency Verification** subsystem establishes the authoritative, tamper-evident re-execution and output comparison framework for AIVARA inference transactions.

Replay verification determines whether a previously executed and immutably persisted **Phase 10.8 Inference Record** can be faithfully re-executed under controlled sandbox conditions, and classifies the resulting consistency against the recorded baseline:

1. **Pre-Replay Eligibility Assessment**: Cryptographically verifies the `InferenceRecord` (Phase 10.8) and embedded `InferenceBinding` (Phase 10.7). Assesses version compatibility and tenant project isolation.
2. **Controlled Sandbox Re-execution**: Invokes the deterministic execution engine (`Phase 10.5`) with exact input identity (`Phase 10.2`), input-model binding (`Phase 10.3`), preprocessing contract (`Phase 10.4`), and resource bounds.
3. **Multi-Tier Output Comparison**:
   - Exact bitwise SHA-256 raw output digest comparison.
   - Structural schema validation (tensor count, tensor names, rank, shape, dtype).
   - Pointwise numerical tolerance comparison: $|a - b| \le \text{atol} + \text{rtol} \times |a|$.
   - Finite numerical sanity verification (NaN, Inf rejection).
4. **Deterministic Classification**: Pure immutable outcome mapping into `CONSISTENT_EXACT`, `CONSISTENT_TOLERANT`, `STRUCTURAL_DIVERGENCE`, `NUMERICAL_DIVERGENCE`, `EXECUTION_DIVERGENCE`, or `NON_REPRODUCIBLE`.

---

## 2. Architecture & Component Hierarchy

```
backend/aivara/inference/replay/
├── __init__.py           # Package exports
├── enums.py              # ReplayEligibilityStatus, ReplayMode, ReplayConsistencyStatus, ComparisonStatus
├── models.py             # ReplayEnvironment, ReplayComparisonResult, ReplayVerificationResult
├── policy.py             # ReplayPolicy (DETERMINISTIC, NUMERICALLY_TOLERANT, NON_REPRODUCIBLE)
├── comparator.py         # Bitwise, structural, and numerical tensor comparison engine
├── engine.py             # Pure functional eligibility, execution, and verification pipelines
└── service.py            # High-level orchestration service with error handling and environment detection
```

---

## 3. Mathematical & Numerical Consistency Criteria

Given recorded raw output tensor $A$ and newly computed replay tensor $B$:

### 3.1 Exact Determinism
$$H_{\text{raw}}(B) = H_{\text{raw}}(A)$$
When canonical raw output digests match bitwise under constant-time comparison (`hmac.compare_digest`), replay consistency is classified as **`CONSISTENT_EXACT`**.

### 3.2 Tolerant Equivalence
When byte digests differ but structure is preserved:
$$\forall i \in \{1, \dots, N\}, \quad |A_i - B_i| \le \text{atol} + \text{rtol} \times |A_i|$$
- If every element satisfies the condition, replay consistency is classified as **`CONSISTENT_TOLERANT`**.
- If any element violates the condition or non-finite values (NaN/Inf) are detected in $B$, replay consistency is classified as **`NUMERICAL_DIVERGENCE`**.

### 3.3 Structural Integrity
Tensors must strictly match:
- Output count: $N_A = N_B$ (`COUNT_MISMATCH`)
- Tensor names: $\text{name}(A_k) = \text{name}(B_k)$ (`NAME_MISMATCH`)
- Tensor rank: $\text{rank}(A_k) = \text{rank}(B_k)$ (`RANK_MISMATCH`)
- Tensor dimensions: $\text{shape}(A_k) = \text{shape}(B_k)$ (`SHAPE_MISMATCH`)
- Tensor data types: $\text{dtype}(A_k) = \text{dtype}(B_k)$ (`DTYPE_MISMATCH` unless explicitly permitted by policy)

---

## 4. Security & Isolation Guarantees

1. **Zero Dynamic Evaluation**: Replay subsystem contains zero `eval()`, `exec()`, `pickle`, `subprocess`, or remote socket calls.
2. **Strict Tenant Isolation**: `project_id` must match across all components. Cross-tenant replay attempts are rejected prior to execution (`PROJECT_MISMATCH`).
3. **Fail-Closed Execution**: Unsupported environments (e.g. CUDA requested on CPU host), timeouts, memory limits, and non-finite numbers immediately fail closed without silent fallbacks.
4. **State Immutability**: All models (`ReplayEnvironment`, `ReplayComparisonResult`, `ReplayVerificationResult`) are frozen Pydantic v2 models with `extra="forbid"`.
5. **Phase Boundary Containment**: Phase 10.9 contains zero Phase 10.10 ledger/provenance evidence persistence.
6. **Zero Database Alterations**: Zero schema migrations, zero table additions, zero column alterations.
