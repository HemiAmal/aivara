# AIVARA Phase 10.6 — Output Schema & Numerical Integrity Architecture & Specification

**Authoritative Specification, Task Output Schemas, Numerical Integrity Rules, and Identity Signatures**

---

## 1. Executive Summary

Phase 10.6 establishes the authoritative **Output Schema & Numerical Integrity** subsystem in AIVARA. It acts as the structural, dimensional, and numerical gatekeeper between controlled model execution (Phase 10.5) and downstream composite cryptographic binding (Phase 10.7).

Phase 10.6 answers one core question:
> *Did the raw execution output produced by Phase 10.5 conform structurally, dimensionally, numerically, and domain-wise to the authoritative model contract and machine learning task specifications?*

---

## 2. Architectural Boundary

```
┌────────────────────────────────────────────────────────────────────────┐
│                        AIVARA INFERENCE PIPELINE                       │
├────────────────────────────────────────────────────────────────────────┤
│  Phase 10.2: SafeInferenceInputBoundary (InputIdentity)                │
│       ↓                                                                │
│  Phase 10.3: Input / Model Binding (InputModelBinding)                 │
│       ↓                                                                │
│  Phase 10.4: Preprocessing & Contract Integrity (TransformedInput)     │
│       ↓                                                                │
│  Phase 10.5: Inference Execution Integrity (InferenceExecution)        │
│       ↓                                                                │
│  [RawExecutionOutput + RawOutputHash]                                  │
│       ↓                                                                │
│  PHASE 10.6: OUTPUT SCHEMA & NUMERICAL INTEGRITY (This Phase)          │
│       │ - Output structure, count, ordering, and names                │
│       │ - Tensor dtypes, shapes, ranks, dimensions                     │
│       │ - Non-finite trapping (NaN, +Inf, -Inf)                        │
│       │ - Task domain rules (Classification, Detection, Seg, Embed)    │
│       │ - Deterministic Validated Output Identity Hash                 │
│       ↓                                                                │
│  ValidatedOutputIdentity + OutputIntegrityAssessment                   │
│       ↓                                                                │
│  Phase 10.7: Cryptographic Input -> Output Binding (FROZEN NEXT PHASE) │
└────────────────────────────────────────────────────────────────────────┘
```

### In-Scope (Phase 10.6):
- Output schema and contract validation against Phase 7 / user-declared contracts.
- Numerical integrity, finiteness, range checking, and domain sanity checks.
- Task-specific output schema evaluations:
  - **Classification**: Logits vs. probabilities, $[0.0, 1.0]$ bounds, explicit probability normalization policy ($|\sum p - 1.0| \le 10^{-4}$).
  - **Object Detection**: Bounding box geometry ($x_1 \le x_2, y_1 \le y_2$), coordinate bounds (normalized $[0.0, 1.0]$ with $\le 1\%$ tolerance), confidence scores $[0.0, 1.0]$, class IDs $\in [0, C-1]$.
  - **Segmentation**: Spatial/channel rank structure ($2\text{D}, 3\text{D}, 4\text{D}$), mask values $\in [0, C-1]$, probability bounds.
  - **Embedding / Vector**: Dimension matching, finiteness, optional unit norm ($L_2 = 1.0$).
  - **Structured Outputs**: Bounded recursive validation (nesting depth $\le 5$, string length $\le 1024$).
- Raw output identity re-verification against Phase 10.5 digest.
- Deterministic RFC 8785 JCS canonical identity hashing (`validated_output_identity`).

### Out-of-Scope (Phase 10.6):
- Composite end-to-end Input-to-Output binding (owned by **Phase 10.7**).
- Inference record database persistence and hash chains (owned by **Phase 10.8**).
- Replay and consistency engine (owned by **Phase 10.9**).
- Evidence and provenance model persistence (owned by **Phase 10.10**).
- REST API and task endpoints (owned by **Phase 10.11**).
- Inferring malicious intent, backdoors, poisoning, or contributor culpability.

---

## 3. Deterministic Identity Formulas

### A. Output Contract Identity Hash
$$\text{output\_contract\_hash} = \text{SHA-256}(\text{RFC8785\_JCS}(\mathcal{D}_{\text{contract}}))$$

Where $\mathcal{D}_{\text{contract}}$ contains:
- `contract_version`: Schema version (e.g. `"1.0"`).
- `task_type`: Standardized task string (`"classification"`, `"object_detection"`, etc.).
- `expected_output_count`: Expected integer count or `None`.
- `outputs`: Alphabetically sorted list of output tensor contracts.
- `strict_ordering`: Boolean flag.
- `strict_names`: Boolean flag.
- `class_count`: Expected class dimension if applicable.
- `require_finite`: Boolean flag.
- `require_probability_normalization`: Boolean flag.
- `probability_normalization_tolerance`: Floating-point tolerance.

### B. Validated Output Identity
$$\text{validated\_output\_identity} = \text{SHA-256}(\text{RFC8785\_JCS}(\mathcal{D}_{\text{validated\_output}}))$$

Where $\mathcal{D}_{\text{validated\_output}}$ contains:
- `schema_version`: `"1.0"`.
- `raw_output_hash`: 64-char lowercase hex digest from Phase 10.5.
- `task_type`: Evaluated task string.
- `output_contract_hash`: Canonical contract hash or `""`.
- `output_count`: Total output tensor count.
- `validation_status`: Overall integrity status string (`"VERIFIED"`, `"INVALID"`, `"MISMATCHED"`, etc.).
- `numerical_status`: Numerical classification (`"FINITE"`, `"NONFINITE"`, `"DOMAIN_VALID"`, etc.).
- `structural_summary`: Index-ordered list of tensor metadata dictionaries (name, shape, rank, dtype, byte_size, element_count, finiteness flags, domain validity, C-contiguous byte hash).

---

## 4. Task-Specific Output Validation Rules

| Task Type | Expected Outputs & Structure | Numerical & Domain Invariants |
|---|---|---|
| **Classification** | Logits / probabilities (1D $[C]$ or 2D $[B, C]$). | Logits: finite floats.<br>Probabilities: $0.0 \le p \le 1.0$, $|\sum p - 1.0| \le 10^{-4}$ if normalization required. |
| **Object Detection** | Bounding boxes $[N, 4]$ or $[B, N, 4]$, scores $[N]$, class IDs $[N]$. | Boxes: $x_1 \le x_2, y_1 \le y_2$, normalized coords in $[-0.01, 1.01]$.<br>Scores: $0.0 \le s \le 1.0$.<br>Classes: non-negative integers $< C$. |
| **Segmentation** | Mask tensors (2D $[H, W]$, 3D $[C, H, W]$ / $[B, H, W]$, 4D $[B, C, H, W]$). | Discrete masks: integer class indices $\in [0, C-1]$.<br>Probability masks: values $\in [0.0, 1.0]$. |
| **Embedding** | Vectors (1D $[D]$ or 2D $[B, D]$). | Finite floats matching contract dimension $D$. Optional unit $L_2$ norm ($\|v\|_2 = 1.0 \pm 10^{-3}$) if contract requires. |
| **Structured** | JSON-compatible primitives (dict, list, str, num, bool). | Bounded nesting depth ($\le 5$), bounded string length ($\le 1024$), finite numbers only. |

---

## 5. Status Taxonomy

- `VERIFIED`: Output structure matches contract, all values are finite, and task domain invariants hold.
- `INVALID`: Non-finite values (NaN/Inf) detected, or task domain violations (e.g. inverted box coordinates, negative probabilities).
- `MISMATCHED`: Structural discrepancy with model contract (output count, names, ordering, dtype, rank, or shape mismatch, or raw output hash mismatch).
- `UNAVAILABLE`: Authoritative model output contract is missing or cannot be located.
- `UNVERIFIABLE`: Output contract exists but cannot be verified deterministically.

---

## 6. Resource Limits & Policy

| Resource Parameter | Policy Ceiling |
|---|---|
| Maximum Output Tensors (`max_outputs`) | 64 |
| Maximum Tensor Elements (`max_tensor_elements`) | 50,000,000 |
| Maximum Tensor Rank (`max_rank`) | 8 |
| Maximum Dimension Size (`max_dimension_size`) | 65,536 |
| Maximum Structured Nesting Depth (`max_structured_nesting_depth`) | 5 |
| Maximum String Length (`max_string_length`) | 1,024 |
| Maximum Metadata Size (`max_metadata_bytes`) | 1,000,000 |
| Probability Sum Tolerance (`probability_sum_tolerance`) | $10^{-4}$ |
| Box Coordinate Margin (`box_coordinate_tolerance`) | $0.01$ (1%) |

---

## 7. Security Invariants
- **Data-Only Execution**: Zero dynamic evaluation (`eval`, `exec`, `pickle`, `subprocess`, `os.system`).
- **Air-Gapped Local Operation**: 100% process-local, zero network sockets or external cloud services.
- **Pure Observational Immutability**: Tensors, execution envelopes, and contracts are never mutated, clipped, or normalized.
- **Database Schema Changes**: 0 (zero migrations, zero table alterations).
