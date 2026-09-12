# PHASE 9.3 — TRIGGER TRANSFORMATION ENGINE

**AIVARA — AI Verification & Assurance**  
**Document ID:** `DOC-AIVARA-PHASE-9.3-TRANSFORMATION`  
**Status:** COMPLETE & FROZEN  
**Upstream Architecture:** [PHASE 9.1 ARCHITECTURE](file:///d:/Downloads/Projects/AiVara/docs/PHASE_9_1_BACKDOOR_TRIGGER_ARCHITECTURE.md) (ADR-061 – ADR-084) & [PHASE 9.2 CANDIDATE GENERATION](file:///d:/Downloads/Projects/AiVara/docs/PHASE_9_2_SAFE_TRIGGER_CANDIDATE_GENERATION.md) (ADR-085)  
**Downstream Consumer:** PHASE 9.4 — CLEAN-VS-TRIGGERED BEHAVIORAL COMPARISON  

---

## 1. MISSION & SCOPE

Phase 9.3 implements the deterministic, safe, and bounded transformation engine that applies an immutable Phase 9.2 [`TriggerCandidateSpec`](file:///d:/Downloads/Projects/AiVara/backend/aivara/backdoor/candidates/models.py#L163) to a validated in-memory array.

$$\text{validated\_input} + \text{TriggerCandidate} \xrightarrow{\text{Trigger Transformation}} \text{transformed\_input} + \text{TransformationResult}$$

### Fundamental Principles
1. **Pure Transformation Layer**: Phase 9.3 converts inputs and candidate specifications into transformed synthetic test inputs. It does NOT execute models, measure activations, perform statistical hypothesis tests, or claim backdoor presence.
2. **Source Immutability**: The source input array is never modified in place. Its cryptographic hash is verified before and after transformation to guarantee byte-level immutability.
3. **Explicit Layout Semantics (ADR-087)**: Tensor layouts (`GRAYSCALE_2D`, `HWC`, `CHW`, `NHWC`, `NCHW`) are strictly typed, resolved, and embedded into the cryptographic transformation identity.
4. **Output Layout Preservation**: The transformed output strictly matches the input layout (`output_layout == input_layout`) with zero silent transposition.

---

## 2. EXPLICIT INPUT LAYOUT CONTRACT (ADR-087)

### Layout Taxonomy: [`InputLayoutEnum`](file:///d:/Downloads/Projects/AiVara/backend/aivara/backdoor/transformation/enums.py#L8)
- `GRAYSCALE_2D`: 2D single-channel image with spatial shape $(H, W)$.
- `HWC`: 3D image with axes $(H, W, C)$ (channel-last).
- `CHW`: 3D image with axes $(C, H, W)$ (channel-first).
- `NHWC`: 4D batched tensor with axes $(N, H, W, C)$.
- `NCHW`: 4D batched tensor with axes $(N, C, H, W)$.

### Axis Mapping Matrix
| Layout | Batch Axis ($N$) | Channel Axis ($C$) | Height Axis ($H$) | Width Axis ($W$) |
| :--- | :--- | :--- | :--- | :--- |
| `GRAYSCALE_2D` | N/A | Implicit (1) | Axis 0 | Axis 1 |
| `HWC` | N/A | Axis 2 | Axis 0 | Axis 1 |
| `CHW` | N/A | Axis 0 | Axis 1 | Axis 2 |
| `NHWC` | Axis 0 | Axis 3 | Axis 1 | Axis 2 |
| `NCHW` | Axis 0 | Axis 1 | Axis 2 | Axis 3 |

### Layout Resolution & Ambiguity Rules
1. **Unambiguous Inference**:
   - `(H, W)` $\implies$ `GRAYSCALE_2D`.
   - `(H, W, C)` with $C \in \{1, 3, 4\}$ and $H, W \ge 16$ (and $H, W \notin \{1, 3, 4\}$) $\implies$ `HWC`.
   - `(C, H, W)` with $C \in \{1, 3, 4\}$ and $H, W \ge 16$ (and $H, W \notin \{1, 3, 4\}$) $\implies$ `CHW`.
   - `(N, H, W, C)` and `(N, C, H, W)` inferred symmetrically for rank 4.
2. **Ambiguity Rejection**:
   - If both spatial and channel candidates match (e.g. $(3, 32, 3)$ or $(4, 4, 3)$), inference fails closed with [`UnsupportedInputShapeError`](file:///d:/Downloads/Projects/AiVara/backend/aivara/backdoor/transformation/exceptions.py#L29) and requires explicit `input_layout`.

---

## 3. TRANSFORMATION INTERFACE

The primary entry point is the [`TriggerTransformationEngine`](file:///d:/Downloads/Projects/AiVara/backend/aivara/backdoor/transformation/engine.py#L39) class and functional helper [`transform_input`](file:///d:/Downloads/Projects/AiVara/backend/aivara/backdoor/transformation/engine.py#L254):

```python
result: TransformationResult = engine.transform(
    input_array=source_array,
    candidate_spec=candidate,
    placement=optional_placement_override,
    input_layout=optional_explicit_layout,
)
```

### Result Representation: [`TransformationResult`](file:///d:/Downloads/Projects/AiVara/backend/aivara/backdoor/transformation/models.py#L32)
- `transformation_id`: Deterministic 64-hex SHA-256 JCS digest.
- `transformation_version`: Algorithm implementation version (`"1.0.0"`).
- `source_input_hash`: 64-hex SHA-256 hash of source array buffer.
- `transformed_input_hash`: 64-hex SHA-256 hash of transformed output buffer.
- `candidate_hash`: Phase 9.2 canonical candidate identity hash.
- `candidate_family`: Frozen v1 trigger family enum.
- `input_shape` & `output_shape`: Exact tensor spatial and channel dimensions.
- `input_dtype` & `output_dtype`: Preserved numerical data types.
- `input_layout` & `output_layout`: Resolved tensor layout enums (`output_layout == input_layout`).
- `placement`: Effective placement specification.
- `clipping_occurred`: Boolean flag indicating if output values required bounding.
- `transformed_array` (or `.array`): Read-only, contiguous transformed numpy array.
- `transformation_metadata`: Structured dictionary convertible to [`TransformationMetadata`](file:///d:/Downloads/Projects/AiVara/backend/aivara/backdoor/transformation/models.py#L13).

---

## 4. SUPPORTED CANDIDATE FAMILIES & BLENDING

Phase 9.3 executes transformations for all four frozen v1 trigger families:

| Family Enum | Supported Parameters | Transformation & Blending Mechanics |
| :--- | :--- | :--- |
| `SPATIAL_PATCH` | `shape` (`SQUARE`, `RECTANGLE`, `CIRCLE`), `relative_width`, `relative_height`, `relative_radius`, `fill_color`, `alpha`, `blend_mode` (`REPLACE`, `ALPHA_BLEND`) | Geometric patch mapped to spatial bounding box. `REPLACE` overwrites source pixels; `ALPHA_BLEND` performs linear interpolation with $\alpha \in [0.0, 1.0]$. |
| `COLOR_PATTERN_PATCH` | `color_space` (`RGB`), `channel_deltas`, `relative_width`, `relative_height`, `alpha`, `blend_mode` (`ALPHA_BLEND`, `ADDITIVE`) | Localized chromatic shifts. `ADDITIVE` computes $S + M \cdot P$; `ALPHA_BLEND` blends deltas into source. |
| `TEXTURE_GRID` | `primitive` (`CHECKER`, `GRID`, `STRIPE_HORIZONTAL`, `STRIPE_VERTICAL`, `DOT_GRID`), `stride_pixels`, `line_width_pixels`, `amplitude`, `alpha`, `color_channels`, `phase_offset` | Full-frame periodic texture synthesis blended onto source with configured alpha and amplitude. |
| `LOCALIZED_PERTURBATION` | `mode` (`ADDITIVE_GAUSSIAN`, `ADDITIVE_UNIFORM`, `MULTIPLICATIVE_UNIFORM`), `relative_width`, `relative_height`, `amplitude`, `noise_std`, `clip_min`, `clip_max` | Bounded localized noise synthesized with isolated `PCG64(random_seed)`. Additive and multiplicative noise scaling. |

### Mathematical Blending Equations
Let $S$ be the source input, $P$ be the synthesized pattern, and $M$ be the spatial occupancy/alpha mask:
- **`REPLACE`**:
  $$\text{Output} = P \cdot (M > 0) + S \cdot (1 - (M > 0))$$
- **`ALPHA_BLEND`**:
  $$\text{Output} = (1 - M) \cdot S + M \cdot P \quad (\text{where } M \in [0, \alpha])$$
- **`ADDITIVE`**:
  $$\text{Output} = S + M \cdot P$$
- **`MULTIPLICATIVE`**:
  $$\text{Output} = S \cdot P \cdot (M > 0) + S \cdot (1 - (M > 0))$$

---

## 5. NUMERICAL, DTYPE & CLIPPING POLICY

- **Supported dtypes**: `float32`, `float64`, `uint8`, `int32`, `int64`. Output strictly preserves source dtype.
- **Finite Check**: Non-finite values (`NaN`, $\pm\infty$) in source input trigger immediate [`NonFiniteInputError`](file:///d:/Downloads/Projects/AiVara/backend/aivara/backdoor/transformation/exceptions.py#L43).
- **Clipping Policy**:
  - `UNIT_FLOAT` $[0.0, 1.0]$: Clamped to $[0.0, 1.0]$.
  - `BYTE_INTEGER` $[0, 255]$: Clamped to $[0, 255]$.
  - `ZERO_CENTERED` $[-1.0, 1.0]$: Clamped to $[-1.0, 1.0]$.
  - If any pixel required clamping, `clipping_occurred = True` is recorded in metadata.

---

## 6. CANONICAL IDENTITIES & HASHING

### Array Buffer Hashing
```python
def compute_input_array_hash(arr: np.ndarray) -> str:
    c_arr = np.ascontiguousarray(arr)
    header = f"{c_arr.dtype.str}:{list(c_arr.shape)}:".encode("utf-8")
    return sha256_bytes(header + c_arr.tobytes())
```

### Transformation Identity (ADR-087)
$$\text{transformation\_id} = \text{SHA-256}(\text{JCS}(\{\text{candidate\_hash}, \text{input\_layout}, \text{placement}, \text{schema\_version}, \text{source\_input\_hash}, \text{transformation\_version}\}))$$

---

## 7. RESOURCE LIMITS & SECURITY BOUNDARIES

- **Spatial Dimension Bounds**: $16 \le H, W \le 4096$. Channels $1 \le C \le 4$.
- **Batch Size Limit**: $N \le 16$ per batch execution (fails closed with [`TransformationBudgetExceededError`](file:///d:/Downloads/Projects/AiVara/backend/aivara/backdoor/transformation/exceptions.py#L59) if $N > 16$).
- **Maximum Array Allocation**: Array size bounded to $\le 4096 \times 4096 \times 4 \times 16$ elements.
- **Pure Data Security**: Candidate and placement parameters are pure numeric data. Zero dynamic evaluation, zero subprocess calls, zero filesystem access, zero network requests.
- **Database Schema**: Zero database schema changes (`DATABASE SCHEMA CHANGES = 0`).

---

## 8. ARCHITECTURAL DECISION RECORDS

### ADR-086: Deterministic In-Memory Trigger Transformation Engine
**Status:** APPROVED & FROZEN  
**Summary:** Implements [`TriggerTransformationEngine`](file:///d:/Downloads/Projects/AiVara/backend/aivara/backdoor/transformation/engine.py#L39) to apply synthetic trigger candidates to numpy arrays with source immutability guarantees, deterministic JCS hashing, and mathematical blending.

### ADR-087: Explicit Input Layout Semantics and Transformation Identity Binding
**Status:** APPROVED & FROZEN  
**Context:** Spatial and channel axes in computer vision tensors vary between frameworks (PyTorch CHW/NCHW vs. TensorFlow/NumPy HWC/NHWC). Applying spatial patches without an explicit layout contract risks silent channel-dimension transposition or transformation corruption.  
**Decision:**
1. Introduce [`InputLayoutEnum`](file:///d:/Downloads/Projects/AiVara/backend/aivara/backdoor/transformation/enums.py#L8) (`GRAYSCALE_2D`, `HWC`, `CHW`, `NHWC`, `NCHW`).
2. Require unambiguous layout inference rules; reject ambiguous shapes that could match multiple layout interpretations unless explicit `input_layout` is provided.
3. Guarantee that `output_layout == input_layout` with zero silent transposition.
4. Bind `input_layout` directly into the deterministic RFC 8785 JCS `transformation_id`.

---

## 9. VERIFICATION & TEST SUMMARY

- **Targeted Transformation Suite**: [`tests/test_backdoor_transformation.py`](file:///d:/Downloads/Projects/AiVara/tests/test_backdoor_transformation.py): **39 / 39 PASSED** (0.27s)
- **Candidate Generation Suite**: [`tests/test_backdoor_candidates.py`](file:///d:/Downloads/Projects/AiVara/tests/test_backdoor_candidates.py): **49 / 49 PASSED**
- **Phase 9.1 Architecture Contracts**: [`tests/test_backdoor_architecture_contracts.py`](file:///d:/Downloads/Projects/AiVara/tests/test_backdoor_architecture_contracts.py): **8 / 8 PASSED**
- **Cumulative Phase 8 Suite**: [`tests/test_behavioral_comprehensive.py`](file:///d:/Downloads/Projects/AiVara/tests/test_behavioral_comprehensive.py): **43 / 43 PASSED**
- **Combined Cumulative Suite**: **131 / 131 PASSED** (1.75s)
- **Database Schema**: 0 migrations, 0 tables modified.
