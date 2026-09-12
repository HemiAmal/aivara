# AIVARA Phase 10.4 — Preprocessing & Contract Integrity Specification

## Status: FROZEN & VERIFIED

---

### 1. Objective

Phase 10.4 establishes the authoritative **Preprocessing & Contract Integrity** layer of the AIVARA Inference Integrity pipeline (`backend/aivara/inference/preprocessing/`).

The purpose of Phase 10.4 is to ensure that every inference preprocessing step applied between the validated `InputModelBinding` (Phase 10.3) and model execution (Phase 10.5) is:
- **Explicit**: Declared through closed enumerations and bounded parameters.
- **Deterministic**: Produces identical numerical and cryptographic outputs under identical inputs and recipes.
- **Content-Addressed**: Identified by a canonical RFC 8785 JCS + SHA-256 digest (`contract_hash`).
- **Validated**: Evaluated against strict physical and numeric limits (e.g. max dimensions, finite float checks, positive scale/std).
- **Semantically Compatible**: Checked against Phase 10.2 `InputIdentity` assumptions and Phase 7 `ValidatedInputContract` model interface guarantees.

---

### 2. Core Separation of Identities

A critical architectural invariant established by ADR-092 is the strict separation of:

1. **Preprocessing Contract Identity (`contract_hash`)**:
   Answers: *"What deterministic recipe was specified?"*
   Computed over the canonical descriptor of operations, input assumptions, and output guarantees.

2. **Transformed Input Identity (`transformed_canonical_hash`)**:
   Answers: *"What exact contiguous byte payload resulted from execution?"*
   Computed over the C-contiguous byte stream of the transformed tensor array.

These two hashes MUST NEVER be collapsed into a single entity.

---

### 3. Preprocessing Contract Schema

#### Immutable Schema: `PreprocessingContract`
| Field | Type | Description |
|---|---|---|
| `schema_version` | `str` | Schema specification version (`"1.0"`, max 16 chars) |
| `contract_version` | `str` | Contract version (`"1.0"`, max 16 chars) |
| `name` | `str` | Descriptive identifier (max 255 chars) |
| `input_assumption` | `InputAssumption` | Declared prerequisites on input tensor/image |
| `operations` | `List[PreprocessingOperation]` | Ordered sequence of transformations (max 32 ops) |
| `output_guarantee` | `OutputGuarantee` | Declared guarantees on output tensor |
| `contract_hash` | `str` | SHA-256 digest of canonical JCS descriptor (64-char lowercase hex) |
| `findings` | `List[InputFinding]` | Observational findings |
| `details` | `Dict[str, Any]` | Audit telemetry |

---

### 4. Supported Operations & Closed Vocabulary

| Operation Type | Supported Parameters | Validation Constraints |
|---|---|---|
| `RESIZE` | `target_width`, `target_height`, `interpolation` (`NEAREST`, `BILINEAR`, `BICUBIC`), `aspect_ratio_policy` (`STRETCH`, `PRESERVE_PAD`, `PRESERVE_CROP`) | Dimensions $\in [1, 8192]$ |
| `CROP` | `x`, `y`, `width`, `height`, `normalized` | Coordinates $\ge 0$, bounded by image dimensions |
| `PAD` | `top`, `bottom`, `left`, `right`, `mode` (`CONSTANT`, `REFLECT`, `SYMMETRIC`, `REPLICATE`), `value` | Extents $\ge 0$, finite fill value |
| `CHANNEL_CONVERT` | `source_space`, `target_space` (`RGB`, `BGR`, `GRAYSCALE`, `RGBA`, `BGRA`) | Standard ITU-R BT.601 luminance coefficients for grayscale |
| `DTYPE_CONVERT` | `source_dtype`, `target_dtype`, `rounding_policy` (`HALF_TO_EVEN`, `FLOOR`, `CEIL`, `ROUND`), `clipping_policy` (`CLIP_TO_RANGE`, `NO_CLIP`, `ERROR_ON_OUT_OF_RANGE`) | Closed whitelist of numeric dtypes |
| `NORMALIZE` | `mean`, `std`, `scale`, `clip_min`, `clip_max` | $\text{std} > 0.0$, all values strictly finite |
| `VALUE_RANGE_SCALE` | `source_min`, `source_max`, `target_min`, `target_max`, `clip` | $\text{max} > \text{min}$, all values strictly finite |
| `NO_OP` | None | Pass-through identity |

---

### 5. Operation Ordering Semantics

Preprocessing operations maintain strictly ordered semantics ($T_1 \circ T_2 \ne T_2 \circ T_1$). JCS preserves list element ordering while sorting object dictionary keys.

---

### 6. Canonical Identity Formula

$$\text{contract\_hash} = \text{SHA256}(\text{RFC8785\_JCS}(\mathcal{D}_{\text{preproc}}))$$

where $\mathcal{D}_{\text{preproc}}$ contains sorted keys:
```json
{
  "contract_version": "1.0",
  "input_assumption": {
    "expected_channels": 3,
    "expected_dtype": "float32",
    "expected_layout": "HWC"
  },
  "name": "imagenet_preprocessing_pipeline",
  "operations": [
    {
      "op_type": "RESIZE",
      "op_version": "1.0",
      "parameters": {
        "aspect_ratio_policy": "STRETCH",
        "interpolation": "BILINEAR",
        "target_height": 224,
        "target_width": 224
      }
    },
    {
      "op_type": "NORMALIZE",
      "op_version": "1.0",
      "parameters": {
        "mean": [0.485, 0.456, 0.406],
        "std": [0.229, 0.224, 0.225]
      }
    }
  ],
  "output_guarantee": {
    "target_channels": 3,
    "target_dtype": "float32",
    "target_layout": "NCHW"
  },
  "schema_version": "1.0"
}
```

---

### 7. Contract Compatibility Verification

The `check_contract_compatibility` function validates:
1. **Input Alignment**: `InputIdentity` layout, dtype, channel count, and rank match contract `input_assumption`.
2. **Model Contract Alignment**: Preprocessing `output_guarantee` matches Phase 7 model input interface (`layout`, `dtype`, `channel_count`).
3. **Absence / Unverifiability**: Returns `UNAVAILABLE` if model contract is absent, or `UNVERIFIABLE` if model verification is indeterminate.

---

### 8. Security & Resource Bounds
- **Zero Arbitrary Execution**: No `eval`, `exec`, `pickle`, `subprocess`, or dynamic callbacks.
- **Air-Gap Guarantee**: 100% process-local, zero network sockets.
- **Resource Bounds**:
  - Max Operations per Contract: 32
  - Max Spatial Dimension: $8,192 \times 8,192$
  - Max Preprocessed Tensor Elements: $50,000,000$
- **Database Schema Changes**: 0
