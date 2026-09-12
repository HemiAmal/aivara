# Phase 10.2: Safe Inference Input Boundary Specification

**AIVARA — AI Verification & Assurance**  
**Subsystem:** Phase 10 — Inference Integrity  
**Phase:** 10.2 — Safe Inference Input Boundary  
**Status:** IMPLEMENTED & VERIFIED  

---

## 1. Objective

Phase 10.2 implements the **Safe Inference Input Boundary** as specified by the permanently frozen Phase 10.1 architecture.

Its sole purpose is to establish a secure, deterministic, bounded, validated identity for an inference input transaction before it enters subsequent preprocessing, execution, postprocessing, output, and cryptographic provenance verification stages.

---

## 2. Input Types Supported

| Input Kind | Data Type / Representation | Structural Properties & Identity Binding |
|---|---|---|
| `TENSOR` | `numpy.ndarray` / numeric array | Rank 1–6, strictly positive dimensions, approved numeric dtype (`float32`, `float64`, `float16`, `int32`, `int64`, `int16`, `int8`, `uint8`, `bool`), C-contiguous byte hash, shape, layout descriptor. |
| `BATCHED_TENSOR` | `numpy.ndarray` (leading batch dim) | Batch dimension $N \le 128$, rank $\ge 2$, layout in `NHWC`, `NCHW`, or `BATCH_VECTOR_2D`. |
| `IMAGE_FILE` | Local regular file path (`.png`, `.jpg`, `.jpeg`, `.webp`, `.bmp`, `.tif`, `.tiff`) | Dual identity: **Raw File SHA-256** (disk bytes) + **Canonical Decoded Pixel SHA-256** (sRGB 8-bit uncompressed buffer prefixed with `aivara-pixels-v1:W:H:C:`). |
| `STRUCTURED` | JSON-compatible `dict` / `list` | RFC 8785 JSON Canonicalization Scheme (JCS) serialization + SHA-256 content hashing. |

---

## 3. Security Boundary & Prohibitions

The Safe Inference Input Boundary treats all inputs as **untrusted data only**. It guarantees:
- **Zero Arbitrary Execution**: Strict prohibition of `eval()`, `exec()`, `pickle.loads()`, `subprocess`, `os.system()`, `os.popen()`, dynamic imports, or shell executions.
- **Strict Path Sandboxing**: Prohibits directory traversal (`..`), UNC network paths (`\\\\`, `//`), URL schemes (`http://`, `file://`, `ftp://`), Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`), and escapes outside authorized root directories.
- **Fail-Closed on Non-Finite Values**: Numerical tensor inputs containing `NaN`, `+Inf`, or `-Inf` fail closed immediately (`NonFiniteValueError` / `INVALID` status). No silent substitution (0, mean, clipping) is permitted.
- **Source Immutability**: The caller's input tensors, images, and data structures are never mutated in place. All conversions (such as contiguous byte extraction) operate on independent views or copies.

---

## 4. Resource Boundaries & Allocation Safety

Resource allocation limits are validated *prior* to materializing or copying large structures:

$$\text{Memory Check: } \left(\prod_{i=0}^{R-1} \text{shape}[i]\right) \times \text{itemsize} \le \text{max\_tensor\_memory\_bytes}$$

- **Max File Size:** 50 MB
- **Max Image Dimensions:** $8192 \times 8192$ px (~67.1 MP)
- **Max Tensor Rank:** 6
- **Max Tensor Elements:** 50,000,000
- **Max Tensor Memory:** 200 MB
- **Max Batch Size:** 128
- **Max Structured Payload:** 10 MB

---

## 5. Input Identity Models

### 5.1 Tensor Canonical Descriptor & Hash

$$\text{TensorDescriptor} = \text{JCS}\left(\{ \text{"byte\_hash"}: \text{SHA256}(\text{C-contiguous bytes}), \text{"dtype"}: \text{dtype\_str}, \text{"element\_count"}: N, \text{"layout"}: \text{layout}, \text{"rank"}: R, \text{"schema\_version"}: \text{"1.0"}, \text{"shape"}: [d_0, \dots, d_{R-1}] \}\right)$$

$$\text{CanonicalHash} = \text{SHA-256}(\text{TensorDescriptor})$$

### 5.2 Image Dual-Identity Model

$$\text{RawFileHash} = \text{SHA-256}(\text{disk file bytes})$$

$$\text{CanonicalPixelHash} = \text{SHA-256}(\text{"aivara-pixels-v1:W:H:C:"} \,\|\, \text{sRGB row-major pixel bytes})$$

$$\text{ImageEnvelope} = \text{JCS}\left(\{ \text{"canonical\_pixel\_hash"}: \text{CanonicalPixelHash}, \text{"channels"}: C, \text{"color\_space"}: \text{"RGB"}, \text{"file\_size\_bytes"}: S, \text{"format"}: F, \text{"height"}: H, \text{"raw\_file\_hash"}: \text{RawFileHash}, \text{"schema\_version"}: \text{"1.0"}, \text{"width"}: W \}\right)$$

$$\text{InputId} = \text{SHA-256}(\text{ImageEnvelope})$$

---

## 6. Layout and Value Range Semantics

### 6.1 Layouts
- `GRAYSCALE_2D`: 2D tensor $(H, W)$
- `HWC`: 3D tensor $(H, W, C)$ where $C \in \{1, 3, 4\}$
- `CHW`: 3D tensor $(C, H, W)$ where $C \in \{1, 3, 4\}$
- `NHWC`: 4D tensor $(N, H, W, C)$ where $C \in \{1, 3, 4\}$
- `NCHW`: 4D tensor $(N, C, H, W)$ where $C \in \{1, 3, 4\}$
- `VECTOR_1D`: 1D feature vector $(D,)$
- `BATCH_VECTOR_2D`: 2D feature batch $(N, D)$
- `TENSOR_ND`: General $N$-D tensor
- `STRUCTURED`: Structured object
- `UNKNOWN`: Ambiguous channel placement (e.g. $(3, 224, 3)$) -> `UNVERIFIABLE` / `AmbiguousLayoutError`.

### 6.2 Value Ranges
- `UNIT_FLOAT`: $[0.0, 1.0]$
- `ZERO_CENTERED`: $[-1.0, 1.0]$
- `BYTE_INTEGER`: $[0, 255]$
- `UNBOUNDED_FLOAT`: Finite real numbers
- Incompatible actual values against declared ranges trigger `MISMATCHED` / `ValueRangeMismatchError`.

---

## 7. Status Taxonomy

- `VERIFIED`: Input is structural, finite, valid, bounded, and identity is established.
- `INVALID`: Structural failure (corrupted image, unsupported dtype, non-finite values, resource limit exceeded).
- `MISSING`: File not found or input is None.
- `UNAVAILABLE`: File unreadable due to OS permissions or I/O error.
- `MISMATCHED`: Declared layout or value range contradicts actual data.
- `UNVERIFIABLE`: Ambiguous layout where layout cannot be verified.

---

## 8. Interface to Phase 10.3

Phase 10.2 exposes:
- [`SafeInferenceInputBoundary`](file:///d:/Downloads/Projects/AiVara/backend/aivara/inference/input/boundary.py#L254)
- [`validate_inference_input()`](file:///d:/Downloads/Projects/AiVara/backend/aivara/inference/input/boundary.py#L42)
- [`InputIdentity`](file:///d:/Downloads/Projects/AiVara/backend/aivara/inference/input/models.py#L58)

Phase 10.3 consumes `InputIdentity` and performs cryptographic binding between the input identity and the Phase 7 Model Fingerprint and model contract.
