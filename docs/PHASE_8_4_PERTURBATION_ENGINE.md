# PHASE 8.4 — DETERMINISTIC CONTROLLED PERTURBATION & SENSITIVITY EXPERIMENT ENGINE

**Status:** APPROVED / FROZEN  
**Phase:** 8.4  
**Subsystem:** Behavioural Analysis  
**Repository:** AIVARA — AI Verification & Assurance  
**Verification Baseline:** 1141 / 1141 tests passing (100%) | 0 Regressions

---

## 1. Objective

Phase 8.4 implements the **Deterministic Controlled Perturbation & Sensitivity Experiment Engine** in the AIVARA Behavioral Analysis subsystem.

The engine establishes a mathematically rigorous, reproducible framework for generating controlled, bounded variations of valid model inputs:

$$\text{ORIGINAL INPUT} \xrightarrow[\text{Specification}]{\text{Controlled Transform}} \text{PERTURBED INPUT} \xrightarrow[\text{Safe Runtime}]{\text{Phase 8.2 Boundary}} \text{OBSERVED OUTPUT}$$

This phase provides the foundational input-variation experiments necessary for downstream behavioral consistency analysis (Phase 8.5) and behavioral anomaly detection (Phase 8.6).

---

## 2. Scope & Critical Boundary

Phase 8.4 is strictly an **experiment generation and transformation engine**. It adheres to the core principle of **Semantic Neutrality**:

```
PERTURBATION SENSITIVITY   ≠  ANOMALY
PERTURBATION SENSITIVITY   ≠  ATTACK SUCCESS
PERTURBATION RESPONSE      ≠  BACKDOOR
NUMERICAL DELTA            ≠  MALICIOUS INTENT
```

### Out-of-Scope (Deferred to Later Phases)
- **Phase 8.5:** Output stability / consistency analysis across perturbations.
- **Phase 8.6:** Statistical anomaly scoring (MAD / Robust z-score) and anomaly classification.
- **Phase 9:** Backdoor detection, trigger inversion, and attack classification.
- **Phase 10:** Inference integrity verification.
- **Phase 11:** Dataset / distribution shift analysis.
- **Phase 12:** Universal risk synthesis.
- **Phase 8.8:** REST API exposure.

---

## 3. Perturbation Taxonomy

Phase 8.4 defines an allowlisted, typed taxonomy of 7 bounded image perturbation transforms (`PerturbationType`):

| Perturbation Type | Description | Primary Parameters |
| :--- | :--- | :--- |
| `GAUSSIAN_NOISE` | Bounded additive normal noise. | `mean`, `std`, `seed` |
| `UNIFORM_NOISE` | Bounded additive uniform noise. | `min_val`, `max_val`, `seed` |
| `BRIGHTNESS` | Multiplicative linear brightness scaling. | `factor` |
| `CONTRAST` | Linear contrast scaling centered at range midpoint. | `factor` |
| `GAUSSIAN_BLUR` | Separable 2D Gaussian kernel convolution. | `kernel_size`, `sigma` |
| `JPEG_COMPRESSION` | Deterministic JPEG compression encoding/decoding. | `quality` |
| `SPATIAL_TRANSLATION` | 2D pixel displacement with border replication/constant fill. | `dx`, `dy`, `border_policy`, `fill_value` |

Arbitrary user-supplied transformation functions, dynamic scripts, and unallowlisted transforms are strictly prohibited.

---

## 4. Identity Model & Hashing

Every transformation and experiment possesses a deterministic, canonical 64-character lowercase SHA-256 identity hash.

### Perturbation Identity (`perturbation_id`)
Binds the canonical perturbation specification, source input digest, and PRNG seed using RFC 8785 JSON Canonicalization Scheme (JCS):

$$\text{perturbation\_id} = \text{SHA-256}\Big(\text{JCS}\big(\langle \text{source\_input\_hash}, \text{perturbation\_type}, \text{parameters}, \text{seed}, \text{implementation\_version} \rangle\big)\Big)$$

### Perturbed Input Identity (`perturbed_input_hash`)
Computed from the canonical contiguous C-order bytes, dtype, and shape of the transformed output array:

$$\text{perturbed\_input\_hash} = \text{SHA-256}\Big(\text{dtype} \mathbin{\Vert} \text{shape} \mathbin{\Vert} \text{array\_bytes}\Big)$$

### Experiment Identity (`experiment_id`)
Binds the execution scope and tenancy:

$$\text{experiment\_id} = \text{SHA-256}\Big(\text{JCS}\big(\langle \text{project\_id}, \text{source\_input\_id}, \text{source\_input\_hash}, \text{perturbation\_id}, \text{model\_id} \rangle\big)\Big)$$

---

## 5. Input Immutability

The engine strictly guarantees that **source inputs are never modified in place**.
- All transformations operate exclusively on isolated deep copies (`np.copy(image)`).
- Input verification checks confirm that original array bytes remain identical before and after transform execution.

---

## 6. Deterministic PRNG Isolation

All stochastic perturbations (`GAUSSIAN_NOISE`, `UNIFORM_NOISE`) utilize an explicit, isolated NumPy `Generator` initialized with an immutable `PCG64` bit generator:

```python
rng = np.random.Generator(np.random.PCG64(seed))
```

- Zero dependence on Python global `random.seed()`.
- Zero dependence on system time or non-deterministic entropy.
- Exact bit-level reproducibility is guaranteed across runs for identical parameter tuples.

---

## 7. Parameter Bounds & Ceilings (`PerturbationLimits`)

Hard ceilings prevent resource exhaustion and unconstrained parameter distortion:

| Limit Dimension | Default Ceiling | Hard Bound Constraint |
| :--- | :--- | :--- |
| `max_noise_std` | `1.0` | $\text{std} \le 1.0$ |
| `max_noise_amplitude` | `1.0` | $\text{max\_val} - \text{min\_val} \le 1.0$ |
| `brightness_factor` | `[0.0, 5.0]` | $0.0 \le \text{factor} \le 5.0$ |
| `contrast_factor` | `[0.0, 5.0]` | $0.0 \le \text{factor} \le 5.0$ |
| `max_blur_kernel_size` | `31` | Odd integer in $[3, 31]$ |
| `max_blur_sigma` | `10.0` | $0.01 \le \sigma \le 10.0$ |
| `jpeg_quality` | `[1, 100]` | $1 \le \text{quality} \le 100$ |
| `max_translation_pixels` | `100` | $|\text{dx}|, |\text{dy}| \le 100$ |
| `max_image_elements` | `50,000,000` | Total elements $\le 5 \times 10^7$ |
| `max_perturbations_per_experiment`| `100` | Batch suite size $\le 100$ |

---

## 8. Transformation Details

### A. Gaussian Noise
Additive Gaussian noise sampled via isolated PRNG, scaled to value range, added to the float64 representation, clipped to representation bounds $[v_{\min}, v_{\max}]$, and cast to original dtype.

### B. Uniform Noise
Additive Uniform noise sampled uniformly in $[\text{min\_val}, \text{max\_val}]$, clipped to representation bounds, and cast to original dtype.

### C. Brightness Scaling
Linear scaling $I' = I \times \text{factor}$, clipped to representation bounds.

### D. Contrast Scaling
Linear scaling centered at range midpoint $\mu = \frac{v_{\min} + v_{\max}}{2.0}$:
$$I' = \mu + \text{factor} \times (I - \mu)$$
clipped to representation bounds.

### E. Gaussian Blur
Separable 1D Gaussian kernel filtering across horizontal and vertical spatial dimensions with edge-replicated boundary padding. Vectorized pure NumPy implementation ensuring cross-platform determinism without external binary dependencies.

### F. JPEG Compression
In-memory buffer encoding/decoding via Pillow with fixed compression parameters (`optimize=False`, `subsampling=0`). Exact image shape, channel arrangement, and dtypes are preserved.

### G. Spatial Translation
Sub-pixel / integer pixel displacement along spatial axes via cyclic roll with boundary zero-fill (`CONSTANT`) or edge replication (`REPLICATE`).

---

## 9. Input Types & Value Range Handling

- **`uint8`:** Implicit range $[0, 255]$.
- **Floating-point (`float32`, `float64`):** Uses declared `value_range` (e.g. $[0.0, 1.0]$, $[-1.0, 1.0]$, $[0.0, 255.0]$).
- Non-image dtypes (e.g., complex, int64) are rejected with `UNSUPPORTED_INPUT`.

---

## 10. Channel Semantics

- **Grayscale:** 2D $(H, W)$ or 3D $(H, W, 1)$ / $(1, H, W)$.
- **RGB:** 3D $(H, W, 3)$ or $(3, H, W)$.
- **RGBA:** 3D $(H, W, 4)$ or $(4, H, W)$ with alpha channel preservation.
- **Batch Tensors:** 4D $(N, C, H, W)$ or $(N, H, W, C)$.
- Zero silent transposition or color-space manipulation.

---

## 11. Numerical Safety & Non-Finite Trapping

- Inputs containing `NaN` or `Inf` are trapped before execution with `UNVERIFIABLE_INPUT`.
- Non-finite outputs are trapped with `TRANSFORMATION_ERROR`.
- Overflow and underflow are eliminated through float64 intermediate accumulators and explicit boundary clipping.

---

## 12. Resource Safety

- Pre-execution validation prevents memory exhaustion from oversized tensors ($> 5 \times 10^7$ elements).
- Suite generation is bounded by `max_perturbations_per_experiment` ceiling.

---

## 13. Experiment Representation (`PerturbationExperiment`)

Immutable Pydantic model capturing the end-to-end experiment lifecycle:
- `experiment_id`: Canonical JCS SHA-256 digest.
- `project_id`, `model_id`, `source_input_id`.
- `source_input_hash`, `perturbation_id`.
- `perturbation_type`, `parameters`, `seed`.
- `input_shape`, `input_dtype`, `output_shape`, `output_dtype`.
- `source_value_range`, `result_value_range`.
- `status`: `SUCCESS | INVALID_PARAMETER | UNSUPPORTED_INPUT | UNVERIFIABLE_INPUT | RESOURCE_LIMIT | TRANSFORMATION_ERROR`.
- `created_at`: ISO 8601 UTC timestamp.

---

## 14. Reproducibility Guarantee

For any identical combination of:
$$\langle \text{source input}, \text{perturbation type}, \text{parameters}, \text{seed}, \text{version} \rangle$$
the engine produces byte-for-byte identical perturbed arrays, `perturbation_id`, and `perturbed_input_hash`.

---

## 15. Security Boundary

- Zero arbitrary code execution or dynamic function evaluation (`eval`/`exec`).
- Zero subprocess creation.
- Zero network socket creation.
- Zero file access outside designated workspaces.
- Strict multi-tenant project isolation.

---

## 16. Offline Operation

All transformations and experiments execute 100% offline and air-gapped without remote calls or telemetry.

---

## 17. Database Boundary

**ZERO DATABASE SCHEMA CHANGES.**  
Perturbation models exist purely at domain and service levels. No database tables, columns, or migrations were introduced.

---

## 18. Phase 8.2 Safe Runtime Integration

Perturbed inputs generated by the engine can be executed directly through the Phase 8.2 `ControlledModelExecutor` without bypassing any resource ceilings, timeouts, or path restrictions.

---

## 19. Phase 8.3 Baseline Integration

Perturbation experiments bind directly to Phase 8.3 baseline input descriptors (`InputItemDescriptor`) via `source_input_hash` without mutating reference profiles.

---

## 20. Future Sensitivity Analysis Boundary

Phase 8.4 provides the input transformations. Sensitivity scoring, prediction stability, and consistency analysis will be implemented in **Phase 8.5**.

---

## 21. Test Results

- **Phase 8.4 Targeted Test Suite:** 24 / 24 PASS (100%)
- **Phase 8.3 Baseline Engine Suite:** 22 / 22 PASS (100%)
- **Phase 8.2 Runtime Boundary Suite:** 23 / 23 PASS (100%)
- **Phase 7 Model Integrity Suite:** 202 / 202 PASS (100%)
- **Full Repository Suite:** 1141 / 1141 PASS (100%)
- **Regressions:** 0

---

## 22. Known Limitations

1. **Declared Range Requirement:** Floating-point arrays must provide or conform to a declared value range (default $[0.0, 1.0]$) for meaningful clipping.
2. **JPEG Lossy Nature:** JPEG compression introduces lossy DCT quantization; bit-level reproduction is guaranteed within the same Pillow library build (`Pillow 12.3.0`).
3. **Single-Transform Architecture:** Phase 8.4 focuses on single, isolated transforms; arbitrary user-defined transformation pipelines are deferred to prevent combinatorial complexity.
