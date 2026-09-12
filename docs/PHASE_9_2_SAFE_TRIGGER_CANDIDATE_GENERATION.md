# PHASE 9.2 — SAFE TRIGGER CANDIDATE GENERATION

**AIVARA — AI Verification & Assurance**  
**Document ID:** `DOC-AIVARA-PHASE-9.2-CANDIDATES`  
**Status:** COMPLETE & FROZEN  
**Upstream Architecture:** [PHASE 9.1 — BACKDOOR / TRIGGER ANALYSIS ARCHITECTURE & REQUIREMENTS](file:///d:/Downloads/Projects/AiVara/docs/PHASE_9_1_BACKDOOR_TRIGGER_ARCHITECTURE.md) (ADR-061 – ADR-084)  
**Downstream Consumer:** PHASE 9.3 — TRIGGER TRANSFORMATION ENGINE  

---

## 1. MISSION & SCOPE

Phase 9.2 establishes the authoritative, secure, deterministic, and bounded subsystem that generates synthetic trigger candidate specifications for defensive model verification within AIVARA.

### Core Principles
1. **Trigger Candidate ≠ Backdoor**: A trigger candidate is a deterministic mathematical specification of a bounded input transformation used to test model response stability under synthetic stimulus.
2. **Defensive Testing Boundary**: Phase 9.2 produces test stimuli specifications. It does NOT modify model weights, train models, poison datasets, implant backdoors, perform adversarial gradient optimization, or execute arbitrary code.
3. **Strict Resource Bounding**: All candidate generation is bounded by a hard ceiling of `MAX_CANDIDATES = 16` and spatial area constraints ($\le 25\%$ canvas area).

---

## 2. FROZEN v1 TRIGGER FAMILIES

Phase 9.2 implements exactly the four frozen v1 candidate families established in Phase 9.1:

| Family Enum | Description | Supported Parameters | Geometric Bounds |
| :--- | :--- | :--- | :--- |
| `SPATIAL_PATCH` | Localized solid or alpha-blended geometric patch | `shape` (`SQUARE`, `RECTANGLE`, `CIRCLE`), `relative_width`, `relative_height`, `relative_radius`, `fill_color`, `alpha`, `blend_mode` (`REPLACE`, `ALPHA_BLEND`) | $0.01 \le \text{dim} \le 0.50$, radius $\le 0.25$, area $\le 0.25$ |
| `COLOR_PATTERN_PATCH` | Localized chromatic / luminance shift | `color_space` (`RGB`), `channel_deltas` ($[-1.0, 1.0]$), `relative_width`, `relative_height`, `alpha`, `blend_mode` | $0.01 \le \text{dim} \le 0.50$, deltas $\in [-1.0, 1.0]$ |
| `TEXTURE_GRID` | Deterministic periodic spatial texture pattern | `primitive` (`CHECKER`, `GRID`, `STRIPE_HORIZONTAL`, `STRIPE_VERTICAL`, `DOT_GRID`), `stride_pixels` ($[2, 128]$), `line_width_pixels` ($[1, 32]$), `amplitude` ($[0.01, 1.0]$), `alpha` ($[0.0, 1.0]$), `color_channels`, `phase_offset` ($[0.0, 1.0]$) | Full canvas periodic modulation bounded by amplitude & stride |
| `LOCALIZED_PERTURBATION` | Bounded localized numerical perturbation | `mode` (`ADDITIVE_GAUSSIAN`, `ADDITIVE_UNIFORM`, `MULTIPLICATIVE_UNIFORM`), `relative_width`, `relative_height`, `amplitude` ($[0.001, 1.0]$), `noise_std` ($[0.001, 0.50]$), `clip_min`, `clip_max` | Localized window, noise bounded by amplitude/std, PCG64 random state |

### Deferred Families (Prohibited in v1)
- Frequency-domain / Fourier triggers
- Wavelet triggers
- Semantic style transfer
- Dynamic generative triggers
- 3D physical triggers
- Unconstrained gradient optimization
- Composite multi-trigger cascades

---

## 3. IMMUTABLE CANDIDATE SCHEMA

Candidate specifications are represented as immutable Pydantic models ([`TriggerCandidateSpec`](file:///d:/Downloads/Projects/AiVara/backend/aivara/backdoor/candidates/models.py#L163)):

```python
class TriggerCandidateSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "1.0.0"
    candidate_id: str
    candidate_family: TriggerFamilyEnum
    parameters: Dict[str, Any]
    placement: PlacementSpec
    input_constraints: InputConstraints
    random_seed: int
    transformation_version: str = "1.0.0"
    candidate_hash: str
```

### Supporting Constraint & Placement Models
- **[`PlacementSpec`](file:///d:/Downloads/Projects/AiVara/backend/aivara/backdoor/candidates/models.py#L123)**: Supports `FIXED_CORNER` (`BOTTOM_RIGHT`, `TOP_LEFT`, `TOP_RIGHT`, `BOTTOM_LEFT`, `CENTER`), `NORMALIZED_POSITION` ($x, y \in [0.0, 1.0]$), and `GRID_CELL` ($8 \times 8$ grid index $[0..7]$).
- **[`InputConstraints`](file:///d:/Downloads/Projects/AiVara/backend/aivara/backdoor/candidates/models.py#L148)**: Declares supported ranks ($[2, 3, 4]$), spatial shape bounds ($[16, 4096]$), expected channels, and value range domain (`UNIT_FLOAT` $[0, 1]$ or `BYTE_INT` $[0, 255]$).

---

## 4. CANONICAL IDENTITY & HASHING

Candidate identity is strictly deterministic and cryptographic.

### RFC 8785 JSON Canonicalization Scheme (JCS)
The canonical dictionary includes all semantic parameters influencing candidate output:
```json
{
  "candidate_family": "SPATIAL_PATCH",
  "input_constraints": { ... },
  "parameters": { ... },
  "placement": { ... },
  "random_seed": 42,
  "schema_version": "1.0.0",
  "transformation_version": "1.0.0"
}
```

### Hashing Pipeline
$$\text{canonical\_bytes} = \text{JCS}(\text{canonical\_dict})$$
$$\text{candidate\_hash} = \text{SHA-256}(\text{canonical\_bytes}) \quad (\text{64-character lowercase hexadecimal})$$

Non-deterministic, transient, or environment-specific values (e.g. wall-clock timestamps, random UUIDs, memory pointers, filesystem paths) are strictly excluded from `candidate_hash`.

---

## 5. RANDOMNESS & PCG64 STATE ISOLATION

Any stochastic component (such as localized Gaussian/uniform noise) is generated using an isolated NumPy Generator backed by the PCG64 bit generator:

$$\text{RNG} = \text{np.random.Generator}(\text{np.random.PCG64}(\text{random\_seed}))$$

- The seed is an explicit parameter in $[0, 2^{32} - 1]$.
- No reliance on global `random` or `np.random` state.
- Identical candidate specification + seed = exact byte-for-byte numerical array reproducibility.

---

## 6. RESOURCE LIMITS & BATCH MANAGEMENT

- **`MAX_CANDIDATES = 16`**: Frozen hard ceiling per assessment batch (ADR-064). Requests requesting $> 16$ candidates fail closed with `CandidateBudgetExceededError`.
- **Duplicate Detection**: Candidate hashes are indexed within batch generation. Duplicate specifications trigger `DuplicateCandidateError`.
- **Deterministic Ordering**: Candidate batches are always sorted lexicographically by `candidate_hash`.
- **Spatial Dimension Bounds**: Pattern synthesis is restricted to target shapes $16 \le H, W \le 4096$ and $1 \le C \le 4$ to prevent memory exhaustion attacks.

---

## 7. SECURITY BOUNDARIES & VALIDATIONS

1. **Parameters are Pure Data**: Strings in candidate parameters are checked against forbidden script, system call, and network patterns (`eval`, `exec`, `subprocess`, `os.system`, `__import__`, URLs, path traversal). Violations raise `SecurityValidationError`.
2. **Finite Float Trapping**: NaN and $\pm\infty$ values are rejected immediately with `InvalidCandidateParameterError`.
3. **Offline Invariant**: Zero network, cloud, or remote service dependencies. 100% local computation.
4. **Database Invariant**: Zero database schema changes (`DATABASE SCHEMA CHANGES = 0`). Candidates remain purely in-memory structures until evidence sealing in Phase 9.6.

---

## 8. ARCHITECTURAL DECISION RECORD

### ADR-085: Deterministic Trigger Candidate Specification and Bounded Generation Framework

**Status:** APPROVED & FROZEN  
**Context:**  
Phase 9.1 froze the backdoor and trigger analysis architecture (ADR-061 to ADR-084). Phase 9.2 requires a concrete, deterministic, and safe representation of synthetic trigger candidates to serve as controlled stimuli for subsequent transformation and statistical comparison.

**Decision:**
1. Define immutable frozen Pydantic models for the 4 v1 trigger families: `SPATIAL_PATCH`, `COLOR_PATTERN_PATCH`, `TEXTURE_GRID`, and `LOCALIZED_PERTURBATION`.
2. Bind candidate identity cryptographically using RFC 8785 JCS canonicalization and SHA-256 hashing.
3. Isolate stochastic perturbation generation using `np.random.PCG64` initialized from explicit seeds.
4. Enforce `MAX_CANDIDATES = 16` fail-closed limit and relative spatial dimension ceiling $\le 0.50$ (relative area $\le 0.25$).
5. Reject malicious string patterns, non-finite floats, and invalid ranges at model construction time.

**Consequences:**
- Guarantees 100% repeatable, tamper-evident candidate definitions across runs and platforms.
- Eliminates risk of trigger generators performing adversarial model poisoning or executing arbitrary code.
- Establishes a clean, stable input contract for Phase 9.3 transformation engine.

---

## 9. VERIFICATION & TEST SUMMARY

- **Targeted Test Suite**: [`tests/test_backdoor_candidates.py`](file:///d:/Downloads/Projects/AiVara/tests/test_backdoor_candidates.py)
  - 49 test cases covering all 4 families, PCG64 determinism, immutability, batch sorting, duplicate rejection, budget overflow ($>16$), NaN/Inf rejection, security string injection, placement modes, texture primitives, perturbation modes, and roundtrip serialization.
  - **Result**: 49 passed in 0.22s.
- **Phase 9.1 Architecture Contracts**: [`tests/test_backdoor_architecture_contracts.py`](file:///d:/Downloads/Projects/AiVara/tests/test_backdoor_architecture_contracts.py)
  - 8 test cases verifying ADR-061 to ADR-084 invariants.
  - **Result**: 8 passed in 0.18s.
- **Cumulative Phase 8 Behavioral Suite**: [`tests/test_behavioral_comprehensive.py`](file:///d:/Downloads/Projects/AiVara/tests/test_behavioral_comprehensive.py)
  - 43 test cases verifying full behavioral runtime integrity.
  - **Result**: 43 passed in 1.49s.
- **Database Schema**: 0 migrations, 0 tables modified.
