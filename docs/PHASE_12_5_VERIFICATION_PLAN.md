# Phase 12.5 — Verification Plan & Test Strategy

**Phase:** Phase 12.5 Evidence Dependency & Correlation Modeling  
**Status:** Executed & Certified  

---

## 1. Test Suite Architecture

The test suite in `tests/phase_12_5/` covers four primary verification domains:

1. **`test_correlation_matrix.py` (Structural Matrix Invariants):**
   - Exact 7-domain canonical sequence assertion.
   - Default canonical matrix validation (dimension 7x7, symmetry, zero diagonal, [0,1] bounds).
   - Zero matrix validation (all-zero independent domains).
   - Cryptographic hash determinism and sensitivity.
   - Rejection of asymmetry, non-zero diagonal, out-of-range values, non-finite values (NaN/Inf), and invalid domain order.

2. **`test_dependency_damping.py` (Core Dependency Damping Behaviors):**
   - Zero correlation matrix produces 1.0 attenuation factors.
   - Inactive domains contribute zero damping to active domains.
   - Cross-domain attenuation computation ($att_j = \prod (1 - C_{ij} \cdot \bar{S}_i)$).
   - Rejection of cross-project evaluation.
   - Proof-layer inviolability (proof evidence is unattenuated with zero decision leakage).

3. **`test_correlation_mutations.py` (Adversarial Mutations M1–M20):**
   - Complete coverage of all 20 mutation vectors (M1–M20).

4. **`test_correlation_traceability.py` (Static AST Boundary Audit):**
   - Zero forbidden responsibilities (no policy engine, no proof overrides, no risk calculators, no decision enums).
   - Zero decision/disposition fields in schemas.
   - Analytical data quality propagation without decision routing.

---

## 2. Regression Results

- **Phase 12.5 Suite:** 37/37 passed.
- **Universal Evidence Stack (12.2 + 12.3 + 12.4 + 12.5):** 195/195 passed.
- **Full Repository Suite:** 2,417/2,417 passed.
- **Bytecode Compilation:** Passed with 0 errors (`python -m compileall backend tests`).
