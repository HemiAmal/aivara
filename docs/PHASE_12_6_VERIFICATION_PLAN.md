# Phase 12.6 — Universal Risk Computation Verification Plan

**Status:** Authoritative Verification Plan  
**Authority:** Phase 12.1 Universal Risk Architecture Freeze  
**Module:** `aivara.universal.risk`  

---

## 1. Verification Strategy

The Phase 12.6 verification suite ensures complete mathematical fidelity, boundary isolation, cryptographic determinism, and safety across 4 testing dimensions:

1. **Unit & Functional Tests (`test_universal_risk_computation.py`):**
   - Empty graph zero risk ($R=0.0$).
   - Single evidence risk computation.
   - Intra-cluster damping ($\lambda_{\text{intra}} = 0.15$).
   - Multiple independent clusters composition ($R(A) = 1 - \prod (1 - S(C_k))$).
   - Phase 12.5 correlation integration & detection attenuation.
   - Proof-layer inviolability ($att = 1.0$).
   - Multi-asset universal risk computation.
   - Project boundary isolation.

2. **Adversarial Mutation Tests (`test_risk_computation_mutations.py`):**
   - 20/20 targeted mutations covering M1 through M20 (weights, confidences, severities, ancestry clustering, project/asset isolation, correlation hashes, NaN/Inf injection, bounds clamps, decision leakage, aggregation leakage).

3. **AST & Static Boundary Audit (`test_risk_computation_traceability.py`):**
   - AST inspection of `aivara.universal.risk.engine` and `aivara.universal.risk.schemas`.
   - Proves zero network imports (`socket`, `requests`, `urllib`, `httpx`).
   - Proves zero decision dispositions (`ACCEPT`, `REVIEW`, `QUARANTINE`, `REJECT`).
   - Proves zero proof rejection overrides in computation engine.
   - Proves zero project/chain risk aggregation in `UniversalRiskComputationEngine`.

4. **Full Universal Evidence Regression:**
   - Phases 12.2, 12.3, 12.4, 12.5, 12.6 complete integration pass.
   - Full repository non-regression pass.
