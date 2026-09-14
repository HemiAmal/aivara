# Phase 12.7 — Policy & Decision Engine Verification Plan

**Status:** Authoritative Test & Verification Plan  
**Authority:** Phase 12.1 Universal Risk Architecture Freeze  

---

## 1. Test Suite Organization

The Phase 12.7 test suite is located in `tests/phase_12_7/`:

1. `test_policy_schema.py`:
   - Valid policy creation and immutability.
   - Requirement fields, versions, and limits.
   - Cryptographic `policy_hash` calculation and tampering detection.
   - Resource governance ceilings (max 100 rules).

2. `test_threshold_evaluation.py`:
   - Exact boundary verification: `0.000000`, `0.299999`, `0.300000`, `0.649999`, `0.650000`, `0.849999`, `0.850000`, `1.000000`.
   - Threshold gap detection and fail-closed rejection.
   - Threshold overlap detection and fail-closed rejection.
   - Custom threshold band evaluation.

3. `test_rule_evaluation.py`:
   - Declarative operator evaluation (`EQUALS`, `GREATER_THAN`, `IN`, `CONTAINS`).
   - Single matching rule vs multiple matching rules.
   - Monotonic escalation (`ACCEPT` -> `REVIEW` -> `QUARANTINE` -> `REJECT`).
   - Priority-based conflict resolution.
   - Duplicate rule ID detection and rejection.

4. `test_policy_engine_determinism.py`:
   - Repeated evaluations across identical inputs producing identical `policy_hash`, `decision_hash`, and traces.
   - Monotonicity verification over continuous risk range $[0.0, 1.0]$.
   - Independent mutation verification (mutating policy ID, version, risk score, decision changes decision hash).

5. `test_policy_mutations.py`:
   - Risk score out-of-bounds ($R < 0.0$, $R > 1.0$, NaN, +Inf).
   - Missing or tampered `risk_hash`.
   - Missing required assessment fields.
   - Disabled policy rejection.

6. `test_policy_traceability.py`:
   - Trace completeness (policy identity, risk identity, threshold trace, rule traces, matched rules, reason).
   - Requirement verification mapping (`REQ-12-POL-001` through `REQ-12-POL-020`).
   - Threat mitigation mapping (`THREAT-12-POL-001` through `THREAT-12-POL-015`).

7. `test_policy_security.py`:
   - AST inspection: Zero `eval`, `exec`, `os.system`, `subprocess`, socket / network calls.
   - Offline air-gap verification.
   - Bounded execution verification ($O(R)$ where $R \le 100$).
