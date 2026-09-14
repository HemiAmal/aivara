# PHASE 12.9 — VERIFICATION & TEST PLAN

**Author:** DeepMind Antigravity Pair Programmer  
**Phase:** 12.9 — Project & Multi-Asset Risk Aggregation  
**Status:** VERIFICATION PLAN FROZEN  

---

## 1. Verification Strategy

The Phase 12.9 test suite verifies the multi-asset and project-level risk aggregation engine across twelve distinct verification categories:

1. **Schema & Model Validation (`test_aggregation_schemas.py`)**:
   - Immutability of Pydantic models.
   - Field constraints, score bounds $[0.0, 1.0]$, IEEE-754 finite checks.
   - RFC 8785 JCS + SHA-256 canonical hashing.

2. **Asset Isolation (`test_asset_isolation.py`)**:
   - Independent assets in the same project maintain identical risk scores despite changes in unrelated assets.

3. **DAG Validation & Cycle Rejection (`test_dag_validation.py`)**:
   - Self-loops ($A \to A$), direct cycles ($A \to B \to A$), and indirect cycles ($A \to B \to C \to A$) fail closed with `DependencyCycleError`.

4. **Chain Identification (`test_chain_identification.py`)**:
   - Single linear chains, branching/forking structures, merging structures, disconnected subgraphs.

5. **Lineage Propagation (`test_lineage_propagation.py`)**:
   - Upstream risk propagation along explicit edges with $\gamma_{\text{prop}}$.
   - Traversal depth bounds ($\Delta \le 5$).

6. **Risk Aggregation (`test_risk_aggregation.py`)**:
   - Sub-additive bounded composition.
   - Monotonicity: constituent risk increase $\implies$ aggregate risk non-decrease.
   - Ancestry collapse: shared root-cause events are damped, not double-counted.

7. **Project Aggregation (`test_project_aggregation.py`)**:
   - Peak dominance verification: high risk on a core asset dominates project risk.
   - Inter-asset damping prevents artificial score inflation.

8. **Proof-Aware Aggregation (`test_proof_aware_aggregation.py`)**:
   - Core deployed asset proof failure forces project $\mathbf{REJECT}$.
   - Peripheral sample asset proof failure forces asset $\mathbf{REJECT}$ and project at least $\mathbf{QUARANTINE}$.
   - Proof non-compensability: proof failure cannot be masked by low detection risk.

9. **Cross-Project Isolation (`test_cross_project_isolation.py`)**:
   - Strict tenant boundary enforcement; cross-project edges fail closed with `ScopeMismatchError`.

10. **Determinism & Hash Integrity (`test_aggregation_determinism.py`)**:
    - 100 repeated evaluations yield identical scores, hashes, and sorted traces.
    - Security-relevant mutations alter canonical hashes.

11. **Resource Governance (`test_resource_governance.py`)**:
    - Maximum asset, edge, and chain depth limits rejected with `AggregationResourceLimitExceededError`.

12. **AST Security & Offline Guarantees (`test_security_ast.py`)**:
    - AST scanning confirms zero `eval`, `exec`, `subprocess`, or network imports.

---

## 2. Regression Targets

- Dedicated Phase 12.9 tests: `tests/phase_12_9/`
- Phase 12 Universal Pipeline tests: `tests/test_universal_evidence_normalization.py`, `tests/phase_12_3`, `tests/phase_12_4`, `tests/phase_12_5`, `tests/phase_12_6`, `tests/phase_12_7`, `tests/phase_12_8`
- Phase 4 Cryptographic tests: `tests/test_signing.py`, `tests/test_chain.py`, `tests/test_verification.py`, `tests/test_keys.py`, `tests/test_tamper_detection.py`
- Full repository test suite: 2,525+ tests
