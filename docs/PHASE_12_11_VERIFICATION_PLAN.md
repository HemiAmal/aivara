# Phase 12.11 Verification Plan: Universal Audit & Compliance Reporting

**Document Status:** Approved & Frozen  
**Scope:** Test Suite Architecture & Verification Gates for Phase 12.11  

---

## 1. Test Suite Architecture (`tests/phase_12_11/`)

1. `test_audit_architecture.py`: Verifies architectural constants, schemas, requirement IDs, and threat coverage matrices.
2. `test_traceability_model.py`: Verifies bi-directional claim grounding from Report -> Decision -> Risk -> Finding -> Evidence -> Provenance.
3. `test_compliance_mapping.py`: Verifies 6-state compliance control evaluation across NIST AI RMF, EU AI Act, ISO/IEC 42001, and OWASP LLM Top 10, ensuring no false positive compliance on absent findings.
4. `test_deterministic_report_generation.py`: Verifies identical outputs produce identical canonical report descriptors and content hashes across multiple runs.
5. `test_cryptographic_integrity.py`: Verifies RFC 8785 JCS + SHA-256 hash generation, tamper detection, and fail-closed integrity checks.
6. `test_report_mutations.py`: Comprehensive mutation testing (mutating fields, evidence IDs, scores, decisions, proof statuses, compliance states) ensuring every mutation changes `report_hash` or fails verification.
7. `test_report_versioning_and_diff.py`: Verifies instance version increments, deterministic semantic diff calculation, and permutation invariance.
8. `test_audit_api_and_export.py`: Verifies FastAPI routes for report generation, retrieval, verification, comparison, and export (JSON, Markdown, Plaintext).
9. `test_security_redaction_and_bola.py`: Verifies automated scrubbing of secrets/tokens and cross-project BOLA access rejection.
10. `test_resource_governance.py`: Verifies ceiling enforcement on max assets, evidence items, and findings.
11. `test_security_ast.py`: Verifies zero dynamic execution (`eval`, `exec`, `__import__`) and zero external network sockets.
12. `test_end_to_end_audit_pipeline.py`: Comprehensive end-to-end audit evaluation from Phase 12.10 task completion through compliance report generation and export.

---

## 2. Verification Gates & Pass Criteria

- **Gate 1 (Phase 12.11 Dedicated Tests):** 100% pass rate across all `tests/phase_12_11/` modules.
- **Gate 2 (Phase 12 Regression Suite):** 100% pass rate across all Phase 12 test suites (`tests/phase_12_3` through `tests/phase_12_11`).
- **Gate 3 (Full Repository Suite):** 100% pass rate across entire repository (~2,585+ tests).
- **Gate 4 (Bytecode Compilation):** Clean compilation of `backend/aivara/universal/audit` and `tests/phase_12_11`.
- **Gate 5 (Frozen Phase Isolation):** `git status --porcelain` confirms zero modifications to frozen phases.
- **Gate 6 (Air-Gap Assurance):** Zero external network calls.
