# Phase 12.8 — Proof & Provenance Integration Verification Plan

**Status:** Authoritative Test & Verification Plan  
**Authority:** Phase 12.1 Universal Risk Architecture Freeze  

---

## 1. Test Suite Organization

The Phase 12.8 test suite is located in `tests/phase_12_8/`:

1. `test_proof_schema.py`:
   - Schema validation, immutability, canonical representation.
   - Proof confidence invariants (`VERIFIED` $\iff 1.0$, non-verified $\ne 1.0$).
   - Cryptographic `proof_result_hash` and `assessment_hash` calculation.

2. `test_valid_provenance.py`:
   - Valid signed provenance record verification.
   - Valid hash chain verification.
   - Evidence and ancestry binding verification.

3. `test_hash_chain_tampering.py`:
   - Mutated payload detection (`TAMPERED`).
   - Corrupted record hash detection.
   - Broken `previous_record_hash` detection.
   - Sequence gap / non-monotonic sequence detection.

4. `test_signature_mutations.py`:
   - Altered signature detection (`INVALID`).
   - Wrong public key verification failure.
   - Malformed signature format detection.
   - Unsigned proof evidence rejection.

5. `test_replay_protection.py`:
   - Duplicate record identity detection (`REPLAY_DETECTED`).
   - Duplicate nonce detection.
   - Replayed provenance across sessions.

6. `test_evidence_binding.py`:
   - Evidence ID mismatch detection (`INVALID`).
   - Evidence payload hash mismatch detection.
   - Finding ID reference validation.

7. `test_ancestry_binding.py`:
   - Ancestry substitution tests across each 5-tuple field (`sample_id`, `dataset_version_id`, `model_fingerprint`, `window_id`, `source_id`).

8. `test_scope_isolation.py`:
   - Cross-project proof reference rejection (`PROJECT_MISMATCH`).
   - Cross-asset isolation (Asset A failure does not affect unrelated Asset B).

9. `test_status_distinction.py`:
   - Distinct classification of `VERIFIED`, `INVALID`, `MISSING`, `UNAVAILABLE`, `TAMPERED`, `REPLAY_DETECTED`.

10. `test_proof_confidence_separation.py`:
    - Detection confidence preservation ($c_d$ untouched).
    - Proof non-compensability (proof failure forces `UniversalDecision.REJECT`).
    - Proof inviolability ($att = 1.0$).

11. `test_proof_determinism.py`:
    - Repeated verification determinism across 100 iterations.
    - Hash sensitivity under mutations.

12. `test_proof_security.py`:
    - AST static verification: Zero `eval`, `exec`, network calls, sockets.
    - Resource limit enforcement (max 5,000 items).
