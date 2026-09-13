# PHASE 12.2 — VERIFICATION PLAN & TEST SPECIFICATION

**Milestone**: Phase 12.2 Implementation & Post-Audit Reconciliation  
**Subsystem**: Universal Risk Engine — Evidence Normalization Layer  
**Status**: RECONCILED & AUDIT-READY (51/51 Tests Passing)  

---

## 1. Test Suite Architecture

The Phase 12.2 verification suite is located at `tests/test_universal_evidence_normalization.py` and validates the following 8 comprehensive test categories (51 tests):

1. **Registry & Domain Integrity (3 Tests)**:
   - `test_default_registry_has_exact_seven_domains`: Verifies registry contains exactly the 7 frozen domains in canonical order.
   - `test_registry_rejects_duplicate_registration`: Verifies duplicate adapter registration raises `DuplicateAdapterError`.
   - `test_registry_rejects_unknown_domain`: Verifies unregistered domains raise `UnknownDomainError`.

2. **Domain-Specific Normalization (All 7 Domains) (7 Tests)**:
   - `test_normalize_dataset_integrity`: Validates Phase 5 normalization.
   - `test_normalize_contributor_risk`: Validates Phase 6 normalization.
   - `test_normalize_model_integrity`: Validates Phase 7 normalization.
   - `test_normalize_behavioral_analysis`: Validates Phase 8 normalization.
   - `test_normalize_backdoor_trigger`: Validates Phase 9 normalization.
   - `test_normalize_inference_integrity`: Validates Phase 10 normalization.
   - `test_normalize_distribution_shift`: Validates Phase 11 normalization.

3. **Security, Isolation & Boundary Enforcement (6 Tests)**:
   - `test_project_mismatch_rejected`: Validates cross-tenant rejection (`ProjectMismatchError`).
   - `test_missing_project_id_rejected`: Validates empty target project rejection.
   - `test_nan_float_rejected`: Validates rejection of `NaN` floats (`InvalidEvidenceError`).
   - `test_inf_float_rejected`: Validates rejection of `+Inf` floats.
   - `test_negative_inf_float_rejected`: Validates rejection of `-Inf` floats.
   - `test_proof_layer_requires_exact_1_0_confidence`: Validates proof confidence invariant.

4. **Ancestry Handling & Fail-Safe Behavior (1 Test)**:
   - `test_missing_ancestry_marked_unverified`: Validates missing ancestry is marked `UNVERIFIED` without fabricating data.

5. **Batch Processing, Deduplication & Resource Limits (4 Tests)**:
   - `test_batch_normalization_all_domains`: Validates batch normalization across all 7 domains.
   - `test_batch_deduplication_via_canonical_hash`: Validates constant-time hash deduplication.
   - `test_batch_with_rejections_and_successes`: Validates error isolation in batch runs.
   - `test_hard_resource_ceiling_enforcement`: Validates $E_{\max} = 5,000$ hard ceiling (`UniversalResourceLimitExceededError`).

6. **Determinism, Hashing & Immutability (3 Tests)**:
   - `test_deterministic_canonical_hashing`: Validates 5-run identical bit-exact hash reproduction.
   - `test_hash_avalanche_on_metric_mutation`: Validates hash avalanche on metric payload modifications.
   - `test_field_order_invariance`: Validates RFC 8785 JCS field order invariance.

7. **RFC 8785 JCS Canonicalization Conformance (14 Tests)**:
   - `test_rfc8785_dict_key_insertion_order`: Dict key order permutation invariance.
   - `test_rfc8785_nested_dictionaries`: Recursive nested object sorting.
   - `test_rfc8785_array_order_preservation`: Array element order significance.
   - `test_rfc8785_unicode_strings`: UTF-8 direct character preservation without escaping.
   - `test_rfc8785_escaped_control_characters`: Minimal required escapes (`\n`, `\t`, `\"`, `\\`).
   - `test_rfc8785_integers_and_safe_domain`: IEEE 754 safe integer formatting.
   - `test_rfc8785_positive_and_negative_floats`: Standard float formatting.
   - `test_rfc8785_zero_and_negative_zero_normalization`: `-0.0` normalized to `0`.
   - `test_rfc8785_scientific_notation_and_ecma262_numbers`: Exponent formatting.
   - `test_rfc8785_nan_rejection`: `NaN` rejected fail-closed.
   - `test_rfc8785_positive_inf_rejection`: `+Inf` rejected fail-closed.
   - `test_rfc8785_negative_inf_rejection`: `-Inf` rejected fail-closed.
   - `test_rfc8785_exact_repeated_canonical_bytes`: 100-run bitwise byte identity.

8. **Source Hash Verification, Confidence Semantics, Provenance & Identity (13 Tests)**:
   - `test_source_hash_correct_supplied_verified`: Valid supplied digest matched & accepted.
   - `test_source_hash_incorrect_supplied_fails_closed`: Forged/mismatched digest rejected (`SourceHashMismatchError`).
   - `test_source_hash_missing_supplied_recomputed`: Automatic source digest derivation.
   - `test_source_hash_raw_bytes_verification`: Verification against raw binary payload bytes.
   - `test_hashes_distinct_source_vs_normalized_vs_envelope`: Strict concept separation across the 3 hashes.
   - `test_confidence_detection_layer_preserved`: Detection confidence (e.g. 0.82) preserved as-is.
   - `test_confidence_proof_layer_requires_1_0`: Proof layer rejecting non-1.0 confidence.
   - `test_confidence_missing_detection_is_none`: Omitted detection confidence defaults to `None`.
   - `test_confidence_out_of_range_rejected`: Confidence outside $[0.0, 1.0]$ rejected.
   - `test_provenance_valid_hex_accepted`: Valid 64-char hex SHA-256 provenance hash accepted.
   - `test_provenance_invalid_hex_rejected`: Malformed provenance hash rejected.
   - `test_stable_evidence_id_deterministic`: Stable UUID5 distinct from cryptographic `canonical_hash`.
   - `test_100_percent_offline_no_sockets`: 100% air-gap socket guarding.
   - `test_no_upstream_mutation`: Deep-copy immutability verification.
