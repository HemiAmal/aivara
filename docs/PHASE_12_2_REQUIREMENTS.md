# PHASE 12.2 — REQUIREMENTS & THREAT TRACEABILITY MATRIX

**Milestone**: Phase 12.2 Implementation & Post-Audit Reconciliation  
**Subsystem**: Universal Risk Engine — Evidence Normalization & Adapters  
**Status**: RECONCILED & AUDIT-READY  

---

## 1. Requirements Traceability Matrix

| Requirement ID | Architecture Section | Requirement Description | Threat ID | Verification Test Function | Test Result |
| :--- | :--- | :--- | :--- | :--- | :---: |
| `REQ-12-NORM-001` | §2 Contract | Construct canonical immutable `UniversalEvidenceEnvelope` | `THREAT-12-NORM-001` | `test_normalize_dataset_integrity` | **PASS** |
| `REQ-12-NORM-002` | §3 Cryptography | Enforce RFC 8785 JCS canonical formatting | `THREAT-12-NORM-002` | `test_rfc8785_dict_key_insertion_order`, `test_rfc8785_nested_dictionaries` | **PASS** |
| `REQ-12-NORM-003` | §3 Cryptography | Recompute and verify supplied `source_payload_hash` | `THREAT-12-NORM-003` | `test_source_hash_correct_supplied_verified`, `test_source_hash_incorrect_supplied_fails_closed` | **PASS** |
| `REQ-12-NORM-004` | §2 Contract | Distinct `source_payload_hash`, `normalized_payload_hash`, `canonical_hash` | `THREAT-12-NORM-004` | `test_hashes_distinct_source_vs_normalized_vs_envelope` | **PASS** |
| `REQ-12-NORM-005` | §4 Adapters | Ingest Dataset Integrity evidence | `THREAT-12-NORM-005` | `test_normalize_dataset_integrity` | **PASS** |
| `REQ-12-NORM-006` | §4 Adapters | Ingest Contributor Risk evidence | `THREAT-12-NORM-005` | `test_normalize_contributor_risk` | **PASS** |
| `REQ-12-NORM-007` | §4 Adapters | Ingest Model Integrity evidence | `THREAT-12-NORM-005` | `test_normalize_model_integrity` | **PASS** |
| `REQ-12-NORM-008` | §4 Adapters | Ingest Behavioral Analysis evidence | `THREAT-12-NORM-005` | `test_normalize_behavioral_analysis` | **PASS** |
| `REQ-12-NORM-009` | §4 Adapters | Ingest Backdoor / Trigger evidence | `THREAT-12-NORM-005` | `test_normalize_backdoor_trigger` | **PASS** |
| `REQ-12-NORM-010` | §4 Adapters | Ingest Inference Integrity evidence | `THREAT-12-NORM-005` | `test_normalize_inference_integrity` | **PASS** |
| `REQ-12-NORM-011` | §4 Adapters | Ingest Distribution Shift evidence | `THREAT-12-NORM-005` | `test_normalize_distribution_shift` | **PASS** |
| `REQ-12-NORM-012` | §6 Registry | Reject unknown or duplicate domain adapters | `THREAT-12-NORM-006` | `test_registry_rejects_duplicate_registration`, `test_registry_rejects_unknown_domain` | **PASS** |
| `REQ-12-NORM-013` | §2 Security | Enforce strict multi-tenant `project_id` matching | `THREAT-12-NORM-007` | `test_project_mismatch_rejected`, `test_missing_project_id_rejected` | **PASS** |
| `REQ-12-NORM-014` | §2 Validation | Reject non-finite floats (`NaN`, `+Inf`, `-Inf`) | `THREAT-12-NORM-008` | `test_nan_float_rejected`, `test_inf_float_rejected`, `test_negative_inf_float_rejected` | **PASS** |
| `REQ-12-NORM-015` | §2 Confidence | Preserve detection confidence without distortion | `THREAT-12-NORM-009` | `test_confidence_detection_layer_preserved` | **PASS** |
| `REQ-12-NORM-016` | §2 Confidence | Enforce `confidence == 1.0` strictly on Proof Layer | `THREAT-12-NORM-010` | `test_confidence_proof_layer_requires_1_0` | **PASS** |
| `REQ-12-NORM-017` | §2 Confidence | Retain `None` for missing detection confidence | `THREAT-12-NORM-011` | `test_confidence_missing_detection_is_none` | **PASS** |
| `REQ-12-NORM-018` | §2 Ancestry | Preserve ancestry path without fabricating values | `THREAT-12-NORM-012` | `test_missing_ancestry_marked_unverified` | **PASS** |
| `REQ-12-NORM-019` | §2 Provenance | Validate and preserve SHA-256 provenance hashes | `THREAT-12-NORM-013` | `test_provenance_valid_hex_accepted`, `test_provenance_invalid_hex_rejected` | **PASS** |
| `REQ-12-NORM-020` | §5 Governance | Enforce session ceiling $E_{\max} \le 5,000$ | `THREAT-12-NORM-014` | `test_hard_resource_ceiling_enforcement` | **PASS** |
| `REQ-12-NORM-021` | §6 Normalizer | Constant-time deduplication via `canonical_hash` | `THREAT-12-NORM-015` | `test_batch_deduplication_via_canonical_hash` | **PASS** |
| `REQ-12-NORM-022` | §6 Normalizer | Deterministic multi-key output sorting | `THREAT-12-NORM-002` | `test_deterministic_canonical_hashing`, `test_field_order_invariance` | **PASS** |
| `REQ-12-NORM-023` | §1 Boundary | Zero universal risk calculation in normalization | `THREAT-12-NORM-011` | Code & schema inspection | **PASS** |
| `REQ-12-NORM-024` | §1 Boundary | 100% offline air-gap execution | `THREAT-12-NORM-007` | `test_100_percent_offline_no_sockets` | **PASS** |
| `REQ-12-NORM-025` | §1 Boundary | Zero mutation of upstream evidence records | `THREAT-12-NORM-001` | `test_no_upstream_mutation` | **PASS** |

---

## 2. Threat Coverage Matrix

| Threat ID | Threat Name | Mitigating Architectural Invariant | Verification Test | Status |
| :--- | :--- | :--- | :--- | :---: |
| `THREAT-12-NORM-001` | In-Place Record Tampering | Immutability (`frozen=True`) and deep copy isolation | `test_no_upstream_mutation` | **MITIGATED** |
| `THREAT-12-NORM-002` | Canonicalization Mismatch | Strict RFC 8785 JCS UTF-16 code unit ordering | `test_rfc8785_dict_key_insertion_order` | **MITIGATED** |
| `THREAT-12-NORM-003` | Forged Source Digest | Authoritative source re-computation and mismatch fail-closed | `test_source_hash_incorrect_supplied_fails_closed` | **MITIGATED** |
| `THREAT-12-NORM-004` | Hash Domain Confusion | Strict cryptographic separation of the 3 payload/envelope hashes | `test_hashes_distinct_source_vs_normalized_vs_envelope` | **MITIGATED** |
| `THREAT-12-NORM-005` | Upstream Format Drift | Strict Pydantic domain models per adapter | `test_batch_normalization_all_domains` | **MITIGATED** |
| `THREAT-12-NORM-006` | Rogue Domain Injection | Closed 7-domain registry rejecting arbitrary extensions | `test_registry_rejects_duplicate_registration` | **MITIGATED** |
| `THREAT-12-NORM-007` | Cross-Tenant Leakage | Mandatory `project_id` matching on every envelope | `test_project_mismatch_rejected` | **MITIGATED** |
| `THREAT-12-NORM-008` | Non-Finite Float Poisoning | Recursive validation rejecting `NaN`, `+Inf`, `-Inf` | `test_nan_float_rejected` | **MITIGATED** |
| `THREAT-12-NORM-009` | Confidence Inflation | Preservation of original upstream confidence without forced 1.0 | `test_confidence_detection_layer_preserved` | **MITIGATED** |
| `THREAT-12-NORM-010` | Invalid Proof Confidence | Strict enforcement that `PROOF` layer confidence equals 1.0 | `test_confidence_proof_layer_requires_1_0` | **MITIGATED** |
| `THREAT-12-NORM-011` | Confidence-as-Risk Fallacy | Zero risk derivation from evidence confidence | Code audit | **MITIGATED** |
| `THREAT-12-NORM-012` | Fabricated Provenance | Explicit `AncestryStatus.UNVERIFIED` for missing lineage | `test_missing_ancestry_marked_unverified` | **MITIGATED** |
| `THREAT-12-NORM-013` | Malformed Provenance Digest | Strict 64-char hex SHA-256 regex/character validation | `test_provenance_invalid_hex_rejected` | **MITIGATED** |
| `THREAT-12-NORM-014` | Memory/CPU DoS Exhaustion | Hard ceilings ($E_{\max}=5,000$, payload $\le 1\text{ MB}$, depth $\le 16$) | `test_hard_resource_ceiling_enforcement` | **MITIGATED** |
| `THREAT-12-NORM-015` | Redundant Graph Expansion | Constant-time canonical hash deduplication | `test_batch_deduplication_via_canonical_hash` | **MITIGATED** |
