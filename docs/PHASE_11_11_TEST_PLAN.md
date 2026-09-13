# Phase 11.11 — Comprehensive Distribution Shift Verification
## Master Verification Test Plan

**Document ID:** `DOC-11-11-TEST-PLAN`  
**Phase:** Phase 11.11 (Verification Planning & Architecture Only)  
**Target Execution Phase:** Phase 11.11.2 (Post-Architecture Freeze)  
**Status:** Permanent Freeze Baseline  

---

### 1. Test Suite Architecture

The Phase 11.11 verification test suite will be structured into 7 dedicated test classes organized under `tests/test_distribution_shift_comprehensive_verification.py` (or partitioned into modular verification files adhering to repository conventions), validating all 85 formal requirements across the 12 verification layers.

```
tests/test_distribution_shift_comprehensive_verification.py
 ├── TestLayer1UnitStatisticalCorrectness (REQ-001 - REQ-010)
 ├── TestLayer2ComponentIntegration (REQ-011 - REQ-020)
 ├── TestLayer3CrossComponentConsistency (REQ-021 - REQ-027)
 ├── TestLayer4EndToEndAssuranceIntegration (REQ-028 - REQ-037)
 ├── TestLayer5ApiTaskOrchestration (REQ-038 - REQ-048)
 ├── TestLayer6SecurityAuthorizationBOLA (REQ-049 - REQ-055)
 ├── TestLayer7DeterminismRepeatability (REQ-056 - REQ-062)
 ├── TestLayer8ResourceGovernanceComplexity (REQ-063 - REQ-067)
 ├── TestLayer9CryptographicIntegrity (REQ-068 - REQ-073)
 ├── TestLayer10OfflineAirGapCompliance (REQ-074 - REQ-077)
 ├── TestLayer11NonRegressionSuite (REQ-078 - REQ-081)
 └── TestLayer12AdversarialMutationResistance (REQ-082 - REQ-085, MUT-001 - MUT-020)
```

---

### 2. Synthetic Multi-Modal Test Fixture Architecture

To ensure 100% offline, deterministic, and self-contained execution, the test suite utilizes parameterized synthetic data generators without downloading external datasets or models:

1. **Tabular Feature Generator (`synthetic_tabular_fixture`):**
   - Reference population $\mathcal{P}_{\text{ref}}$: $N=1000$ samples with 4 continuous features ($X_1 \sim \mathcal{N}(0, 1), X_2 \sim \text{Exp}(1.0), X_3 \sim \text{Uniform}(0, 10), X_4 \sim \mathcal{N}(5, 2)$), 2 categorical features ($C_1 \in \{A, B, C\}, C_2 \in \{\text{Low}, \text{Med}, \text{High}\}$), and 1 binary label ($Y \in \{0, 1\}$).
   - Target populations $\mathcal{P}_{\text{tgt}}$:
     - `stationary`: identical parameters (seed 43).
     - `mild_shift`: shift on $X_1 \sim \mathcal{N}(0.5, 1.0)$ ($\text{PSI} \approx 0.12$).
     - `severe_shift`: shift on $X_1 \sim \mathcal{N}(3.0, 1.0), C_1 \sim P(A)=0.9$ ($\text{PSI} > 0.50, \text{TVD} > 0.40$).
     - `label_skew`: $P(Y=1) = 0.10$ vs baseline $0.50$.

2. **Image Descriptor Generator (`synthetic_image_fixture`):**
   - Reference image set: 50 synthetic $64 \times 64$ RGB/Grayscale images with balanced luminance ($\mu_{\text{gray}} = 128, \sigma = 30$).
   - Target image sets:
     - `clean`: identical luminance distribution.
     - `adversarial_darkened`: brightness shifted to $\mu_{\text{gray}} = 30$.
     - `corrupt_batch`: contains 5 valid images, 2 truncated byte files, 1 oversized file, and 1 non-image text file.

3. **Representation Embedding Generator (`synthetic_representation_fixture`):**
   - Generates normalized L2 unit vectors ($\Vert v \Vert_2 = 1.0$) in dimension $D = 128$.
   - Simulates reference clustering vs target cluster centroid translation for Kernel MMD and Energy Distance testing.

4. **Temporal Time-Series Generator (`synthetic_temporal_fixture`):**
   - Reference stream: $N=1000$ timestamped samples across 10 consecutive daily windows ($\mathcal{W}_0$ through $\mathcal{W}_9$).
   - Trajectory variants:
     - `stationary_stream`: constant mean over all 10 windows.
     - `abrupt_regime_shift`: step change at day 5 ($+4.0\sigma$).
     - `gradual_drift`: linear drift of $+0.3\sigma$ per window across windows 0 to 9.
     - `transient_spike`: anomalous excursion isolated to window 4 only.

5. **Contributor Source Generator (`synthetic_source_fixture`):**
   - Multi-contributor dataset with $G = 5$ distinct sources (`src_alpha`, `src_beta`, `src_gamma`, `src_delta`, `src_epsilon`).
   - Variants with balanced contributor contributions, sub-threshold groups ($N < 30$), and label-confounded source distributions.

---

### 3. Detailed Test Execution Plan by Layer

#### Suite 1: Pure Statistical & Mathematical Correctness (Layer 1)
- **Files / Functions:** `test_ks_2samp_validity`, `test_wasserstein_1d_accuracy`, `test_psi_quantile_smoothing`, `test_categorical_chi2_tvd`, `test_jsd_symmetry_bounds`, `test_kernel_mmd_permutation`, `test_energy_distance_nonnegativity`, `test_benjamini_hochberg_fdr_stepup`, `test_sample_size_floor_enforcement`, `test_sample_size_ceiling_subsampling`.
- **Pass Criteria:** All statistical invariants match analytical bounds within machine precision tolerances; $N < 30$ fails closed with `InsufficientDataError`.

#### Suite 2: Component Integration & Delegation (Layer 2)
- **Files / Functions:** `test_feature_engine_statistical_delegation`, `test_image_engine_descriptor_integration`, `test_representation_engine_onnx_pipeline`, `test_temporal_engine_window_partitioning`, `test_temporal_trajectory_state_machine`, `test_source_engine_5stage_canonicalization`, `test_source_engine_project_scoped_pseudonymization`, `test_source_engine_linear_topology`, `test_source_engine_simpsons_paradox_safeguard`, `test_assurance_engine_ancestry_clustering`.
- **Pass Criteria:** Zero duplicate statistical engines invoked; 100% of statistical tests routed to `StatisticalDriftEngine`; canonicalization and pseudonymization fully conform to specifications.

#### Suite 3: Cross-Component Consistency & Taxonomy (Layer 3)
- **Files / Functions:** `test_population_count_reconciliation_across_engines`, `test_contract_hash_immutability_across_engines`, `test_schema_definition_symmetry`, `test_consistent_dual_gating_thresholds`, `test_descriptive_finding_type_taxonomy`, `test_evidence_layer_categorization_detection_vs_proof`, `test_zero_duplicate_statistical_implementations`.
- **Pass Criteria:** Emitted profile headers, sample counts, and hashes remain identical across engines; all findings have `evidence_layer="detection"`.

#### Suite 4: End-to-End Multi-Modal Assurance Integration (Layer 4)
- **Files / Functions:** `test_multimodal_correlation_damping`, `test_bounded_asymptotic_risk_aggregation`, `test_disposition_policy_threshold_mapping`, `test_proof_layer_non_compensability_override`, `test_fail_closed_insufficient_evidence`, `test_integrated_profile_hash_integrity`, `test_evidence_set_hash_invariance`, `test_policy_hash_attestation`, `test_strict_non_attribution_descriptive_findings`, `test_full_lineage_graph_linkage`.
- **Pass Criteria:** $R \in [0.0, 1.0]$; proof failure forces $\mathbf{REJECT}$; correlation damping applies $\lambda_{\text{corr}} = 0.10$; zero accusatory terminology in outputs.

#### Suite 5: REST API & Asynchronous Task Orchestration (Layer 5)
- **Files / Functions:** `test_api_async_task_creation_202`, `test_api_async_threadpool_execution`, `test_api_task_state_machine_transitions`, `test_api_idempotency_request_fingerprinting`, `test_api_idempotency_conflict_409`, `test_api_cooperative_task_cancellation`, `test_api_sse_event_streaming`, `test_api_sse_reconnection_replay_last_event_id`, `test_api_result_retrieval_200`, `test_api_result_retrieval_incomplete_409`, `test_api_sanitized_error_responses`.
- **Pass Criteria:** FastAPI endpoints return enveloped `ApiResponse[T]`; SSE streaming functions with sequence numbers and replay buffer; task state machine transitions linearly.

#### Suite 6: Security & Multi-Tenant Isolation (Layer 6)
- **Files / Functions:** `test_bola_project_isolation_404`, `test_path_traversal_rejection`, `test_remote_url_rejection`, `test_sse_subscriber_limit_429`, `test_payload_size_limit_413`, `test_contributor_salt_secrecy`, `test_safe_deserialization_no_pickle`.
- **Pass Criteria:** Cross-project requests return HTTP 404; path traversal strings rejected; zero unsafe deserialization calls.

#### Suite 7: Determinism & Thread-Safety (Layer 7)
- **Files / Functions:** `test_end_to_end_pipeline_repeatability_seed42`, `test_permutation_test_seed_determinism`, `test_utc_microsecond_timestamp_formatting`, `test_temporal_multikey_sorting_order`, `test_rfc8785_jcs_canonical_key_ordering`, `test_floating_point_digest_consistency`, `test_concurrent_task_execution_thread_safety`.
- **Pass Criteria:** Repeated executions produce bit-for-bit identical cryptographic digests and results; concurrent thread runs match serial execution.

#### Suite 8: Resource Governance & Complexity (Layer 8)
- **Files / Functions:** `test_temporal_window_limit_cap_k50`, `test_source_group_limit_cap_g50`, `test_dimensionality_bound_cap_d4096`, `test_source_linear_complexity_scaling`, `test_memory_boundedness_under_100mb`.
- **Pass Criteria:** Hard limits enforced; $O(G)$ linear complexity verified; heap delta $< 100\text{MB}$.

#### Suite 9: Cryptographic Attestation & Digest Verification (Layer 9)
- **Files / Functions:** `test_contract_hash_rfc8785_sha256`, `test_population_hash_integrity`, `test_analytical_profile_hash_integrity`, `test_integrated_assurance_profile_hash`, `test_api_request_fingerprint_hashing`, `test_operational_id_vs_cryptographic_hash_separation`.
- **Pass Criteria:** All digests conform to RFC 8785 JCS + SHA-256; operational UUIDs omitted from content hashes.

#### Suite 10: 100% Offline Air-Gap Verification (Layer 10)
- **Files / Functions:** `test_zero_outbound_network_sockets`, `test_zero_external_telemetry_packages`, `test_zero_remote_model_downloads`, `test_local_sqlite_persistence_airgap`.
- **Pass Criteria:** 0 network calls under socket interceptor; 0 telemetry packages in AST scan; 100% local persistence.

#### Suite 11: Non-Regression Guarantee (Layer 11)
- **Files / Functions:** `test_full_repository_baseline_2102_pass`, `test_zero_new_database_migrations`, `test_zero_new_dependencies`, `test_zero_frozen_backend_code_changes`.
- **Pass Criteria:** Full repository passes 2,102 / 2,102 tests; 0 schema changes; 0 modified lines in frozen backend modules.

#### Suite 12: Adversarial Mutation & Tampering Suite (Layer 12)
- **Files / Functions:** `test_adversarial_mutations_mut001_to_mut020` executing all 20 test cases defined in `docs/PHASE_11_11_MUTATION_MATRIX.md`.
- **Pass Criteria:** 100% of mutation assertions pass.

---

### 4. Gating & Acceptance Criteria

Execution of the Phase 11.11 verification suite in Phase 11.11.2 will require:
1. **100% Test Pass Rate:** 0 failures, 0 errors across all verification test cases.
2. **Preservation of 2,102 Baseline Tests:** Baseline tests + new comprehensive verification tests all pass cleanly.
3. **Zero Production Changes:** 0 lines of code modified in `backend/aivara/drift/` and `backend/aivara/assurance/`.
4. **Zero Database Migrations:** 0 changes to SQLite tables or Alembic migration history.
5. **Zero External Dependencies:** 0 packages added to python environment.
