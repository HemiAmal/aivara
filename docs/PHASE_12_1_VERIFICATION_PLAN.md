# PHASE 12.1 — VERIFICATION PLAN SPECIFICATION
# Universal Risk Engine: Master Test Strategy, Verification Layers & Assurance Criteria

**Milestone**: Phase 12.1 Architecture & Requirements Freeze (Post-Audit Reconciled)  
**Authoritative Subsystem**: Universal Risk Engine (URE) / Universal Evidence + Risk Engine  
**Status**: MASTER VERIFICATION PLAN BASELINE  

---

## 1. Verification Strategy Overview

The Phase 12 Verification Plan establishes the comprehensive test architecture, verification layers, test suites, and acceptance criteria required to validate the Universal Risk Engine during future implementation phases.

Verification is organized into 12 structured layers, directly aligned with the repository's 12-layer verification standard:
1. **Layer 1**: Unit Correctness & Invariant Validation
2. **Layer 2**: Upstream Component Ingestion & Normalization
3. **Layer 3**: Evidence Graph & $N:M$ Junction Traversal
4. **Layer 4**: Hierarchical Multi-Asset Risk Mathematics
5. **Layer 5**: Dependency, Ancestry & $7 \times 7$ Correlation Damping
6. **Layer 6**: Proof-Layer Inviolability & Affected Scope Overrides
7. **Layer 7**: Versioned Cryptographic Policy Governance
8. **Layer 8**: REST API & Asynchronous Task Orchestration
9. **Layer 9**: Security, Multi-Tenant Isolation & Privacy
10. **Layer 10**: Cryptographic Integrity, Merkle Roots & Dossier Sealing
11. **Layer 11**: Resource Governance & 100% Offline Air-Gap Compliance
12. **Layer 12**: Adversarial Mutation Resistance & Repository Non-Regression

---

## 2. Layered Test Suite Specifications

### Layer 1: Unit Correctness & Invariant Validation
- **Target**: `UniversalEvidenceEnvelope`, schemas, enum definitions, input sanitization.
- **Traceable Requirements**: `REQ-12-ING-002`, `REQ-12-ING-003`, `REQ-12-ING-006`, `REQ-12-ING-007`, `REQ-12-GOV-008`.
- **Test Scenarios**:
  - Validation of finite numerical metrics (rejecting `NaN`, `+Inf`, `-Inf` with `InvalidEvidenceError`).
  - Validation of confidence boundaries ($[0.0, 1.0]$) and severity enums.
  - Evidence deduplication via constant-time SHA-256 hash comparisons.
  - Verification of non-attribution language invariants in finding and rationale formatters.

### Layer 2: Upstream Component Ingestion & Normalization
- **Target**: Multi-domain evidence adapters for the exact seven domains (Phases 5, 6, 7, 8, 9, 10, and 11).
- **Traceable Requirements**: `REQ-12-ING-001`, `REQ-12-ING-004`, `REQ-12-ING-005`, `REQ-12-ING-008`.
- **Test Scenarios**:
  - Ingestion of Phase 5 dataset quality metrics and label noise evidence.
  - Ingestion of Phase 6 Empirical Bayes contributor anomaly profiles.
  - Ingestion of Phase 7 structural model fingerprints and weight hashes.
  - Ingestion of Phase 8 behavioral stability metrics and perturbation flags.
  - Ingestion of Phase 9 backdoor trigger simulation and spectral signatures.
  - Ingestion of Phase 10 18-checkpoint inference verification records.
  - Ingestion of Phase 11 multi-modal distribution shift profiles.

### Layer 3: Evidence Graph & $N:M$ Junction Traversal
- **Target**: Graph construction, DAG traversal, $N:M$ junction resolution, cycle detection.
- **Traceable Requirements**: `REQ-12-GRP-001`, `REQ-12-GRP-002`, `REQ-12-GRP-003`, `REQ-12-GRP-004`, `REQ-12-GRP-005`, `REQ-12-GRP-006`, `REQ-12-GRP-007`, `REQ-12-GRP-008`.
- **Test Scenarios**:
  - Verification of $1:N$ and $N:M$ finding-evidence bindings projected from existing persisted entities.
  - Acyclic graph traversal ordering from Evidence $\to$ Findings $\to$ Lineage $\to$ Project Risk.
  - Injection of circular references and verification of immediate fail-closed `GraphCycleDetectedError`.
  - Traversal safety depth ceiling ($\Delta \le 5$) and breadth ceiling ($\beta \le 100$) enforcement.
  - Calculation of deterministic `evidence_graph_merkle_root`.

### Layer 4: Hierarchical Multi-Asset Risk Mathematics
- **Target**: Sub-additive saturation, cluster scoring, asset-level risk $R(A)$, cross-asset lineage $R_{\text{chain}}$, project risk $R_{\text{project}}$.
- **Traceable Requirements**: `REQ-12-RSK-001`, `REQ-12-RSK-002`, `REQ-12-RSK-003`, `REQ-12-RSK-004`, `REQ-12-RSK-005`, `REQ-12-RSK-006`, `REQ-12-RSK-007`, `REQ-12-RSK-008`.
- **Test Scenarios**:
  - Proof of mathematical boundedness ($R \in [0.0, 1.0]$) across extreme input ranges.
  - Monotonicity verification: adding evidence cannot decrease risk.
  - Score dilution resistance: flooding with low-severity items cannot reduce high-severity risk.
  - Dominance preservation: critical asset risk ($R(A) \ge 0.85$) dominates project risk $R_{\text{project}}$.
  - Lineage risk compounding along explicit DAG dependency chains ($R_{\text{chain}} \equiv 0.0$ if unlinked).

### Layer 5: Dependency, Ancestry & $7 \times 7$ Correlation Damping
- **Target**: Ancestry clustering, intra-cluster damping ($\lambda_{\text{intra}}$), symmetric $7 \times 7$ inter-domain correlation matrix ($\mathbf{C}$).
- **Traceable Requirements**: `REQ-12-COR-001`, `REQ-12-COR-002`, `REQ-12-COR-003`, `REQ-12-COR-004`, `REQ-12-COR-005`, `REQ-12-COR-006`.
- **Test Scenarios**:
  - Grouping multiple evidence items sharing the same parent artifact key and applying intra-cluster damping.
  - Validation of $7 \times 7$ matrix symmetry ($\mathbf{C}_{ij} = \mathbf{C}_{ji}$) and zero diagonal ($\mathbf{C}_{ii} = 0.0$).
  - Attenuation of co-occurring cross-domain symptoms (e.g., image quality degradation + feature drift).
  - Verification that inactive domains exert zero damping on active domains.
  - Invariant check: correlation damping NEVER attenuates proof-layer violations.
  - Missing or ambiguous ancestry handling: sets $\text{ancestry\_status}=\mathbf{UNVERIFIED}$, emits $\mathbf{INSUFFICIENT\_EVIDENCE}$, routes to $\mathbf{REVIEW}$.

### Layer 6: Proof-Layer Inviolability & Affected Scope Overrides
- **Target**: Proof failure detection, affected scope isolation, project-level propagation.
- **Traceable Requirements**: `REQ-12-PRF-001`, `REQ-12-PRF-002`, `REQ-12-PRF-003`, `REQ-12-PRF-004`, `REQ-12-PRF-005`, `REQ-12-PRF-006`.
- **Test Scenarios**:
  - Injection of broken model weight hash forcing Model disposition to $\mathbf{REJECT}$ and $R=1.0$.
  - Injection of broken inference signature forcing Inference disposition to $\mathbf{REJECT}$.
  - Verification that $R_{\text{detection}} = 0.0$ cannot compensate for a proof violation.
  - Isolation of unrelated Asset $B$ from Asset $A$'s proof failure.
  - Propagation of core proof failure forcing Project disposition to $\mathbf{REJECT}$.
  - Handling missing mandatory proof transitioning to $\mathbf{UNVERIFIABLE}$ / $\mathbf{QUARANTINE}$.

### Layer 7: Versioned Cryptographic Policy Governance
- **Target**: `UniversalRiskPolicy`, `UniversalDecisionPolicy`, policy hashing, threshold mapping.
- **Traceable Requirements**: `REQ-12-POL-001`, `REQ-12-POL-002`, `REQ-12-POL-003`, `REQ-12-POL-004`, `REQ-12-POL-005`, `REQ-12-POL-006`, `REQ-12-DEC-001`, `REQ-12-DEC-002`, `REQ-12-DEC-003`, `REQ-12-DEC-005`, `REQ-12-DEC-006`.
- **Test Scenarios**:
  - RFC 8785 JCS canonicalization and SHA-256 policy digest derivation (`risk_policy_hash`, `decision_policy_hash`, `correlation_matrix_hash`).
  - Rejection of invalid policy parameters (negative weights, non-monotonic thresholds, non-symmetric $\mathbf{C}$).
  - Verification that modifying policy text alters policy hash and leaves historical evaluations intact.
  - Verification of deterministic disposition mapping ($\mathbf{ACCEPT}, \mathbf{REVIEW}, \mathbf{QUARANTINE}, \mathbf{REJECT}$).

### Layer 8: REST API & Asynchronous Task Orchestration
- **Target**: FastAPI routes, `RiskTask` state machine, SSE progress streaming, error enveloping.
- **Traceable Requirements**: `REQ-12-DEC-006`, `REQ-12-SEC-006`, `REQ-12-CRY-003`.
- **Test Scenarios**:
  - `POST /api/v1/projects/{project_id}/risk/evaluate` accepting payload and returning `202 Accepted`.
  - Task state machine transitions (`QUEUED` $\to$ `RUNNING` $\to$ `COMPLETED`).
  - Cooperative cancellation handling on long-running graph traversals.
  - Idempotency key conflict detection returning `409 Conflict` on mismatched payloads.
  - SSE real-time event streaming with monotonic sequence numbers and keepalive pings.

### Layer 9: Security, Multi-Tenant Isolation & Privacy
- **Target**: Multi-tenant project boundary checks, BOLA/IDOR protection, path traversal defenses, pseudonymization.
- **Traceable Requirements**: `REQ-12-SEC-001`, `REQ-12-SEC-002`, `REQ-12-SEC-003`, `REQ-12-SEC-004`, `REQ-12-SEC-005`.
- **Test Scenarios**:
  - Cross-tenant evidence ingestion attempt returning immediate generic 404 / `ProjectMismatchError`.
  - Path traversal in artifact URIs (`../../secrets`) sanitized and blocked.
  - Project-salted SHA-256 pseudonymization of contributor IDs across multiple projects.
  - Error message sanitization verifying zero leakage of database tables or internal paths.

### Layer 10: Cryptographic Integrity, Merkle Roots & Dossier Sealing
- **Target**: SHA-256 hash chains, Merkle trees, `UniversalAssuranceDossier`, Ed25519 signing.
- **Traceable Requirements**: `REQ-12-CRY-001`, `REQ-12-CRY-002`, `REQ-12-CRY-003`, `REQ-12-CRY-004`, `REQ-12-CRY-005`, `REQ-12-CRY-006`.
- **Test Scenarios**:
  - Verification of RFC 8785 JCS canonical ordering and formatting.
  - Merkle root verification over sorted evidence hashes.
  - Unbroken provenance chain verification: $\text{Dossier} \to \text{Decision} \to \text{Risk} \to \text{Contribution} \to \text{Finding} \to \text{Evidence} \to \text{ProvenanceRecord}$.
  - Dossier generation, self-verification, and Ed25519 signature validation.
  - Single-bit tamper detection across evidence, findings, policies, and results.

### Layer 11: Resource Governance & 100% Offline Air-Gap Compliance
- **Target**: Hard safety ceilings, $O(V+E)$ complexity validation, empirical performance targets ($<2.0\text{s}, <150\text{MB}$), socket blocking.
- **Traceable Requirements**: `REQ-12-GOV-001`, `REQ-12-GOV-002`, `REQ-12-GOV-003`, `REQ-12-GOV-004`.
- **Test Scenarios**:
  - Hard safety ceiling enforcement ($E_{\max}=5000, F_{\max}=1000, A_{\max}=250, \Delta \le 5, \beta \le 100$) failing closed on overflow.
  - Algorithmic linear time complexity verification on increasing graph node sizes.
  - Empirical benchmark validating execution in $< 2.0\text{s}$ and peak memory $< 150\text{MB}$ RSS on reference workstation.
  - Socket-blocking fixture verifying 0 socket creation, 0 DNS calls, and 0 HTTP requests.

### Layer 12: Adversarial Mutation Resistance & Repository Non-Regression
- **Target**: Systematic mutation testing (20+ mutation vectors), full repository regression.
- **Traceable Requirements**: `REQ-12-GOV-005`, `REQ-12-GOV-006`, `REQ-12-GOV-007`.
- **Test Scenarios**:
  - Inverting threshold conditions $\implies$ Killed.
  - Disabling proof override $\implies$ Killed.
  - Removing correlation damping $\implies$ Killed.
  - Disabling cycle detection $\implies$ Killed.
  - Permuting dictionary keys $\implies$ Identical JCS hash.
  - Execution of full repository test suite preserving 2,231/2,231 baseline pass rate.

---

## 3. Acceptance & Freeze Criteria for Implementation

A future Phase 12 implementation will achieve certification and permanent freeze if and only if:
1. 100% of defined requirements (`REQ-12-*`) are verified by passing, non-vacuous executable tests.
2. 100% of defined threats (`THREAT-12-*`) are mitigated and verified.
3. 100% of adversarial mutations are killed.
4. All 12 verification layers are certified as FULL.
5. Zero modifications to frozen Phase 0–11 production code.
6. Zero database schema breaking changes.
7. Zero new runtime dependencies.
8. 100% offline air-gap execution verified (0 network calls).
9. Full repository test pass rate maintained at 100% (2,231+ tests passing).
