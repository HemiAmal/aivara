# PHASE 12.1 — FORMAL REQUIREMENTS SPECIFICATION
# Universal Risk Engine: Evidence Graphs, Hierarchical Risk & Universal Assurance

**Milestone**: Phase 12.1 Architecture & Requirements Freeze (Post-Audit Reconciled)  
**Authoritative Subsystem**: Universal Risk Engine (URE) / Universal Evidence + Risk Engine  
**Status**: FORMAL REQUIREMENTS FREEZE BASELINE  

---

## 1. Scope & Requirement Classification

This specification defines the authoritative functional, security, cryptographic, mathematical, architectural, and resource requirements for **Phase 12: Universal Risk Engine**.

The requirements are organized into 10 traceable categories:
- **Category 1 (ING)**: Universal Evidence Ingestion & Normalization (`REQ-12-ING-001` .. `008`)
- **Category 2 (GRP)**: Evidence Graph & $N:M$ Finding Binding (`REQ-12-GRP-001` .. `008`)
- **Category 3 (RSK)**: Hierarchical Multi-Asset Risk Modeling (`REQ-12-RSK-001` .. `008`)
- **Category 4 (COR)**: Cross-Subsystem Correlation & Damping (`REQ-12-COR-001` .. `006`)
- **Category 5 (PRF)**: Proof-Layer Non-Compensability & Overrides (`REQ-12-PRF-001` .. `006`)
- **Category 6 (POL)**: Versioned Cryptographic Policy Governance (`REQ-12-POL-001` .. `006`)
- **Category 7 (DEC)**: Universal Decision & Disposition Mapping (`REQ-12-DEC-001` .. `006`)
- **Category 8 (SEC)**: Security, Multi-Tenant Isolation & Privacy (`REQ-12-SEC-001` .. `006`)
- **Category 9 (CRY)**: Cryptographic Integrity & Dossier Synthesis (`REQ-12-CRY-001` .. `006`)
- **Category 10 (GOV)**: Resource Governance, Offline Air-Gap & Non-Regression (`REQ-12-GOV-001` .. `008`)

**Total Requirements**: 68 Formal Traceable Requirements.

---

## 2. Formal Requirements

### Category 1: Universal Evidence Ingestion & Normalization (ING)

- **REQ-12-ING-001**: The Universal Risk Engine MUST ingest heterogeneous evidence records produced by the exact seven upstream assurance subsystems (1: Dataset Integrity, 2: Contributor Risk, 3: Model Integrity, 4: Behavioral Analysis, 5: Backdoor/Triggers, 6: Inference Integrity, 7: Distribution Shift).
- **REQ-12-ING-002**: The engine MUST normalize all ingested evidence records into a standardized `UniversalEvidenceEnvelope` preserving original domain types, calibrated confidence scores, severity levels, and cryptographic digests.
- **REQ-12-ING-003**: The engine MUST strictly segregate ingested evidence into `evidence_layer="proof"` (deterministic binary invariant, confidence = 1.0) and `evidence_layer="detection"` (probabilistic statistical metric, confidence $\in [0.0, 1.0)$).
- **REQ-12-ING-004**: The engine MUST validate that every ingested evidence item contains a valid `project_id` matching the target evaluation project, rejecting cross-project evidence with a fail-closed `ProjectMismatchError`.
- **REQ-12-ING-005**: The engine MUST extract, validate, and index primary asset references (`target_asset_type`, `target_asset_id`) and immutable ancestry keys (`sample_id`, `dataset_version_id`, `model_fingerprint`, `source_group_id`, `window_id`, `inference_id`).
- **REQ-12-ING-006**: The engine MUST deduplicate identical evidence items within an evaluation run using constant-time comparisons over canonical evidence SHA-256 hashes (`evidence_hash`).
- **REQ-12-ING-007**: The engine MUST validate all ingested numerical metrics, verifying they are finite real numbers ($\mathbb{R}$) and strictly rejecting `NaN`, `+Inf`, and `-Inf` with a `InvalidEvidenceError`.
- **REQ-12-ING-008**: The engine MUST maintain zero modification or mutation of ingested upstream evidence objects throughout the entire evaluation pipeline.

---

### Category 2: Evidence Graph & $N:M$ Finding Binding (GRP)

- **REQ-12-GRP-001**: The engine MUST construct a Directed Acyclic Graph (DAG) connecting Assets $\to$ Findings $\to$ Evidence items $\to$ Risk Assessments within the evaluated project.
- **REQ-12-GRP-002**: The engine MUST formalize $N:M$ relationships between Findings and Evidence items via a logical junction model (`finding_evidence`), allowing a single evidence item to support multiple findings and a single finding to synthesize multiple evidence items.
- **REQ-12-GRP-003**: The engine MUST operate on existing Phase 3–11 persisted entities without requiring schema migrations, treating existing `evidence.finding_id` as the genesis reference and projecting in-memory $N:M$ graphs deterministically.
- **REQ-12-GRP-004**: The engine MUST enforce cycle detection during graph construction using topological sort visited tracking and reject cyclic dependencies with a `GraphCycleDetectedError`.
- **REQ-12-GRP-005**: The graph traversal depth MUST be constrained by a hard safety ceiling ($\Delta \le 5$) to prevent recursion stack overflow.
- **REQ-12-GRP-006**: The graph traversal breadth MUST be constrained by a hard safety ceiling of $\beta \le 100$ child nodes per parent.
- **REQ-12-GRP-007**: The engine MUST support bidirectional graph queries (retrieving all evidence for a finding, and all findings linked to an evidence item).
- **REQ-12-GRP-008**: The engine MUST compute a deterministic cryptographic Merkle root hash representing the topological state of the project evidence graph (`evidence_graph_merkle_root`).

---

### Category 3: Hierarchical Multi-Asset Risk Modeling (RSK)

- **REQ-12-RSK-001**: The engine MUST compute risk hierarchically across three distinct operational tiers: (1) Asset-Level Risk $R(A)$, (2) Cross-Asset Lineage Risk $R_{\text{chain}}$, and (3) Project-Level Operational Risk $R_{\text{project}}$.
- **REQ-12-RSK-002**: All computed risk scores at every tier MUST be mathematically bounded in the real interval $R \in [0.0, 1.0]$.
- **REQ-12-RSK-003**: Risk computation MUST use sub-additive asymptotic saturation: $R = 1.0 - \prod (1.0 - S_k)$, guaranteeing mathematical monotonicity and preventing score dilution.
- **REQ-12-RSK-004**: For each individual asset (Dataset, Model, Contributor, Inference Pipeline), the engine MUST partition evidence into Modality Clusters and compute asset risk $R(A) \in [0.0, 1.0]$.
- **REQ-12-RSK-005**: The engine MUST model cross-asset dependency risk along explicit DAG lineage chains (e.g., Model $M$ trained on Dataset $D$) using a configurable lineage propagation coefficient $\gamma_{\text{prop}} \in [0.0, 0.50]$, setting $R_{\text{chain}} \equiv 0.0$ if no lineage edge exists.
- **REQ-12-RSK-006**: Project-level risk $R_{\text{project}}$ MUST synthesize individual asset risks and lineage risks using a dominance-preserving formulation: critical asset failure dominates the project score while unrelated healthy assets cannot contaminate one another.
- **REQ-12-RSK-007**: Risk scores MUST represent **operational and assurance risk** (likelihood of functional, statistical, or specification divergence) and MUST NOT be described as probabilities of malicious intent, attacker presence, or contributor guilt.
- **REQ-12-RSK-008**: The engine MUST output a detailed, deterministic mathematical breakdown of all component risk contributions for full explainability and auditability.

---

### Category 4: Cross-Subsystem Correlation & Damping (COR)

- **REQ-12-COR-001**: The engine MUST cluster evidence items originating from the same physical root artifact using immutable ancestry keys (`sample_id`, `dataset_version_id`, `model_fingerprint`, `window_id`, `source_id`).
- **REQ-12-COR-002**: Within each modality cluster, the engine MUST apply intra-cluster damping ($\lambda_{\text{intra}} \in [0.0, 0.50]$, default: $0.15$) to prevent inflating risk from multiple symptoms of the same localized defect.
- **REQ-12-COR-003**: The engine MUST govern cross-subsystem correlation using a deterministic, symmetric $7 \times 7$ correlation matrix $\mathbf{C} \in [0.0, 1.0]^{7 \times 7}$ with mandatory zero diagonal ($\mathbf{C}_{ii} = 0.0$) and exact canonical domain ordering.
- **REQ-12-COR-004**: The correlation matrix MUST be content-addressed with SHA-256 (`correlation_matrix_hash`) and configurable via versioned risk policies.
- **REQ-12-COR-005**: Correlation damping MUST ONLY attenuate detection-layer evidence and MUST NEVER attenuate proof-layer violations.
- **REQ-12-COR-006**: When evidence ancestry is missing or ambiguous, the engine MUST NOT assume the evidence is safe; it MUST flag an $\mathbf{INSUFFICIENT\_EVIDENCE}$ advisory, mark the item as $\mathbf{UNVERIFIED}$, and route to $\mathbf{REVIEW}$.

---

### Category 5: Proof-Layer Non-Compensability & Overrides (PRF)

- **REQ-12-PRF-001**: Any active proof-layer failure on Asset $A$ MUST immediately force Asset $A$'s risk score to $R(A) = 1.0$ and disposition to $\mathbf{REJECT}$.
- **REQ-12-PRF-002**: Proof-layer failures MUST be strictly non-compensable: zero detection-layer risk, high statistical p-values, or positive benchmark metrics CANNOT reduce, dilute, or override a proof failure within its affected scope.
- **REQ-12-PRF-003**: Proof violations on Asset $A$ MUST NOT automatically reject unrelated Asset $B$ unless an explicit dependency/lineage edge connects $A$ to $B$ in the DAG.
- **REQ-12-PRF-004**: A proof failure on a core deployed asset (e.g., model weight hash mismatch) MUST propagate to force Project disposition to $\mathbf{REJECT}$.
- **REQ-12-PRF-005**: An isolated proof failure on a peripheral sample (e.g., single inference record hash mismatch) MUST force that inference asset to $\mathbf{REJECT}$ and Project disposition to at least $\mathbf{QUARANTINE}$.
- **REQ-12-PRF-006**: Missing proof artifacts where proof is mandatory MUST transition the evaluation state to $\mathbf{UNVERIFIABLE}$ / $\mathbf{QUARANTINE}$ and NEVER to $\mathbf{ACCEPT}$.

---

### Category 6: Versioned Cryptographic Policy Governance (POL)

- **REQ-12-POL-001**: All risk aggregation weights, damping factors, lineage coefficients, and disposition thresholds MUST be governed by immutable, versioned policy objects (`UniversalRiskPolicy`, `UniversalDecisionPolicy`).
- **REQ-12-POL-002**: Every policy object MUST be cryptographically content-addressed using RFC 8785 JSON Canonicalization Scheme (JCS) and SHA-256 (`risk_policy_hash`, `decision_policy_hash`).
- **REQ-12-POL-003**: The engine MUST validate policy schemas and reject any policy with invalid mathematical parameters (e.g., negative weights, non-monotonic thresholds, or non-symmetric correlation matrix) with a `PolicyValidationError`.
- **REQ-12-POL-004**: The engine MUST support project-specific policy overrides while strictly enforcing global minimum security invariants (e.g., mandatory proof override cannot be disabled).
- **REQ-12-POL-005**: Any modification to a policy definition MUST result in an immediate change to the policy hash and MUST NOT alter historical assessments bound to earlier policy versions.
- **REQ-12-POL-006**: Policy evaluation MUST be completely deterministic and execute 100% offline without remote policy servers.

---

### Category 7: Universal Decision & Disposition Mapping (DEC)

- **REQ-12-DEC-001**: The engine MUST map calibrated risk scores and proof states to four standardized disposition outcomes: $\mathbf{ACCEPT}$, $\mathbf{REVIEW}$, $\mathbf{QUARANTINE}$, and $\mathbf{REJECT}$.
- **REQ-12-DEC-002**: Default disposition mapping MUST follow calibrated thresholds:
  - $\mathbf{ACCEPT}$: $R < 0.30 \land \text{No Proof Violations} \land \text{Sufficient Evidence}$
  - $\mathbf{REVIEW}$: $0.30 \le R < 0.65 \lor \text{Insufficient Non-Critical Evidence}$
  - $\mathbf{QUARANTINE}$: $0.65 \le R < 0.85 \lor \text{Peripheral Proof Violation} \lor \text{Conflicting Critical Evidence}$
  - $\mathbf{REJECT}$: $R \ge 0.85 \lor \text{Core Proof Failure}$
- **REQ-12-DEC-003**: When evaluated domains lack sufficient sample size or required evidence, the engine MUST emit an explicit $\mathbf{INSUFFICIENT\_EVIDENCE}$ state and route to $\mathbf{REVIEW}$.
- **REQ-12-DEC-004**: The engine MUST enforce the invariant: $\text{Absence of Evidence} \ne \text{Proof of Safety}$.
- **REQ-12-DEC-005**: Every disposition decision MUST include an automated, deterministic textual rationale detailing the primary risk drivers, active findings, proof status, and policy version used.
- **REQ-12-DEC-006**: Disposition decisions MUST be generated at both the individual asset level and the aggregate project level.

---

### Category 8: Security, Multi-Tenant Isolation & Privacy (SEC)

- **REQ-12-SEC-001**: The engine MUST enforce strict multi-tenant project isolation; cross-project evidence ingestion, graph traversal, or risk aggregation MUST be strictly prevented and fail closed with a generic 404.
- **REQ-12-SEC-002**: Ingestion of external paths, artifact URIs, or model references MUST be sanitized against path traversal attacks (`..`, absolute drive traversal).
- **REQ-12-SEC-003**: The engine MUST sanitize all human and contributor identifiers using project-salted SHA-256 pseudonymization, preventing cross-project re-identification.
- **REQ-12-SEC-004**: All error messages produced by the engine MUST be sanitized to prevent leaking internal database schemas, filesystem layouts, or memory addresses.
- **REQ-12-SEC-005**: Ingestion of adversarial evidence payloads designed to trigger quadratic or exponential complexity MUST be throttled by strict resource governors.
- **REQ-12-SEC-006**: The engine MUST be resilient against replay attacks and idempotency collisions through cryptographic request and execution fingerprinting.

---

### Category 9: Cryptographic Integrity & Dossier Synthesis (CRY)

- **REQ-12-CRY-001**: The engine MUST use standard library `hashlib` (SHA-256) and pure-Python `rfc8785` (JCS) for all canonical serialization and hashing.
- **REQ-12-CRY-002**: Every universal risk assessment MUST maintain an unbroken, verifiable provenance chain: $\text{Dossier} \to \text{Decision} \to \text{RiskAssessment} \to \text{RiskContribution}[] \to \text{Finding}[] \to \text{Evidence}[] \to \text{ProvenanceRecord}[]$.
- **REQ-12-CRY-003**: The engine MUST synthesize a tamper-evident `UniversalAssuranceDossier` cryptographically binding project digests, evidence graph Merkle roots, policy hashes, asset scores, and project dispositions.
- **REQ-12-CRY-004**: The assurance dossier MUST be verifiable offline by recomputing all constituent hashes and Merkle paths without external infrastructure.
- **REQ-12-CRY-005**: Any single-bit tampering of an evidence item, finding, policy parameter, or asset identity MUST produce an avalanche effect that invalidates the dossier hash.
- **REQ-12-CRY-006**: The engine MUST support signing the synthesized dossier using Phase 4 local Ed25519 digital signatures.

---

### Category 10: Resource Governance, Offline Air-Gap & Non-Regression (GOV)

- **REQ-12-GOV-001**: The engine MUST enforce mandatory hard resource safety ceilings per evaluation run ($E_{\max} \le 5,000, F_{\max} \le 1,000, A_{\max} \le 250, \Delta \le 5, \beta \le 100$), failing closed with `ResourceLimitExceededError` if exceeded.
- **REQ-12-GOV-002**: Graph traversal algorithms MUST exhibit $O(V + E)$ algorithmic complexity where applicable.
- **REQ-12-GOV-003**: The engine MUST satisfy empirical performance acceptance targets of $< 2.0\text{s}$ execution time and $< 150\text{MB}$ peak RSS on the reference workstation environment, validated via empirical benchmark suites.
- **REQ-12-GOV-004**: The engine MUST operate 100% offline with zero outbound network connections, zero DNS queries, zero cloud telemetry, and zero remote API dependencies.
- **REQ-12-GOV-005**: All mathematical calculations, sorting routines, tie-breaking, and hashing operations MUST be 100% deterministic across multiple runs on identical inputs.
- **REQ-12-GOV-006**: Phase 12 implementation MUST NOT modify any frozen Phase 0–11 production files or alter existing database schemas without a formal versioned migration plan.
- **REQ-12-GOV-007**: Phase 12 MUST preserve 100% test pass rate across the full 2,231-test repository baseline.
- **REQ-12-GOV-008**: Finding and risk descriptions MUST strictly adhere to non-attribution language, describing observations without inferring malicious intent or culpability.
