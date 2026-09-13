# PHASE 12.1 — UNIVERSAL RISK ENGINE ARCHITECTURE SPECIFICATION
# Universal Evidence + Risk Engine: Multi-Asset Assurance, Evidence Graphs & Policy Governance

**Milestone**: Phase 12.1 Architecture & Requirements Freeze (Post-Audit Reconciled)  
**Authoritative Subsystem**: Universal Risk Engine (URE) / Universal Evidence + Risk Engine  
**Status**: ARCHITECTURAL BASELINE SPECIFICATION  

---

## 1. Scope

The Universal Risk Engine (URE) serves as the central assurance, risk quantification, and policy disposition authority for AIVARA. It synthesizes evidence, findings, and cryptographic proofs generated across all upstream verification domains into unified asset-level and project-level operational risk evaluations.

### In-Scope Capabilities
1. **Multi-Domain Ingestion**: Ingesting and normalizing evidence from the exact seven upstream assurance subsystems (Phases 5–11).
2. **Evidence Graph & $N:M$ Traversal**: Constructing an in-memory Directed Acyclic Graph (DAG) formalizing $N:M$ relationships between Findings and Evidence items.
3. **Hierarchical Risk Quantification**: Evaluating calibrated operational risk across 3 tiers: Asset-Level $R(A)$, Cross-Asset Lineage $R_{\text{chain}}$, and Project-Level $R_{\text{project}}$.
4. **Sub-Additive Bounded Risk Composition**: Monotonic asymptotic risk saturation ($R \in [0.0, 1.0]$) preventing score dilution.
5. **Two-Stage Correlation Damping**: Applying ancestry clustering and an immutable $7 \times 7$ inter-domain correlation matrix to eliminate double-counting of shared root causes.
6. **Proof-Layer Inviolability**: Non-compensable enforcement of cryptographic proof violations within their formal affected scope ($R(A)=1.0 \implies \mathbf{REJECT}$).
7. **Versioned Policy Governance**: Immutable, cryptographically hashed policy specifications (`UniversalRiskPolicy`, `UniversalDecisionPolicy`).
8. **Deterministic Disposition Decisioning**: Mapping risk and proof states to standardized outcomes ($\mathbf{ACCEPT}, \mathbf{REVIEW}, \mathbf{QUARANTINE}, \mathbf{REJECT}$).
9. **Cryptographic Assurance Dossier**: Generating RFC 8785 JCS + SHA-256 tamper-evident compliance dossiers and Merkle audit trees.
10. **100% Offline Air-Gapped Execution**: Zero external dependencies or network operations on local workstations.

---

## 2. Non-Scope & Anti-Goals

1. **No Upstream Detector Duplication**: Phase 12 does NOT execute image processing, model parsing, hypothesis testing, trigger generation, or replay execution. It consumes upstream outputs.
2. **No Opaque ML/Neural Risk Scoring**: Zero black-box machine learning models for risk scoring; all risk mathematics are deterministic and closed-form.
3. **No Intent Attribution or Guilt Inference**: Phase 12 evaluates operational/technical assurance risk, NEVER malicious intent, attacker psychology, or legal culpability.
4. **No Destructive Database Alterations**: Zero breaking schema modifications to frozen Phase 3 ORM tables during baseline operation.
5. **No Cloud or Remote Services**: Zero cloud API integrations, remote policy servers, or external key management calls.

---

## 3. Upstream / Downstream Architectural Boundaries

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       UPSTREAM ASSURANCE DOMAINS                            │
│                                                                             │
│  Domain 0: Dataset Integrity (Phase 5)    Domain 1: Contributor Risk (Phase 6)│
│  Domain 2: Model Integrity (Phase 7)      Domain 3: Behavioral Analysis (Ph 8)│
│  Domain 4: Backdoor / Triggers (Phase 9)  Domain 5: Inference Integrity (Ph 10│
│  Domain 6: Distribution Shift (Features, Images, Embeddings, Time, Source)  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Raw Evidence & Findings
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PHASE 12: UNIVERSAL RISK ENGINE                          │
│                                                                             │
│  ┌────────────────────────┐  ┌────────────────────────┐  ┌────────────────┐ │
│  │ Evidence Normalization │  │ Finding/Evidence Graph │  │ Policy Engine  │ │
│  └───────────┬────────────┘  └───────────┬────────────┘  └───────┬────────┘ │
│              │                           │                       │          │
│              ▼                           ▼                       ▼          │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │ Hierarchical Risk Synthesis (Asset -> Cross-Asset Lineage -> Project)  │ │
│  │ Proof Non-Compensability + 7x7 Correlation Damping + Bounded Saturation│ │
│  └───────────────────────────────────────┬────────────────────────────────┘ │
│                                          │                                  │
│                                          ▼                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │ Policy Disposition Mapping (ACCEPT / REVIEW / QUARANTINE / REJECT)     │ │
│  │ Tamper-Evident Universal Assurance Dossier & Merkle Audit Root         │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Audited Dossier & Risk Assessment
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DOWNSTREAM CONSUMERS & INTERFACES                        │
│                                                                             │
│  REST API Endpoints (/api/v1/projects/{id}/risk/...)                        │
│  Compliance & Audit Report Generators                                       │
│  Local Workstation Operator Dashboard                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Phase 11.9 Boundary vs Phase 12 Scope
- **Phase 11.9 (`MultiModalRiskIntegrationEngine`)**: Single-target asset scope, primarily distribution-shift evidence, single-asset ancestry clustering, flat risk aggregation.
- **Phase 12 (`UniversalRiskEngine`)**: Universal scope across all 7 subsystems, multi-asset graph traversal ($N:M$ bindings), cross-asset lineage propagation, project-wide risk synthesis, and enterprise compliance dossiers. **Phase 12 reuses Phase 11.9's mathematical principles (sub-additive saturation, proof non-compensability, JCS hashing) while extending them to multi-asset and whole-project hierarchies.**

---

## 4. Universal Evidence Model & Ingestion Envelope

All upstream evidence is ingested into a canonical, in-memory **`UniversalEvidenceEnvelope`**:
- `evidence_id`: String UUID or content hash.
- `project_id`: Project tenant UUID.
- `source_subsystem`: Enum (`DATASET_INTEGRITY`, `CONTRIBUTOR_RISK`, `MODEL_INTEGRITY`, `BEHAVIORAL_ANALYSIS`, `BACKDOOR_TRIGGER`, `INFERENCE_INTEGRITY`, `DISTRIBUTION_SHIFT`).
- `evidence_layer`: Enum (`PROOF` vs `DETECTION`).
- `evidence_type`: Domain-specific type string.
- `severity`: Enum (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- `confidence`: Calibrated float $\in [0.0, 1.0]$ ($1.0$ for `PROOF`).
- `primary_asset_type`: Enum (`PROJECT`, `DATASET`, `MODEL`, `INFERENCE`, `CONTRIBUTOR`).
- `primary_asset_id`: Asset UUID.
- `ancestry_keys`: Dict containing parent keys (`sample_id`, `dataset_version_id`, `model_fingerprint`, `source_group_id`, `window_id`, `inference_id`).
- `data_json`: Canonical JSON payload containing physical metrics.
- `evidence_hash`: SHA-256(RFC 8785 JCS(`data_json`)).
- `provenance_hash`: Phase 4/5 hash-linked audit record digest.
- `created_at_utc`: Normalized ISO-8601 UTC timestamp.

---

## 5. Finding / Evidence Graph & $N:M$ Topology

Phase 12 formalizes the $N:M$ relationship between findings and evidence:
- **Junction Abstraction (`finding_evidence`)**: Links $F_{\text{id}} \leftrightarrow E_{\text{id}}$ with explicit binding metadata (`relevance_weight`, `binding_type`).
- **Initial Operation**: Phase 12 operates directly on existing Phase 3–11 persisted entities without requiring schema migrations. The in-memory graph is a deterministic projection of existing relationships.
- **DAG Invariant**: Traversal proceeds strictly along directed acyclic edges:
  $$\text{Evidence} \longrightarrow \text{Asset Finding} \longrightarrow \text{Cross-Asset Finding} \longrightarrow \text{Project Risk}$$
- **Cycle Prevention**: Topological sorting with DFS visited-path tracking guarantees immediate detection and rejection of cycles (`GraphCycleDetectedError`).
- **Hard Safety Ceilings**: Maximum traversal depth $\Delta \le 5$, maximum child nodes per parent $\beta \le 100$.

---

## 6. Project & Asset Hierarchy

Phase 12 evaluates risks across a 4-level structural hierarchy:
```
Level 0: Project (Tenant Container & Global Genesis Hash)
  │
  ├── Level 1: Datasets (Versions, Samples, Contributors, Partitions)
  ├── Level 1: AI Models (Versions, Checkpoints, Weights, Fingerprints)
  └── Level 1: Inference Pipelines (Inputs, Contracts, Outputs, Replays)
        │
        ├── Level 2: Domain Findings (Localized observations)
        │     └── Level 3: Evidence Items (Raw normalized observations)
        │
        └── Level 2: Cross-Asset Lineage Chains (e.g. Dataset -> Model -> Inference)
```

---

## 7. Universal Risk Model: Three-Tier Hierarchy

### Tier 1: Asset-Level Risk ($R(A)$)
For each asset $A \in \{\text{Datasets}, \text{Models}, \text{Contributors}, \text{InferencePipelines}\}$:
1. Partition asset evidence into modality clusters: $\mathcal{C}_1, \dots, \mathcal{C}_K$.
2. Compute cluster severity score:
   $$S(\mathcal{C}_k) = \min\left(1.0, \max_{e \in \mathcal{C}_k} (w_e \cdot c_e \cdot s_e) + \lambda_{\text{intra}} \sum_{e \in \mathcal{C}_k \setminus \{e^*\}} w_e \cdot c_e \cdot s_e\right)$$
3. Compute asset risk:
   $$R(A) = 1.0 - \prod_{k=1}^K (1.0 - S(\mathcal{C}_k))$$

### Tier 2: Cross-Asset Lineage Risk ($R_{\text{chain}}$)
Captures risk compounding along the explicit DAG dependency chain (e.g., Model $M$ depends on Dataset $D$):
$$R_{\text{chain}}(D \to M) = \gamma_{\text{prop}} \cdot R(D) \cdot R_{\text{vuln}}(M)$$
where $\gamma_{\text{prop}} \in [0.0, 0.50]$ (default: $0.25$) is the lineage propagation factor. If no explicit dependency edge exists between $D$ and $M$, $R_{\text{chain}}(D \to M) \equiv 0.0$.

### Tier 3: Project Operational Risk ($R_{\text{project}}$)
Synthesizes all individual asset risks and explicit lineage risks:
$$R_{\text{project}} = 1.0 - (1.0 - \max_A R(A))^{\alpha_{\text{peak}}} \cdot \prod_{A \in \mathcal{A}} (1.0 - \lambda_{\text{inter}} R(A))$$
where $\alpha_{\text{peak}} \ge 1.0$ guarantees that high risk in any single critical asset dominates the project score, while $\lambda_{\text{inter}} \in [0.05, 0.20]$ prevents artificial inflation across multiple healthy assets.

---

## 8. Correlation Damping & $7 \times 7$ Governance

To eliminate double-counting of multi-symptom defects:
- **Intra-Cluster Damping ($\lambda_{\text{intra}} = 0.15$)**: Attenuates multiple evidence items derived from the same underlying artifact.
- **$7 \times 7$ Inter-Domain Correlation Matrix ($\mathbf{C} \in [0.0, 1.0]^{7 \times 7}$)**:
  - Canonical domain ordering: (0) `DATASET_INTEGRITY`, (1) `CONTRIBUTOR_RISK`, (2) `MODEL_INTEGRITY`, (3) `BEHAVIORAL_ANALYSIS`, (4) `BACKDOOR_TRIGGER`, (5) `INFERENCE_INTEGRITY`, (6) `DISTRIBUTION_SHIFT`.
  - Mandatory symmetry: $\mathbf{C}_{ij} = \mathbf{C}_{ji}$.
  - Mandatory zero diagonal: $\mathbf{C}_{ii} = 0.0$.
  - Attenuation formula: $w_{\text{effective}}(e_j) = w_j \cdot \prod_{i \neq j, \text{active}(i)} (1.0 - \mathbf{C}_{ij} \cdot \bar{S}_i)$.
  - Inactive domains exert zero damping on other domains.
- **Proof Inviolability**: Correlation damping NEVER attenuates proof-layer violations.

---

## 9. Proof Model, Non-Compensability & Affected Scope

- **Proof Classification**: Cryptographic hashes, digital signatures, Merkle paths, execution determinism, and tenant boundary verifications.
- **Asset-Level Affected Scope**: Proof failure on Asset $A \implies R(A) = 1.0 \land \text{Disposition}(A) = \mathbf{REJECT}$.
- **Unrelated Asset Isolation**: Unrelated Asset $B$ is **NOT** automatically rejected.
- **Lineage Propagation**: Propagation occurs if and only if an explicit DAG lineage edge connects $A$ to downstream assets.
- **Project-Level Disposition**:
  - Core deployed asset failure $\implies \text{Project Disposition} = \mathbf{REJECT}$.
  - Isolated peripheral sample failure $\implies \text{Asset} = \mathbf{REJECT} \land \text{Project Disposition} \ge \mathbf{QUARANTINE}$.

---

## 10. Universal Decision Model

Maps risk scores and proof states to 4 standardized dispositions:
1. $\mathbf{ACCEPT}$: $R < 0.30 \land \text{No Proof Failures} \land \text{Sufficient Evidence}$.
2. $\mathbf{REVIEW}$: $0.30 \le R < 0.65 \lor \text{Insufficient Non-Critical Evidence}$.
3. $\mathbf{QUARANTINE}$: $0.65 \le R < 0.85 \lor \text{Peripheral Proof Violation} \lor \text{Conflicting Evidence}$.
4. $\mathbf{REJECT}$: $R \ge 0.85 \lor \text{Core Proof Failure}$.

---

## 11. Policy Governance Model

- **`UniversalRiskPolicy`**: Versioned configuration of domain weights, damping factors, lineage coefficients, and the $7 \times 7$ correlation matrix.
- **`UniversalDecisionPolicy`**: Versioned configuration of disposition thresholds and escalation actions.
- **Policy Hashing**: Deterministic RFC 8785 JCS + SHA-256 digests (`risk_policy_hash`, `decision_policy_hash`, `correlation_matrix_hash`) bound into every assessment.

---

## 12. Provenance Architecture & Cryptographic Chain

The URE enforces an unbroken, testable cryptographic audit chain:
$$\text{UniversalAssuranceDossier} \longrightarrow \text{Decision} \longrightarrow \text{RiskAssessment} \longrightarrow \text{RiskContribution}[] \longrightarrow \text{Finding}[] \longrightarrow \text{Evidence}[] \longrightarrow \text{ProvenanceRecord}[]$$
- Any missing or broken link triggers fail-closed error handling (`ProvenanceIntegrityError`).
- Missing ancestry flags $\mathbf{INSUFFICIENT\_EVIDENCE}$ and routes to $\mathbf{REVIEW}$; the engine never fabricates ancestry.

---

## 13. Cryptographic Identity & Merkle Trees

- **Evidence Merkle Root**: Computed over sorted canonical evidence hashes.
- **Assessment Digest**:
  $$\text{AssessmentHash} = \text{SHA-256}(\text{JCS}(\text{ProjectDigest} \mathbin{\Vert} \text{MerkleRoot} \mathbin{\Vert} \text{PolicyHashes} \mathbin{\Vert} \text{Scores}))$$
- **Assurance Dossier**: Exportable, self-verifying envelope signed with local Ed25519 keys.

---

## 14. Database Architecture

- **Existing Tables Reused**: `projects`, `contributors`, `datasets`, `dataset_versions`, `samples`, `ai_models`, `inference_records`, `findings`, `evidence`, `risk_assessments`, `provenance_records`.
- **Future Entity (`finding_evidence`)**: Formal junction table linking `finding_id` and `evidence_id`, introduced in a later subphase without breaking legacy columns.

---

## 15. REST API Architecture (Future Subphase Proposal)

- `POST /api/v1/projects/{project_id}/risk/evaluate`: Initiate universal risk assessment.
- `GET /api/v1/projects/{project_id}/risk/assessments/{assessment_id}`: Retrieve completed risk assessment and disposition.
- `GET /api/v1/projects/{project_id}/risk/graph`: Retrieve project evidence-finding DAG.
- `GET /api/v1/projects/{project_id}/risk/dossier/{assessment_id}`: Export verifiable assurance dossier.

---

## 16. Task & Orchestration Architecture

- Leverages the Phase 11.10 asynchronous job model: `QUEUED` $\to$ `RUNNING` $\to$ `COMPLETED` / `FAILED` / `CANCELLED`.
- Offloaded to in-process thread pool (`max_workers=4`) with cooperative cancellation checks.

---

## 17. Security & Multi-Tenant Boundaries

- Strict `project_id` scoping on all queries and graph traversals.
- Defense-in-depth sanitization against path traversal and numerical anomalies (`NaN`/`Inf`).
- Project-salted SHA-256 pseudonymization of contributor and source identifiers.

---

## 18. Resource Governance: Ceilings, Complexity & Performance Targets

1. **Hard Resource Safety Ceilings**: $E_{\max} = 5,000$ evidence items, $F_{\max} = 1,000$ findings, $A_{\max} = 250$ assets, $\Delta \le 5$, $\beta \le 100$. Exceeding limits fails closed.
2. **Algorithmic Complexity Guarantees**: Graph traversal and cycle detection operate in $O(V + E)$ linear time where applicable.
3. **Empirical Performance Acceptance Targets**: Execution time $< 2.0\text{s}$ and peak memory $< 150\text{MB}$ RSS on the reference workstation environment.

---

## 19. Offline-First Guarantees

- 100% offline air-gapped execution.
- Zero socket connections, remote APIs, cloud telemetry, or external model downloads.

---

## 20. Auditability & Observability

- Comprehensive structured logging with sensitive data redaction.
- Deterministic, explainable mathematical breakdown of all risk components and damping steps.

---

## 21. Failure & Safety Modes

- Malformed or conflicting evidence triggers fail-closed error handling (`ConflictingEvidenceError`).
- Incomplete required domains emit $\mathbf{INSUFFICIENT\_EVIDENCE}$ routing to $\mathbf{REVIEW}$.

---

## 22. Observability & Metrics

- Structured diagnostic events: `EVIDENCE_INGESTED`, `GRAPH_CONSTRUCTED`, `RISK_EVALUATED`, `DOSSIER_SEALED`.

---

## 23. Compliance Reporting

- Automated generation of structured compliance profiles mapping findings to NIST AI RMF, EU AI Act, and ISO/IEC 42001 assurance categories.

---

## 24. Future Extensibility & Subphase Roadmap

### Proposed Subphase Roadmap (*PROPOSED — NOT YET FROZEN*):
1. **Phase 12.1**: Architecture & Requirements Freeze (Current Baseline)
2. **Phase 12.2**: Universal Evidence Normalization & Multi-Domain Adapters
3. **Phase 12.3**: Evidence Graph & $N:M$ Finding-Evidence Junction Engine
4. **Phase 12.4**: Hierarchical Multi-Asset Risk Aggregation Engine
5. **Phase 12.5**: Cross-Subsystem Correlation & Dependency Damping Engine
6. **Phase 12.6**: Proof-Layer Non-Compensability & Inviolable Override Subsystem
7. **Phase 12.7**: Versioned Cryptographic Policy Governance Engine
8. **Phase 12.8**: Universal Decision Mapping & Assurance Dossier Sealing
9. **Phase 12.9**: REST API & Asynchronous Task Orchestration
10. **Phase 12.10**: Enterprise Compliance & Audit Reporting
11. **Phase 12.11**: Comprehensive Verification, Layered Certification & Permanent Freeze
