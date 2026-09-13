# PHASE 12.1 — RESEARCH NOTES
# Universal Risk Engine: Evidence Graphs, Hierarchical Risk & Universal Assurance

**Milestone**: Phase 12.1 Architecture & Requirements Freeze (Post-Audit Reconciled)  
**Authoritative Subsystem**: Universal Risk Engine (URE) / Universal Evidence + Risk Engine  
**Status**: ARCHITECTURE RESEARCH & DESIGN SPECIFICATION  

---

## 1. Executive Summary & Problem Context

AIVARA has permanently established and frozen seven upstream assurance and detection domains spanning Phases 4 through 11:
1. **Dataset Integrity (Phase 5)**: Sharpness, exposure, noise, clipping, out-of-distribution (OOD) distance, near-duplicates, label ambiguity.
2. **Contributor Risk (Phase 6)**: Contributor exposure normalization, Empirical Bayes prior estimation, Leave-One-Out (LOO) subgroup anomaly profiles.
3. **Model Integrity (Phase 7)**: Structural graph parsing, layer-by-layer weight hashing, quantization verification, Merkle weight trees.
4. **Behavioral Analysis (Phase 8)**: Black-box/white-box perturbations, output stability, continuous drift, adversarial behavioral heuristics.
5. **Backdoor & Trigger Detection (Phase 9)**: Patch and blended trigger simulation, activation clustering, spectral signature decomposition.
6. **Inference Execution Integrity (Phase 10)**: 18-checkpoint verification pipeline, input-model binding, replay determinism, provenance sealing.
7. **Distribution Shift (Phase 11)**: Two-sample hypothesis testing, dual-gated feature/dataset drift, visual descriptors, ONNX representation shift, temporal windowing, source partitioning, multi-modal risk integration.

### The Architectural Gap
Each upstream subsystem produces localized findings and evidence scoped to an individual artifact (a specific dataset, model, inference record, or temporal window). However, enterprise-grade AI verification requires **holistic assurance across the complete AI lifecycle graph**:
- How does a defect in a dataset (e.g., contaminated contributor annotations) propagate risk to downstream models trained on that dataset and inference executions performed by those models?
- How do we synthesize hundreds of heterogeneous evidence items from disparate domains without double-counting correlated symptoms of the same root cause?
- How do we enforce non-compensable cryptographic proof failures across an entire project while still providing granular, actionable risk diagnostics without falsely contaminating unrelated assets?
- How do we formalize the $N:M$ relationship between findings and evidence without introducing breaking changes or database migration risks to frozen schemas?

Phase 12 bridges this gap as the **Universal Evidence + Risk Engine (URE)**.

---

## 2. Universal Evidence Normalization & Upstream Integration

### 2.1 Upstream Evidence Taxonomy

| Subsystem Domain | Evidence Types Produced | Evidence Layer | Primary Asset Scope | Ancestry Keys |
| :--- | :--- | :---: | :--- | :--- |
| **1. Dataset Integrity (Phase 5)** | `image_quality`, `ood_score`, `near_duplicate_cluster`, `label_noise` | Detection | `DatasetVersion` | `dataset_id`, `dataset_version_id`, `sample_id` |
| **2. Contributor Risk (Phase 6)** | `contributor_anomaly_profile`, `loo_divergence`, `group_skew` | Detection | `Contributor` | `project_id`, `contributor_id`, `group_id` |
| **3. Model Integrity (Phase 7)** | `weight_hash_merkle`, `layer_structure_digest`, `quantization_delta` | Proof & Detection | `AIModel` | `model_id`, `model_hash`, `file_hash` |
| **4. Behavioral Analysis (Phase 8)** | `output_stability_metric`, `perturbation_sensitivity`, `behavioral_drift` | Detection | `AIModel` | `model_id`, `baseline_run_id` |
| **5. Backdoor / Triggers (Phase 9)** | `activation_cluster_divergence`, `spectral_signature`, `trigger_patch_score` | Detection | `AIModel` / `Dataset` | `model_id`, `dataset_version_id`, `target_class` |
| **6. Inference Integrity (Phase 10)** | `18_checkpoint_verification`, `replay_consistency`, `provenance_chain` | Proof | `InferenceRecord` | `inference_id`, `model_id`, `input_hash`, `output_hash` |
| **7. Distribution Shift (Phase 11)** | `feature_drift`, `image_shift`, `representation_shift`, `temporal_regime`, `source_shift` | Detection | `DatasetVersion` / `AIModel` | `dataset_version_id`, `reference_hash`, `window_id`, `source_group` |

### 2.2 Universal Evidence Normalization Schema

To ingest heterogeneous evidence without altering upstream structures, Phase 12 defines a normalized, in-memory **Universal Evidence Envelope**:
```python
class UniversalEvidenceEnvelope:
    evidence_id: str                      # UUID or canonical evidence digest
    project_id: str                       # Strict tenant boundary
    source_subsystem: SubsystemDomain     # Exact 7 domains: DATASET_INTEGRITY .. DISTRIBUTION_SHIFT
    evidence_layer: EvidenceLayer         # PROOF (1.0) vs DETECTION (0.0..1.0)
    evidence_type: str                    # Canonical type string
    severity: Severity                    # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: float                     # Calibrated confidence in [0.0, 1.0] (1.0 for proof)
    primary_asset_type: AssetType         # PROJECT, DATASET, MODEL, INFERENCE, CONTRIBUTOR
    primary_asset_id: str                 # Unique asset UUID/fingerprint
    ancestry_keys: Dict[str, str]        # Direct parent and ancestor identifiers
    evidence_payload: Dict[str, Any]      # Canonical RFC 8785 verifiable payload
    evidence_hash: str                    # SHA-256(JCS(evidence_payload))
    provenance_hash: Optional[str]        # Phase 4/5 provenance chain link
    created_at_utc: str                   # Normalized ISO-8601 UTC timestamp
```

---

## 3. Relational Evidence Graph & $N:M$ Junction Traversal

### 3.1 The $N:M$ Architectural Model
In Phase 3, `EvidenceModel.finding_id` was established as a 1:N foreign key (`findings` $\to$ `evidence`). However, real-world assurance analysis exhibits an $N:M$ topology:
1. **One Finding $\to$ Multiple Evidence Items**: A `HIGH_DATASET_CORRUPTION` finding requires evidence from image sharpness, OOD distances, and label noise.
2. **One Evidence Item $\to$ Multiple Findings**: An anomalous model embedding distance ($e_{\text{repr}}$) serves as evidence for both a `REPRESENTATION_DISTRIBUTION_SHIFT` finding (Phase 11) and a `MODEL_BEHAVIORAL_ANOMALY` finding (Phase 8).
3. **Cross-Asset Finding Binding**: A project-level `SUPPLY_CHAIN_COMPROMISE` finding synthesizes findings from Contributor $C_1$, Dataset $D_1$, and Model $M_1$.

### 3.2 Junction Entity Architecture: `finding_evidence`
Phase 12 formalizes the $N:M$ junction architecture:
- **Phase 12 Initial Operation**: Operates purely on existing Phase 3–11 persisted entities (`findings`, `evidence`, `risk_assessments`) and their existing relational foreign keys.
- **Canonical Future Junction**: Represented logically by `finding_evidence` with schema:
  $$\text{FindingEvidenceJunction}(F_{\text{id}}, E_{\text{id}}, \text{relevance\_weight}, \text{binding\_type}, \text{created\_at})$$
- **Database Non-Breaking Evolution**:
  - Existing `evidence.finding_id` remains as the *primary genesis finding* (preserving 100% backward compatibility with Phases 3–11).
  - Any future persistent junction table is strictly additive with zero modifications to legacy columns.
  - Until persistent storage exists, the in-memory graph is a deterministic projection of authoritative existing relationships.
- **Graph Invariants**:
  - **Directed Acyclic Graph (DAG)**: Strictly acyclic: $\text{Evidence} \to \text{Asset Finding} \to \text{Cross-Asset Finding} \to \text{Project Risk}$.
  - **Safety Ceilings**: Maximum traversal depth $\Delta \le 5$, maximum child nodes per parent $\beta \le 100$.

---

## 4. Mathematical Risk Aggregation & Composition

### 4.1 Three-Tier Hierarchical Risk Formulation

Phase 12 extends Phase 11.9's sub-additive formulation into a **3-tier hierarchical risk model**:

#### Tier 1: Asset-Level Risk ($R(A)$)
For each asset $A \in \{\text{Datasets}, \text{Models}, \text{Contributors}, \text{InferencePipelines}\}$:
1. Partition asset evidence into modality clusters: $\mathcal{C}_1, \dots, \mathcal{C}_K$.
2. Compute cluster severity score:
   $$S(\mathcal{C}_k) = \min\left(1.0, \max_{e \in \mathcal{C}_k}(w_e \cdot c_e \cdot s_e) + \lambda_{\text{intra}} \sum_{e \in \mathcal{C}_k \setminus \{e^*\}} w_e \cdot c_e \cdot s_e\right)$$
3. Compute asset risk:
   $$R(A) = 1.0 - \prod_{k=1}^K \left(1.0 - S(\mathcal{C}_k)\right)$$

#### Tier 2: Cross-Asset Lineage Risk ($R_{\text{chain}}$)
Captures risk compounding along the explicit DAG dependency chain (e.g., Model $M$ depends on Dataset $D$ with contributor $C$):
$$R_{\text{chain}}(D \to M) = \gamma_{\text{prop}} \cdot R(D) \cdot R_{\text{vuln}}(M)$$
where $\gamma_{\text{prop}} \in [0.0, 0.50]$ (default: $0.25$) is the lineage propagation factor. If no explicit dependency edge exists between $D$ and $M$, $R_{\text{chain}}(D \to M) \equiv 0.0$.

#### Tier 3: Project-Level Operational Risk ($R_{\text{project}}$)
Synthesizes all individual asset risks and explicit lineage risks:
$$R_{\text{project}} = 1.0 - (1.0 - \max_{A} R(A))^{\alpha_{\text{peak}}} \cdot \prod_{A \in \mathcal{A}} (1.0 - \lambda_{\text{inter}} R(A))$$
where $\alpha_{\text{peak}} \ge 1.0$ guarantees that high risk in any single critical asset dominates the project score, while $\lambda_{\text{inter}} \in [0.05, 0.20]$ prevents artificial inflation across multiple healthy assets.

---

## 5. Proof-Layer Non-Compensability & Affected Scope

### 5.1 Formal Definition of Affected Scope
Statistical detections are probabilistic: $c_e \in [0.0, 1.0)$, $p$-values, effect sizes.  
Cryptographic proofs are binary: $\text{Valid} \equiv 1.0$, $\text{Violated} \equiv 0.0$.

$$\mathbf{Invariant}: \quad \text{Proof Layer Failure on Asset } A \implies R(A) = 1.0 \land \text{Disposition}(A) = \mathbf{REJECT}$$

### 5.2 Deterministic Scope & Propagation Rules
1. **Asset-Level Proof Violation**: Proof failure on Asset $A$ strictly makes Asset $A$'s affected scope non-compensable ($R(A)=1.0, \text{Disposition}(A)=\mathbf{REJECT}$).
2. **Unrelated Asset Isolation**: Unrelated Asset $B$ (having no lineage or dependency relationship to $A$) is **NOT** automatically rejected; its risk score $R(B)$ is computed purely from $B$'s own evidence.
3. **Lineage-Based Propagation**: Propagation to downstream Asset $M$ occurs if and only if an explicit lineage dependency edge exists in the DAG (e.g., Model $M$ depends on tampered Dataset $D$).
4. **Project-Level Disposition**:
   - Core Asset Proof Failure (e.g., primary model weight hash mismatch, provenance ledger break): Forces Project Disposition to $\mathbf{REJECT}$.
   - Peripheral Proof Failure (e.g., isolated single inference record hash mismatch): Forces Asset Disposition to $\mathbf{REJECT}$ and Project Disposition to at least $\mathbf{QUARANTINE}$.

Proof failures cannot be compensated, averaged, or mitigated by zero detection risk in other components.

---

## 6. Immutable Evidence Ancestry & Double-Counting Prevention

### 6.1 The Double-Counting Hazard
In assurance pipelines, risk can be double-counted when both a raw observation and an upstream synthesized finding representing the same physical artifact are aggregated as independent items:
$$\text{Raw Evidence} \longrightarrow \text{Finding} \longrightarrow \text{Domain Synthesized Finding} \longrightarrow \text{URE}$$

### 6.2 Ancestry Collapse & Exclusion Rules
1. **Evidence Ancestry Path**: Every evidence item maintains an immutable ancestry vector:
   $$\text{AncestryPath}(e) = \langle \text{sample\_id}, \text{dataset\_version\_id}, \text{model\_fingerprint}, \text{window\_id}, \text{source\_id} \rangle$$
2. **Ancestry Collapse Rule**: If two evidence items $e_1, e_2$ share the identical non-empty primary ancestry key, the URE collapses them into the same modality cluster $\mathcal{C}_k$ and applies intra-cluster damping ($\lambda_{\text{intra}}$).
3. **Synthesized Finding Exclusion**: When both a raw evidence item $e_{\text{raw}}$ and an upstream synthesized finding $F_{\text{synth}}$ derived from $e_{\text{raw}}$ are present, the URE includes only the synthesized finding's calibrated score, excluding the redundant raw item from independent additive accumulation.
4. **Missing / Ambiguous Ancestry Handling**: If ancestry metadata is missing or corrupted:
   - The URE **MUST NOT** assume the evidence is safe.
   - The URE marks the item as $\text{ancestry\_status} = \mathbf{UNVERIFIED}$, flags an $\mathbf{INSUFFICIENT\_EVIDENCE}$ advisory, and routes the assessment to $\mathbf{REVIEW}$.
   - The URE **NEVER** silently fabricates or hallucinates missing ancestry.

---

## 7. $7 \times 7$ Inter-Domain Correlation Matrix Governance

### 7.1 Canonical Domain Order & Dimensions
The URE defines a symmetric, zero-diagonal correlation penalty matrix $\mathbf{C} \in [0.0, 1.0]^{7 \times 7}$ across the exact seven upstream assurance domains:

| Index | Subsystem Domain Name | Short Key |
| :---: | :--- | :--- |
| `0` | **Dataset Integrity** | `DATASET_INTEGRITY` |
| `1` | **Contributor Risk** | `CONTRIBUTOR_RISK` |
| `2` | **Model Integrity** | `MODEL_INTEGRITY` |
| `3` | **Behavioral Analysis** | `BEHAVIORAL_ANALYSIS` |
| `4` | **Backdoor / Trigger Analysis** | `BACKDOOR_TRIGGER` |
| `5` | **Inference Integrity** | `INFERENCE_INTEGRITY` |
| `6` | **Distribution Shift** | `DISTRIBUTION_SHIFT` |

### 7.2 Matrix Invariants & Mathematical Formulation
1. **Dimensions**: Fixed $7 \times 7$.
2. **Symmetry**: Mandatory $\mathbf{C}_{ij} = \mathbf{C}_{ji}$ for all $i, j \in \{0, \dots, 6\}$.
3. **Zero Diagonal**: Mandatory $\mathbf{C}_{ii} = 0.0$ (intra-domain correlation is governed by intra-cluster damping $\lambda_{\text{intra}}$).
4. **Numeric Range**: $\mathbf{C}_{ij} \in [0.0, 1.0]$.
5. **Effective Weight Attenuation**:
   $$w_{\text{effective}}(e_j) = w_j \cdot \prod_{i \neq j, \text{active}(i)} (1.0 - \mathbf{C}_{ij} \cdot \bar{S}_i)$$
   where $\bar{S}_i$ is the normalized mean severity of active domain $i$.
6. **Inactive Domain Rule**: If a domain has no active evidence, it exerts zero damping on other domains ($\bar{S}_i = 0.0$).
7. **Policy Ownership & Cryptographic Hashing**:
   $$\text{correlation\_matrix\_hash} = \text{SHA-256}(\text{RFC 8785 JCS}(\{\text{version}, \text{domain\_order}, \text{dimension}, \text{matrix\_values}\}))$$
8. **Extensibility Invariant**: If future major phases introduce new domains, a formal version bump and new matrix schema must be published; zero dynamic or unversioned domain additions are permitted.

---

## 8. Cryptographic Provenance Chain Definition

### 8.1 Verifiable Ancestry Chain
The URE establishes a concrete, cryptographically verifiable provenance chain connecting the top-level assurance dossier back to genesis evidence:
```
UniversalAssuranceDossier
    │ (dossier_hash = SHA-256(JCS(dossier_payload)))
    ▼
Decision (disposition, rationale, policy_hashes)
    │ (decision_hash = SHA-256(JCS(decision_payload)))
    ▼
RiskAssessment (R_project, R_asset[], component_scores)
    │ (assessment_hash = SHA-256(JCS(assessment_payload)))
    ▼
RiskContribution[] (cluster_scores, damping_logs)
    │
    ▼
Finding[] (finding_id, finding_type, severity, confidence)
    │ (finding_hash = SHA-256(JCS(finding_payload)))
    ▼
Evidence[] (evidence_id, evidence_hash, data_json)
    │ (evidence_hash = SHA-256(JCS(data_json)))
    ▼
ProvenanceRecord[] (Phase 4 hash-linked audit chain)
```

### 8.2 Broken Chain / Incomplete Provenance Behavior
- If any cryptographic digest along the chain fails to verify, the engine immediately halts with a `ProvenanceIntegrityError` and sets the disposition to $\mathbf{REJECT}$.
- If provenance links are absent for an asset, the engine emits $\mathbf{UNVERIFIED\_PROVENANCE}$ and sets disposition to at least $\mathbf{QUARANTINE}$.

---

## 9. Resource Governance: Ceilings, Complexity & Performance Targets

Phase 12 explicitly partitions resource governance into three formal categories:

### A. Hard Resource Safety Ceilings (Mandatory Safety Constraints)
- **Maximum Evidence Records**: $E_{\max} = 5,000$ per evaluation run.
- **Maximum Findings**: $F_{\max} = 1,000$ per project.
- **Maximum Assets**: $A_{\max} = 250$ per project.
- **Maximum Graph Traversal Depth**: $\Delta \le 5$.
- **Maximum Graph Breadth**: $\beta \le 100$ children per parent.
- **Exceeding Hard Ceilings**: Triggers an immediate fail-closed `ResourceLimitExceededError`.

### B. Algorithmic Complexity Guarantees (Mathematical Design)
- **Graph Construction & DAG Traversal**: Guaranteed $O(V + E)$ linear time complexity using iterative BFS/DFS with visited sets.
- **Cycle Detection**: Guaranteed $O(V + E)$ using depth-first topological sorting.
- **Risk Aggregation**: Guaranteed $O(K)$ where $K \le 100$ is the number of modality clusters.

### C. Empirical Performance Acceptance Targets (Workstation Benchmarks)
- **Execution Time Target**: $< 2.0\text{s}$ for a maximum capacity workload ($E=5000, F=1000, A=250$) on the reference workstation environment.
- **Memory Consumption Target**: $< 150\text{MB}$ peak RSS during graph synthesis and risk aggregation.
- **Acceptance Verification**: Performance targets are empirical acceptance criteria validated in performance test suites, NOT mathematical universal constants.
