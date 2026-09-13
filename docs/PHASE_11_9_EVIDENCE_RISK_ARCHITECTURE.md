# Phase 11.9: Evidence, Findings & Multi-Modal Risk Integration Architecture

**Project**: AIVARA — AI Verification & Assurance  
**Phase**: 11 — Distribution Shift / Data Drift Analysis  
**Subphase**: 11.9.1 — Architecture & Requirements Freeze  
**Status**: AUTHORITATIVE FROZEN ARCHITECTURE SPECIFICATION  
**Date**: September 2026  

---

## 1. Architectural Overview & Design Philosophy

Phase 11.9 defines the **Evidence, Findings & Multi-Modal Risk Integration Engine** (`backend/aivara/drift/integration_engine.py`). It serves as the central synthesis authority that transforms heterogeneous, multi-modal evidence outputs (from Phases 4–10 and Phases 11.1–11.8) into calibrated risk signals, plain-language rationales, and policy-driven operational dispositions.

### The 5-Stage Synthesis Flow
$$\boxed{\text{Stage 1: Evidence Ingestion}} \longrightarrow \boxed{\text{Stage 2: Clustering \& Finding Synthesis}} \longrightarrow \boxed{\text{Stage 3: Confidence Calibration}} \longrightarrow \boxed{\text{Stage 4: Damped Risk Aggregation}} \longrightarrow \boxed{\text{Stage 5: Policy Disposition}}$$

```
+---------------------------------------------------------------------------------------------------------+
|                                    AIVARA INTEGRATION ARCHITECTURE                                      |
+---------------------------------------------------------------------------------------------------------+
|                                                                                                         |
|   Phase 4–10 & Phase 11.1–11.8 Subsystems                                                               |
|   [Phase 4: Provenance] [Phase 5: Data Integrity] [Phase 6: Contrib Risk] [Phase 7: Model Integrity]     |
|   [Phase 8: Behavior]   [Phase 9: Trigger Lab]    [Phase 10: Inference]   [Phase 11.1–11.8: Drift]      |
|                              │                                                                          |
|                              ▼                                                                          |
|   [Layer 1: Evidence Boundary & Ingestion] ────────► Validates schema, tenant scope & RFC 8785 digests  |
|                              │                                                                          |
|                              ▼                                                                          |
|   [Layer 2: Validation & Deduplication]   ────────► Content-addressed deduplication (evidence_hash)     |
|                              │                                                                          |
|                              ▼                                                                          |
|   [Layer 3: Ancestry Clustering]          ────────► Groups by shared asset lineage (Modality Clusters)  |
|                              │                                                                          |
|                              ▼                                                                          |
|   [Layer 4: Finding Synthesis]            ────────► Synthesizes multi-modal findings (Non-Attribution)  |
|                              │                                                                          |
|                              ▼                                                                          |
|   [Layer 5: Confidence Calibration]       ────────► Proof (1.0) vs. Detection (1 - p_adj) bounds       |
|                              │                                                                          |
|                              ▼                                                                          |
|   [Layer 6: Damped Risk Aggregation]      ────────► Damped inter-modality aggregation (lambda = 0.10)   |
|                              │                                                                          |
|                              ▼                                                                          |
|   [Layer 7: Decision Policy Dispatch]     ────────► Maps risk to ACCEPT, REVIEW, QUARANTINE, REJECT     |
|                              │                                                                          |
|                              ▼                                                                          |
|   [Layer 8: Audit Trail & Lineage Binding]────────► Decision -> Risk -> Finding -> Evidence -> Artifact |
|                              │                                                                          |
|                              ▼                                                                          |
|   [Layer 9: Cryptographic Fingerprinting] ────────► RFC 8785 JCS + SHA-256 Integrated Profile Hash      |
|                              │                                                                          |
|                              ▼                                                                          |
|   [Layer 10: Domain & Provenance Output]  ────────► Output IntegratedAssuranceProfile & RiskAssessment  |
+---------------------------------------------------------------------------------------------------------+
```

---

## 2. Layer-by-Layer Architectural Specification

### Layer 1: Evidence Boundary & Ingestion
- Ingests standard `EvidenceModel` / `EvidenceRead` objects from upstream subsystems.
- Validates tenant boundary: asserts that all evidence records match `target_project_id`. Throws `ProjectMismatchError` on any discrepancy.
- Enforces strict resource budget: $E \le 1000$ evidence items per evaluation.

### Layer 2: Validation & Deduplication
- Computes deterministic content digest for each record:
  $$\text{evidence\_hash} = \text{SHA-256}(\text{RFC8785}(e.\text{data\_json}))$$
- Filters out exact duplicate evidence records, tracking duplicate count in accounting metadata.

### Layer 3: Evidential Ancestry Clustering
- Resolves the **Primary Asset Ancestor** for each evidence record:
  - `dataset_version_id` (for sample, feature, and dataset drift)
  - `model_fingerprint` (for model integrity and inference binding)
  - `source_group_id` (for contributor and source partitions)
  - `window_id` (for temporal window sequences)
- Clusters evidence sharing identical asset ancestry into a unified **Modality Cluster** $\mathcal{C}_k$.

### Layer 4: Finding Synthesis
- Unifies individual detector alerts into consolidated `FindingModel` instances under the `detection` evidence layer.
- **Strict Non-Attribution Template**:
  `"Title: Multi-modal distribution divergence observed across {modalities}."`
  `"Description: Statistically significant divergence detected relative to baseline reference. Observational non-stationarity identified without causal attribution."`
- Preserves all underlying `FindingModel` IDs in `linked_finding_ids`.

### Layer 5: Confidence Calibration
- **Proof Layer**: $\text{Confidence} = 1.0$ (Strictly required by Pydantic validator).
- **Detection Layer**:
  $$\text{Confidence} = \max\left(0.50, \min\left(0.99, 1.0 - p_{\text{adj}}\right)\right)$$
  where $p_{\text{adj}}$ is the Benjamini-Hochberg FDR-adjusted p-value from Phase 11.3.

### Layer 6: Damped Multi-Modal Risk Aggregation
To eliminate artificial risk inflation from multiple detectors observing the same physical shift:
1. For each cluster $\mathcal{C}_k$, compute primary component score:
   $$S(\mathcal{C}_k) = \max_{e_i \in \mathcal{C}_k} \left( w(e_i) \cdot c(e_i) \right) + \sum_{e_j \in \mathcal{C}_k \setminus \{e_{\max}\}} \lambda_{\text{corr}} \cdot \left( w(e_j) \cdot c(e_j) \right)$$
   where $\lambda_{\text{corr}} = 0.10$ is the correlation damping coefficient and $w(e)$ is the category severity weight.
2. Compute composite overall risk score $R \in [0.0, 1.0]$:
   $$R = 1.0 - \prod_{k=1}^K \left( 1.0 - S(\mathcal{C}_k) \right)$$
   This bounded sub-additive aggregation ensures asymptotic saturation at $1.0$ without linear over-accumulation.

### Layer 7: Decision Policy Dispatch
Evaluates composite risk score $R$ against versioned policy thresholds $\mathcal{P}_{\text{dec}}$:
- **Proof Violation Rule**: If any Proof Layer violation exists $\implies \text{Disposition} = \mathbf{REJECT}$.
- **Detection Decision Mapping**:
  $$\text{Disposition} = \begin{cases}
  \mathbf{ACCEPT} & \text{if } R < 0.30 \\
  \mathbf{REVIEW} & \text{if } 0.30 \le R < 0.65 \\
  \mathbf{QUARANTINE} & \text{if } 0.65 \le R < 0.85 \\
  \mathbf{REJECT} & \text{if } R \ge 0.85
  \end{cases}$$
- **Fail-Closed Missing Data Rule**: If critical required modalities are unanalyzed $\implies \text{Disposition} = \mathbf{INSUFFICIENT\_EVIDENCE}$ (routes to `REVIEW`).

### Layer 8: Audit Trail & Lineage Binding
- Binds every downstream decision to its full antecedent DAG:
  $$\text{Disposition} \longleftrightarrow \text{RiskScore} \longleftrightarrow \text{Findings} \longleftrightarrow \text{EvidenceRecords} \longleftrightarrow \text{ArtifactHashes}$$
- Emits human-readable explainability rationale detailing primary contributing dimensions.

### Layer 9: Cryptographic Fingerprinting (RFC 8785 JCS)
- Computes deterministic SHA-256 digests over all canonical structures:
  - `evidence_set_hash`: SHA-256 over lexicographically sorted evidence digests.
  - `risk_policy_hash`: SHA-256 over canonical risk weighting configuration.
  - `decision_policy_hash`: SHA-256 over canonical decision thresholds.
  - `integrated_profile_hash`: SHA-256 over canonical `IntegratedAssuranceProfile` descriptor.

### Layer 10: Domain & Provenance Output
- Synthesizes `IntegratedAssuranceProfile` and standard `RiskAssessment` schemas compatible with AIVARA SQLite database models. Zero new tables or migrations required.

---

## 3. Schema Definitions for Integration Models

```python
class EvidenceCategory(str, Enum):
    CRYPTOGRAPHIC_PROOF = "CRYPTOGRAPHIC_PROOF"
    DATASET_INTEGRITY = "DATASET_INTEGRITY"
    CONTRIBUTOR_RISK = "CONTRIBUTOR_RISK"
    MODEL_INTEGRITY = "MODEL_INTEGRITY"
    BEHAVIORAL_ANOMALY = "BEHAVIORAL_ANOMALY"
    TRIGGER_ACTIVATION = "TRIGGER_ACTIVATION"
    INFERENCE_INTEGRITY = "INFERENCE_INTEGRITY"
    DISTRIBUTION_SHIFT = "DISTRIBUTION_SHIFT"

class IntegratedAssuranceProfile(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default="1.0", max_length=20)
    analysis_version: str = Field(default="1.0", max_length=20)
    project_id: str = Field(..., min_length=1, max_length=64)
    target_asset_type: str = Field(..., min_length=1, max_length=50)
    target_asset_id: str = Field(..., min_length=1, max_length=64)
    overall_disposition: Disposition
    overall_risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_level: str = Field(..., min_length=1, max_length=20)
    proof_violations_count: int = Field(default=0, ge=0)
    detection_findings_count: int = Field(default=0, ge=0)
    evidence_set_hash: str = Field(..., min_length=64, max_length=64)
    risk_policy_hash: str = Field(..., min_length=64, max_length=64)
    decision_policy_hash: str = Field(..., min_length=64, max_length=64)
    integrated_profile_hash: str = Field(..., min_length=64, max_length=64)
    component_scores: Dict[str, float] = Field(default_factory=dict)
    rationale: str = Field(..., min_length=1)
    synthesized_findings: List[Dict[str, Any]] = Field(default_factory=list)
    deduplicated_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
```

---

## 4. Architectural Summary

Phase 11.9 establishes a mathematically sound, tamper-evident, and explainable synthesis engine that unifies all AIVARA assurance outputs while upholding the foundational non-attribution and proof-layer separation invariants.
