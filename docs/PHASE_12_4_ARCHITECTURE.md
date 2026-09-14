# PHASE 12.4 — HIERARCHICAL MULTI-ASSET RISK AGGREGATION ENGINE ARCHITECTURE

## 1. Executive Summary

Phase 12.4 establishes the authoritative **Hierarchical Multi-Asset Risk Aggregation Engine** for the AIVARA verification workstation.

Consuming the immutable, cycle-free `UniversalEvidenceGraph` from Phase 12.3 and the canonical `UniversalEvidenceEnvelope` contracts from Phase 12.2, Phase 12.4 calculates closed-form, sub-additive, bounded operational risk across a 3-tier hierarchy:
1. **Tier 1 (Asset Level $R(A)$)**: Modality clustering with intra-cluster damping ($\lambda_{\text{intra}} = 0.15$) and asymptotic saturation.
2. **Tier 2 (Lineage Chain Risk $R_{\text{chain}}$)**: Pairwise compounding along explicit DAG dependency edges ($\gamma_{\text{prop}} = 0.25$).
3. **Tier 3 (Project Operational Risk $R_{\text{project}}$)**: Dominance-preserving multi-asset synthesis ($\alpha_{\text{peak}} = 1.0, \lambda_{\text{inter}} = 0.10$).

---

## 2. Mathematical Formulations

### Tier 1: Asset-Level Operational Risk ($R(A)$)
For each target asset $A$:
1. Group evidence and findings into ancestry clusters: $\mathcal{C}_1, \dots, \mathcal{C}_K$.
2. Compute intra-cluster damped score:
   $$S(\mathcal{C}_k) = \min\left(1.0, \max_{e \in \mathcal{C}_k}(w_e \cdot c_e \cdot s_e) + \lambda_{\text{intra}} \sum_{e \in \mathcal{C}_k \setminus \{e^*\}} w_e \cdot c_e \cdot s_e\right)$$
3. Compute asset risk via sub-additive bounded composition:
   $$R(A) = 1.0 - \prod_{k=1}^K (1.0 - S(\mathcal{C}_k)) \in [0.0, 1.0]$$

### Tier 2: Cross-Asset Lineage Chain Risk ($R_{\text{chain}}$)
For an explicit DAG lineage edge $A_1 \to A_2$:
$$R_{\text{chain}}(A_1 \to A_2) = \gamma_{\text{prop}} \cdot R(A_1) \cdot R(A_2) \in [0.0, 1.0]$$

### Tier 3: Project Operational Risk ($R_{\text{project}}$)
Synthesizes all individual asset risks $\{R(A) : A \in \mathcal{A}\}$:
$$R_{\text{project}} = 1.0 - (1.0 - \max_{A \in \mathcal{A}} R(A))^{\alpha_{\text{peak}}} \cdot \prod_{A \in \mathcal{A}} (1.0 - \lambda_{\text{inter}} R(A)) \in [0.0, 1.0]$$

---

## 3. Analytical Uncertainty & Data Quality State

Missing or ambiguous ancestry is treated purely as an **analytical data-quality state**:
- Tracked via `EvidenceSufficiencyStatus` (`SUFFICIENT`, `INSUFFICIENT_ANCESTRY`, `UNVERIFIED`).
- Preserves mathematical risk calculation without fabrications or synthetic heuristics.
- **Phase 12.4 does NOT perform decision routing or assign policy dispositions** (e.g., no routing to `REVIEW`, `ACCEPT`, `QUARANTINE`, or `REJECT`).
- Phase 12.8 is the sole authoritative owner of policy disposition mapping and dossier decision sealing.

---

## 4. Component Architecture & Package Layout

```
backend/aivara/universal/risk/
├── enums.py         # RiskLevel, AggregationStage, EvidenceSufficiencyStatus, AggregationSchemaVersion
├── exceptions.py    # NonFiniteRiskError, RiskOutOfRangeError, InvalidPolicyConfigurationError
├── config.py        # ImmutableAggregationConfig with JCS canonical hashing
├── schemas.py       # RiskContribution, AssetRiskAssessment, ChainRiskAssessment, ProjectRiskAssessment, HierarchicalRiskAssessment
├── aggregator.py    # HierarchicalRiskAggregator (Closed-form math engine)
└── __init__.py      # Package export interface
```

---

## 5. Subsystem Boundary Rules

- **Phase 12.4 calculates risk. Phase 12.4 does not make decisions.**
- **Strict Boundary Separation**:
  - No cross-subsystem correlation matrix damping ($\mathbf{C}_{7 \times 7}$ belongs to Phase 12.5).
  - No proof-layer rejection overrides / non-compensable REJECT (belongs to Phase 12.6).
  - No global mutable policy registry (belongs to Phase 12.7).
  - No disposition decision mapping / dossier sealing (belongs to Phase 12.8).
