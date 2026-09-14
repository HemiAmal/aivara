# Phase 12.5 — Evidence Dependency & Correlation Modeling Architecture

**Status:** Authoritative Design Specification  
**Authority:** Phase 12.1 Universal Risk Architecture Freeze  
**Upstream Dependencies:** Phase 12.2 Normalization, Phase 12.3 Evidence Graph, Phase 12.4 Cross-Subsystem Evidence Ingestion  
**Downstream Phases:** Phase 12.6 Universal Risk Computation  

---

## 1. Architectural Mission & Positioning

Phase 12.5 establishes the mathematical dependency and cross-domain correlation layer for AIVARA. It models how evidence in one assurance domain informs the interpretation and severity damping of detection-layer evidence in another domain.

```
Universal Evidence Graph (Phase 12.3 / 12.4)
                    │
                    ▼
     [Evidence Dependency Layer]
                    │
                    ▼
   [7x7 Canonical Correlation Matrix]
                    │
                    ▼
    [Damped Detection Domain Summaries]
                    │
                    ▼
  [Phase 12.6 Universal Risk Computation]
```

---

## 2. Frozen 7x7 Cross-Domain Correlation Matrix

The canonical cross-domain correlation matrix $C \in [0,1]^{7 \times 7}$ is defined over the 7 frozen canonical assurance domains:

0. `DATASET_INTEGRITY` (Phase 5)
1. `CONTRIBUTOR_RISK` (Phase 6)
2. `MODEL_INTEGRITY` (Phase 7)
3. `BEHAVIORAL_ANALYSIS` (Phase 8)
4. `BACKDOOR_TRIGGER` (Phase 9)
5. `INFERENCE_INTEGRITY` (Phase 10)
6. `DISTRIBUTION_SHIFT` (Phase 11)

### Matrix Invariants:
1. **Dimension:** Exactly $7 \times 7$.
2. **Domain Order:** Strictly follows the canonical 0..6 sequence.
3. **Range:** $C_{ij} \in [0.0, 1.0]$.
4. **Symmetry:** $C_{ij} = C_{ji}$ for all $i, j$.
5. **Zero Diagonal:** $C_{ii} = 0.0$ for all $i$ (no self-damping).
6. **Cryptographic Identity:** Computed via RFC 8785 JCS canonicalization + SHA-256 (`matrix_hash`).

---

## 3. Mathematical Dependency Formulation

### 3.1 Domain Detection Mean Severity ($\bar{S}_i$)
For an active domain $i$, the mean detection severity is computed over detection-layer evidence:
$$\bar{S}_i = \frac{1}{|E_i^{\text{det}}|} \sum_{e \in E_i^{\text{det}}} (w_e \cdot c_e \cdot s_e)$$
where:
- $w_e \in [0.0, 1.0]$: Evidence relevance weight
- $c_e \in [0.0, 1.0]$: Detection confidence
- $s_e \in [0.0, 1.0]$: Severity weight (`CRITICAL`=1.0, `HIGH`=0.70, `MEDIUM`=0.40, `LOW`=0.10, `INFO`=0.05)

### 3.2 Cross-Domain Attenuation ($att_j$)
For target detection domain $j$:
$$att_j = \prod_{i \ne j, \text{active}(i)} (1 - C_{ij} \cdot \bar{S}_i)$$
$$\bar{S}_j^{\text{damped}} = \bar{S}_j \cdot att_j$$

---

## 4. Hard Security & Boundary Invariants

1. **Proof-Layer Inviolability:** Proof-layer evidence ($layer == PROOF$) is NEVER attenuated, damped, or compensated. Proof evidence retains its invariant proof semantics.
2. **No Decision Leakage:** Phase 12.5 outputs strictly analytical metrics (`DomainCorrelationSummary`, `CrossDomainContributionTrace`, `CrossDomainCorrelationAssessment`). It NEVER outputs `ACCEPT`, `REVIEW`, `QUARANTINE`, or `REJECT`.
3. **No Risk Computation:** Universal risk, project risk, chain risk, and asset risk calculations belong strictly to Phase 12.6 and Phase 12.9.
4. **Multi-Tenant Isolation:** Assessment cannot evaluate cross-project graphs ($P_{\text{assessment}} = P_{\text{graph}}$).
5. **100% Offline Air-Gap:** Zero network calls, zero external APIs, zero socket communication.
