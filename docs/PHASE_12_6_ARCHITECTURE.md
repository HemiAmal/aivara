# Phase 12.6 — Universal Risk Computation Architecture

**Status:** Authoritative Design Specification  
**Authority:** Phase 12.1 Universal Risk Architecture Freeze  
**Upstream Dependencies:** Phase 12.2 Normalization, Phase 12.3 Evidence Graph, Phase 12.4 Cross-Subsystem Evidence Ingestion, Phase 12.5 Evidence Dependency & Correlation Modeling  
**Downstream Phases:** Phase 12.7 Policy & Decision Engine, Phase 12.8 Proof & Provenance Integration, Phase 12.9 Project & Multi-Asset Risk Aggregation  

---

## 1. Architectural Mission & Positioning

Phase 12.6 transforms validated, normalized, ancestry-tagged, and correlated evidence from the Universal Evidence Graph into deterministic, bounded, and cryptographically verifiable asset-level and universal risk assessments.

```
Universal Evidence Graph (Phase 12.3 / 12.4)
                    │
                    ▼
     [Phase 12.5 Correlation Engine]
      (Domain Attenuation Factors)
                    │
                    ▼
    [Phase 12.6 Universal Risk Engine]
  ┌─────────────────────────────────────┐
  │ 1. Evidence Term Calculation        │
  │    term(e) = w_e × c_e × s_e × att  │
  │ 2. Ancestry-Aware Clustering        │
  │    C_k from standardized ancestry   │
  │ 3. Intra-Cluster Damping (λ=0.15)   │
  │    S(C_k) = min(1, max + 0.15*sum)  │
  │ 4. Bounded Composition              │
  │    R(A) = 1 - Π (1 - S(C_k))        │
  │ 5. RFC 8785 JCS + SHA-256 Hashing   │
  └─────────────────────────────────────┘
                    │
                    ▼
       UniversalRiskAssessment
        (Numerical Score & Hash)
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
 [Phase 12.7 Policy]    [Phase 12.9 Multi-Asset]
```

---

## 2. Mathematical Formulation & Invariants

### 2.1 Evidence Contribution (`term(e)`)
For an individual evidence node $e \in E$:
$$term(e) = w_e \times c_e \times s_e$$
where:
- $w_e \in [0.0, 1.0]$: Evidence relevance weight
- $c_e \in [0.0, 1.0]$: Detection confidence (from upstream evidence)
- $s_e \in [0.0, 1.0]$: Canonical severity multiplier:
  - `CRITICAL` = 1.00
  - `HIGH` = 0.70
  - `MEDIUM` = 0.40
  - `LOW` = 0.10
  - `INFO` = 0.05

### 2.2 Phase 12.5 Correlation Integration
When a Phase 12.5 `CrossDomainCorrelationAssessment` is provided:
- For detection evidence ($layer == DETECTION$):
  $$term_{\text{damped}}(e) = term(e) \times att_{\text{domain}(e)}$$
  where $att_{\text{domain}(e)}$ is the domain attenuation factor computed by Phase 12.5.
- For proof evidence ($layer == PROOF$):
  $$term_{\text{damped}}(e) = term(e) \quad (\text{Proof Inviolability, } att = 1.0)$$

### 2.3 Ancestry-Aware Clustering ($C_k$)
Evidence items referencing the same anomaly / lineage are grouped by standard ancestry tuple:
$$\langle \text{sample\_id}, \text{dataset\_version\_id}, \text{model\_fingerprint}, \text{window\_id}, \text{source\_id} \rangle$$
If ancestry is missing or unlinked, an independent cluster ID is assigned and tagged as `INSUFFICIENT_ANCESTRY`.

### 2.4 Intra-Cluster Damping ($\lambda_{\text{intra}} = 0.15$)
To prevent redundant additive inflation from co-occurring observations in the same cluster:
$$S(C_k) = \min\left(1.0, \max_{e \in C_k}(term(e)) + \lambda_{\text{intra}} \sum_{e' \ne \max} term(e')\right)$$

### 2.5 Bounded Asset Risk Composition ($R(A)$)
Over all clusters $C_k$ associated with asset $A$:
$$R(A) = 1.0 - \prod_{k} (1.0 - S(C_k))$$
Invariant: $0.0 \le R(A) \le 1.0$.

### 2.6 Deterministic Decimal Rounding
All floating-point results are rounded using `Decimal` arithmetic with `ROUND_HALF_UP` to 6 decimal places.

### 2.7 Cryptographic Identity (`risk_hash`)
Assessment identity is computed over canonicalized fields (schema version, policy version, project ID, asset ID, risk score, cluster scores, correlation hash, graph Merkle root) using RFC 8785 JSON Canonicalization Scheme (JCS) and SHA-256.

---

## 3. Responsibility Reconciliation: 12.6 vs 12.9

| Architectural Capability | Phase 12.6 (Current) | Phase 12.9 (Future) | Notes / Boundary |
|---|---|---|---|
| Evidence Term Calculation ($term(e)$) | **OWNED** | — | Single evidence contribution |
| Ancestry-Aware Clustering ($C_k$) | **OWNED** | — | Intra-cluster grouping |
| Intra-Cluster Damping ($\lambda_{\text{intra}} = 0.15$) | **OWNED** | — | Within-cluster damping |
| Asset-Level Bounded Risk ($R(A)$) | **OWNED** | — | Per-asset risk composition |
| Universal Risk ($R_{\text{universal}}$) | **OWNED** | — | Asset risk collection & evaluation |
| Lineage / Inter-Asset Propagation ($\gamma_{\text{prop}}$) | — | **RESERVED** | Belongs strictly to 12.9 |
| Chain Risk Aggregation ($R_{\text{chain}}$) | — | **RESERVED** | Belongs strictly to 12.9 |
| Inter-Asset Damping ($\lambda_{\text{inter}}$) | — | **RESERVED** | Belongs strictly to 12.9 |
| Peak Risk Exponent ($\alpha_{\text{peak}}$) | — | **RESERVED** | Belongs strictly to 12.9 |
| Project-Level Risk Aggregation ($R_{\text{project}}$) | — | **RESERVED** | Belongs strictly to 12.9 |

---

## 4. Hard Security & Boundary Invariants

1. **Zero Policy Decisions:** Phase 12.6 computes numerical $R(A) \in [0.0, 1.0]$. It NEVER outputs `ACCEPT`, `REVIEW`, `QUARANTINE`, or `REJECT`.
2. **Zero Proof Overrides:** Proof evidence semantics are preserved without attenuation, but Phase 12.6 NEVER issues final proof overrides ($R=1.0 \rightarrow \text{REJECT}$).
3. **Zero Chain / Project Aggregation:** Phase 12.6 produces asset and universal risk. Chain risk and project risk aggregation remain reserved for Phase 12.9.
4. **Project Boundary Isolation:** Evidence from project $P_A$ cannot contribute to risk calculation of project $P_B$.
5. **Asset Boundary Isolation:** Evidence bound to asset $A_1$ cannot contribute to asset $A_2$ risk.
6. **100% Offline Air-Gap:** Zero network calls, zero external APIs, zero socket communication.
