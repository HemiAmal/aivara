# PHASE 12.9 — PROJECT & MULTI-ASSET RISK AGGREGATION ARCHITECTURE

**Author:** DeepMind Antigravity Pair Programmer  
**Phase:** 12.9 — Project & Multi-Asset Risk Aggregation  
**Status:** ARCHITECTURAL BASELINE SPECIFICATION  
**Upstream Phases:** Phase 12.1 (Freeze), Phase 12.2 (Normalization), Phase 12.3 (Graph), Phase 12.4 (Ingestion), Phase 12.5 (Correlation), Phase 12.6 (Universal Risk), Phase 12.7 (Policy & Decision), Phase 12.8 (Proof & Provenance)  
**Downstream Phases:** Phase 12.10 Universal Risk API & Task Integration, Phase 12.11 Audit & Compliance Reporting  

---

## 1. Purpose & Scope

Phase 12.9 extends AIVARA from single-asset risk assessment to deterministic:
1. **Tier-1 Asset-Level Risk $R(A)$**: Ancestry clustering and intra-cluster damping for individual assets.
2. **Tier-2 Cross-Asset Lineage / Chain Risk $R_{\text{chain}}$**: Compounding risk along explicit Directed Acyclic Graph (DAG) dependencies.
3. **Tier-3 Project Operational Risk $R_{\text{project}}$**: Multi-asset synthesis preserving peak dominance and inter-asset damping.
4. **Proof-Aware Disposition Escalation**: Reconciling Phase 12.8 cryptographic proof assessments into project-level assurance decisions.

---

## 2. Architectural Position

```
[Universal Evidence (Phase 12.2)]
       │
       ▼
[Finding/Evidence Graph (Phase 12.3)]
       │
       ▼
[Cross-Subsystem Ingestion (Phase 12.4)]
       │
       ▼
[Correlation & Attenuation (Phase 12.5)]
       │
       ▼
[Universal Risk Computation (Phase 12.6)]
       │
       ▼
[Policy & Decision Engine (Phase 12.7)]
       │
       ▼
[Proof & Provenance Integration (Phase 12.8)]
       │
       ▼
>>> [Phase 12.9 Project & Multi-Asset Risk Aggregation] <<<
       │
       ├── Tier 1: Asset-Level Risk Synthesis R(A)
       ├── Tier 2: DAG Lineage & Chain Risk R_chain
       ├── Tier 3: Project Risk R_project (Peak Dominance)
       └── Proof Escalation (Core = REJECT, Peripheral = QUARANTINE)
       │
       ▼
[Phase 12.10 Universal Risk API & Task Integration]
```

---

## 3. Mathematical Foundations

### Tier 1: Asset-Level Risk $R(A)$
For each asset $A \in \{\text{Datasets}, \text{Models}, \text{InferencePipelines}, \text{Contributors}\}$:
1. Partition asset evidence into ancestry clusters $\mathcal{C}_1, \dots, \mathcal{C}_K$.
2. Compute cluster severity score:
   $$S(\mathcal{C}_k) = \min\left(1.0, \max_{e \in \mathcal{C}_k} (w_e \cdot c_e \cdot s_e) + \lambda_{\text{intra}} \sum_{e \in \mathcal{C}_k \setminus \{e^*\}} w_e \cdot c_e \cdot s_e\right)$$
   where $\lambda_{\text{intra}} = 0.15$.
3. Compute asset risk via sub-additive bounded composition:
   $$R(A) = 1.0 - \prod_{k=1}^K (1.0 - S(\mathcal{C}_k))$$

### Tier 2: Cross-Asset Lineage Chain Risk $R_{\text{chain}}$
For explicit dependency edges connecting upstream source asset $A_{\text{src}}$ to downstream target asset $A_{\text{tgt}}$ (e.g., Dataset $\to$ Model):
$$R_{\text{chain}}(A_{\text{src}} \to A_{\text{tgt}}) = \min\left(1.0, \gamma_{\text{prop}} \cdot R(A_{\text{src}}) \cdot R(A_{\text{tgt}})\right)$$
where $\gamma_{\text{prop}} \in [0.0, 0.50]$ (default: $0.25$) is the lineage propagation factor.
For multi-hop chains $A_1 \to A_2 \to \dots \to A_m$:
$$R_{\text{chain}} = 1.0 - \prod_{i=1}^{m-1} \left(1.0 - R_{\text{chain}}(A_i \to A_{i+1})\right)$$
If no explicit dependency edge connects $A$ and $B$, $R_{\text{chain}}(A \to B) \equiv 0.0$.

### Tier 3: Project Operational Risk $R_{\text{project}}$
Project risk synthesizes all individual asset risks with peak dominance preservation:
$$R_{\text{project}} = 1.0 - (1.0 - \max_{A \in \mathcal{A}} R(A))^{\alpha_{\text{peak}}} \cdot \prod_{A \in \mathcal{A}} (1.0 - \lambda_{\text{inter}} R(A))$$
where:
- $\alpha_{\text{peak}} \ge 1.0$ (default: $1.50$) ensures that critical risk in any single asset dominates the project score.
- $\lambda_{\text{inter}} \in [0.05, 0.20]$ (default: $0.10$) provides bounded compounding across independent healthy assets without artificial inflation.

---

## 4. Asset Roles & Proof-Aware Escalation

Assets are classified into distinct structural roles:
1. `CORE_DEPLOYED`: Primary AI models, production inference pipelines, and authoritative root training sets.
2. `PERIPHERAL_SAMPLE`: Test batches, experimental partitions, peripheral telemetry.
3. `SUPPORTING_INPUT`: Feature registries, reference baselines.

### Proof Escalation Rules
- **Core Asset Proof Failure**: If a `CORE_DEPLOYED` asset has an authoritative proof failure (`TAMPERED`, `INVALID`, `REPLAY_DETECTED`), the project-level disposition is escalated to $\mathbf{REJECT}$.
- **Peripheral Asset Proof Failure**: If a `PERIPHERAL_SAMPLE` asset suffers a proof failure, the affected asset is $\mathbf{REJECT}$, and the project disposition is escalated to at least $\mathbf{QUARANTINE}$.
- **Asset Isolation**: Proof failure on Asset $A$ does not automatically reject independent Asset $B$.

---

## 5. DAG Validation & Cycle Detection

- Dependency graphs between assets must be strictly Directed Acyclic Graphs (DAGs).
- Self-dependencies ($A \to A$), direct cycles ($A \to B \to A$), and indirect cycles ($A \to B \to C \to A$) fail closed with `DependencyCycleError`.
- Bounded traversal depth: $\Delta \le 5$.

---

## 6. Deterministic Ordering & Cryptographic Identity

- Strict canonical sorting on all project IDs, asset IDs, chain paths, edges, and contribution IDs.
- Deterministic hashing via RFC 8785 JSON Canonicalization Scheme (JCS) + SHA-256 for all assessment schemas.

---

## 7. 100% Offline & Resource Governance

- Air-gapped: zero network calls, cloud services, or telemetry.
- Bounded limits: `MAX_PROJECT_ASSETS = 500`, `MAX_CHAIN_DEPTH = 5`, `MAX_DEPENDENCY_EDGES = 2,000`.
- Complexity: $O(V + E)$ linear graph traversal and topological evaluation.
