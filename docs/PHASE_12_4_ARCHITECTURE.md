# Phase 12.4 — Cross-Subsystem Evidence Ingestion Architecture

**Status:** Authoritative Design Specification  
**Authority:** Phase 12.1 Universal Risk Architecture Freeze  
**Upstream Dependencies:** Phase 12.2 Normalization, Phase 12.3 Evidence Graph  
**Downstream Phases:** Phase 12.5 Correlation & Dependency Modeling  

---

## 1. Architectural Mission

Phase 12.4 establishes the controlled, isolated, deterministic ingestion boundary between the seven upstream assurance subsystems (Phases 5–11) and the Universal Evidence Architecture (Phase 12.2 Normalization and Phase 12.3 Graph).

```
Phase 5  (Dataset Integrity)       ──┐
Phase 6  (Contributor Risk)        ──┤
Phase 7  (Model Integrity)          ──┤
Phase 8  (Behavioral Analysis)     ──┼──> [Phase 12.4 Ingestion Service & Handlers]
Phase 9  (Backdoor Trigger)        ──┤             │
Phase 10 (Inference Integrity)     ──┤             ▼ (Normalization + Validation)
Phase 11 (Distribution Shift)      ──┘     [Phase 12.3 Universal Evidence Graph]
```

---

## 2. Hard Architectural Invariants

1. **Zero Risk Computation:** Phase 12.4 does NOT calculate universal, asset, chain, or project risk (owned by Phase 12.6/12.9).
2. **Zero Correlation Damping:** Phase 12.4 does NOT apply 7×7 cross-subsystem correlation matrices or damping parameters (owned by Phase 12.5).
3. **Zero Policy Decisions:** Phase 12.4 NEVER outputs `ACCEPT`, `REVIEW`, `QUARANTINE`, or `REJECT` disposition decisions (owned by Phase 12.7).
4. **Zero Proof Overrides:** Phase 12.4 preserves detection vs. proof confidence without synthetic promotion or attenuation.
5. **Project Boundary Isolation:** Items cannot cross tenant boundaries ($E_{\text{project}} = \text{Target}_{\text{project}}$).
6. **Strict Idempotency:** Ingesting an identical evidence payload multiple times yields `DUPLICATE_SKIPPED` without mutating existing state or graph structures.
7. **Resource Bounds Governance:** Hard bounds ($E_{\max} = 5,000$, $F_{\max} = 1,000$, $A_{\max} = 250$, $\Delta_{\max} = 5$, $\beta_{\max} = 100$).

---

## 3. Ingestion Pipeline Stages

Every evidence record passes through a strict 9-stage pipeline:

1. **Format Validation:** Verified against `UpstreamEvidenceItem` schema with finite numerical bounds.
2. **Project Boundary Check:** Cross-tenant rejection before any parsing.
3. **Domain Verification:** Canonical mapping to one of the 7 upstream subsystems.
4. **Source Payload Verification:** Cryptographic SHA-256 match against supplied payload digest.
5. **Domain Transformation Hook:** Handled via domain-specific `BaseDomainIngestionHandler`.
6. **Phase 12.2 Normalization:** Routed through `UniversalEvidenceNormalizer` into `UniversalEvidenceEnvelope`.
7. **Ancestry & Cycle Defense:** Self-loops and cycles rejected.
8. **Deduplication:** Hash-based deduplication against seen envelopes.
9. **Graph Binding:** Non-duplicate items bound to `UniversalEvidenceGraphBuilder` with N:M finding edges.

---

## 4. Canonical Subsystem Domains

| Index | Canonical Domain | Upstream Subsystem | Ingestion Handler |
|---|---|---|---|
| 0 | `DATASET_INTEGRITY` | Phase 5 | `DatasetIngestionHandler` |
| 1 | `CONTRIBUTOR_RISK` | Phase 6 | `ContributorIngestionHandler` |
| 2 | `MODEL_INTEGRITY` | Phase 7 | `ModelIngestionHandler` |
| 3 | `BEHAVIORAL_ANALYSIS` | Phase 8 | `BehavioralIngestionHandler` |
| 4 | `BACKDOOR_TRIGGER` | Phase 9 | `BackdoorIngestionHandler` |
| 5 | `INFERENCE_INTEGRITY` | Phase 10 | `InferenceIngestionHandler` |
| 6 | `DISTRIBUTION_SHIFT` | Phase 11 | `DistributionIngestionHandler` |
