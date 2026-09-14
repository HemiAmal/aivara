# Phase 12.8 — Proof & Provenance Integration Architecture

**Status:** Authoritative Design Specification  
**Authority:** Phase 12.1 Universal Risk Architecture Freeze  
**Upstream Dependencies:** Phase 12.2 Normalization, Phase 12.3 Evidence Graph, Phase 12.4 Cross-Subsystem Ingestion, Phase 12.5 Correlation, Phase 12.6 Risk Computation, Phase 12.7 Policy Engine  
**Downstream Phases:** Phase 12.9 Multi-Asset / Project Risk Aggregation, Phase 12.10 Universal Risk API & Tasks  

---

## 1. Architectural Mission & Positioning

Phase 12.8 integrates AIVARA's Phase 4 cryptographic provenance and verification infrastructure into the Phase 12 Universal Assurance pipeline.

```
Universal Evidence Graph (12.3 / 12.4)
                 │
                 ▼
Correlation Modeling (12.5)
                 │
                 ▼
Universal Risk Computation (12.6)
                 │
                 ▼
Policy & Decision Engine (12.7)
                 │
                 ▼
┌──────────────────────────────────────────────────────────────┐
│ Phase 12.8 — Proof & Provenance Integration                  │
│                                                              │
│ 1. Phase 4 Cryptographic Verification Reuse (JCS + Ed25519)  │
│ 2. Hash-Chain & Record Integrity Validation                  │
│ 3. Nonce Replay Protection & Sequence Monotonicity           │
│ 4. Evidence Payload Binding & 5-Tuple Ancestry Binding       │
│ 5. Project & Asset Scope Isolation                           │
│ 6. Strict Non-Compensability: Proof Inviolability (att=1.0)  │
│ 7. Granular Status: VERIFIED, INVALID, MISSING, TAMPERED...  │
│ 8. UniversalProofAssessment & Override Synthesis (REJECT)    │
└──────────────────────────────────────────────────────────────┘
                 │
                 ▼
      UniversalProofAssessment
                 │
                 ▼
[Phase 12.9 Multi-Asset / Project Aggregation]
```

---

## 2. Detection vs Proof Segregation & Non-Compensability

### 2.1 Core Architectural Distinction
- **Detection Layer ($layer == DETECTION$):** Answers "Does the artifact appear anomalous?" Produces statistical finding confidence $c_e \in [0.0, 1.0]$.
- **Proof Layer ($layer == PROOF$):** Answers "Can the security-relevant claim be cryptographically established?" Produces proof confidence $c_e = 1.0$ if and only if cryptographic verification succeeds (`VERIFIED`).

### 2.2 Proof Non-Compensability
- Detection evidence cannot compensate for missing or broken cryptographic proof.
- Proof evidence is inviolable: under Phase 12.5 correlation modeling, proof evidence attenuation factor is identically $1.0$ ($att_{\text{proof}} = 1.0$).
- When a proof-layer claim fails verification (`INVALID`, `TAMPERED`, `REPLAY_DETECTED`), Phase 12.8 flags `proof_override_required = True` and sets `override_decision = UniversalDecision.REJECT`.

---

## 3. Cryptographic Verification Pipeline

Phase 12.8 reuses the unified Phase 4 verification layers:
1. **Layer A (Input & Schema):** Nonce format, sequence number, schema version.
2. **Layer B (Record Integrity):** Recomputes SHA-256 over canonical RFC 8785 JCS payload.
3. **Layer C (Chain Linkage):** Sequence monotonicity, genesis hash, previous-record hash continuity.
4. **Layer D (Signature Validity):** Ed25519 public key verification over canonical payload.
5. **Layer E (Key Lifecycle):** Signer key status verification (`ACTIVE`, `ROTATED`, `REVOKED`, `EXPIRED`).
6. **Layer F (Evidence & Ancestry Binding):** Exact matching of `evidence_id`, `normalized_payload_hash`, and 5-tuple ancestry path (`<sample_id, dataset_version_id, model_fingerprint, window_id, source_id>`).
7. **Layer G (Scope Isolation):** Verification of matching `project_id` and `asset_id`.

---

## 4. Status Model

| Status | Meaning | Proof Confidence | Override Consequence (Proof Layer) |
|---|---|---|---|
| `VERIFIED` | All cryptographic checks and bindings pass | `1.0` | None |
| `INVALID` | Signature mismatch or broken ancestry/scope binding | None / `0.0` | `UniversalDecision.REJECT` |
| `MISSING` | No provenance record attached to proof evidence | None / `0.0` | `UniversalDecision.REJECT` |
| `UNAVAILABLE` | Reference exists but material unresolvable | None / `0.0` | Flagged for review |
| `TAMPERED` | Canonical record hash or previous hash modified | None / `0.0` | `UniversalDecision.REJECT` |
| `REPLAY_DETECTED` | Nonce collision or sequence rollback detected | None / `0.0` | `UniversalDecision.REJECT` |

---

## 5. Scope Isolation & Resource Ceilings

- **Asset Isolation:** Proof failure affecting Asset $A_1$ does not invalidate unrelated Asset $A_2$ unless explicit DAG lineage connects them.
- **Project Isolation:** Cross-project provenance references are strictly rejected.
- **Resource Ceilings:** Max 5,000 evidence proof items, max 5,000 provenance records. Verification time complexity is $O(P + E)$.
- **100% Offline:** Zero network imports, remote API calls, or cloud telemetry.
