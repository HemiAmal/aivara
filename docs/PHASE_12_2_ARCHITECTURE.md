# PHASE 12.2 — UNIVERSAL EVIDENCE NORMALIZATION & ADAPTERS ARCHITECTURE

**Milestone**: Phase 12.2 Implementation & Post-Audit Reconciliation  
**Subsystem**: Universal Risk Engine — Universal Evidence Normalization Layer  
**Status**: RECONCILED & AUDIT-READY  

---

## 1. Scope & Objective

Phase 12.2 implements the **Universal Evidence Normalization Layer** for AIVARA. It establishes the canonical evidence boundary by translating raw evidence records from all seven upstream assurance domains into an immutable, cryptographically content-addressed `UniversalEvidenceEnvelope`.

### Core Boundary
$$\text{Upstream Evidence} \longrightarrow \text{Domain Adapter} \longrightarrow \text{Validation} \longrightarrow \text{Universal Evidence Envelope}$$

Phase 12.2 strictly normalizes evidence without computing risk, constructing the final risk DAG, performing cross-domain damping, or evaluating project dispositions.

---

## 2. Universal Evidence Envelope Contract

The canonical `UniversalEvidenceEnvelope` schema is defined in `backend/aivara/universal/schemas.py`:
- `schema_version`: String SemVer (`"1.0.0"`).
- `envelope_version`: String SemVer (`"1.0.0"`).
- `evidence_id`: Canonical unique string identifier (Stable UUID5).
- `project_id`: Strict tenant container identifier.
- `domain`: One of the exact seven `SubsystemDomain` enums.
- `evidence_type`: Domain-specific type string.
- `evidence_layer`: Enum (`PROOF` vs `DETECTION`).
- `severity`: Enum (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- `confidence`: Optional float $\in [0.0, 1.0]$ (strictly $1.0$ for `PROOF`, preserved upstream value for `DETECTION`, `None` if omitted).
- `primary_asset_type`: Target asset category (`dataset`, `model`, `inference`, `contributor`, `project`).
- `primary_asset_id`: Target asset identifier.
- `finding_id`: Optional genesis finding reference.
- `source_record_id`: Optional upstream ORM ID.
- `source_entity_type`: Upstream source entity type.
- `ancestry_status`: Enum (`VERIFIED`, `UNVERIFIED`, `NOT_APPLICABLE`).
- `ancestry_path`: `AncestryPath` vector ($\langle \text{sample\_id}, \text{dataset\_version\_id}, \text{model\_fingerprint}, \text{window\_id}, \text{source\_id} \rangle$).
- `parent_evidence_ids`: Sorted list of parent evidence hashes.
- `derived_from_evidence_ids`: Sorted list of derived evidence hashes.
- `source_payload_hash`: SHA-256 of raw source payload (recomputed & verified against authoritative data; fails closed on mismatch).
- `normalized_payload_hash`: SHA-256 of RFC 8785 JCS normalized `data_json`.
- `provenance_record_ids`: List of Phase 4/5 provenance IDs.
- `provenance_hashes`: List of Phase 4/5 provenance hashes (validated for 64-char hex SHA-256 format).
- `data_json`: Normalized payload dictionary containing only finite real numbers.
- `metadata_json`: Additional contextual metadata.
- `created_at_utc`: ISO-8601 UTC timestamp.
- `canonical_hash`: SHA-256(RFC 8785 JCS(`canonical_envelope_dict`)).

---

## 3. Cryptographic Identity & Hashing Triad

The normalization boundary establishes a strict separation between three cryptographic hashes:
1. **`source_payload_hash`**:
   $$\text{SHA-256}(\text{Authoritative Raw Source Bytes or Structured Source Data})$$
   - Verified fail-closed if supplied upstream.
2. **`normalized_payload_hash`**:
   $$\text{SHA-256}(\text{RFC 8785 JCS}(\text{data\_json}))$$
   - Canonical representation of standardized domain metrics.
3. **`canonical_hash`**:
   $$\text{SHA-256}(\text{RFC 8785 JCS}(\text{Envelope Excl. canonical\_hash}))$$
   - Complete tamper-evident cryptographic envelope identity.

---

## 4. Seven Upstream Domain Adapters

Implemented in `backend/aivara/universal/adapters/`:
1. **Dataset Integrity Adapter (`DatasetIntegrityEvidenceAdapter`)**: Ingests image quality, OOD distances, near-duplicates, label noise, and Merkle manifests.
2. **Contributor Risk Adapter (`ContributorRiskEvidenceAdapter`)**: Ingests Empirical Bayes anomaly profiles, LOO subgroup divergence, and contributor identities.
3. **Model Integrity Adapter (`ModelIntegrityEvidenceAdapter`)**: Ingests structural fingerprints, weight Merkle proofs, and quantization deltas.
4. **Behavioral Analysis Adapter (`BehavioralAnalysisEvidenceAdapter`)**: Ingests output stability metrics, perturbation flags, and behavioral drift.
5. **Backdoor / Trigger Adapter (`BackdoorTriggerEvidenceAdapter`)**: Ingests trigger activation deltas, spectral signature decomposition, and patch scores.
6. **Inference Integrity Adapter (`InferenceIntegrityEvidenceAdapter`)**: Ingests 18-checkpoint verification records, input-model binding digests, and replay evidence.
7. **Distribution Shift Adapter (`DistributionShiftEvidenceAdapter`)**: Ingests feature/dataset drift, visual shift, representation shift, temporal trajectories, and source partitions.

---

## 5. Resource Governance Hierarchy

- **Global URE Ceilings (Phase 12.1 Frozen Authority)**:
  - $E_{\max} = 5,000$ (Max evidence envelopes per session)
  - $F_{\max} = 1,000$ (Max findings per session)
  - $A_{\max} = 250$ (Max assurance assets per session)
  - $\Delta \le 5$ (Max graph DAG depth)
  - $\beta \le 100$ (Max DAG branching factor)
- **Local Normalization Safety Limits (Phase 12.2 Subordinate Boundaries)**:
  - Max Raw Payload Size: $1,048,576\text{ bytes } (1\text{ MB})$
  - Max Ingested Batch Size: $5,000\text{ items}$
  - Max Collection Elements: $1,024\text{ entries}$
  - Max Payload Nesting Depth: $16\text{ levels}$
  - Max Field String Length: $512\text{ chars}$ ($128\text{ chars}$ for IDs)

---

## 6. Adapter Registry & Normalizer Orchestrator

- **`AdapterRegistry`**: Thread-safe registry enforcing exactly seven domain adapters with zero duplicate registrations.
- **`UniversalEvidenceNormalizer`**: Orchestrates single and batch normalizations, enforces the hard safety ceiling ($E_{\max} = 5,000$), performs constant-time deduplication over `canonical_hash`, and produces canonically sorted `NormalizationReport` objects.
