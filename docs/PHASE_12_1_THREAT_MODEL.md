# PHASE 12.1 — THREAT MODEL SPECIFICATION
# Universal Risk Engine: Adversarial Threat Vectors, Attack Surfaces & Defense Invariants

**Milestone**: Phase 12.1 Architecture & Requirements Freeze (Post-Audit Reconciled)  
**Authoritative Subsystem**: Universal Risk Engine (URE) / Universal Evidence + Risk Engine  
**Status**: THREAT MODEL BASELINE SPECIFICATION  

---

## 1. Threat Modeling Methodology

The Phase 12 Threat Model analyzes adversarial attack surfaces, structural vulnerabilities, and failure modes across the Universal Risk Engine, covering multi-asset evidence ingestion, graph traversal, risk aggregation, policy evaluation, cryptographic sealing, and offline air-gap enforcement.

Threats are categorized across 8 primary security and integrity domains:
1. **Evidence Ingestion & Integrity Attacks** (`THREAT-12-ING-001` .. `004`)
2. **Graph Topology & Traversal Exploits** (`THREAT-12-GRP-001` .. `004`)
3. **Risk Scoring & Aggregation Manipulation** (`THREAT-12-RSK-001` .. `004`)
4. **Proof Inviolability & Override Bypasses** (`THREAT-12-PRF-001` .. `003`)
5. **Policy Governance & Tampering Attacks** (`THREAT-12-POL-001` .. `004`)
6. **Multi-Tenant Isolation & Privacy Attacks** (`THREAT-12-SEC-001` .. `004`)
7. **Cryptographic Integrity & Anti-Replay Attacks** (`THREAT-12-CRY-001` .. `004`)
8. **Resource Exhaustion & Air-Gap Bypasses** (`THREAT-12-GOV-001` .. `004`)

**Total Distinct Threats**: 31 Formal Threat Vectors.

---

## 2. Threat Vector Matrix

| Threat ID | Threat Category | Threat Description | Affected Asset | Mitigation Strategy | Traceable Requirements |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `THREAT-12-ING-001` | Ingestion | **Evidence Injection**: Adversary submits unauthenticated or synthetic evidence records. | `UniversalEvidenceEnvelope` | Canonical validation, domain type enforcement, and upstream provenance verification. | `REQ-12-ING-001`, `REQ-12-ING-002` |
| `THREAT-12-ING-002` | Ingestion | **Evidence Duplication**: Submitting identical evidence repeatedly to inflate risk. | Modality Clusters | Constant-time SHA-256 hash deduplication and ancestry path collapse prior to aggregation. | `REQ-12-ING-006`, `REQ-12-COR-001` |
| `THREAT-12-ING-003` | Ingestion | **Evidence Substitution / Tampering**: Altering metrics within an evidence record. | `data_json` | RFC 8785 JCS canonicalization + SHA-256 evidence hash verification. | `REQ-12-ING-008`, `REQ-12-CRY-001` |
| `THREAT-12-ING-004` | Ingestion | **NaN / Inf Metric Injection**: Submitting non-finite floats to corrupt calculations. | Statistical Metrics | Strict numerical sanitization rejecting `NaN`, `+Inf`, and `-Inf`. | `REQ-12-ING-007` |
| `THREAT-12-GRP-001` | Graph | **Cyclic Graph Poisoning**: Constructing circular finding/evidence references to cause infinite recursion. | Evidence Graph | Cycle detection via DFS visited sets; immediate fail-closed `GraphCycleDetectedError`. | `REQ-12-GRP-004` |
| `THREAT-12-GRP-002` | Graph | **Graph Explosion DoS**: Injecting thousands of cross-linked nodes to exhaust memory. | Evidence Graph | Hard safety depth ceiling $\Delta \le 5$ and breadth ceiling $\beta \le 100$. | `REQ-12-GRP-005`, `REQ-12-GRP-006` |
| `THREAT-12-GRP-003` | Graph | **Orphan Finding Manipulation**: Submitting findings disconnected from underlying evidence. | Finding Models | Fail-closed validation requiring at least one verified supporting evidence item. | `REQ-12-GRP-002`, `REQ-12-DEC-004` |
| `THREAT-12-GRP-004` | Graph | **Cross-Asset Scope Confusion**: Mislinking dataset evidence to an unrelated model finding. | Asset Hierarchy | Strict asset type and asset UUID lineage validation during graph binding. | `REQ-12-ING-005`, `REQ-12-GRP-001` |
| `THREAT-12-RSK-001` | Risk | **Risk Dilution Attack**: Flooding evaluation with hundreds of low-severity items to dilute critical risk. | Hierarchical Risk | Sub-additive asymptotic saturation and dominance-preserving project aggregation. | `REQ-12-RSK-003`, `REQ-12-RSK-006` |
| `THREAT-12-RSK-002` | Risk | **Risk Laundering via Modality Splitting**: Fragmenting one defect into multiple sub-types to evade thresholds. | Modality Clusters | Ancestry-aware clustering grouping evidence by shared physical artifact keys. | `REQ-12-COR-001` |
| `THREAT-12-RSK-003` | Risk | **Double-Counting Inflation**: Exploiting coupled multi-modal symptoms to artificially spike risk. | Risk Scores | Symmetric $7 \times 7$ inter-domain correlation damping matrix $\mathbf{C}$ attenuating co-occurring signals. | `REQ-12-COR-003` |
| `THREAT-12-RSK-004` | Risk | **Non-Attribution Language Violation**: Injecting subjective intent/guilt claims into rationale. | Assessment Rationale | Automated sanitization enforcing objective, descriptive language invariants. | `REQ-12-RSK-007`, `REQ-12-GOV-008` |
| `THREAT-12-PRF-001` | Proof | **Proof Violation Dilution**: Attempting to offset a broken hash or signature with high statistical confidence. | Proof Invariants | Strict proof non-compensability forcing $R(A)=1.0 \land \mathbf{REJECT}$ on affected asset. | `REQ-12-PRF-001`, `REQ-12-PRF-002` |
| `THREAT-12-PRF-002` | Proof | **Missing Proof Suppress-to-Accept**: Attempting to pass missing cryptographic proof as healthy. | Proof Validation | Fail-closed policy mapping missing mandatory proof to $\mathbf{UNVERIFIABLE}$ / $\mathbf{QUARANTINE}$. | `REQ-12-PRF-006` |
| `THREAT-12-PRF-003` | Proof | **Proof Scope Contagion Escape / False Contamination**: Escaping core rejection or falsely rejecting unrelated assets. | Asset Scope & Lineage | Deterministic lineage rules: core failure rejects project; isolated failure rejects asset; unrelated asset isolated. | `REQ-12-PRF-003`, `REQ-12-PRF-004`, `REQ-12-PRF-005` |
| `THREAT-12-POL-001` | Policy | **Policy Tampering & Inversion**: Modifying policy thresholds to silently convert `REJECT` to `ACCEPT`. | Policy Objects | RFC 8785 JCS + SHA-256 policy hashing bound into every assessment signature. | `REQ-12-POL-002`, `REQ-12-POL-005` |
| `THREAT-12-POL-002` | Policy | **Policy Rollback Attack**: Substituting older, more lenient policy versions. | Policy Versions | SemVer compatibility checks and cryptographic policy hash verification. | `REQ-12-POL-001`, `REQ-12-POL-005` |
| `THREAT-12-POL-003` | Policy | **Mathematical Policy Corruption**: Specifying negative weights, non-monotonic thresholds, or non-symmetric $\mathbf{C}$. | Policy Validation | Strict schema validation requiring $\sum w > 0$, symmetric $\mathbf{C}$, and monotonic thresholds. | `REQ-12-POL-003`, `REQ-12-COR-003` |
| `THREAT-12-POL-004` | Policy | **Policy Override Bypass**: Attempting to disable proof override via custom policy JSON. | Policy Invariants | Hardcoded engine-level enforcement preventing policy-based proof disablement. | `REQ-12-POL-004`, `REQ-12-PRF-002` |
| `THREAT-12-SEC-001` | Security | **Cross-Tenant BOLA / IDOR**: Ingesting or viewing evidence across different `project_id` boundaries. | Multi-Tenant Data | Strict router-level and engine-level `project_id` scoping returning generic 404. | `REQ-12-SEC-001` |
| `THREAT-12-SEC-002` | Security | **Path Traversal in Artifact References**: Injecting `../../etc/passwd` in artifact URIs. | Local Filesystem | Strict path normalization and workspace jail validation. | `REQ-12-SEC-002` |
| `THREAT-12-SEC-003` | Security | **Contributor Re-Identification**: De-anonymizing contributors from evidence payloads. | Contributor Privacy | Project-salted SHA-256 pseudonymization prohibiting raw PII storage. | `REQ-12-SEC-003` |
| `THREAT-12-SEC-004` | Security | **Internal Schema / Path Leakage**: Triggering verbose errors disclosing SQL or server paths. | API Responses | Centralized error sanitization producing structured generic `ApiErrorResponse`. | `REQ-12-SEC-004` |
| `THREAT-12-CRY-001` | Crypto | **Dossier Tampering & Forgery**: Modifying historical assessment results or Merkle roots. | Assurance Dossier | End-to-end cryptographic Merkle verification and Ed25519 signature checks. | `REQ-12-CRY-003`, `REQ-12-CRY-005` |
| `THREAT-12-CRY-002` | Crypto | **Idempotency Replay Collision**: Submitting conflicting evaluations under the same idempotency key. | API Tasks | RFC 8785 request fingerprinting raising `409 Conflict` on payload mismatch. | `REQ-12-SEC-006` |
| `THREAT-12-CRY-003` | Crypto | **Hash Collision / Preimage Attack**: Forging evidence payloads to match existing hashes. | SHA-256 Hashes | Standard SHA-256 256-bit cryptographic strength and structured type binding. | `REQ-12-CRY-001` |
| `THREAT-12-CRY-004` | Crypto | **Provenance Chain Severance**: Detaching evidence from Phase 4 cryptographic audit records. | Provenance Records | Mandatory unbroken provenance chain verification: $\text{Dossier} \to \text{Decision} \to \text{Risk} \to \text{Ev} \to \text{Prov}$. | `REQ-12-CRY-002`, `REQ-12-CRY-004` |
| `THREAT-12-GOV-001` | Governance | **Resource Exhaustion DoS**: Submitting 100,000 evidence items to crash local workstation. | Workstation CPU/RAM | Hard safety ceilings $E_{\max} \le 5,000, F_{\max} \le 1,000, A_{\max} \le 250$ with fail-closed rejection. | `REQ-12-GOV-001` |
| `THREAT-12-GOV-002` | Governance | **Air-Gap Exfiltration**: Attempting outbound socket or HTTP calls during risk evaluation. | Air-Gap Boundary | Zero network library usage and automated socket-blocking test fixtures. | `REQ-12-GOV-004` |
| `THREAT-12-GOV-003` | Governance | **Non-Deterministic Replay Divergence**: Varying risk scores across identical runs. | Determinism | Explicit canonical sorting on all graph nodes, evidence sets, and dictionary keys. | `REQ-12-GOV-005` |
| `THREAT-12-GOV-004` | Governance | **Backward Incompatibility Regressions**: Breaking existing Phase 0–11 data models or queries. | Historical DB | Non-breaking evolution; zero modifications to frozen Phase 0–11 database tables. | `REQ-12-GOV-006`, `REQ-12-GOV-007` |

---

## 3. Threat Mitigation Verification Strategy

Every threat in this matrix is directly mapped to concrete verification layers and executable tests in the Phase 12.1 Verification Plan:
- **Unit & Property Tests**: Validate numerical sanitization, hash deduplication, cycle detection, and sub-additive risk bounds.
- **Security & BOLA Tests**: Validate cross-tenant rejection, path traversal defenses, and error sanitization.
- **Cryptographic Mutation Tests**: Validate avalanche sensitivity upon single-bit payload or policy modifications.
- **Air-Gap Interception Tests**: Verify zero socket or outbound network attempts during complete evaluation pipelines.
