# Phase 12.7 — Policy & Decision Engine Architecture

**Status:** Authoritative Design Specification  
**Authority:** Phase 12.1 Universal Risk Architecture Freeze  
**Upstream Dependencies:** Phase 12.6 Universal Risk Computation (`UniversalRiskAssessment`)  
**Downstream Phases:** Phase 12.8 Proof & Provenance Integration, Phase 12.9 Project & Multi-Asset Risk Aggregation, Phase 12.10 Universal Risk API & Task Integration  

---

## 1. Architectural Mission & Positioning

Phase 12.7 is the single point in the AIVARA pipeline responsible for translating quantitative, continuous risk evaluations into discrete, actionable security decisions (`ACCEPT`, `REVIEW`, `QUARANTINE`, `REJECT`).

```
Universal Evidence Graph (12.3 / 12.4)
                 │
                 ▼
Correlation Modeling (12.5)
                 │
                 ▼
Universal Risk Computation (12.6) ──> UniversalRiskAssessment (R in [0.0, 1.0])
                 │
                 ▼
┌──────────────────────────────────────────────────────────────┐
│ Phase 12.7 — Policy & Decision Engine                        │
│                                                              │
│ 1. Immutable Policy Governance (Schema, Rules, Thresholds)   │
│ 2. Fail-Closed Validation of Policy & Risk Inputs            │
│ 3. Threshold Interval Evaluation (Contiguous [0, 1])         │
│ 4. Deterministic Declarative Rule Evaluation                 │
│ 5. Monotonic Conflict Resolution (REJECT > QUARANTINE > ...) │
│ 6. Cryptographic Decision Descriptor & SHA-256 Content-Hash  │
│ 7. Comprehensive Auditable Decision Trace                    │
└──────────────────────────────────────────────────────────────┘
                 │
                 ▼
      UniversalPolicyDecision
       (Decision, Trace, Hash)
                 │
         ┌───────┴───────┐
         ▼               ▼
  [Phase 12.8 Proof]   [Phase 12.9 Aggregation]
```

---

## 2. Hard Boundaries & Invariants

1. **Zero Risk Recomputation:** Phase 12.7 consumes `UniversalRiskAssessment` as immutable ground truth. It never re-scores evidence, alters severities, adjusts correlation damping, or recalculates $R(A)$.
2. **Risk $\rightarrow$ Decision Separation:**
   - Phase 12.6 owns: $\text{Evidence} \rightarrow \text{Risk}$
   - Phase 12.7 owns: $\text{Risk} \rightarrow \text{Decision}$
3. **Zero Proof Verification:** Phase 12.8 owns Ed25519 signature checks, cryptographic ledger traversal, and proof override semantics. Phase 12.7 evaluates only properties legitimately present on its input contracts.
4. **Zero Multi-Asset Aggregation:** Phase 12.9 owns chain-level and project-level risk aggregation. Phase 12.7 operates strictly on individual assessments presented to it.
5. **Zero REST API / DB Schema Migrations:** Phase 12.10 owns API routing. Persistence remains in-memory and immutable.
6. **100% Offline Air-Gap:** Zero network I/O, external APIs, telemetry, or remote lookups.
7. **Monotonic Decision Precedence:** Under standard risk evaluation and conflicting rule outcomes, the most restrictive decision strictly takes precedence:
   $$\text{ACCEPT} < \text{REVIEW} < \text{QUARANTINE} < \text{REJECT}$$

---

## 3. Threshold Evaluation & Invariants

### 3.1 Standard 4-Tier Risk Band Partition
The canonical risk interval $[0.0, 1.0]$ is partitioned into four contiguous, non-overlapping intervals:

| Band Name | Interval | Baseline Decision | Standard Reason Code |
|---|---|---|---|
| `ACCEPT_BAND` | $[0.000000, 0.300000)$ | `ACCEPT` | `RISK_BELOW_REVIEW_THRESHOLD` |
| `REVIEW_BAND` | $[0.300000, 0.650000)$ | `REVIEW` | `RISK_IN_REVIEW_BAND` |
| `QUARANTINE_BAND` | $[0.650000, 0.850000)$ | `QUARANTINE` | `RISK_IN_QUARANTINE_BAND` |
| `REJECT_BAND` | $[0.850000, 1.000000]$ | `REJECT` | `RISK_ABOVE_REJECT_THRESHOLD` |

### 3.2 Partition Completeness & Non-Overlap Invariants
Any valid `UniversalPolicy` must satisfy:
$$\bigcup_{i} B_i = [0.0, 1.0] \quad \text{and} \quad B_i \cap B_j = \emptyset \quad (\forall i \ne j)$$
Any gap or overlap raises a fail-closed typed exception (`ThresholdGapError` or `ThresholdOverlapError`).

---

## 4. Rule Evaluation & Precedence

### 4.1 Declarative Conditions
Policy rules are defined with declarative fields, operators, and target values without dynamic code execution:
- Operators: `EQUALS`, `NOT_EQUALS`, `GREATER_THAN`, `GREATER_EQUAL`, `LESS_THAN`, `LESS_EQUAL`, `IN`, `CONTAINS`.
- Evaluated attributes include: `risk_score`, `risk_level`, `evidence_sufficiency`, `finding_count`, `cluster_count`, `has_critical_severity`, `critical_finding_count`, `has_insufficient_ancestry`, domain statistics (`domain_count.<domain>`, `domain_max_score.<domain>`).

### 4.2 Deterministic Ordering & Escalation
1. Rules are evaluated in strictly deterministic order sorted by `(rule.priority, rule.rule_id)`.
2. The baseline decision $D_0$ is derived from threshold band matching.
3. Every matched rule $r_k$ proposes a target decision $D(r_k)$.
4. The final decision is resolved as:
   $$D_{\text{final}} = \max\left(D_0, \max_{k \in \text{Matched}} D(r_k)\right)$$
5. If $D_{\text{final}} > D_0$, the decision is flagged as escalated (`escalation_applied = True`), with the highest-severity triggering rule identified in the structured `DecisionReason`.

---

## 5. Cryptographic Hashing & Content Addressing

All policy configurations and decision records have deterministically computed content addresses using RFC 8785 JSON Canonicalization Scheme (JCS) and SHA-256:

### 5.1 Policy Hash (`policy_hash`)
$$\text{policy\_hash} = \text{SHA256}(\text{JCS}(\text{CanonicalPolicyDescriptor}))$$
Includes: `schema_version`, `policy_id`, `policy_version`, `policy_name`, `description`, `enabled`, `default_decision`, `thresholds`, `rules`.

### 5.2 Decision Hash (`decision_hash`)
$$\text{decision\_hash} = \text{SHA256}(\text{JCS}(\text{CanonicalDecisionDescriptor}))$$
Includes: `schema_version`, `project_id`, `asset_id`, `policy_id`, `policy_version`, `policy_hash`, `risk_assessment_hash`, `risk_score`, `threshold_band`, `matched_rule_ids`, `triggering_rule_id`, `reason_code`, `decision`.
*(Nondeterministic fields like timestamps and internal UUIDs are excluded from the canonical descriptor).*

---

## 6. Resource Governance & Complexity

- Maximum Policy Rules: 100 ($R \le 100$).
- Maximum Threshold Bands: 20.
- Maximum Rule ID Length: 128 chars.
- Maximum Reason Summary Length: 512 chars.
- Time Complexity: $O(R)$ where $R$ is the bounded number of policy rules.
- Space Complexity: $O(R)$ for trace generation.
