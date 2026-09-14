# Phase 12.7 — Policy & Decision Engine Requirements Specification

**Status:** Authoritative Requirement Baseline  
**Authority:** Phase 12.1 Universal Risk Architecture Freeze  

---

## 1. Requirement Inventory

| Requirement ID | Category | Description | Verification Method |
|---|---|---|---|
| `REQ-12-POL-001` | Policy Schema | Policy must be an immutable Pydantic V2 model with schema_version, policy_id, policy_version, thresholds, rules, default_decision. | Unit / Contract Test |
| `REQ-12-POL-002` | Canonical Identity | Policy must compute a deterministic SHA-256 hash using RFC 8785 JCS canonicalization over its security-relevant fields. | Cryptographic Test |
| `REQ-12-POL-003` | Decision Vocabulary | System must support canonical decision enum: ACCEPT, REVIEW, QUARANTINE, REJECT with strict monotonic ordering: ACCEPT < REVIEW < QUARANTINE < REJECT. | Enum / Sorting Test |
| `REQ-12-POL-004` | Default Thresholds | Standard default policy must partition [0.0, 1.0] into [0, 0.30) ACCEPT, [0.30, 0.65) REVIEW, [0.65, 0.85) QUARANTINE, [0.85, 1.00] REJECT. | Boundary Value Test |
| `REQ-12-POL-005` | Boundary Precision | Threshold boundaries must be evaluated deterministically using 6-decimal rounding without floating-point ambiguity. | Numerical Test |
| `REQ-12-POL-006` | Threshold Integrity | Policies with threshold gaps or overlaps in [0.0, 1.0] must be rejected with typed exceptions (ThresholdGapError / ThresholdOverlapError). | Validation Test |
| `REQ-12-POL-007` | Declarative Rules | Policy rules must use declarative condition operators without executing arbitrary code (`eval`, `exec`, shell). | Security / AST Test |
| `REQ-12-POL-008` | Monotonic Precedence | Decision conflict resolution must select the most restrictive decision among baseline threshold and matched rules. | Precedence Test |
| `REQ-12-POL-009` | Risk Input Validation | UniversalPolicyEngine must validate Phase 12.6 UniversalRiskAssessment, verifying bounds, finiteness, and cryptographic risk_hash. | Fail-Closed Test |
| `REQ-12-POL-010` | Fail-Closed Behavior | Any corrupted, malformed, or mismatched policy or risk assessment must fail closed with typed exceptions. | Mutation Test |
| `REQ-12-POL-011` | Decision Trace | Every evaluation must produce a complete structured trace capturing policy ID/version/hash, risk hash, threshold trace, rule traces, matched rules, and reason. | Traceability Test |
| `REQ-12-POL-012` | Decision Hash | The final decision must produce a cryptographic decision_hash using RFC 8785 JCS and SHA-256, omitting non-deterministic fields. | Cryptographic Test |
| `REQ-12-POL-013` | Determinism | Repeated evaluations of identical policy and risk assessment must yield identical decision, reason, traces, and hashes. | Determinism Test |
| `REQ-12-POL-014` | Monotonicity with Risk | Under default threshold policy, monotonically increasing risk scores must never produce a less restrictive decision. | Monotonicity Test |
| `REQ-12-POL-015` | Zero Risk Recomputation | Phase 12.7 must not recalculate evidence terms, damping, or risk scores. | Architectural Boundary Test |
| `REQ-12-POL-016` | Proof Boundary | Phase 12.7 must not verify Ed25519 signatures, traverse provenance ledgers, or apply proof overrides (reserved for 12.8). | Architectural Boundary Test |
| `REQ-12-POL-017` | Multi-Asset Boundary | Phase 12.7 must not aggregate multi-asset or chain risks (reserved for 12.9). | Architectural Boundary Test |
| `REQ-12-POL-018` | Offline Air-Gap | Policy evaluation must execute 100% offline with zero network calls or remote dependencies. | Air-Gap Test |
| `REQ-12-POL-019` | Resource Governance | Policy rules are bounded (max 100 rules, max 20 bands, max string lengths) ensuring O(R) time and space complexity. | Resource Limit Test |
| `REQ-12-POL-020` | Structured Reason | Explanations must use standardized reason codes and structured fields (triggering_rule_id, threshold_band, escalation_applied). | Reason Structure Test |
