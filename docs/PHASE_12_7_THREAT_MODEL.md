# Phase 12.7 — Policy & Decision Engine Threat Model

**Status:** Authoritative Threat Analysis  
**Authority:** Phase 12.1 Universal Risk Architecture Freeze  

---

## 1. Threat Inventory & Mitigations

| Threat ID | Threat Description | Attack Vector | Severity | Mitigation in Phase 12.7 |
|---|---|---|---|---|
| `THREAT-12-POL-001` | Policy Tampering | Modifying policy rule definitions or thresholds in transit or memory. | CRITICAL | Immutable Pydantic models + RFC 8785 JCS SHA-256 `policy_hash` verification. |
| `THREAT-12-POL-002` | Permissive Threshold Gap | Exploiting gap in threshold intervals (e.g. [0, 0.3) and [0.35, 1.0]) to bypass governance. | HIGH | Strict contiguous interval validation rejecting any gap with `ThresholdGapError`. |
| `THREAT-12-POL-003` | Ambiguous Threshold Overlap | Overlapping interval boundaries leading to non-deterministic or permissive decision routing. | HIGH | Validation rejecting overlapping bounds with `ThresholdOverlapError`. |
| `THREAT-12-POL-004` | Arbitrary Code Execution | Malicious policy definitions attempting to execute Python `eval()`/`exec()` or shell commands. | CRITICAL | Purely declarative AST-free condition evaluation (`PolicyRuleCondition` + `RuleConditionOperator`). Zero dynamic code execution. |
| `THREAT-12-POL-005` | Risk Input Forgery | Passing fabricated `UniversalRiskAssessment` with falsified risk score or mismatching `risk_hash`. | CRITICAL | Engine validates canonical risk hash over assessment payload using Phase 12.6 contract before evaluation. |
| `THREAT-12-POL-006` | Decision Precedence Manipulation | Inserting low-severity rules to downgrade a `REJECT` or `QUARANTINE` decision to `ACCEPT`. | HIGH | Monotonic resolution rule: $D = \max(D_0, D(r_1), \dots)$ where `ACCEPT < REVIEW < QUARANTINE < REJECT`. |
| `THREAT-12-POL-007` | Rule Identifier Collision / Shadowing | Injecting duplicate rule IDs to override security constraints. | MEDIUM | `validate_rules_limits_and_uniqueness` rejects duplicate rule IDs with `DuplicateRuleIdError`. |
| `THREAT-12-POL-008` | Non-Deterministic Evaluation | Python set ordering or dictionary hash randomness causing inconsistent decisions across runs. | MEDIUM | Strict sorting on all collections (`sorted(rules, key=...)`, canonical JCS serialization). |
| `THREAT-12-POL-009` | Floating-Point Precision Drift | Boundary edge cases (0.299999 vs 0.300000) oscillating due to float inaccuracies. | MEDIUM | Deterministic 6-decimal rounding (`Decimal(str(val)).quantize(...)`) across all comparisons. |
| `THREAT-12-POL-010` | Denial of Service via Resource Exhaustion | Supplying a policy with 100,000 rules or deep recursion to exhaust CPU/memory. | MEDIUM | Hard caps: `MAX_POLICY_RULES = 100`, bounded O(R) iteration, no recursion. |
| `THREAT-12-POL-011` | Silent Permissive Fallback | Engine encountering unrecognized error and falling back to `ACCEPT`. | CRITICAL | Fail-closed semantics: default fallback decision is strictly `REJECT` and errors raise typed exceptions. |
| `THREAT-12-POL-012` | Audit Log Tampering | Fabricating or tampering with decision explanation strings. | HIGH | Structured `DecisionReason` and `DecisionTrace` bound into cryptographic `decision_hash`. |
| `THREAT-12-POL-013` | Exfiltration / Network Channel Injection | Policy engine contacting remote endpoints or telemetry. | HIGH | 100% offline air-gapped architecture with zero network imports or calls. |
| `THREAT-12-POL-014` | Cross-Project Policy Misattribution | Using Project A's policy to evaluate Project B's risk assessment. | MEDIUM | Decision record binds `project_id`, `asset_id`, `policy_id`, and `risk_assessment_hash`. |
| `THREAT-12-POL-015` | Schema Confusion Attack | Submitting an incompatible schema version to bypass policy checks. | HIGH | Strict schema version validation against `PolicySchemaVersion.V1_0`. |
