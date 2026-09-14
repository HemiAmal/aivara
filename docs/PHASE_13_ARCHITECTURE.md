# PHASE 13 — ATTACK SIMULATION LAB ARCHITECTURE

## 1. Executive Summary & Purpose
The **AIVARA Attack Simulation Lab (Phase 13)** is a controlled, deterministic, offline, and safe security-testing subsystem. Its core purpose is to simulate adversarial conditions and asset tampering against synthetic, disposable test fixtures and verify that the frozen **Phase 12 Universal Assurance Core** correctly detects, contains, neutrally attributes, and fails closed.

```
+-----------------------------------------------------------------------------------+
|                            PHASE 13 ATTACK SIMULATION LAB                         |
|                                                                                   |
|  [Scenario Registry] ---> [Synthetic Fixtures] ---> [Deterministic Mutations]    |
|                                 |                                |                |
|                                 v                                v                |
|                           [Clean Control]                [Mutated Attack]         |
|                                 |                                |                |
|                                 +----------------+---------------+                |
|                                                  |                                |
|                                                  v                                |
|                                        [Attack Lab Runner]                        |
+--------------------------------------------------|--------------------------------+
                                                   |
                                                   v
+-----------------------------------------------------------------------------------+
|                        PHASE 12 UNIVERSAL ASSURANCE CORE (FROZEN)                 |
|                                                                                   |
|   [Normalizer] -> [Evidence Graph] -> [Ingestion] -> [Correlation Engine]        |
|        -> [Universal Risk Engine] -> [Policy Engine] -> [Proof Engine]            |
|        -> [Multi-Asset Aggregator] -> [Audit Generator]                           |
+--------------------------------------------------|--------------------------------+
                                                   |
                                                   v
+-----------------------------------------------------------------------------------+
|                                 EVALUATION & AUDIT                                |
|                                                                                   |
|  [Observed Phase 12 Result] <---> [Expected-Result Oracle]                        |
|                                         |                                         |
|                                         v                                         |
|                 [Paired Comparator & Outcome Classification]                      |
|                                         |                                         |
|                                         v                                         |
|                 [Cryptographic Audit & Simulation Report (JSON/MD)]               |
+-----------------------------------------------------------------------------------+
```

---

## 2. Core Architectural Principles
1. **Defensive Simulation, Not Exploitation**: The lab operates strictly on synthetic, disposable local fixtures. No real-world exploit delivery, payload execution, or malware.
2. **100% Offline Air-Gapped Operation**: Zero network socket imports, zero telemetry, zero cloud calls, zero remote API dependencies.
3. **Paired Experiments (Clean Control vs Attack Mutation)**: Every attack scenario is paired with an identical clean control differing only in the target mutation to isolate true signals from fixture variance.
4. **Separation of Oracle and Assurance Core**: The expected-result oracle specifies expected evidence/finding categories and decision ranges, but never independently calculates or duplicates Phase 12 risk mathematics.
5. **Strict Non-Attribution & Objectivity**: Consistent with Phase 12 Invariants `I3`–`I8`, all contributor anomalies are evaluated through neutral, pseudonymized technical metrics without personal or organizational blaming.
6. **Zero Phase 12 Production Modifications**: Phase 12 is permanently frozen. Phase 13 consumes existing Phase 12 interfaces without modifying them.

---

## 3. Subsystem Component Architecture

The Attack Simulation Lab is implemented in `backend/aivara/attacklab/`:

### 3.1 `enums.py`
Defines discrete simulation taxonomy:
- `AttackDomain`: `DATASET_INTEGRITY`, `CONTRIBUTOR_RISK`, `MODEL_INTEGRITY`, `BEHAVIORAL_INTEGRITY`, `BACKDOOR_TRIGGER`, `INFERENCE_INTEGRITY`, `DISTRIBUTION_SHIFT`, `PROOF_PROVENANCE`, `SECURITY_BOUNDARY`.
- `AttackClass`: Discrete attack categories (e.g. `LABEL_FLIPPING`, `SAMPLE_POISONING`, `WEIGHT_MUTATION`, `BACKDOOR_TRIGGER_INJECTION`, `PREPROCESSING_MISMATCH`, `FEATURE_DRIFT`, `PROOF_SIGNATURE_TAMPERING`, `CROSS_PROJECT_BOLA`).
- `MutationType`: Exact mutation operators (`BIT_FLIP`, `INJECTION`, `SUBSTITUTION`, `REDACTION`, `SCALING`, `SEVER_CHAIN`, `UNAUTHORIZED_ACCESS`).
- `SimulationStatus`: Lifecycle states (`INITIALIZED`, `GENERATING_FIXTURES`, `EXECUTING_CLEAN`, `EXECUTING_ATTACK`, `EVALUATING_ORACLE`, `COMPLETED`, `FAILED`).
- `OracleOutcome`: Classification results (`EXPECTED_DETECTION`, `EXPECTED_NO_DETECTION`, `FALSE_NEGATIVE`, `FALSE_POSITIVE`, `UNEXPECTED_FAILURE`, `BLOCKED_BY_POLICY`, `BLOCKED_BY_RESOURCE`, `INVALID_SCENARIO`).

### 3.2 `schemas.py`
Pydantic V2 models for:
- `ScenarioDefinition`: Stable, deterministic scenario declaration.
- `MutationDefinition`: Specification of target entity, copy-only mutation rule, and parameters.
- `CleanControlDefinition`: Specification of baseline control.
- `FixturePayload`: Synthetic data container with content hashes.
- `SimulationStepResult`: Execution trace of a single pipeline run.
- `SimulationOutcome`: Oracle comparison, differential findings, and detection classification.
- `SimulationReport`: Full cryptographic report with scenario, clean, attack, and audit traces.

### 3.3 `fixtures.py`
Synthetic fixture generator providing deterministic, offline test assets:
- Tabular & numeric datasets
- Contributor activity logs
- Model contracts & weight fingerprints
- Behavioral evaluation traces
- Paired backdoor trigger candidates
- Inference input/output bindings
- Shifted population distributions
- Cryptographic provenance records

### 3.4 `mutations.py`
Deterministic mutation engine:
- Operates strictly on in-memory deep copies or disposable copies.
- Generates verified before/after SHA-256 digests.
- Enforces strict safety boundaries rejecting unsafe deserialization, filesystem traversal, or non-finite numbers.

### 3.5 `controls.py`
Clean control generator ensuring exact parity between control and attack baselines prior to mutation.

### 3.6 `oracle.py`
Expected-result oracle that formalizes expectations (e.g., expected finding types, proof status, minimum/maximum risk bounds, decision boundaries) without duplicating risk formulas.

### 3.7 `comparator.py`
Differential analysis engine evaluating the delta between Clean Control and Attack Mutation results:
- Verifies finding emergence
- Checks risk escalation monotonicity
- Confirms proof non-compensability

### 3.8 `evidence.py`
Bridge converting simulation findings and artifacts into canonical Phase 12 `UniversalEvidenceEnvelope` records.

### 3.9 `runner.py`
Deterministic orchestrator executing the full simulation lifecycle:
1. Validates scenario definition and resource budget.
2. Generates clean fixture and runs Phase 12 baseline pipeline.
3. Applies mutation to copy and runs Phase 12 attack pipeline.
4. Executes oracle evaluation and outcome classification.
5. Emits sealed `SimulationReport`.

### 3.10 `scenarios.py`
Pre-built Golden Scenario suite (`G01` to `G20`) covering all 7 assurance domains, proof tampering, multi-domain compositions, and security boundary attacks.

### 3.11 `reporting.py`
JSON and Markdown reporting engine producing RFC 8785 JCS + SHA-256 verifiable simulation audit dossiers.

---

## 4. Safety & Security Boundaries
- **Isolated Workspace**: All operations are restricted to project-scoped temporary fixtures.
- **Fail-Closed Resource Ceilings**: Max scenarios per run ($S \le 100$), max mutations per scenario ($M \le 20$), max fixture size ($10\text{ MB}$), max execution timeout ($30\text{s}$).
- **No Unsafe Execution**: Untrusted models or arbitrary code are never executed dynamically.
