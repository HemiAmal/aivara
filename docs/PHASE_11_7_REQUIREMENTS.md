# PHASE 11.7 — TEMPORAL & WINDOWED DISTRIBUTION SHIFT: REQUIREMENTS
=============================================================================

**PROJECT**: AIVARA — AI Verification & Assurance  
**PARENT PHASE**: PHASE 11 — DISTRIBUTION SHIFT / DATA DRIFT ANALYSIS  
**SUBPHASE**: 11.7.1 — ARCHITECTURE & REQUIREMENTS FREEZE  
**STATUS**: AUTHORITATIVE REQUIREMENTS SPECIFICATION  
**DATE**: 2026-09-13  

---

## 1. Functional Requirements (FR)

- **FR-1: Temporal Metadata Resolution**: The system shall support extraction and validation of timestamp fields from dataset metadata, supporting both `event_time` (primary observation timestamp) and `ingested_at` (server ingestion timestamp).
- **FR-2: Strict UTC Normalization**: All temporal strings shall be parsed and normalized to standard ISO 8601 UTC format (`YYYY-MM-DDTHH:MM:SS.ffffffZ`). Unparseable or timezone-ambiguous strings shall be rejected.
- **FR-3: Deterministic Chronological Sorting**: Observations shall be sorted by primary key `normalized_timestamp_utc ASC` with a secondary deterministic tie-breaking key `sample_id ASC` or `sample_hash ASC`.
- **FR-4: Window Partitioning Topologies**: The engine shall partition time-ordered populations into deterministic windows using:
  1. *Fixed Non-Overlapping Windows*: Disjoint time intervals $[t_k, t_{k+1})$.
  2. *Sliding / Rolling Windows*: Windows of duration $W$ sliding forward by step $\delta \ge W/2$.
- **FR-5: Dual Comparison Topologies**: The analyzer shall execute:
  1. *Baseline-to-Windows Comparison*: $\mathcal{W}_0 \leftrightarrow \mathcal{W}_k$ for all $k \in \{1, \dots, K\}$.
  2. *Adjacent-Windows Comparison*: $\mathcal{W}_{k-1} \leftrightarrow \mathcal{W}_k$ for all $k \in \{1, \dots, K\}$.
- **FR-6: Modality-Aware Drift Orchestration**: The temporal analyzer shall compose with existing modality analyzers without duplicating code:
  - Tabular / continuous features via Phase 11.4 schemas.
  - Image descriptors via Phase 11.5 descriptors.
  - Learned representations via Phase 11.6 representation contracts.
- **FR-7: Sample & Window Accounting**: Track total observations, timestamped observations, missing timestamp count, invalid timestamp count, total generated windows, valid windows ($N \ge 30$), and sparse/empty windows ($N < 30$).
- **FR-8: Persistence Classification**: Classify temporal drift trajectories into deterministic categories:
  - `NO_MATERIAL_SHIFT`: No window exhibits material drift ($p_{\text{adj}} \ge 0.05$ or effect size below threshold).
  - `TRANSIENT_SHIFT`: Shift observed in isolated window(s) ($k \le 1$), reverting to baseline in subsequent windows.
  - `PERSISTENT_SHIFT`: Shift sustained across $\ge 2$ consecutive windows.
  - `GRADUAL_DRIFT`: Monotonically increasing effect size divergence over $\ge 3$ consecutive windows.
  - `ABRUPT_SHIFT`: Acute divergence exceeding $3\times$ threshold appearing in a single step and persisting.
- **FR-9: Change-Point Candidate Detection**: Identify timestamp boundaries where the adjacent distribution discrepancy (Kernel MMD or Wasserstein $W_1$) achieves a local maximum with statistical significance ($p_{\text{adj}} \le 0.05$).
- **FR-10: Neutral Finding & Evidence Generation**: Produce structured `FindingModel` (`evidence_layer="detection"`) and `EvidenceModel` records binding temporal boundary hashes, window metrics, and non-accusatory recommendations.

---

## 2. Statistical Requirements (SR)

- **SR-1: Phase 11.3 Engine Authority**: All hypothesis tests (Two-Sample KS, Chi-Square, Kernel MMD, Energy Distance, Permutation Tests with $B=100$) must be executed directly by `StatisticalDriftEngine`. Zero duplicate statistical math permitted.
- **SR-2: Dual-Gate Evaluation**: A window comparison is marked `MATERIAL_SHIFT` if and only if both:
  1. Adjusted significance $p_{\text{adj}} \le 0.05$.
  2. Effect size $\ge$ threshold ($\text{PSI} \ge 0.10, \text{TVD} \ge 0.05, \text{MMD}^2 \ge 0.02, \text{Energy} \ge 1.0$).
- **SR-3: Sample Size Floor**: Any window with valid sample count $N < 30$ shall be marked `INSUFFICIENT_DATA` and excluded from hypothesis testing.
- **SR-4: Multi-Tier Multiple Testing Control**:
  - *Within-Window*: Benjamini–Hochberg FDR at $q^* = 0.05$ across all $M$ features.
  - *Across-Windows*: Benjamini–Hochberg FDR at $q^* = 0.05$ across the sequence of $K$ window comparisons against baseline.
- **SR-5: Zero Double-Correction**: Do not apply secondary FDR corrections to multivariate metrics already controlled at the window level.
- **SR-6: Deterministic PRNG Seed**: All permutation tests and subsampling must use a fixed, cryptographically derived seed.

---

## 3. Security & Non-Functional Requirements (SECR / NFR)

- **SECR-1: Air-Gap & 100% Offline**: Zero external network, DNS, NTP, or cloud API calls.
- **SECR-2: Static Security Hygiene**: Zero `eval`, `exec`, `pickle`, `subprocess`, or `os.system` constructs in codebase.
- **SECR-3: Canonical Hashing**: All contracts, window descriptors, and profiles must compute SHA-256 digests over RFC 8785 JSON Canonicalization Scheme (JCS) serializations.
- **SECR-4: Non-Attribution Invariant**: Findings and evidence must never accuse contributors of malice, fraud, or dataset poisoning based on statistical drift alone.
- **NFR-1: Bounded Complexity**: Total window count $K \le 50$; max window sample size $N_w \le 5000$. Total pairwise comparisons capped at $2K - 1 = 99$.
- **NFR-2: Memory Ceiling**: In-memory window buffers must not exceed $200\,\text{MB}$. Intermediate raw sample matrices must be released after window statistical evaluation.
- **NFR-3: Zero Database Schema Changes**: 0 new SQLite tables, 0 migrations. All results stored in existing `findings`, `evidence`, and `provenance_records` tables.

---

## 4. Failure States Matrix

| Condition | Failure Code / Decision State | Engine Behavior |
| :--- | :--- | :--- |
| Temporal metadata field absent in dataset | `MISSING_TEMPORAL_METADATA` | Fail closed; return `INVALID_TEMPORAL_CONTRACT` profile. |
| Timezone ambiguous or invalid string | `MALFORMED_TIMESTAMP` | Exclude invalid samples; if total valid $< 30$, abort. |
| Untimestamped samples exceed $10\%$ | `INSUFFICIENT_TEMPORAL_COVERAGE` | Raise warning; if valid window count $< 2$, abort. |
| Total valid windows generated $< 2$ | `INSUFFICIENT_WINDOWS` | Return `INSUFFICIENT_DATA` status profile. |
| Baseline window sample count $< 30$ | `INSUFFICIENT_BASELINE_DATA` | Return `INSUFFICIENT_DATA` status profile. |
| Cross-project dataset comparison | `PROJECT_MISMATCH` | Raise `ProjectMismatchError` domain exception. |
| Modality mismatch between windows | `INCOMPATIBLE_DATA` | Raise `IncompatiblePopulationError` exception. |
| Window count $K > 50$ or samples $> 5000$ | `RESOURCE_LIMIT_EXCEEDED` | Enforce deterministic subsampling and cap $K \le 50$. |

---

## 5. Implementation Test Strategy

Future implementation tests (Phase 11.7.2) must cover:
1. **Timestamp Normalization**: UTC conversion, leap years, sub-second precision, timezone offset validation.
2. **Deterministic Partitioning**: Fixed vs sliding windows, boundary inclusivity $[t_k, t_{k+1})$, deterministic sorting.
3. **Trajectory Classifications**: Verification of `NO_MATERIAL_SHIFT`, `TRANSIENT_SHIFT`, `PERSISTENT_SHIFT`, `GRADUAL_DRIFT`, and `ABRUPT_SHIFT` on synthetic time series.
4. **Change-Point Localization**: Correct detection of true injection window step change.
5. **Multiple-Testing Invariants**: FDR adjusted $p$-value calibration across $K$ windows.
6. **Cryptographic Sensitivity**: Mutation of timestamp, window duration, or baseline shifts hash.
7. **Security AST & Air-Gap Scans**: Zero network calls, zero forbidden Python execution primitives.
