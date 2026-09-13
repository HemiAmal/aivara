# Phase 11.8.2: Contributor & Source-Aware Distribution Shift Implementation Guide

**Project**: AIVARA — AI Verification & Assurance  
**Phase**: 11 — Distribution Shift / Data Drift Analysis  
**Subphase**: 11.8.2 — Contributor & Source-Aware Distribution Shift Implementation  
**Status**: COMPLETE

---

## 1. Executive Implementation Overview

Phase 11.8.2 implements the **Contributor & Source-Aware Distribution Shift Engine** according to the frozen architecture defined in `docs/PHASE_11_8_SOURCE_ARCHITECTURE.md` and ADR-101.

The engine provides deterministic, content-addressed, and statistically rigorous evaluation of whether data distributions vary across contributing entities, collection pipelines, acquisition channels, or hardware devices.

### Core Semantic Invariant
The engine strictly enforces that:
$$\text{Source-Associated Distribution Shift} \ne \text{Malicious Intent}$$
$$\text{Source-Associated Distribution Shift} \ne \text{Dataset Poisoning}$$
$$\text{Source-Associated Distribution Shift} \ne \text{Contributor Fraud}$$
$$\text{Source-Associated Distribution Shift} \ne \text{Causal Attribution}$$

All outputs are formulated as observational/associational findings within standard detection layers.

---

## 2. Module Architecture & Code Layout

The implementation resides cleanly in `backend/aivara/drift/`:

```
backend/aivara/drift/
├── enums.py               <- Extended with SourceType, SourceTrustState, SourceGroupStatus, etc.
├── schemas.py             <- Extended with SourceContext, SourceObservation, SourceGroupAccounting,
│                             SourceGroupDescriptor, SourceComparisonResult, SourceAnalysisContract,
│                             and SourceAnalysisProfile
├── source_engine.py       <- SourceDistributionShiftEngine, 5-stage canonicalization,
│                             pseudonymization, reconciliation, and RFC 8785 hashing
├── __init__.py            <- Exported public symbols
```

---

## 3. Key Subsystem Details

### 3.1 5-Stage Authoritative Canonicalization Pipeline
Implemented in `canonicalize_source_id(raw_id: Any) -> str`:
1. **Unicode NFKC Normalization**: Standardizes character representations.
2. **Control Character Stripping**: Removes non-printable characters while preserving standard whitespace.
3. **Whitespace Collapsing**: Trims leading/trailing whitespace and compresses consecutive spaces.
4. **Lowercase Folding**: Ensures case-insensitive equality without lossy transformations.
5. **Length Capping**: Truncates identifiers to $\le 128$ characters; falls back to `"missing"` on empty strings.

### 3.2 Project-Scoped Pseudonymization
Implemented in `derive_project_scoped_pseudonym(project_id: str, canonical_source_id: str, salt: Optional[str]) -> str`:
$$\text{PseudonymID} = \text{SHA-256}(\text{project\_id} \parallel \text{salt} \parallel \text{canonical\_source\_id})[:16]$$
- Provides cross-project unlinkability.
- Avoids leaking raw contributor PII into persistent logs or downstream ledgers.

### 3.3 Exact Reconciliation Accounting
Implemented in `SourceGroupAccounting`:
$$\text{Total Observations} = \sum N_{\text{eligible}} + \sum N_{\text{insufficient}} + N_{\text{missing}} + N_{\text{invalid}} + N_{\text{unknown}}$$
- Every observation is strictly accounted for.
- Emits `EXCESSIVE_SOURCE_FRAGMENTATION` advisory finding if sub-threshold sample ratio $> 20\%$.

### 3.4 $O(G)$ Source-vs-Reference Statistical Topology
Rather than generating $O(G^2)$ pairwise combinations, the engine performs exactly $G-1$ comparisons against a fixed, immutable reference group ($P_{\text{source\_g}} \leftrightarrow P_{\text{reference}}$).
- Subsamples large groups ($N > 5000$) deterministically using contract-bound seeds.
- Reuses Phase 11.3 `StatisticalDriftEngine` algorithms directly (KS test, PSI, Chi-Square, TVD, Kernel MMD).

### 3.5 Benjamini-Hochberg FDR & Dual-Gate Decision
- Multiplicity control applied across the comparison family with $q^* = 0.05$.
- Dual-Gate Rule:
  $$\text{Material Shift} \iff (p_{\text{adj}} \le 0.05) \land (\text{Effect Size} \ge \text{Metric Threshold})$$
  - Continuous (1D): $\text{PSI} \ge 0.10$
  - Categorical: $\text{TVD} \ge 0.05$
  - Multivariate Embeddings: $\text{MMD}^2 \ge 0.02$

### 3.6 Confounding & Simpson's Paradox Protection
- Computes $P(Y \mid S)$ label distributions for each source group.
- If $\text{TVD}(\text{label proportions}) \ge 0.15$, attaches a non-causal confounding caveat to findings.

---

## 4. Cryptographic Identity & Verification

All descriptors implement `.to_canonical_dict()` and are hashed using RFC 8785 Canonical JSON Serialization (JCS) and SHA-256:
- `source_contract_hash`: SHA-256 digest of canonical contract descriptor.
- `source_group_hash`: SHA-256 digest of source group descriptor.
- `source_analysis_profile_hash`: SHA-256 digest of the entire evaluation profile (including comparisons, accounting, and group descriptors).

Any mutation in project ID, seed, sample payloads, or grouping alters the profile hash.
