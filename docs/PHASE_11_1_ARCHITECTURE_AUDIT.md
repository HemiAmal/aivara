# PHASE 11.1 — ARCHITECTURE AUDIT REPORT
## Comprehensive Repository Audit for Distribution Shift & Data Drift Analysis

**Date:** 2026-09-13  
**Project:** AIVARA — AI Verification & Assurance  
**Phase:** 11.1 (Distribution Shift / Data Drift Architecture & Requirements Freeze)  
**Parent Phase:** Phase 11 — Distribution Shift / Data Drift Analysis  
**Governing Rule:** Phases 0–10 are PERMANENTLY FROZEN. Zero modifications permitted.

---

## 1. EXECUTIVE SUMMARY

An exhaustive audit of the AIVARA repository was conducted to assess existing subsystems, domain models, database schemas, cryptographic primitives, and analytical utilities in preparation for **Phase 11: Distribution Shift / Data Drift Analysis**.

The repository provides a rich, mature, and strictly frozen foundation. The audit confirms that:
1. **Zero Database Schema Changes** are required. Existing tables (`datasets`, `dataset_versions`, `samples`, `findings`, `evidence`, `risk_assessments`, `audit_events`, `provenance_records`, `projects`) fully support distribution shift analysis, findings, and evidence storage.
2. **Zero Duplicate Subsystems** will be created. Phase 11 will integrate directly with the existing `EvidenceModel`, `FindingModel`, `ProvenanceRecordModel`, `AuditEventModel`, and `InferenceTaskManager`/service patterns.
3. **Detection vs. Proof Separation** (ADR-028) is preserved: Distribution shift analysis is an analytical **Detection Layer** capability ($\text{evidence\_layer} = \text{detection}$, with calibrated confidence $\in [0.0, 1.0]$), distinct from the mathematical proof layers of Phases 2, 4, 7, and 10.
4. **Shift $\neq$ Malice**: Distribution shift constitutes objective statistical evidence of population divergence; it does NOT automatically imply poisoning, backdoor insertion, or contributor misconduct.

---

## 2. REPOSITORY AUDIT MATRIX (SECTIONS A–Q)

### A. Existing Dataset Architecture
- **Location:** `backend/aivara/dataset/` (`ingester.py`, `schemas.py`, `exceptions.py`, `parsers/`)
- **Capabilities:** Supports COCO (`coco_parser.py`), YOLO (`yolo_parser.py`), ImageFolder (`imagefolder_parser.py`), and generic formats.
- **Data Entities:** `DatasetModel`, `DatasetVersionModel`, `SampleModel`, `SampleContributorModel`.
- **Reuse Status:** **100% Reusable without modification**. Datasets and dataset versions provide the immutable sample registries and file paths required for reference and target populations.

### B. Existing Dataset Integrity Architecture
- **Location:** `backend/aivara/dataset/` (`detector.py`, `image_validator.py`, `path_security.py`, `duplicates/`, `flipping/`, `anomalies/`, `ood/`, `fingerprinting/`)
- **Capabilities:** Validates file magic, dimensions, corruption, duplicate hashes (exact and perceptual), label flipping, and out-of-distribution / basic drift (`ood/drift.py`).
- **Reuse Status:** **100% Reusable as upstream filters**. Dataset integrity ensures that reference and target inputs are uncorrupted, safely bounded, and verified prior to high-level statistical shift analysis.

### C. Existing Finding Architecture
- **Location:** `backend/aivara/domain/schemas.py` (`FindingBase`, `FindingCreate`, `FindingRead`), `backend/aivara/database/models.py` (`FindingModel`)
- **Fields:** `engine_id`, `engine_version`, `evidence_layer`, `finding_type`, `title`, `description`, `severity`, `confidence`, `affected_asset_type`, `affected_asset_id`, `disposition`, `analysis_mode`, `recommendation`, `metadata_json`.
- **Constraint (ADR-028):** `evidence_layer == "detection"` allows calibrated probabilistic confidence $\in [0.0, 1.0]$.
- **Reuse Status:** **100% Reusable**. Phase 11 generates standard `FindingModel` instances with `affected_asset_type="dataset"` or `"dataset_version"`, `finding_type="distribution_shift"`, and `evidence_layer="detection"`. Zero new finding models or tables are needed.

### D. Existing Evidence Architecture
- **Location:** `backend/aivara/domain/schemas.py` (`EvidenceBase`, `EvidenceCreate`, `EvidenceRead`), `backend/aivara/database/models.py` (`EvidenceModel`), `backend/aivara/evidence/`
- **Fields:** `finding_id`, `evidence_layer`, `evidence_type`, `title`, `description`, `data_json`, `artifact_path`, `artifact_hash`, `confidence`, `evidence_hash`.
- **Reuse Status:** **100% Reusable**. Detailed statistical outputs (p-values, test statistics, effect sizes, histogram bins, multiple-testing corrections, affected feature lists) are stored inside `data_json` of `EvidenceModel`.

### E. Existing Risk Architecture
- **Location:** `backend/aivara/contributor_risk/`, `backend/aivara/services/orchestration_service.py`, `backend/aivara/database/models.py` (`RiskAssessmentModel`)
- **Capabilities:** Aggregates findings across datasets, models, contributors, and inference transactions into unified risk scores and disposition recommendations (`ACCEPT`, `REVIEW`, `QUARANTINE`).
- **Reuse Status:** **100% Reusable**. Phase 11 findings feed into the standard risk aggregation pipeline without altering risk scoring algorithms.

### F. Existing Provenance Architecture
- **Location:** `backend/aivara/crypto/` (`signing.py`, `chain.py`, `tamper_detection.py`), `backend/aivara/services/provenance_service.py`, `backend/aivara/database/models.py` (`ProvenanceRecordModel`)
- **Capabilities:** Ed25519 asymmetric signatures, Merkle-linked hash chains, `previous_record_hash` continuity, replay attack prevention.
- **Reuse Status:** **100% Reusable**. Phase 11 analysis executions commit an audit/provenance block linking reference dataset hash, target dataset hash, analysis configuration, and generated findings into the project's provenance chain.

### G. Existing Project Isolation
- **Location:** Enforced across all services via `project_id` foreign keys, tenant filtering on queries, and `CrossProjectContaminationError` / `ProjectIsolationError` checks.
- **Reuse Status:** **100% Reusable**. Reference and target datasets must belong to the same authorized `project_id` unless explicit multi-project comparison contracts are authorized.

### H. Existing Task Execution Infrastructure
- **Location:** `backend/aivara/services/` (`InferenceTaskManager`, `BehavioralTaskManager`, `BackdoorTaskManager`, `ScanTaskManager`)
- **Capabilities:** In-memory, thread-safe asynchronous task execution, cooperative cancellation (`is_cancelled`), lifecycle states (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`), and per-subscriber `asyncio.Queue` event dispatch for SSE.
- **Reuse Status:** **Pattern Reusable**. Phase 11 will follow the established `DistributionShiftTaskManager` singleton pattern with cooperative cancellation and SSE streaming.

### I. Existing Numerical / Statistical Utilities
- **Location:** `backend/aivara/dataset/ood/drift.py`, `backend/aivara/backdoor/statistics/`
- **Capabilities:** Basic MMD with Gaussian RBF kernel, non-parametric Energy Distance, permutation testing, median heuristic for bandwidth estimation.
- **Gap / New Scope for Phase 11:** Phase 11 requires a formal, comprehensive, multi-method drift engine supporting:
  - 1D Continuous tests: Two-sample Kolmogorov–Smirnov (KS), Wasserstein Distance (Earth Mover's Distance), Population Stability Index (PSI).
  - Categorical / Discrete tests: Chi-Square Goodness-of-Fit / Independence, Total Variation Distance (TVD), Jensen–Shannon Divergence (JSD).
  - High-Dimensional / Multivariate tests: Kernel Maximum Mean Discrepancy (MMD), Energy Distance with deterministic permutation testing.
  - Multiple Hypothesis Testing corrections: Benjamini–Hochberg (FDR), Holm–Bonferroni (FWER).

### J. Existing Image Processing Capabilities
- **Location:** `backend/aivara/dataset/image_validator.py`, `backend/aivara/dataset/ood/features.py`
- **Capabilities:** PIL / Pillow safe image reading, color space conversion (RGB, HSV, Grayscale), luminance histograms, color channel statistics (mean, variance, skewness), perceptual hashing (pHash, dHash, aHash).
- **Reuse Status:** **100% Reusable**. Image distribution shift can extract deterministic visual feature vectors (color distributions, luminance, saturation, spatial frequency/Laplacian sharpness, aspect ratios) using existing local processing routines without external dependencies.

### K. Existing Model / Embedding Capabilities
- **Location:** `backend/aivara/model_integrity/`, `backend/aivara/behavioral/runtime/`
- **Capabilities:** Safe local loading of PyTorch, TorchScript, and ONNX models for offline forward inference and feature extraction.
- **Reuse Status:** **100% Reusable**. Embedding distribution shift compares latent representation vectors generated by locally registered, verified models (`AIModelModel`). Cloud embeddings and remote model APIs remain strictly forbidden.

### L. Existing API Architecture
- **Location:** `backend/aivara/api/routers/`, `backend/aivara/api/schemas/`
- **Capabilities:** FastAPI REST endpoints, standard `ApiResponse[T]` envelope (`success`, `data`, `error`, `timestamp`), dependency injection (`Depends(get_db)`), SSE streaming (`text/event-stream`).
- **Reuse Status:** **Pattern Reusable**. Phase 11 endpoints will be mounted under `/api/v1/projects/{project_id}/distribution-shift/`.

### M. Existing Database Schema
- **Location:** `backend/aivara/database/models.py`
- **Assessment:** All 14 foundational entities (`ProjectModel`, `ContributorModel`, `SampleContributorModel`, `DatasetModel`, `DatasetVersionModel`, `SampleModel`, `AIModelModel`, `ModelVersionModel`, `ModelFingerprintModel`, `InferenceRecordModel`, `FindingModel`, `EvidenceModel`, `RiskAssessmentModel`, `AuditEventModel`, `ProvenanceRecordModel`, `ReportModel`) are present and indexed.
- **Decision:** **Zero Schema Changes**. Distribution shift metadata, configurations, and statistical outputs are fully accommodated within existing JSON columns (`EvidenceModel.data_json`, `FindingModel.metadata_json`, `DatasetVersionModel.metadata_json`).

### N. Existing Security Controls
- **Location:** `backend/aivara/dataset/path_security.py`, AST scanning, resource constraints.
- **Controls:** Absolute path traversal prevention, symlink resolution restrictions, strictly offline/air-gapped operation, prohibition of dynamic code execution (`eval`, `exec`, `pickle`, `subprocess`, `os.system`, `shell=True`).
- **Reuse Status:** **Mandatory Enforcement**. Phase 11 will enforce identical security controls.

### O. Existing Resource Limits
- **Limits Established in Phases 5, 8, 9, 10:**
  - Maximum sample size per evaluation: Bounded subsampling (e.g. $N \le 50,000$).
  - Maximum permutation budget: $B \le 1,000$ (default $B = 100$).
  - Maximum feature dimensions: $D \le 4,096$.
  - Execution timeouts: Guarded via cooperative cancellation and configurable execution budgets.
- **Reuse Status:** **Mandatory Enforcement**. Phase 11 will adopt strict bounded resource limits to prevent denial-of-service or memory exhaustion.

### P. Existing Test Architecture
- **Location:** `tests/`
- **Framework:** `pytest`, `pytest-asyncio`, in-memory SQLite fixtures (`test_db`), deterministic test datasets.
- **Current Suite:** 1922 passing tests.
- **Reuse Status:** **100% Reusable**. Phase 11 test suites will build on existing fixtures and test helpers.

### Q. Existing Limitations Relevant to Distribution Shift
1. **Sample Size Sensitivity:** High-dimensional two-sample tests (e.g. MMD, Energy Distance) require adequate sample sizes ($N \ge 30$) to achieve statistical power; small samples ($N < 30$) must explicitly yield `INSUFFICIENT_DATA`.
2. **Computational Cost of Permutations:** Exact permutation tests have $O(B \cdot (N+M)^2)$ kernel matrix complexity; deterministic subsampling and matrix caching are mandatory for large datasets.
3. **Local Representation Dependency:** Deep embedding drift analysis requires a locally registered, valid model artifact. When no feature extractor is supplied, the system must gracefully fall back to statistical pixel/tabular analysis or report `UNAVAILABLE` rather than failing ungracefully.

---

## 3. AUDIT CONCLUSION & REUSE PLAN

| Subsystem / Layer | Existing Component | Phase 11 Action |
| :--- | :--- | :--- |
| **Dataset Ingestion & Storage** | `DatasetModel`, `DatasetVersionModel`, `SampleModel` | **Reuse Directly** |
| **Dataset Parsers & Integrity** | `aivara.dataset.parsers`, `aivara.dataset.image_validator` | **Reuse Directly** |
| **Domain Finding Schema** | `FindingModel`, `FindingCreate`, `FindingRead` | **Reuse Directly** (with `finding_type="distribution_shift"`) |
| **Domain Evidence Schema** | `EvidenceModel`, `EvidenceCreate`, `EvidenceRead` | **Reuse Directly** (with `evidence_type="statistical_drift_evidence"`) |
| **Risk Assessment & Scoring** | `RiskAssessmentModel`, `orchestration_service.py` | **Reuse Directly** |
| **Cryptographic Provenance** | `ProvenanceRecordModel`, `provenance_service.py` | **Reuse Directly** |
| **Database Persistence** | SQLite / SQLAlchemy (`models.py`) | **Zero Schema Changes** |
| **Task Management & SSE** | `TaskManager` design pattern (`asyncio.Queue`) | **Adopt Established Pattern** |
| **Statistical Drift Engine** | `aivara.dataset.ood.drift` | **Extend in Phase 11 with Multi-Method Engine** |
| **REST API Architecture** | FastAPI + `ApiResponse[T]` envelope | **Adopt Established Pattern** |
