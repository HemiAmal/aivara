# AIVARA — Architectural Decision Records

**AI Verification & Assurance**
**Version:** 0.1.0-draft
**Date:** 2026-08-31

---

This document captures the reasoning behind key architectural decisions for AIVARA. Each decision is numbered, titled, and documents the context, options considered, decision made, and consequences.

---

## Table of Contents

1. [ADR-001: Offline-First with No Cloud Dependencies](#adr-001-offline-first-with-no-cloud-dependencies)
2. [ADR-002: Evidence-Based Trust over Opaque Scoring](#adr-002-evidence-based-trust-over-opaque-scoring)
3. [ADR-003: Two-Layer Detection and Proof Architecture](#adr-003-two-layer-detection-and-proof-architecture)
4. [ADR-004: SQLite as Primary Database](#adr-004-sqlite-as-primary-database)
5. [ADR-005: Blockchain as Optional Adapter, Not Core Dependency](#adr-005-blockchain-as-optional-adapter-not-core-dependency)
6. [ADR-006: Engine Registry Pattern for Modular Analysis](#adr-006-engine-registry-pattern-for-modular-analysis)
7. [ADR-007: SSE over WebSocket for Progress Reporting](#adr-007-sse-over-websocket-for-progress-reporting)
8. [ADR-008: In-Process Async Task Runner over External Queue](#adr-008-in-process-async-task-runner-over-external-queue)
9. [ADR-009: White-Box to Black-Box Graceful Degradation](#adr-009-white-box-to-black-box-graceful-degradation)
10. [ADR-010: Ed25519 for Digital Signatures](#adr-010-ed25519-for-digital-signatures)
11. [ADR-011: Hash-Linked Record Chains for Tamper Evidence](#adr-011-hash-linked-record-chains-for-tamper-evidence)
12. [ADR-012: Model Merging — Integrity + Fingerprinting](#adr-012-model-merging--integrity--fingerprinting)
13. [ADR-013: Inference Merging — Replay + Tampering + Provenance](#adr-013-inference-merging--replay--tampering--provenance)
14. [ADR-014: No Model Retraining in Baseline Assessment](#adr-014-no-model-retraining-in-baseline-assessment)
15. [ADR-015: Zustand for Frontend State Management](#adr-015-zustand-for-frontend-state-management)
16. [ADR-016: TOML for Configuration Format](#adr-016-toml-for-configuration-format)
17. [ADR-017: DINOv2 as Primary Embedding Model, CLIP as Optional](#adr-017-dinov2-as-primary-embedding-model-clip-as-optional)
18. [ADR-018: Alembic for Database Migrations](#adr-018-alembic-for-database-migrations)
19. [ADR-019: Docker as Primary Deployment Mechanism](#adr-019-docker-as-primary-deployment-mechanism)
20. [ADR-020: Protocol-Based Interfaces over Abstract Base Classes](#adr-020-protocol-based-interfaces-over-abstract-base-classes)
21. [ADR-021: Explicit Coverage and Limitation Reporting](#adr-021-explicit-coverage-and-limitation-reporting)
22. [ADR-022: Configurable Sampling Strategy for Large Datasets](#adr-022-configurable-sampling-strategy-for-large-datasets)
23. [ADR-023: PyTorch Pickle Loading Security Policy](#adr-023-pytorch-pickle-loading-security-policy)
24. [ADR-024: Monorepo with Independent Frontend and Backend](#adr-024-monorepo-with-independent-frontend-and-backend)
25. [ADR-025: Three-Tier Disposition System](#adr-025-three-tier-disposition-system)

---

## ADR-001: Offline-First with No Cloud Dependencies

**Status:** ACCEPTED

**Context:**
AIVARA targets environments where internet connectivity is unavailable, unreliable, or prohibited (air-gapped networks, classified environments, high-security facilities). Many AI security tools assume cloud connectivity for model hosting, API access, or telemetry.

**Decision:**
The system operates completely offline. No cloud service, external API, or paid service is required at runtime. All dependencies (Python packages, NPM packages, embedding models, fonts) are bundled or pre-cached before deployment.

**Alternatives Considered:**
1. **Cloud-optional** (online features with offline fallback): Rejected — creates a two-tier experience and may introduce subtle dependencies on cloud services.
2. **Online-only**: Rejected — excludes the primary target audience.

**Consequences:**
- All embedding models (DINOv2, CLIP) must be pre-downloaded and shipped with the deployment bundle.
- Docker images are larger (include all dependencies).
- An explicit air-gapped deployment workflow must be documented and maintained.
- No automatic updates; updates must be manually deployed.
- The air-gapped bundle script (`scripts/bundle-offline.sh`) becomes a critical artifact.

---

## ADR-002: Evidence-Based Trust over Opaque Scoring

**Status:** ACCEPTED

**Context:**
Many AI evaluation tools produce a single "trust score" or "quality score" without transparent methodology. This is insufficient for security-critical assurance decisions where analysts need to understand *why* a system is trustworthy or not.

**Decision:**
The fundamental flow is: `Evidence → Finding → Confidence → Risk → Decision`. Every trust-related decision is traceable to specific evidence. No opaque "AI trust score" is produced. Risk scores are derived from documented, configurable rules applied to evidence-backed findings.

**Alternatives Considered:**
1. **Ensemble ML model producing a trust score**: Rejected — opaque, non-auditable, and antithetical to the project's purpose.
2. **Rule-based scoring without evidence linking**: Rejected — scores without evidence cannot be audited or challenged.

**Consequences:**
- Every engine must produce structured findings with attached evidence.
- The Evidence Engine becomes a critical shared infrastructure component.
- Risk calculation logic must be transparent and configurable.
- Reports must trace decisions to evidence.
- More development effort than a simple score, but fundamentally more trustworthy.

---

## ADR-003: Two-Layer Detection and Proof Architecture

**Status:** ACCEPTED

**Context:**
AI security evaluation involves two fundamentally different kinds of analysis: (1) detecting anomalies and suspicious patterns using statistical/ML methods, and (2) proving integrity and provenance using cryptographic methods. These serve different purposes and have different confidence characteristics.

**Decision:**
Separate the system into two conceptual layers:
- **Layer 1 (Detection):** Uses ML, CV, statistics, embeddings, and behavioural testing to identify anomalies.
- **Layer 2 (Proof):** Uses hashes, signatures, provenance chains, timestamps, and nonces to establish cryptographic integrity.

A cryptographic hash proves artifact identity relative to a reference. It does NOT prove the artifact is benign. Both layers are complementary.

**Alternatives Considered:**
1. **Single unified layer**: Rejected — conflates probabilistic detection with deterministic proof, making it harder to reason about confidence.

**Consequences:**
- Findings are tagged with their source layer, enabling different confidence interpretations.
- Cryptographic evidence (hash match, signature valid) has confidence = 1.0 by definition.
- Statistical evidence has variable confidence based on the method and sample size.
- The analyst can distinguish between "this artifact hasn't been tampered with" (proof) and "this artifact may contain suspicious patterns" (detection).

---

## ADR-004: SQLite as Primary Database

**Status:** ACCEPTED

**Context:**
AIVARA is a desktop-first, single-user application. It must operate offline without requiring database server infrastructure.

**Decision:**
Use SQLite as the primary and only database. Enable WAL (Write-Ahead Logging) mode for improved concurrent read performance. Serialize writes through the API layer.

**Alternatives Considered:**
1. **PostgreSQL**: Rejected — requires a separate server process, complicates air-gapped deployment, overkill for single-user.
2. **DuckDB**: Considered for analytical queries, but lacks the maturity and SQLAlchemy integration of SQLite.
3. **SQLite + DuckDB hybrid**: Deferred — may be valuable if analytical query performance becomes an issue on large datasets.

**Consequences:**
- No database server to install, configure, or maintain.
- Single-file database simplifies backup and data portability.
- Write concurrency is limited (single writer). This is acceptable for a single-user desktop application.
- JSON columns are used for semi-structured data; queryable via SQLite JSON functions (available since 3.38.0).
- Schema migrations are managed via Alembic (see ADR-018).
- If multi-user support is ever needed, this decision should be revisited.

---

## ADR-005: Blockchain as Optional Adapter, Not Core Dependency

**Status:** ACCEPTED

**Context:**
The requirements mention Hyperledger Fabric/Besu for a permissioned blockchain layer. However, blockchain introduces significant infrastructure complexity (multi-node consensus, network configuration, chaincode deployment) that conflicts with the offline-first, desktop-first design.

**Decision:**
The blockchain layer is implemented as an optional adapter behind a `ProvenanceStoreAdapter` Protocol. The default implementation is a SQLite-backed hash-linked ledger with Ed25519 signatures. This provides local tamper detection and non-repudiation without blockchain infrastructure.

When blockchain is enabled:
1. Records are written to SQLite first (local resilience).
2. Records are submitted to blockchain via the adapter (write-through).
3. Blockchain failure does not block core operations.

**Alternatives Considered:**
1. **Blockchain required**: Rejected — a single-node blockchain provides no consensus advantage and adds enormous complexity.
2. **No blockchain at all**: Considered, but rejected to preserve future multi-party verification use cases.
3. **Lightweight local blockchain (e.g., embedded ledger)**: Considered, but the SQLite hash chain already provides equivalent local integrity guarantees.

**Consequences:**
- The core system is fully functional without blockchain.
- The `ProvenanceStoreAdapter` interface is defined in v1.
- A `NoOpBlockchainAdapter` stub is created for testing.
- Hyperledger integration is deferred to a phase where there is a concrete multi-party deployment requirement.
- Air-gapped deployments will never use blockchain (no network = no consensus).

---

## ADR-006: Engine Registry Pattern for Modular Analysis

**Status:** ACCEPTED

**Context:**
The system has 8+ analysis engines. Adding, removing, or replacing engines should not require modifying core orchestration code.

**Decision:**
Implement an Engine Registry pattern:
- Each engine implements the `AnalysisEngine` Protocol.
- Each engine registers itself with the central registry at startup.
- The pipeline coordinator queries the registry for enabled engines and executes them.
- Engines are discovered by package, not by hardcoded imports.

**Alternatives Considered:**
1. **Hardcoded engine list**: Rejected — adding a new engine requires modifying the coordinator.
2. **Plugin system with dynamic loading**: Overkill for v1. The registry pattern provides extensibility without the complexity of a full plugin system.
3. **Dependency injection container**: Considered, but Python's Protocol pattern + a simple registry dictionary is sufficient.

**Consequences:**
- New engines are added by: (1) creating a directory in `engines/`, (2) implementing the `AnalysisEngine` protocol, (3) registering in the registry.
- No modification of existing code is required.
- The registry provides the `system/capabilities` endpoint with available engines and their supported attack classes.
- Engine configuration is namespaced under `[engines.<engine_id>]` in the TOML config.

---

## ADR-007: SSE over WebSocket for Progress Reporting

**Status:** ACCEPTED

**Context:**
Long-running operations (dataset audits, model analysis, simulations) need to report progress to the frontend in real-time.

**Decision:**
Use Server-Sent Events (SSE) for progress reporting. SSE provides unidirectional server-to-client streaming over standard HTTP, which is sufficient for progress updates.

**Alternatives Considered:**
1. **WebSocket**: Rejected — bidirectional communication is not needed for progress reporting. WebSocket adds connection management complexity.
2. **Polling**: Simpler but creates unnecessary load and introduces latency. Retained as a fallback if SSE is not supported by the client.

**Consequences:**
- Each long-running operation has a dedicated SSE endpoint (e.g., `/api/v1/audits/{id}/progress`).
- All engines report progress via a unified `ProgressEvent` schema.
- Frontend uses the standard `EventSource` API.
- If bidirectional communication is needed later (e.g., interactive simulation control), WebSocket can be added for that specific use case without replacing SSE for progress.

---

## ADR-008: In-Process Async Task Runner over External Queue

**Status:** ACCEPTED

**Context:**
Audit operations are long-running and should not block the API thread. A task execution mechanism is needed.

**Decision:**
Use an in-process async task runner built on Python's `asyncio`. Tasks are submitted to a bounded semaphore-controlled executor. No external task queue (Celery, Redis, RabbitMQ) is required.

**Alternatives Considered:**
1. **Celery + Redis**: Rejected — requires Redis server, which conflicts with offline-first and adds infrastructure complexity.
2. **Python `multiprocessing` pool**: Considered for CPU-bound tasks (e.g., hashing, embedding computation). Retained as an option for CPU-intensive sub-tasks within the async runner.
3. **Dramatiq**: Lighter than Celery but still requires a broker.

**Consequences:**
- No additional infrastructure dependencies.
- Concurrency is controlled via `max_workers` configuration.
- CPU-bound tasks (hashing, image processing) use `asyncio.to_thread()` or `ProcessPoolExecutor` for parallelism.
- The task runner interface is abstract enough that a Celery backend could be substituted later without changing the service layer.
- Memory usage must be monitored — all tasks share the same process.

---

## ADR-009: White-Box to Black-Box Graceful Degradation

**Status:** ACCEPTED

**Context:**
Some model formats allow inspection of internal weights and architecture (white-box), while others may be opaque or restricted (black-box). The system must handle both cases.

**Decision:**
Engines that support white-box analysis must gracefully fall back to black-box analysis when internals are not accessible. Findings are tagged with `analysis_mode: white_box | black_box`, and confidence scores are adjusted to reflect the reduced analysis depth.

**Fallback conditions:**
- Model format does not support weight extraction → black-box
- Model is encrypted or obfuscated → black-box
- White-box analyzer throws an unsupported operation error → black-box

**Alternatives Considered:**
1. **Fail if white-box is unavailable**: Rejected — excludes models that are legitimately opaque.
2. **Separate white-box and black-box engines**: Rejected — duplicates orchestration logic.

**Consequences:**
- Every model-related engine has both `white_box_analyze()` and `black_box_analyze()` paths.
- `ModelLoader.supports_white_box()` indicates capability.
- Findings from black-box analysis carry lower confidence by default.
- The report explicitly states which analysis mode was used for each finding.

---

## ADR-010: Ed25519 for Digital Signatures

**Status:** ACCEPTED

**Context:**
Inference records and provenance records require digital signatures for non-repudiation and tamper evidence.

**Decision:**
Use Ed25519 (Edwards-curve Digital Signature Algorithm) via the Python `cryptography` library.

**Alternatives Considered:**
1. **RSA-2048/4096**: Rejected — larger keys, slower signing, no meaningful security advantage for this use case.
2. **ECDSA (P-256)**: Viable, but Ed25519 has simpler, more consistent implementations and is less susceptible to implementation errors.
3. **HMAC only**: Rejected — HMAC provides integrity but not non-repudiation (symmetric key means both parties can produce the MAC).

**Consequences:**
- Small key sizes (32 bytes public, 64 bytes private) simplify storage and transmission.
- Deterministic signatures (no random nonce in signing) aid reproducibility.
- The Python `cryptography` library provides a well-audited implementation.
- Key management is simple (see Architecture §11.3).

---

## ADR-011: Hash-Linked Record Chains for Tamper Evidence

**Status:** ACCEPTED

**Context:**
The provenance ledger and inference records must be tamper-evident. If any record is modified, the tampering must be detectable.

**Decision:**
Records form hash-linked chains: each record includes the hash of the previous record. The chain is verified by recomputing hashes sequentially. Additionally, each record is individually signed with Ed25519.

```
Record N: hash(data_N + hash_N-1) + sign(hash_N)
Record N-1: hash(data_N-1 + hash_N-2) + sign(hash_N-1)
...
Record 0 (genesis): hash(data_0) + sign(hash_0)
```

**Alternatives Considered:**
1. **Individual signatures only (no chain)**: Insufficient — individual records can be deleted or reordered without detection.
2. **Merkle tree**: More complex; useful for parallel verification but unnecessary for sequential provenance records.
3. **Full blockchain**: See ADR-005. The hash chain provides equivalent local integrity guarantees without the infrastructure.

**Consequences:**
- Modifying any record invalidates all subsequent hashes.
- Deleting a record breaks the chain.
- Reordering records is detectable via sequence numbers and hash verification.
- Chain verification is O(n) — acceptable for local provenance chains.
- Genesis record (first record in a project) has `previous_record_hash = "0"` (sentinel).

---

## ADR-012: Model Merging — Integrity + Fingerprinting

**Status:** ACCEPTED

**Context:**
The requirements list "Model Integrity Engine" and "Model Fingerprinting" as separate modules (modules 3 and 4). However, fingerprinting is a technique used *within* model integrity assessment.

**Decision:**
Merge into a single `model` engine package containing separate analyzers:
- `weight_analysis.py` — statistical analysis of weight tensors
- `architecture_analysis.py` — architecture structure comparison
- `fingerprinting.py` — generating and comparing model fingerprints
- `format_validation.py` — validating model file integrity

**Consequences:**
- Simpler module structure without losing capability.
- Fingerprinting is available as a standalone operation (e.g., for model registration) and as part of full model audit.
- The engine exposes both `generate_fingerprint()` and `full_audit()` methods.

---

## ADR-013: Inference Merging — Replay + Tampering + Provenance

**Status:** ACCEPTED

**Context:**
The requirements list "Inference Provenance Engine" (module 7), "Replay Detection" (module 8), and "Inference Tampering Detection" (module 9) as separate modules. All three operate on inference records and share data access patterns.

**Decision:**
Merge into a single `inference` engine package containing separate analyzers:
- `seal_manager.py` — creating cryptographic seals for inference records
- `provenance_verifier.py` — verifying the inference hash chain
- `replay_detector.py` — detecting replayed inference requests
- `tampering_detector.py` — detecting modified inference records

**Consequences:**
- Unified access to inference records.
- Shared hash chain verification logic.
- Each analyzer remains independently testable.
- The API surface remains the same (separate endpoints for seal, verify, detect replay).

---

## ADR-014: No Model Retraining in Baseline Assessment

**Status:** ACCEPTED

**Context:**
Requirement 6 states that baseline assessment must not require retraining the supplied model. This constrains the analysis methods available.

**Decision:**
Baselines are established through non-training methods:
1. **Dataset baseline:** Statistical profiling (class distribution, image statistics, embedding cluster structure).
2. **Model baseline:** Weight tensor statistics, architecture fingerprinting, activation pattern profiling on synthetic or held-out probes.
3. **Behavioral baseline:** Inference consistency testing using synthetic perturbations (rotation, noise, scale changes).

No gradient computation through the training loss is performed. Feature extraction and inference (forward pass only) are permitted.

**Alternatives Considered:**
1. **Allow light fine-tuning for baseline**: Rejected per requirements. Also impractical in air-gapped environments where training infrastructure may be unavailable.

**Consequences:**
- Some backdoor detection techniques that require retraining (e.g., fine-pruning) cannot be used.
- Neural Cleanse (which optimizes a trigger pattern via gradient descent on the model) is permitted because it does not modify the model weights — it only computes gradients to reverse-engineer potential triggers.
- The system's capabilities and limitations must reflect this constraint (see Architecture §15).

---

## ADR-015: Zustand for Frontend State Management

**Status:** ACCEPTED

**Context:**
The React frontend needs state management for project state, audit progress, findings, and user preferences.

**Decision:**
Use Zustand for client-side state management.

**Alternatives Considered:**
1. **Redux Toolkit**: Full-featured but introduces significant boilerplate for a single-user desktop app.
2. **React Context + useReducer**: Simpler but lacks middleware, devtools, and persistence capabilities.
3. **Jotai/Recoil**: Atomic state management — good for fine-grained reactivity but less suited to the entity-based domain model.

**Consequences:**
- Minimal boilerplate.
- TypeScript-native with good type inference.
- Built-in middleware for persistence (localStorage), devtools, and immer integration.
- Stores are organized by domain: `projectStore`, `auditStore`, `findingsStore`, `settingsStore`.

---

## ADR-016: TOML for Configuration Format

**Status:** ACCEPTED

**Context:**
The system needs a configuration file format that is human-readable, supports comments, and is well-suited to hierarchical configuration.

**Decision:**
Use TOML as the configuration file format. Python 3.11+ includes `tomllib` in the standard library.

**Alternatives Considered:**
1. **YAML**: More common in DevOps but susceptible to subtle parsing issues (Norway problem, type coercion). Requires external library.
2. **JSON**: No comments. Not human-friendly for configuration.
3. **INI**: Too limited for nested configuration.
4. **Environment variables only**: Insufficient for complex, nested engine configurations.

**Consequences:**
- Configuration files are in `config/*.toml`.
- Parsed by `tomllib` (stdlib) and validated by Pydantic `BaseSettings`.
- Comments in config files serve as inline documentation.
- TOML's table syntax maps cleanly to the engine configuration namespace (`[engines.dataset]`, `[engines.model]`, etc.).

---

## ADR-017: DINOv2 as Primary Embedding Model, CLIP as Optional

**Status:** ACCEPTED

**Context:**
Image embeddings are needed for duplicate detection, OOD detection, and distribution shift analysis. Two models were proposed: DINOv2 and CLIP.

**Decision:**
- **DINOv2 ViT-S/14** (~86MB) is the primary embedding model. It is always shipped and enabled.
- **CLIP ViT-B/32** (~338MB) is optional and only used for text-image consistency analysis (label-image matching). It is disabled by default and can be enabled via configuration.

**Alternatives Considered:**
1. **CLIP as primary**: Rejected — CLIP embeddings are text-image aligned, which is useful for label matching but suboptimal for pure image-to-image similarity compared to DINOv2.
2. **Both always enabled**: Rejected — adds 338MB to the offline bundle without clear benefit for all users.
3. **Neither (use perceptual hashing only)**: Rejected — perceptual hashes are insufficient for semantic OOD detection and distribution shift analysis.

**Consequences:**
- Baseline offline bundle is ~86MB lighter when CLIP is disabled.
- Configuration: `[embedding_models] clip_path = ""` (empty = disabled).
- Label-image consistency analysis degrades gracefully when CLIP is unavailable (falls back to statistical methods).
- DINOv2 model hash is recorded in `config/model_manifest.json` for integrity verification.

---

## ADR-018: Alembic for Database Migrations

**Status:** ACCEPTED

**Context:**
The SQLite schema will evolve as new engines and features are added. A migration strategy is needed to upgrade existing databases without data loss.

**Decision:**
Use Alembic (the migration tool for SQLAlchemy) with auto-generation of migration scripts from model changes.

**Alternatives Considered:**
1. **Manual SQL scripts**: Error-prone, no rollback support.
2. **SQLite-specific migration tools**: Fewer features, less community support.
3. **Drop-and-recreate**: Unacceptable — destroys existing audit data.

**Consequences:**
- Migration scripts are version-controlled in `backend/alembic/versions/`.
- Migrations run automatically at startup (with a confirmation prompt in production).
- Downgrade paths are maintained for at least one version.
- SQLite has limitations on `ALTER TABLE` (no `DROP COLUMN` before 3.35.0); migrations must account for this.

---

## ADR-019: Docker as Primary Deployment Mechanism

**Status:** ACCEPTED

**Context:**
The system needs a reliable, reproducible deployment mechanism that works in air-gapped environments.

**Decision:**
Docker + Docker Compose is the primary deployment mechanism. The system consists of two containers: `aivara-backend` (Python/FastAPI) and `aivara-frontend` (Nginx serving built React app).

Tauri (desktop packaging) is deferred to a later phase.

**Alternatives Considered:**
1. **Native Python + npm dev server**: Works for development but is not reproducible for deployment.
2. **Tauri immediately**: Adds Rust build complexity and platform-specific issues. Not justified until the core system is stable.
3. **Electron**: Heavy, memory-intensive, and bundles a full Chromium instance.
4. **PyInstaller/Nuitka**: Python-only packaging; doesn't solve the frontend serving problem.

**Consequences:**
- `docker/Dockerfile.backend` and `docker/Dockerfile.frontend` define the build.
- `docker/docker-compose.yml` orchestrates both services.
- Air-gapped deployment uses `docker save` / `docker load`.
- Docker images are self-contained (no runtime downloads).
- Development can use native tooling (`uvicorn` + `vite dev`) without Docker.

---

## ADR-020: Protocol-Based Interfaces over Abstract Base Classes

**Status:** ACCEPTED

**Context:**
Engine and loader interfaces need to be defined in a way that enables type checking, testability, and loose coupling.

**Decision:**
Use Python `typing.Protocol` (structural subtyping) for all core interfaces instead of `abc.ABC` (nominal subtyping).

**Alternatives Considered:**
1. **`abc.ABC` / `abc.abstractmethod`**: Requires explicit inheritance. Couples implementations to the interface module.
2. **No formal interface (duck typing only)**: Loses type checking benefits and IDE support.

**Consequences:**
- Implementations don't need to inherit from the interface — they just need to match the method signatures.
- MyPy enforces protocol conformance at type-check time.
- Test doubles (mocks, fakes) are trivially created without inheriting from the interface.
- All protocols are defined in `core/interfaces.py`.

---

## ADR-021: Explicit Coverage and Limitation Reporting

**Status:** ACCEPTED

**Context:**
Requirement 16 states that the system must explicitly report coverage and limitations. Overstating capabilities is dangerous in a security tool.

**Decision:**
- Every engine declares its `supported_attack_classes` and `known_limitations` as protocol properties.
- The system exposes a `/api/v1/system/coverage` endpoint listing all supported attack classes, detection methods, expected confidence ranges, and known limitations.
- Every assurance report includes a "Coverage and Limitations" section.
- The confidence calibration disclaimer is included in every report.

**Alternatives Considered:**
1. **Implicit coverage (just list attacks without limitations)**: Rejected — dangerous and dishonest.
2. **Coverage in documentation only (not in reports)**: Rejected — the report is the deliverable; limitations must travel with the conclusions.

**Consequences:**
- Adding a new attack class to the system requires updating the engine's `supported_attack_classes` property.
- The architecture document (§15) maintains the canonical coverage table.
- Reports include a machine-readable coverage manifest in JSON format.

---

## ADR-022: Configurable Sampling Strategy for Large Datasets

**Status:** ACCEPTED

**Context:**
Datasets may range from tens of images to millions. Full analysis of large datasets is computationally prohibitive.

**Decision:**
Implement configurable sampling strategies:
- **Full scan**: Analyze all images (default for datasets < 10K images).
- **Random sampling**: Uniform random sample of N images.
- **Stratified sampling**: Sample proportional to class distribution.
- **Cluster-based sampling**: Embed images, cluster, sample from each cluster.

The sample size is configurable per engine via `[engines.<id>].sample_size`.

**Alternatives Considered:**
1. **Always full scan**: Not feasible for large datasets.
2. **Fixed sample size**: Doesn't adapt to dataset characteristics.

**Consequences:**
- Findings from sampled analyses include the sampling method and size in metadata.
- Confidence is adjusted based on sample coverage (e.g., analyzing 10% of images yields lower confidence than 100%).
- The report states the sampling strategy used.

---

## ADR-023: PyTorch Pickle Loading Security Policy

**Status:** ACCEPTED

**Context:**
PyTorch `.pth` files use Python's `pickle` module for serialization. Pickle can execute arbitrary code during deserialization, making it a known attack vector.

**Decision:**
1. **Prefer safe formats**: Recommend TorchScript (`.pt`/`.ts`) and ONNX (`.onnx`), which do not use pickle.
2. **If `.pth` is loaded**: Use `torch.load(..., weights_only=True)` to prevent arbitrary code execution.
3. **Display a warning**: Alert the analyst that a pickle-based model is being loaded.
4. **Document the risk**: Include in the threat model and report.

**Alternatives Considered:**
1. **Reject `.pth` files entirely**: Too restrictive — many legitimate models are distributed as `.pth`.
2. **Load without restrictions**: Unacceptable security risk for a security tool.
3. **Sandboxed execution**: Complex and potentially bypassable.

**Consequences:**
- `weights_only=True` prevents most pickle-based attacks but may fail for models that require custom unpickling.
- If `weights_only=True` fails, the system refuses to load the model and recommends conversion to ONNX or TorchScript.
- The analyst is always informed of the model format and its security implications.

---

## ADR-024: Monorepo with Independent Frontend and Backend

**Status:** ACCEPTED

**Context:**
The system has a React frontend and a Python backend. These need to be developed, tested, and deployed independently while sharing a repository.

**Decision:**
Use a monorepo structure with clear separation:
- `frontend/` — React/TypeScript/Vite application
- `backend/` — Python/FastAPI application
- Communication via HTTP REST API only (localhost)

**Alternatives Considered:**
1. **Separate repositories**: Complicates versioning and cross-cutting changes.
2. **Single-language stack (e.g., all Python with Jinja templates)**: Limits frontend capabilities and developer experience.
3. **Single-language stack (e.g., all TypeScript with Node.js backend)**: Python has superior ML/CV library support.

**Consequences:**
- Frontend and backend can be developed and tested independently.
- API contracts (Pydantic models) serve as the interface specification.
- Docker Compose orchestrates both services.
- CI/CD can run frontend and backend pipelines independently.
- TypeScript types in `frontend/src/api/types.ts` must be kept in sync with Pydantic models in `backend/aivara/core/schemas.py`. Consider auto-generation in Phase 2.

---

## ADR-025: Three-Tier Disposition System

**Status:** ACCEPTED

**Context:**
The final output of the system is a disposition for each audited asset. The disposition must be clear, actionable, and not overloaded with nuance that prevents decision-making.

**Decision:**
Three dispositions:
- **ACCEPT**: The asset passes all checks at the configured thresholds. No action required.
- **REVIEW**: The asset has findings that require human expert review. Not necessarily compromised, but cannot be automatically accepted.
- **QUARANTINE**: The asset has critical findings indicating likely compromise, tampering, or unacceptable risk. Must not be used until resolved.

Disposition thresholds are configurable:
- Risk score < `accept_below` (default 0.3) → ACCEPT
- Risk score < `review_below` (default 0.7) → REVIEW
- Risk score ≥ `review_below` → QUARANTINE

**Alternatives Considered:**
1. **Binary (PASS/FAIL)**: Too coarse — many situations require human judgment.
2. **Five-tier (ACCEPT/CAUTION/REVIEW/SUSPECT/QUARANTINE)**: Too granular — creates decision paralysis.
3. **Numeric score only (no disposition)**: Requires every consumer to implement their own thresholds.

**Consequences:**
- Dispositions are produced at multiple scopes: per-finding, per-audit, per-asset, and per-project.
- Higher-scope dispositions are the maximum severity of their constituent dispositions (e.g., if any finding is QUARANTINE, the asset disposition is QUARANTINE).
- Thresholds are configurable in `[risk]` configuration, allowing organizations to set their own risk appetite.
- The rationale for each disposition is included as a human-readable string.

---

## Architecture Review — Impact on Decisions

**Date:** 2026-08-31
**Context:** An adversarial architecture review (ARCHITECTURE.md §16) identified 31 findings. This section documents how those findings affect existing ADRs, amend accepted decisions, and introduce new decision records.

---

### ADR Amendments

The following accepted ADRs are amended based on review findings:

#### ADR-001 Amendment (ref: AR-001, AR-002, AR-003, AR-004, AR-005)

**Original decision:** "All dependencies are bundled or pre-cached before deployment."

**Amendment:** The original decision was correct in principle but insufficiently enforced. The following specific violations were identified and must be addressed:

| Source | Violation | Resolution |
|--------|-----------|------------|
| `torch.hub.load()` (AR-001) | Phones home to GitHub | Never call at runtime. Mandatory local-path loading. Startup validation. |
| WeasyPrint `url_fetcher` (AR-002) | Resolves external CSS/font URLs | Custom `url_fetcher` that only allows `file://`. Network-blocked integration test. |
| FastAPI Swagger UI (AR-003) | Loads JS/CSS from `cdn.jsdelivr.net` | Disable by default. Local static files for dev mode. |
| Cleanlab telemetry (AR-004) | Potential usage telemetry | Pin version, audit source, set `CLEANLAB_TELEMETRY=0`, wrap behind adapter. |
| ONNX Runtime (AR-005) | May download execution providers | CPU-only default, explicit provider list, `ORT_DISABLE_ALL_TELEMETRY=1`. |

**New requirement:** Docker containers for air-gapped deployment MUST use `network_mode: none` (or equivalent). This is the defense-in-depth guarantee that no code path — known or unknown — can phone home.

**Status:** AMENDED

---

#### ADR-005 Amendment (ref: AR-010)

**Original decision:** "Define the `ProvenanceStoreAdapter` protocol in v1. Create a `NoOpBlockchainAdapter` stub."

**Amendment:** Premature. The adapter interface should NOT be defined in v1 because the blockchain's query model, consistency guarantees, and transaction semantics are unknown. Defining an interface without these constraints produces a wrong abstraction.

**Revised decision:**
1. Build the SQLite provenance ledger directly with clean internal methods.
2. Do not define a `ProvenanceStoreAdapter` protocol.
3. Keep `blockchain_tx_id` as a nullable column for forward-compatibility.
4. Remove all Hyperledger references from v1 scope and documentation.
5. Extract the adapter protocol WHEN blockchain requirements are concrete (Phase 2+).

**Status:** AMENDED

---

#### ADR-009 Amendment (ref: AR-025, AR-026)

**Original decision:** "Findings from black-box analysis carry lower confidence by default."

**Amendment:** "Lower confidence" was undefined, leading to inconsistent behavior across engines.

**Revised decision:**
1. Define a global `black_box_confidence_ceiling = 0.7`. Black-box findings cannot exceed this confidence.
2. Define a per-engine `black_box_confidence_factor = 0.7`. Final confidence = `min(raw * factor, ceiling)`.
3. Make `analysis_mode` optional. Only model-related engines set it. Non-model engines use `NOT_APPLICABLE`.
4. Findings must include the fallback reason in their description.
5. These parameters are configurable in `[risk]` config.

**Status:** AMENDED

---

#### ADR-011 Amendment (ref: AR-015, AR-016)

**Original decision:** "Genesis record has `previous_record_hash = '0'` (sentinel)."

**Amendment:** The `"0"` sentinel provides no integrity protection. An attacker can create a new genesis record.

**Revised decision:**
1. Replace the sentinel with a genesis nonce: `SHA-256(project_id + random_32_bytes)`.
2. The genesis nonce is stored in the `Project` table, separate from the provenance chain.
3. Chain verification starts by validating the genesis record against the stored nonce.
4. All timestamps must be UTC. Clock trust is a documented assumption.
5. Primary replay detection uses nonce uniqueness + sequence numbers. Timestamps are supplementary.

**Status:** AMENDED

---

#### ADR-023 Amendment (ref: AR-011)

**Original decision:** "TorchScript and ONNX are safe; only pickle-based `.pth` files are risky."

**Amendment:** This is incorrect. TorchScript can contain custom operators and embedded code. ONNX can contain custom ops. No model format should be considered safe.

**Revised decision:**
1. ALL model formats are treated as untrusted input.
2. TorchScript: Inspect computation graph for custom ops before executing inference. Flag custom ops as a finding.
3. ONNX: Validate with `onnx.checker.check_model()`. Verify only standard operators are used. Flag custom ops.
4. All model inference runs in a subprocess with resource limits (timeout, memory, output size).
5. Security classification per model: `STANDARD_OPS_ONLY` (lower risk) vs. `CUSTOM_OPS_DETECTED` (elevated risk).
6. The analyst is always informed of the security classification.

**Status:** AMENDED

---

#### ADR-024 Amendment (ref: AR-019)

**Original decision:** "TypeScript types must be kept in sync with Pydantic models. Consider auto-generation in Phase 2."

**Amendment:** Manual synchronization is a known source of data mismatches. In a security tool, hidden findings due to type mismatches are unacceptable.

**Revised decision:**
1. Auto-generation is promoted to P0 (Must Have).
2. Use `openapi-typescript` to generate TypeScript types from FastAPI's OpenAPI schema at build time.
3. Generated types are committed to the repository. CI validates freshness.
4. Frontend build does not require a running backend.

**Status:** AMENDED

---

### New ADRs

#### ADR-026: Subprocess Isolation for Untrusted Model Inference

**Status:** ACCEPTED

**Context:**
Review findings AR-011 and AR-012 identified that model inference runs in the main process without resource limits. A malicious model could exhaust memory, enter an infinite loop, or exploit a vulnerability in the model runtime.

**Decision:**
All model inference (ONNX, PyTorch, TorchScript) runs in a subprocess with configurable resource limits:
- `inference_timeout_seconds = 60`
- `inference_max_memory_mb = 4096`
- `inference_max_output_mb = 100`

If limits are exceeded, the subprocess is killed and the event is recorded as a finding with severity HIGH.

**Consequences:**
- Subprocess communication uses `multiprocessing` with pickle-safe data (numpy arrays serialized as shared memory or files).
- Adds latency (~100ms per inference call for subprocess overhead).
- Prevents the API server from crashing due to model behavior.
- Resource exhaustion is itself a finding, providing evidence of potential denial-of-service attack.

---

#### ADR-027: Image Input Validation and Decompression Bomb Protection

**Status:** ACCEPTED

**Context:**
Review finding AR-013 identified that image decoders (Pillow, OpenCV) are an attack surface. Crafted images can exploit decoder vulnerabilities or exhaust memory via decompression bombs.

**Decision:**
1. Validate image headers before full decode: magic bytes, dimension bounds (< 20,000 × 20,000), file size bounds.
2. Set `PIL.Image.MAX_IMAGE_PIXELS = 200_000_000`.
3. Process images in worker subprocesses with memory limits.
4. Pin Pillow and OpenCV to CVE-patched versions. Document version requirements.
5. Reject TIFF and SVG formats unless explicitly enabled.

**Consequences:**
- Adds a validation step before image processing (~1ms per image).
- Some legitimate large images (satellite, medical) may require configuration adjustment.
- Decoder crashes in subprocesses are contained and recorded as findings.

---

#### ADR-028: Detection/Proof Layer Enforcement in Data Model

**Status:** ACCEPTED

**Context:**
Review finding AR-018 identified that the two-layer architecture (Detection vs. Proof) exists conceptually but is not enforced in the data model. The `Finding` and `Evidence` interfaces don't distinguish between the layers.

**Decision:**
1. Add `evidence_layer: DETECTION | PROOF` field to both `Finding` and `Evidence`.
2. Proof-layer findings MUST have `confidence = 1.0`. This is enforced by validation.
3. Proof-layer evidence types: `HASH_MISMATCH`, `SIGNATURE_VERIFICATION`, `CHAIN_VERIFICATION`, `TIMESTAMP_ANOMALY`.
4. Detection-layer evidence types: all others.
5. Risk aggregation treats proof-layer findings as deterministic (no confidence weighting).

**Consequences:**
- The data model now enforces the two-layer architecture.
- The dashboard can visually separate deterministic integrity violations from probabilistic detections.
- Risk aggregation is more accurate: a hash mismatch is not a "maybe."

---

#### ADR-029: Normalized Annotation Storage with Contributor Tables

**Status:** ACCEPTED

**Context:**
Review findings AR-021 and AR-028 identified that: (a) storing annotations as JSON inside `DatasetImage` prevents efficient queries, and (b) contributor data buried in provenance JSON prevents the Contributor Risk Engine from functioning.

**Decision:**
1. Add an `Annotation` table: `(id, image_id, class_name, class_id, bbox_x, bbox_y, bbox_w, bbox_h, segmentation_json, contributor_id, confidence)`.
2. Add a `Contributor` table: `(id, project_id, external_id, name, source, metadata_json, first_seen, last_seen)`.
3. Add an `ImageContributor` junction table: `(image_id, contributor_id, contribution_type)`.
4. `DatasetImage.labels` JSON column is removed. `DatasetImage.metadata` JSON is retained for EXIF and other semi-structured data.
5. Add indexes on `Annotation.class_id`, `Annotation.image_id`, `ImageContributor.contributor_id`.

**Consequences:**
- Contributor Risk Engine can efficiently query contributor patterns.
- Annotation queries (e.g., "all images with class X") use SQL indexes instead of JSON scanning.
- Schema is more complex but supports the analysis requirements.
- Data import is slightly slower due to normalization, but query performance improves dramatically.

---

### Review Impact Summary

| ADR | Change Type | Review Finding |
|-----|------------|----------------|
| ADR-001 | AMENDED | AR-001, AR-002, AR-003, AR-004, AR-005 |
| ADR-005 | AMENDED | AR-010 |
| ADR-009 | AMENDED | AR-025, AR-026 |
| ADR-011 | AMENDED | AR-015, AR-016 |
| ADR-023 | AMENDED | AR-011 |
| ADR-024 | AMENDED | AR-019 |
| ADR-026 | NEW | AR-011, AR-012 |
| ADR-027 | NEW | AR-013, AR-014 |
| ADR-028 | NEW | AR-018 |
| ADR-029 | NEW | AR-021, AR-028 |

Findings AR-006, AR-007, AR-008, AR-009, AR-017, AR-020, AR-022, AR-023, AR-024, AR-027, AR-029, AR-030, AR-031 are addressed by updates to ARCHITECTURE.md §16 and do not require new or amended ADRs — they are resolved by implementing the solutions described in the review findings.

---

#### ADR-088: Paired Trigger Activation and Controlled Behavioral Comparison

**Status:** ACCEPTED / IMPLEMENTED (Phase 9.4)

**Context:**
Evaluating whether a model exhibits trigger-like vulnerability requires comparing triggered executions against both clean baselines and empirical controls (`LOCATION_SHUFFLED` and `MAGNITUDE_MATCHED_NOISE`) on identical input samples across diverse model modalities (classification, detection, segmentation, and generic tensors).

**Decision:**
1. **Paired Correspondence:** All evaluations enforce strict 1-to-1 pairing ($\text{clean\_sample}_i \leftrightarrow \text{triggered\_sample}_i$).
2. **Four Conditions:** Implement `CLEAN`, `ACTIVE_TRIGGER`, `LOCATION_SHUFFLED`, and `MAGNITUDE_MATCHED_NOISE` as standard evaluation conditions.
3. **Deterministic PCG64 Randomness:** Derive all control condition seeds using RFC 8785 JCS + SHA-256 over canonical sample identity.
4. **Task-Aware Activation Decision Rules:**
   - **Detection Count Delta:** $\text{abs\_delta} = |n_{\text{cond}} - n_{\text{clean}}| \ge \text{count\_delta\_threshold} \ge 1$.
   - **Detection IoU Drop:** $\Delta\text{IoU} = \text{clean\_iou} - \text{condition\_iou} \ge \text{iou\_drop\_threshold}$ (clean-relative degradation).
   - **Segmentation Ground Truth mIoU Drop:** $\Delta\text{mIoU} = \text{clean\_miou} - \text{condition\_miou} \ge \theta_{\text{drop}}$.
   - **Segmentation Reference Model Agreement Drop:** $\Delta A = A_{\text{clean, ref}} - A_{\text{condition, ref}} \ge \theta_{\text{drop}}$.
   - **Segmentation Clean-vs-Condition Disagreement:** $D = 1.0 - \text{agreement}(\text{cond}, \text{clean}) \ge \theta_{\text{drop}}$ (preserved separate behavioral metric).
5. **Realized RMS Matching:** Magnitude matched noise computes and matches the realized RMS delta ($\sqrt{\frac{1}{|S|}\sum (X_{\text{trig}} - X_{\text{clean}})^2}$) within declared tolerance ($\le 25\%$).
6. **Geometry-Aware Location Shuffling:** Coordinates bounded by candidate dimensions and spatial slack across all candidate families.
7. **Denominator & Target Safety:** TAR and TSR fail-safe to `None` if denominators are zero or target labels are absent.
8. **Support Eligibility Separation:** Explicit `support_status` (`SUPPORT_ELIGIBLE` vs `INSUFFICIENT_SUPPORT`) separated from execution status (`COMPLETED`).
9. **Zero Database Changes:** Zero database schema modifications or migrations.
10. **No Maliciousness Inference:** Purely observational comparative layer; no inferences of malice or compromise.

---

*End of Architectural Decision Records*

