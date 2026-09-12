# Phase 10.8 — Inference Record Integrity Subsystem

**Document Version:** 1.1 (Audit Corrected & Verified)  
**Phase:** 10.8 (PERMANENTLY FROZEN & VERIFIED)  
**Security Level:** CRITICAL / CANONICAL REPLAY & TAMPER RESISTANCE  

---

> [!IMPORTANT]
> **Assurance Semantics Disclaimer:**  
> A `VERIFIED` inference record establishes persistence and cryptographic integrity of the recorded inference identity. It does **not** establish model safety, prediction correctness, absence of backdoors, contributor trustworthiness, or dataset integrity.

---

## 1. Overview & Purpose

The **Phase 10.8 Inference Record Integrity** subsystem transforms the verified, cryptographically closed Phase 10.7 `InferenceBinding` into an immutable, persistent `InferenceRecord`.

The subsystem provides:
1. **Persistent Inference Records**: Reuses `InferenceRecordModel` in `backend/aivara/database/models.py` (`DATABASE SCHEMA CHANGES = 0`).
2. **Canonical Record Descriptor**: Commits exactly 8 atomic fields under RFC 8785 JSON Canonicalization Scheme (JCS).
3. **Record Integrity Identity**: Computes deterministic `record_integrity_hash` = SHA-256(JCS(canonical_record_descriptor)).
4. **Binding to Phase 10.7**: Fails closed if the embedded `InferenceBinding` is invalid, unverified, or mismatched.
5. **Transactional Persistence & Read-Back Verification**: Ensures records are written transactionally and verified immediately upon read-back.
6. **Offline Tamper Detection**: Reconstructs descriptors on retrieval to detect any out-of-band modifications to database rows.

---

## 2. Actual SQLAlchemy Persistence Schema (`InferenceRecordModel`)

Inspection of `backend/aivara/database/models.py` confirms the exact schema:

```python
class InferenceRecordModel(Base):
    __tablename__ = "inference_records"

    id = Column(String(36), primary_key=True, default=new_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    model_id = Column(String(36), ForeignKey("ai_models.id", ondelete="RESTRICT"), nullable=False)
    input_hash = Column(String(64), nullable=False)
    input_path = Column(Text, nullable=False)
    preprocessing_hash = Column(String(64), nullable=True)
    config_hash = Column(String(64), nullable=True)
    output_json = Column(JSON, default=dict, nullable=False)
    output_hash = Column(String(64), nullable=False)
    sequence_number = Column(Integer, nullable=False)
    nonce = Column(String(64), nullable=True)
    signature = Column(Text, nullable=True)
    previous_record_hash = Column(String(64), nullable=True)
    record_hash = Column(String(64), nullable=True)
    verification_status = Column(String(50), default="unverified", nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    __table_args__ = (
        Index("ix_inference_records_project_id", "project_id"),
        Index("ix_inference_records_model_id", "model_id"),
        Index("ix_inference_records_sequence", "project_id", "model_id", "sequence_number", unique=True),
    )
```

### Schema Field Mapping

| Domain / Identity Field | Database Column / Location | Column Type & Constraints |
|---|---|---|
| `record_id` | `id` | `String(36)`, Primary Key, Not Null |
| `project_id` | `project_id` | `String(36)`, Foreign Key, Indexed, Not Null |
| `record_status` | `verification_status` | `String(50)`, Not Null |
| `record_integrity_hash` | `record_hash` | `String(64)`, Nullable (populated upon creation) |
| `inference_binding_hash` | `output_json["inference_binding_hash"]` / `output_hash` | `String(64)` |
| `schema_version` | `output_json["schema_version"]` | `String(16)` inside JSON |
| `record_version` | `output_json["record_version"]` | `String(16)` inside JSON |
| `record_type` | `output_json["record_type"]` | `String(32)` inside JSON |
| `binding_version` | `output_json["binding_version"]` | `String(16)` inside JSON |
| `created_at` | `created_at` / `output_json["created_at"]` | `DateTime`, Not Null |

**Result**: The existing database model accommodates every required field. `DATABASE SCHEMA CHANGES = 0`.

---

## 3. The 8 Committed Record Descriptor Fields

The canonical descriptor dictionary committed to `record_integrity_hash` contains **exactly 8 fields**:

| # | Field Name | Type | Description |
|---|---|---|---|
| 1 | `binding_version` | String | Semantic version of the composite binding format (`"1.0"`) |
| 2 | `inference_binding_hash` | String | Phase 10.7 canonical binding hash (64-char lowercase hex) |
| 3 | `project_id` | String | Tenant project identifier |
| 4 | `record_id` | String | Unique record identifier (UUID or hex token) |
| 5 | `record_status` | String | Verification status (`"VERIFIED"`, `"INVALID"`, `"TAMPERED"`) |
| 6 | `record_type` | String | Categorical record classification (`"STANDARD"`, `"BATCH"`, `"AUDIT"`) |
| 7 | `record_version` | String | Semantic record format version (`"1.0"`) |
| 8 | `schema_version` | String | Schema specification version (`"1.0"`) |

---

## 4. Cryptographic Identity vs Non-Identity Metadata

To prevent temporal non-determinism and preserve the integrity boundary:

1. **Cryptographic Identity Fields (Committed to `record_integrity_hash`)**:
   - `binding_version`, `inference_binding_hash`, `project_id`, `record_id`, `record_status`, `record_type`, `record_version`, `schema_version`.
   - Modifying ANY of these fields in the database row or JSON immediately causes `record_integrity_hash` recomputation divergence, resulting in `InferenceRecordStatus.TAMPERED` (`is_valid=False`).

2. **Non-Identity Metadata (Excluded from Descriptor)**:
   - `created_at`: Stored as persistence timestamp metadata. Excluded from the descriptor to ensure record identity is deterministic across replays and independent of creation time.
   - `findings`: Observational audit findings generated during verification.
   - `details`: Diagnostic operational telemetry (e.g. latency, worker ID, execution environment details).

3. **Underlying Phase 10.7 Transaction Identity**:
   - `binding` (and its 18 atomic transaction components) is committed via `inference_binding_hash`. Tampering with any tensor, contract, model fingerprint, or execution parameter invalidates the Phase 10.7 binding hash.

---

## 5. Security & Isolation Invariants

1. **Fail-Closed Binding Validation**: A record cannot be created or verified as `VERIFIED` without an untampered, verified Phase 10.7 binding.
2. **Deterministic & Nonce-less Identity**: Pure function over RFC 8785 canonical descriptors.
3. **Tenant Isolation**: Cross-project binding, retrieval, or persistence raises `InferenceRecordProjectMismatchError`.
4. **Database Schema Invariant**: `DATABASE SCHEMA CHANGES = 0`. Uses existing `InferenceRecordModel` and JSON storage.
5. **Zero Execution / Non-Executable**: Phase 10.8 executes zero models, zero preprocessing pipelines, and zero tensor computations.
6. **No Replay / No Blockchain**: Replay verification belongs to Phase 10.9; evidence & provenance ledger binding belongs to Phase 10.10.
