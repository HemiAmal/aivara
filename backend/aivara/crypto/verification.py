"""AIVARA Unified Cryptographic Provenance Verification Engine (Phase 4.9).

Provides a comprehensive, multi-layer verification engine for AIVARA's
cryptographic provenance records and hash-linked chains. Reconciles and composes
the cryptographic primitives established in Phases 4.1 through 4.8:
  - Canonical Serialization (RFC 8785 JCS) via `aivara.crypto.canonical`
  - Content Hashing (SHA-256) via `aivara.crypto.hashing`
  - Key Lifecycle Management via `aivara.crypto.keys`
  - Ed25519 Digital Signatures via `aivara.crypto.signing`
  - Nonces, Sequences & Chain Linkage via `aivara.crypto.chain`

Enforces five distinct verification layers:
  - Layer A: Input & Schema Validation
  - Layer B: Canonical Record Hash Integrity
  - Layer C: Chain Linkage & Monotonic Continuity
  - Layer D: Digital Signature Cryptographic Verification
  - Layer E: Signer Key Identity & Lifecycle Status
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set, Union

from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel, ConfigDict, Field

from aivara.core.exceptions import AivaraException
from aivara.crypto.canonical import (
    CANONICAL_SCHEMA_VERSION,
    canonicalize_provenance_payload,
)
from aivara.crypto.chain import (
    GENESIS_ACTION,
    GENESIS_PREVIOUS_RECORD_HASH,
    GENESIS_SEQUENCE_NUMBER,
    ChainRecord,
)
from aivara.crypto.hashing import (
    hash_provenance_payload,
    is_valid_sha256,
    secure_compare_hashes,
)
from aivara.crypto.keys import (
    Ed25519KeyHandle,
    KeyManager,
    KeyStatus,
    validate_key_id,
)
from aivara.crypto.signing import (
    VerificationResult as SigVerificationResult,
    VerificationStatus as SigVerificationStatus,
    verify_hash_signature,
    verify_provenance_signature,
)


# =====================================================================
# Exceptions
# =====================================================================


class VerificationEngineError(AivaraException):
    """Base exception for verification engine failures."""

    def __init__(
        self,
        message: str,
        code: str = "VERIFICATION_ENGINE_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


# =====================================================================
# Failure Taxonomy & Status Enums
# =====================================================================


class FailureCode(str, Enum):
    """Machine-readable taxonomy of verification failure causes."""

    # Layer A: Input & Schema
    MALFORMED_INPUT = "MALFORMED_INPUT"
    INVALID_SCHEMA = "INVALID_SCHEMA"
    INVALID_PROJECT = "INVALID_PROJECT"
    INVALID_SEQUENCE = "INVALID_SEQUENCE"
    INVALID_NONCE = "INVALID_NONCE"
    INVALID_HASH_FORMAT = "INVALID_HASH_FORMAT"

    # Layer B: Canonical Record Integrity
    RECORD_HASH_MISMATCH = "RECORD_HASH_MISMATCH"

    # Layer C: Chain Continuity & Linkage
    GENESIS_INVALID = "GENESIS_INVALID"
    BROKEN_CHAIN = "BROKEN_CHAIN"
    SEQUENCE_VIOLATION = "SEQUENCE_VIOLATION"
    SEQUENCE_GAP = "SEQUENCE_GAP"
    DUPLICATE_SEQUENCE = "DUPLICATE_SEQUENCE"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    DUPLICATE_NONCE = "DUPLICATE_NONCE"
    DUPLICATE_RECORD = "DUPLICATE_RECORD"
    PROJECT_MISMATCH = "PROJECT_MISMATCH"

    # Layer D: Signature Verification
    MISSING_SIGNATURE = "MISSING_SIGNATURE"
    MALFORMED_SIGNATURE = "MALFORMED_SIGNATURE"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    UNKNOWN_SIGNER_KEY = "UNKNOWN_SIGNER_KEY"
    SIGNER_KEY_MISMATCH = "SIGNER_KEY_MISMATCH"


class VerificationFailure(BaseModel):
    """Structured record of an individual verification failure."""

    model_config = ConfigDict(frozen=True)

    code: FailureCode = Field(..., description="Machine-readable failure code")
    message: str = Field(..., description="Human-readable explanation of the failure")
    layer: str = Field(..., description="Verification layer where failure occurred (INPUT, RECORD, CHAIN, SIGNATURE, KEY)")
    field: Optional[str] = Field(None, description="Record field associated with the failure, if applicable")
    sequence_number: Optional[int] = Field(None, description="Sequence number of the failing record, if applicable")


# =====================================================================
# Machine-Readable Verification Evidence
# =====================================================================


class VerificationEvidence(BaseModel):
    """Diagnostic machine-readable evidence collected during verification."""

    model_config = ConfigDict(frozen=True)

    project_id: Optional[str] = None
    sequence_number: Optional[int] = None
    expected_sequence: Optional[int] = None
    nonce: Optional[str] = None
    stored_record_hash: Optional[str] = None
    computed_record_hash: Optional[str] = None
    stored_previous_record_hash: Optional[str] = None
    expected_previous_record_hash: Optional[str] = None
    signer_key_id: Optional[str] = None
    signature_present: bool = False
    key_status: Optional[str] = None
    key_is_active: Optional[bool] = None
    details: Dict[str, Any] = Field(default_factory=dict)


# =====================================================================
# Unified Verification Results
# =====================================================================


class UnifiedVerificationResult(BaseModel):
    """Complete diagnostic outcome of a single provenance record verification.

    Distinguishes:
      - overall_valid: True only when all applicable layers pass.
      - record_valid: True if canonical payload recomputed hash matches stored record_hash.
      - chain_valid: True if chain linkage checks pass (None if record-only verification).
      - signature_valid: True if signature is cryptographically valid (None if unsigned).
      - signature_present: Whether a digital signature is present on the record.
      - signer_key_id: 64-character lowercase hex ID of the signer key.
      - key_status: Lifecycle status of the signer key (ACTIVE, ROTATED, REVOKED, EXPIRED).
      - key_is_active: Whether the key is currently active (decoupled from validity).
      - failures: Structured collection of all failures detected.
      - warnings: Non-fatal diagnostic warnings (e.g. clock anomalies).
      - evidence: Machine-readable evidence for findings generation.
    """

    model_config = ConfigDict(frozen=True)

    overall_valid: bool = Field(..., description="True if all applicable checks pass")
    record_valid: bool = Field(..., description="True if canonical record hash matches")
    chain_valid: Optional[bool] = Field(None, description="True if chain checks pass, None if record-only")
    signature_valid: Optional[bool] = Field(None, description="True if signature valid, None if unsigned")
    signature_present: bool = Field(default=False, description="Whether a digital signature is present on the record")
    signer_key_id: Optional[str] = Field(None, description="Identifier of signer key")
    key_status: Optional[KeyStatus] = Field(None, description="Lifecycle status of verification key if resolved")
    key_is_active: Optional[bool] = Field(None, description="Whether signer key is currently ACTIVE")
    failures: List[VerificationFailure] = Field(default_factory=list, description="Structured collection of failures")
    warnings: List[str] = Field(default_factory=list, description="Non-fatal warnings")
    evidence: Optional[VerificationEvidence] = Field(None, description="Machine-readable evidence")

    @property
    def is_valid(self) -> bool:
        """Alias for overall_valid for backward compatibility."""
        return self.overall_valid

    @property
    def has_failures(self) -> bool:
        """True if any failure was recorded."""
        return len(self.failures) > 0

    @property
    def failure_codes(self) -> List[FailureCode]:
        """List of all unique failure codes recorded."""
        return [f.code for f in self.failures]


class UnifiedChainVerificationResult(BaseModel):
    """Complete diagnostic outcome of a full provenance chain verification.

    Evaluates genesis integrity, sequential monotonicity, previous-record hash
    continuity, nonce uniqueness, individual record hash integrity, and digital
    signatures across all records in the chain.
    """

    model_config = ConfigDict(frozen=True)

    overall_valid: bool = Field(..., description="True if all records and chain links are valid")
    chain_valid: bool = Field(..., description="True if chain structure, genesis, and links are intact")
    records_verified_count: int = Field(default=0, description="Total records inspected")
    signatures_verified_count: int = Field(default=0, description="Total valid signatures verified")
    failed_sequence_number: Optional[int] = Field(None, description="First sequence number where failure occurred")
    failures: List[VerificationFailure] = Field(default_factory=list, description="All failures encountered")
    warnings: List[str] = Field(default_factory=list, description="All warnings encountered")
    record_results: List[UnifiedVerificationResult] = Field(default_factory=list, description="Per-record results")
    evidence: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Chain-wide diagnostic evidence")

    @property
    def is_valid(self) -> bool:
        """Alias for overall_valid for backward compatibility."""
        return self.overall_valid

    @property
    def has_failures(self) -> bool:
        """True if any failure was recorded."""
        return len(self.failures) > 0

    @property
    def failure_codes(self) -> List[FailureCode]:
        """List of all unique failure codes recorded."""
        return [f.code for f in self.failures]


# =====================================================================
# Single-Record Verification Engine
# =====================================================================


def verify_record(
    record: Union[ChainRecord, Dict[str, Any]],
    key_manager: Optional[KeyManager] = None,
    public_key: Optional[Union[ed25519.Ed25519PublicKey, Ed25519KeyHandle]] = None,
    allow_unsigned: bool = True,
    expected_project_id: Optional[str] = None,
    expected_sequence: Optional[int] = None,
    expected_previous_record_hash: Optional[str] = None,
) -> UnifiedVerificationResult:
    """Verify a single provenance record across all applicable verification layers.

    Evaluates:
      - Layer A: Input validation (fields, formats, sequence, nonces, hashes).
      - Layer B: Canonical record hash integrity (recomputed SHA-256 JCS digest).
      - Layer D: Digital signature verification (if signature is present).
      - Layer E: Signer key resolution and lifecycle status reporting.

    Preserves multiple failures: If a record has both a hash mismatch AND an invalid
    signature, BOTH failures are collected in the result.

    Args:
        record: ChainRecord instance or dictionary containing provenance record fields.
        key_manager: Optional KeyManager to resolve signer public key from signer_key_id.
        public_key: Optional Ed25519PublicKey or Ed25519KeyHandle supplied directly.
        allow_unsigned: If False, unsigned records produce a MISSING_SIGNATURE failure.
        expected_project_id: Optional expected project ID to check against.
        expected_sequence: Optional expected sequence number to check against.
        expected_previous_record_hash: Optional expected previous record hash.

    Returns:
        UnifiedVerificationResult detailing all verification outcomes.
    """
    failures: List[VerificationFailure] = []
    warnings: List[str] = []

    # -------------------------------------------------------------
    # Layer A: Extract & Validate Record Input Fields
    # -------------------------------------------------------------
    data: Dict[str, Any]
    if isinstance(record, ChainRecord):
        data = record.model_dump()
    elif isinstance(record, dict):
        data = dict(record)
    else:
        failures.append(
            VerificationFailure(
                code=FailureCode.MALFORMED_INPUT,
                layer="INPUT",
                message=f"Unsupported record type: '{type(record).__name__}'. Expected ChainRecord or dict.",
            )
        )
        return UnifiedVerificationResult(
            overall_valid=False,
            record_valid=False,
            chain_valid=None,
            signature_valid=None,
            signature_present=False,
            failures=failures,
            warnings=warnings,
        )

    # Required field presence check
    required_fields = [
        "project_id",
        "record_type",
        "actor",
        "action",
        "timestamp",
        "sequence_number",
        "nonce",
        "previous_record_hash",
        "record_hash",
        "signer_key_id",
    ]
    missing_fields = [f for f in required_fields if f not in data or data[f] is None]
    if missing_fields:
        for mf in missing_fields:
            failures.append(
                VerificationFailure(
                    code=FailureCode.MALFORMED_INPUT,
                    layer="INPUT",
                    field=mf,
                    message=f"Missing required provenance field: '{mf}'.",
                )
            )

    project_id = str(data.get("project_id", ""))
    record_type = str(data.get("record_type", ""))
    actor = str(data.get("actor", ""))
    action = str(data.get("action", ""))
    timestamp = str(data.get("timestamp", ""))
    sequence_number = data.get("sequence_number")
    nonce = data.get("nonce")
    previous_record_hash = data.get("previous_record_hash")
    record_hash = data.get("record_hash")
    signer_key_id = data.get("signer_key_id")
    target_type = data.get("target_type")
    target_id = data.get("target_id")
    input_hash = data.get("input_hash")
    output_hash = data.get("output_hash")
    model_id = data.get("model_id")
    model_weight_digest = data.get("model_weight_digest")
    config_hash = data.get("config_hash")
    metadata_json = data.get("metadata_json")
    schema_version = str(data.get("schema_version", CANONICAL_SCHEMA_VERSION))
    signature = data.get("signature")

    seq_int: Optional[int] = None
    if sequence_number is not None:
        if isinstance(sequence_number, int) and sequence_number >= 0:
            seq_int = sequence_number
        else:
            failures.append(
                VerificationFailure(
                    code=FailureCode.INVALID_SEQUENCE,
                    layer="INPUT",
                    field="sequence_number",
                    message=f"Sequence number must be a non-negative integer, got '{sequence_number}'.",
                )
            )

    if expected_sequence is not None and seq_int is not None and seq_int != expected_sequence:
        failures.append(
            VerificationFailure(
                code=FailureCode.SEQUENCE_VIOLATION,
                layer="CHAIN",
                field="sequence_number",
                sequence_number=seq_int,
                message=f"Sequence mismatch: expected {expected_sequence}, got {seq_int}.",
            )
        )

    if expected_project_id is not None and project_id != expected_project_id:
        failures.append(
            VerificationFailure(
                code=FailureCode.PROJECT_MISMATCH,
                layer="INPUT",
                field="project_id",
                sequence_number=seq_int,
                message=f"Project mismatch: expected '{expected_project_id}', got '{project_id}'.",
            )
        )

    if nonce is not None:
        if not isinstance(nonce, str) or not is_valid_sha256(nonce):
            failures.append(
                VerificationFailure(
                    code=FailureCode.INVALID_NONCE,
                    layer="INPUT",
                    field="nonce",
                    sequence_number=seq_int,
                    message=f"Invalid nonce format: '{nonce}'. Must be a 64-character lowercase hex string.",
                )
            )

    if previous_record_hash is not None:
        if not isinstance(previous_record_hash, str) or not is_valid_sha256(previous_record_hash):
            failures.append(
                VerificationFailure(
                    code=FailureCode.INVALID_HASH_FORMAT,
                    layer="INPUT",
                    field="previous_record_hash",
                    sequence_number=seq_int,
                    message=f"Invalid previous_record_hash format: '{previous_record_hash}'.",
                )
            )
        elif (
            expected_previous_record_hash is not None
            and previous_record_hash != expected_previous_record_hash
        ):
            failures.append(
                VerificationFailure(
                    code=FailureCode.BROKEN_CHAIN,
                    layer="CHAIN",
                    field="previous_record_hash",
                    sequence_number=seq_int,
                    message=(
                        f"Previous record hash mismatch: expected '{expected_previous_record_hash}', "
                        f"got '{previous_record_hash}'."
                    ),
                )
            )

    if record_hash is not None:
        if not isinstance(record_hash, str) or not is_valid_sha256(record_hash):
            failures.append(
                VerificationFailure(
                    code=FailureCode.INVALID_HASH_FORMAT,
                    layer="INPUT",
                    field="record_hash",
                    sequence_number=seq_int,
                    message=f"Invalid record_hash format: '{record_hash}'.",
                )
            )

    if signer_key_id is not None:
        if not isinstance(signer_key_id, str) or not is_valid_sha256(signer_key_id):
            failures.append(
                VerificationFailure(
                    code=FailureCode.MALFORMED_INPUT,
                    layer="INPUT",
                    field="signer_key_id",
                    sequence_number=seq_int,
                    message=f"Invalid signer_key_id format: '{signer_key_id}'. Must be a 64-char lowercase hex string.",
                )
            )

    # -------------------------------------------------------------
    # Layer B: Canonical Record Hash Integrity
    # -------------------------------------------------------------
    record_valid = False
    computed_hash: Optional[str] = None

    if (
        not any(f.layer == "INPUT" for f in failures)
        and nonce is not None
        and seq_int is not None
        and previous_record_hash is not None
        and signer_key_id is not None
        and record_hash is not None
    ):
        try:
            computed_hash = hash_provenance_payload(
                record_type=record_type,
                project_id=project_id,
                actor=actor,
                action=action,
                sequence_number=seq_int,
                nonce=nonce,
                timestamp=timestamp,
                signer_key_id=signer_key_id,
                target_type=target_type,
                target_id=target_id,
                input_hash=input_hash,
                output_hash=output_hash,
                model_id=model_id,
                model_weight_digest=model_weight_digest,
                config_hash=config_hash,
                previous_record_hash=previous_record_hash,
                metadata_json=metadata_json,
                schema_version=schema_version,
            )
            if secure_compare_hashes(computed_hash, record_hash):
                record_valid = True
            else:
                record_valid = False
                failures.append(
                    VerificationFailure(
                        code=FailureCode.RECORD_HASH_MISMATCH,
                        layer="RECORD",
                        field="record_hash",
                        sequence_number=seq_int,
                        message=(
                            f"Record hash mismatch at sequence {seq_int}: stored '{record_hash}' "
                            f"!= recomputed canonical hash '{computed_hash}'."
                        ),
                    )
                )
        except Exception as err:
            record_valid = False
            failures.append(
                VerificationFailure(
                    code=FailureCode.RECORD_HASH_MISMATCH,
                    layer="RECORD",
                    field="record_hash",
                    sequence_number=seq_int,
                    message=f"Error recomputing canonical record hash: {err}",
                )
            )

    # -------------------------------------------------------------
    # Layers D & E: Digital Signature & Signer Key Lifecycle
    # -------------------------------------------------------------
    signature_present = signature is not None and len(str(signature).strip()) > 0
    signature_valid: Optional[bool] = None
    resolved_key_status: Optional[KeyStatus] = None
    key_is_active: Optional[bool] = None

    if signature_present:
        target_hash = record_hash or computed_hash
        if not target_hash or not is_valid_sha256(target_hash):
            signature_valid = False
            failures.append(
                VerificationFailure(
                    code=FailureCode.MALFORMED_SIGNATURE,
                    layer="SIGNATURE",
                    sequence_number=seq_int,
                    message="Cannot verify signature: record hash is missing or invalid.",
                )
            )
        else:
            sig_ver: Optional[SigVerificationResult] = None

            if public_key is not None:
                # Direct public key verification
                sig_ver = verify_hash_signature(
                    record_hash=target_hash,
                    signature=str(signature),
                    public_key=public_key,
                    signer_key_id=signer_key_id,
                )
            elif key_manager is not None and signer_key_id is not None:
                # Resolved via KeyManager
                sig_ver = verify_provenance_signature(
                    record_hash=target_hash,
                    signature=str(signature),
                    signer_key_id=signer_key_id,
                    key_manager=key_manager,
                )
            else:
                # Signature is present but no key or key manager provided
                signature_valid = False
                failures.append(
                    VerificationFailure(
                        code=FailureCode.UNKNOWN_SIGNER_KEY,
                        layer="SIGNATURE",
                        field="signer_key_id",
                        sequence_number=seq_int,
                        message=(
                            f"Record sequence {seq_int} contains a signature, but no KeyManager "
                            f"or public key was provided to verify it."
                        ),
                    )
                )

            if sig_ver is not None:
                resolved_key_status = sig_ver.key_status
                key_is_active = sig_ver.key_is_active

                if sig_ver.is_valid:
                    signature_valid = True
                else:
                    signature_valid = False
                    # Map signature status to FailureCode
                    mapped_code: FailureCode
                    if sig_ver.status == SigVerificationStatus.MALFORMED_SIGNATURE:
                        mapped_code = FailureCode.MALFORMED_SIGNATURE
                    elif sig_ver.status == SigVerificationStatus.UNKNOWN_SIGNER_KEY:
                        mapped_code = FailureCode.UNKNOWN_SIGNER_KEY
                    else:
                        mapped_code = FailureCode.INVALID_SIGNATURE

                    failures.append(
                        VerificationFailure(
                            code=mapped_code,
                            layer="SIGNATURE",
                            field="signature",
                            sequence_number=seq_int,
                            message=sig_ver.error_message or "Digital signature verification failed.",
                        )
                    )
    else:
        # Record is unsigned
        signature_valid = None
        if not allow_unsigned:
            failures.append(
                VerificationFailure(
                    code=FailureCode.MISSING_SIGNATURE,
                    layer="SIGNATURE",
                    field="signature",
                    sequence_number=seq_int,
                    message=f"Record sequence {seq_int} is unsigned, but unsigned records are disallowed.",
                )
            )

    # -------------------------------------------------------------
    # Overall Outcome & Machine-Readable Evidence
    # -------------------------------------------------------------
    overall_valid = (
        len(failures) == 0
        and record_valid
        and (signature_valid is not False)
    )

    evidence = VerificationEvidence(
        project_id=project_id if project_id else None,
        sequence_number=seq_int,
        expected_sequence=expected_sequence,
        nonce=nonce if isinstance(nonce, str) else None,
        stored_record_hash=record_hash if isinstance(record_hash, str) else None,
        computed_record_hash=computed_hash,
        stored_previous_record_hash=previous_record_hash if isinstance(previous_record_hash, str) else None,
        expected_previous_record_hash=expected_previous_record_hash,
        signer_key_id=signer_key_id if isinstance(signer_key_id, str) else None,
        signature_present=signature_present,
        key_status=resolved_key_status.value if resolved_key_status else None,
        key_is_active=key_is_active,
    )

    return UnifiedVerificationResult(
        overall_valid=overall_valid,
        record_valid=record_valid,
        chain_valid=None,
        signature_valid=signature_valid,
        signature_present=signature_present,
        signer_key_id=signer_key_id if isinstance(signer_key_id, str) else None,
        key_status=resolved_key_status,
        key_is_active=key_is_active,
        failures=failures,
        warnings=warnings,
        evidence=evidence,
    )


# =====================================================================
# Full Provenance Chain Verification Engine
# =====================================================================


def verify_provenance_chain(
    records: Sequence[Union[ChainRecord, Dict[str, Any]]],
    key_manager: Optional[KeyManager] = None,
    expected_project_id: Optional[str] = None,
    allow_unsigned: bool = True,
) -> UnifiedChainVerificationResult:
    """Verify an entire hash-linked provenance chain with detailed multi-layer diagnostics.

    Verifies:
      1. Non-empty chain sequence.
      2. Project consistency across every record.
      3. Genesis record anchor at sequence 0 (`previous_record_hash = "0" * 64`, action `genesis`).
      4. Gapless monotonic sequence ordering (`0, 1, 2, 3, ...`).
      5. Per-record cryptographic nonces (256-bit lowercase hex, project-unique).
      6. Continuous previous-record hash linkage (`record[N].previous_record_hash == record[N-1].record_hash`).
      7. Recomputed canonical SHA-256 record hash integrity for every record.
      8. Replay detection (no duplicate nonces, sequences, or record hashes).
      9. Ed25519 digital signatures if present, resolving keys via `key_manager`.
      10. Key lifecycle status reporting (ACTIVE, ROTATED, REVOKED, EXPIRED).

    Args:
        records: Sequence of ChainRecord instances or record dictionaries.
        key_manager: Optional KeyManager to resolve signer public keys.
        expected_project_id: Optional project ID to enforce.
        allow_unsigned: Whether unsigned records are permitted without producing an error.

    Returns:
        UnifiedChainVerificationResult containing comprehensive diagnostics.
    """
    if not records or len(records) == 0:
        return UnifiedChainVerificationResult(
            overall_valid=False,
            chain_valid=False,
            records_verified_count=0,
            signatures_verified_count=0,
            failed_sequence_number=None,
            failures=[
                VerificationFailure(
                    code=FailureCode.BROKEN_CHAIN,
                    layer="CHAIN",
                    message="Provenance chain is empty.",
                )
            ],
            warnings=[],
            record_results=[],
        )

    # 1. Resolve project ID
    first_record = records[0]
    first_project = (
        first_record.project_id
        if isinstance(first_record, ChainRecord)
        else str(first_record.get("project_id", ""))
    )
    target_project_id = expected_project_id or first_project

    if not target_project_id:
        return UnifiedChainVerificationResult(
            overall_valid=False,
            chain_valid=False,
            records_verified_count=0,
            signatures_verified_count=0,
            failed_sequence_number=None,
            failures=[
                VerificationFailure(
                    code=FailureCode.INVALID_PROJECT,
                    layer="CHAIN",
                    message="Missing project_id in provenance chain.",
                )
            ],
            warnings=[],
            record_results=[],
        )

    # 2. Check Genesis record (index 0, sequence 0)
    genesis_rec = records[0]
    genesis_seq = (
        genesis_rec.sequence_number
        if isinstance(genesis_rec, ChainRecord)
        else genesis_rec.get("sequence_number")
    )
    genesis_prev_hash = (
        genesis_rec.previous_record_hash
        if isinstance(genesis_rec, ChainRecord)
        else genesis_rec.get("previous_record_hash")
    )
    genesis_proj = (
        genesis_rec.project_id
        if isinstance(genesis_rec, ChainRecord)
        else genesis_rec.get("project_id")
    )

    failures: List[VerificationFailure] = []
    warnings: List[str] = []
    record_results: List[UnifiedVerificationResult] = []
    first_failed_seq: Optional[int] = None

    if genesis_seq != GENESIS_SEQUENCE_NUMBER:
        failures.append(
            VerificationFailure(
                code=FailureCode.GENESIS_INVALID,
                layer="CHAIN",
                field="sequence_number",
                sequence_number=genesis_seq,
                message=(
                    f"Genesis record must have sequence {GENESIS_SEQUENCE_NUMBER}, "
                    f"got {genesis_seq}."
                ),
            )
        )
        if first_failed_seq is None:
            first_failed_seq = genesis_seq

    if genesis_proj != target_project_id:
        failures.append(
            VerificationFailure(
                code=FailureCode.PROJECT_MISMATCH,
                layer="CHAIN",
                field="project_id",
                sequence_number=genesis_seq,
                message=f"Genesis project '{genesis_proj}' != target project '{target_project_id}'.",
            )
        )
        if first_failed_seq is None:
            first_failed_seq = genesis_seq

    if genesis_prev_hash != GENESIS_PREVIOUS_RECORD_HASH:
        failures.append(
            VerificationFailure(
                code=FailureCode.GENESIS_INVALID,
                layer="CHAIN",
                field="previous_record_hash",
                sequence_number=genesis_seq,
                message=(
                    f"Genesis previous_record_hash mismatch: expected '{GENESIS_PREVIOUS_RECORD_HASH}', "
                    f"got '{genesis_prev_hash}'."
                ),
            )
        )
        if first_failed_seq is None:
            first_failed_seq = genesis_seq

    # 3. Iterate through chain records, verifying individually and linking
    seen_nonces: Set[str] = set()
    seen_hashes: Set[str] = set()
    seen_sequences: Set[int] = set()
    signatures_verified = 0

    for i, current in enumerate(records):
        cur_dict = current.model_dump() if isinstance(current, ChainRecord) else dict(current)
        cur_seq = cur_dict.get("sequence_number")
        cur_nonce = cur_dict.get("nonce")
        cur_hash = cur_dict.get("record_hash")
        cur_prev_hash = cur_dict.get("previous_record_hash")
        cur_proj = cur_dict.get("project_id")

        expected_seq = i
        expected_prev_hash = (
            GENESIS_PREVIOUS_RECORD_HASH
            if i == 0
            else (
                records[i - 1].record_hash
                if isinstance(records[i - 1], ChainRecord)
                else records[i - 1].get("record_hash")
            )
        )

        # Cross-record chain validations
        if cur_proj != target_project_id:
            failures.append(
                VerificationFailure(
                    code=FailureCode.PROJECT_MISMATCH,
                    layer="CHAIN",
                    field="project_id",
                    sequence_number=cur_seq,
                    message=(
                        f"Project mismatch at sequence {cur_seq}: record project '{cur_proj}' "
                        f"!= target project '{target_project_id}'."
                    ),
                )
            )
            if first_failed_seq is None:
                first_failed_seq = cur_seq

        if cur_seq != expected_seq:
            mapped_code = FailureCode.SEQUENCE_VIOLATION
            if cur_seq in seen_sequences:
                mapped_code = FailureCode.DUPLICATE_SEQUENCE
            elif isinstance(cur_seq, int) and cur_seq > expected_seq:
                mapped_code = FailureCode.SEQUENCE_GAP

            failures.append(
                VerificationFailure(
                    code=mapped_code,
                    layer="CHAIN",
                    field="sequence_number",
                    sequence_number=cur_seq,
                    message=(
                        f"Sequence violation at index {i}: expected sequence {expected_seq}, "
                        f"got {cur_seq}."
                    ),
                )
            )
            if first_failed_seq is None:
                first_failed_seq = cur_seq

        if isinstance(cur_seq, int):
            seen_sequences.add(cur_seq)

        # Replay checks: nonce uniqueness
        if cur_nonce in seen_nonces:
            failures.append(
                VerificationFailure(
                    code=FailureCode.DUPLICATE_NONCE,
                    layer="CHAIN",
                    field="nonce",
                    sequence_number=cur_seq,
                    message=f"Replay detected: duplicate nonce '{cur_nonce}' at sequence {cur_seq}.",
                )
            )
            if first_failed_seq is None:
                first_failed_seq = cur_seq
        elif isinstance(cur_nonce, str):
            seen_nonces.add(cur_nonce)

        # Chain hash linkage check
        if i > 0 and cur_prev_hash != expected_prev_hash:
            failures.append(
                VerificationFailure(
                    code=FailureCode.BROKEN_CHAIN,
                    layer="CHAIN",
                    field="previous_record_hash",
                    sequence_number=cur_seq,
                    message=(
                        f"Broken chain at sequence {cur_seq}: previous_record_hash '{cur_prev_hash}' "
                        f"!= preceding record_hash '{expected_prev_hash}'."
                    ),
                )
            )
            if first_failed_seq is None:
                first_failed_seq = cur_seq

        # Replay check: record hash uniqueness
        if cur_hash in seen_hashes:
            failures.append(
                VerificationFailure(
                    code=FailureCode.DUPLICATE_RECORD,
                    layer="CHAIN",
                    field="record_hash",
                    sequence_number=cur_seq,
                    message=f"Replay detected: duplicate record hash '{cur_hash}' at sequence {cur_seq}.",
                )
            )
            if first_failed_seq is None:
                first_failed_seq = cur_seq
        elif isinstance(cur_hash, str):
            seen_hashes.add(cur_hash)

        # Single-record verification for payload integrity, schema, and signature
        rec_res = verify_record(
            record=current,
            key_manager=key_manager,
            allow_unsigned=allow_unsigned,
            expected_project_id=target_project_id,
            expected_sequence=expected_seq,
            expected_previous_record_hash=expected_prev_hash,
        )
        record_results.append(rec_res)

        if rec_res.signature_valid is True:
            signatures_verified += 1

        if not rec_res.overall_valid:
            if first_failed_seq is None:
                first_failed_seq = cur_seq
            for rf in rec_res.failures:
                # Avoid exact duplicate failure records
                if rf not in failures:
                    failures.append(rf)

        warnings.extend(rec_res.warnings)

        # Clock anomaly warning
        if i > 0:
            prev_dict = records[i - 1].model_dump() if isinstance(records[i - 1], ChainRecord) else dict(records[i - 1])
            prev_ts = prev_dict.get("timestamp")
            cur_ts = cur_dict.get("timestamp")
            if prev_ts and cur_ts and str(cur_ts) < str(prev_ts):
                warn_msg = (
                    f"Clock anomaly detected at sequence {cur_seq}: "
                    f"timestamp '{cur_ts}' is earlier than preceding record '{prev_ts}'."
                )
                if warn_msg not in warnings:
                    warnings.append(warn_msg)

    chain_valid = len(failures) == 0
    overall_valid = chain_valid and all(r.overall_valid for r in record_results)

    return UnifiedChainVerificationResult(
        overall_valid=overall_valid,
        chain_valid=chain_valid,
        records_verified_count=len(records),
        signatures_verified_count=signatures_verified,
        failed_sequence_number=first_failed_seq if not overall_valid else None,
        failures=failures,
        warnings=warnings,
        record_results=record_results,
        evidence={
            "project_id": target_project_id,
            "chain_length": len(records),
            "signatures_verified": signatures_verified,
            "unique_nonces_count": len(seen_nonces),
            "unique_hashes_count": len(seen_hashes),
        },
    )


# =====================================================================
# Unified Verification Engine Class
# =====================================================================


class ProvenanceVerificationEngine:
    """Configurable unified verification engine for provenance records and chains.

    Encapsulates verification rules and optional KeyManager resolution for convenient
    caller usage.
    """

    def __init__(
        self,
        key_manager: Optional[KeyManager] = None,
        allow_unsigned: bool = True,
    ) -> None:
        """Initialize the verification engine.

        Args:
            key_manager: Optional KeyManager for resolving signer public keys.
            allow_unsigned: Whether unsigned records are permitted.
        """
        self.key_manager = key_manager
        self.allow_unsigned = allow_unsigned

    def verify_record(
        self,
        record: Union[ChainRecord, Dict[str, Any]],
        public_key: Optional[Union[ed25519.Ed25519PublicKey, Ed25519KeyHandle]] = None,
        expected_project_id: Optional[str] = None,
        expected_sequence: Optional[int] = None,
        expected_previous_record_hash: Optional[str] = None,
    ) -> UnifiedVerificationResult:
        """Verify a single provenance record."""
        return verify_record(
            record=record,
            key_manager=self.key_manager,
            public_key=public_key,
            allow_unsigned=self.allow_unsigned,
            expected_project_id=expected_project_id,
            expected_sequence=expected_sequence,
            expected_previous_record_hash=expected_previous_record_hash,
        )

    def verify_chain(
        self,
        records: Sequence[Union[ChainRecord, Dict[str, Any]]],
        expected_project_id: Optional[str] = None,
    ) -> UnifiedChainVerificationResult:
        """Verify an entire hash-linked provenance chain."""
        return verify_provenance_chain(
            records=records,
            key_manager=self.key_manager,
            expected_project_id=expected_project_id,
            allow_unsigned=self.allow_unsigned,
        )
