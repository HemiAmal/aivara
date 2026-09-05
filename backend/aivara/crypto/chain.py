"""Nonce, Sequence, and Hash-Linked Provenance Chain Engine for AIVARA (Phase 4.6).

Provides:
  - Cryptographically secure 256-bit nonce generation via CSPRNG.
  - Per-project monotonic sequence number management (genesis = 0, normal = 1, 2, 3...).
  - Deterministic genesis state anchor per project.
  - Previous-record hash linking protected under canonical SHA-256 record hashes.
  - Replay detection for duplicate nonces, sequences, and record hashes.
  - Independent crypto-layer ChainRecord model.
  - In-memory ProvenanceChain builder and verification engine.
  - Seamless Phase 4.5 digital signature verification when signatures are present.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union

from pydantic import BaseModel, ConfigDict, Field

from aivara.core.exceptions import AivaraException
from aivara.crypto.canonical import CANONICAL_SCHEMA_VERSION, format_canonical_datetime
from aivara.crypto.hashing import (
    hash_provenance_payload,
    is_valid_sha256,
    sha256_text,
)
from aivara.crypto.keys import (
    Ed25519KeyHandle,
    KeyManager,
    validate_key_id,
)
from aivara.crypto.signing import (
    SignatureResult,
    VerificationResult,
    VerificationStatus,
    sign_hash,
    verify_hash_signature,
)

# =====================================================================
# Constants
# =====================================================================

NONCE_BYTES_LEN: int = 32
NONCE_HEX_LEN: int = 64

GENESIS_SEQUENCE_NUMBER: int = 0
FIRST_NORMAL_SEQUENCE_NUMBER: int = 1

GENESIS_PREVIOUS_RECORD_HASH: str = "0" * 64
GENESIS_RECORD_TYPE: str = "GENESIS"
GENESIS_ACTION: str = "CHAIN_INITIALIZATION"
GENESIS_ACTOR: str = "AIVARA_SYSTEM"
GENESIS_TIMESTAMP: str = "1970-01-01T00:00:00Z"
GENESIS_SIGNER_KEY_ID: str = "0" * 64


# =====================================================================
# Exceptions
# =====================================================================


class ChainError(AivaraException, ValueError):
    """Base exception for all chain construction, verification, and replay errors."""

    def __init__(
        self,
        message: str,
        code: str = "CHAIN_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class InvalidProjectError(ChainError):
    """Raised when a record belongs to a different project than the chain."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_PROJECT", details=details)


class InvalidSequenceError(ChainError):
    """Raised when a sequence number is invalid (e.g. negative or non-integer)."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_SEQUENCE", details=details)


class SequenceGapError(ChainError):
    """Raised when a gap/jump is detected in sequence numbering."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="SEQUENCE_GAP", details=details)


class DuplicateSequenceError(ChainError):
    """Raised when an already-issued sequence number is reused."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="DUPLICATE_SEQUENCE", details=details)


class InvalidNonceError(ChainError):
    """Raised when a nonce fails 256-bit lowercase hexadecimal validation."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_NONCE", details=details)


class DuplicateNonceError(ChainError):
    """Raised when a nonce is reused within the same project chain."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="DUPLICATE_NONCE", details=details)


class InvalidPreviousHashError(ChainError):
    """Raised when previous_record_hash does not match the preceding record's hash."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_PREVIOUS_HASH", details=details)


class BrokenChainError(ChainError):
    """Raised when a chain fails structural integrity or hash continuity."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="BROKEN_CHAIN", details=details)


class RecordHashMismatchError(ChainError):
    """Raised when a record's recomputed canonical hash does not match its record_hash."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="RECORD_HASH_MISMATCH", details=details)


class DuplicateRecordError(ChainError):
    """Raised when a record with an identical record_hash is submitted again."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="DUPLICATE_RECORD", details=details)


class ReplayDetectedError(ChainError):
    """Raised when a replayed record is detected (duplicate nonce, sequence, or hash)."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="REPLAY_DETECTED", details=details)


# =====================================================================
# Nonce Generation & Validation
# =====================================================================


def generate_nonce() -> str:
    """Generate a cryptographically secure 256-bit (32-byte) random nonce.

    Uses Python's `secrets` module (OS-level CSPRNG) to prevent predictability.

    Returns:
        64-character lowercase hexadecimal string.
    """
    return secrets.token_hex(NONCE_BYTES_LEN).lower()


def validate_nonce(nonce: str) -> None:
    """Validate that a nonce is strictly a 64-character lowercase hexadecimal string.

    Args:
        nonce: Nonce string to validate.

    Raises:
        InvalidNonceError: If nonce is not a 64-char lowercase hex string.
    """
    if not isinstance(nonce, str) or not is_valid_sha256(nonce):
        raise InvalidNonceError(
            f"Invalid nonce: '{nonce}'. Must be a 64-character lowercase hex string."
        )


# =====================================================================
# Genesis Helper
# =====================================================================


def compute_genesis_nonce(project_id: str) -> str:
    """Derive a deterministic 256-bit nonce for a project's genesis state.

    Args:
        project_id: Project identifier string.

    Returns:
        64-character lowercase hex digest string.
    """
    return sha256_text(f"AIVARA_GENESIS_NONCE:{project_id}")


# =====================================================================
# Chain Record Model
# =====================================================================


class ChainRecord(BaseModel):
    """Self-contained cryptographic proof-layer provenance record.

    Encapsulates all protected canonical fields, hash linkage, and optional
    digital signature. Independent of database or ORM structures.
    """

    model_config = ConfigDict(frozen=True)

    project_id: str = Field(..., description="Project identifier")
    sequence_number: int = Field(..., ge=0, description="Monotonic sequence number (0=genesis)")
    nonce: str = Field(..., description="256-bit cryptographic nonce (64 hex characters)")
    previous_record_hash: str = Field(..., description="SHA-256 hash of preceding record (64 hex chars)")
    record_hash: str = Field(..., description="SHA-256 digest of canonical protected fields (64 hex chars)")
    signer_key_id: str = Field(..., description="64-character lowercase hex ID of the signer key")

    # Protected payload fields required for deterministic re-canonicalization
    record_type: str = Field(..., description="Provenance event category")
    actor: str = Field(..., description="Actor identity")
    action: str = Field(..., description="Action performed")
    timestamp: str = Field(..., description="UTC ISO 8601 timestamp string")
    target_type: Optional[str] = Field(None, description="Target asset type")
    target_id: Optional[str] = Field(None, description="Target asset identifier")
    input_hash: Optional[str] = Field(None, description="Input SHA-256 hash")
    output_hash: Optional[str] = Field(None, description="Output SHA-256 hash")
    model_id: Optional[str] = Field(None, description="Model identifier")
    model_weight_digest: Optional[str] = Field(None, description="Model weight digest")
    config_hash: Optional[str] = Field(None, description="Configuration hash")
    metadata_json: Optional[Dict[str, Any]] = Field(None, description="Supplementary metadata")
    schema_version: str = Field(default=CANONICAL_SCHEMA_VERSION, description="Canonical schema version")

    # Optional digital signature from Phase 4.5
    signature: Optional[str] = Field(None, description="Base64-encoded Ed25519 signature (88 chars)")

    @property
    def is_genesis(self) -> bool:
        """Whether this record represents the genesis record (sequence 0)."""
        return self.sequence_number == GENESIS_SEQUENCE_NUMBER

    def compute_record_hash(self) -> str:
        """Recompute the deterministic SHA-256 record hash from protected fields."""
        return hash_provenance_payload(
            record_type=self.record_type,
            project_id=self.project_id,
            actor=self.actor,
            action=self.action,
            sequence_number=self.sequence_number,
            nonce=self.nonce,
            timestamp=self.timestamp,
            signer_key_id=self.signer_key_id,
            target_type=self.target_type,
            target_id=self.target_id,
            input_hash=self.input_hash,
            output_hash=self.output_hash,
            model_id=self.model_id,
            model_weight_digest=self.model_weight_digest,
            config_hash=self.config_hash,
            previous_record_hash=self.previous_record_hash,
            metadata_json=self.metadata_json,
            schema_version=self.schema_version,
        )

    def verify_record_hash(self) -> bool:
        """Verify that the stored record_hash matches the recomputed canonical hash."""
        return self.compute_record_hash() == self.record_hash


# =====================================================================
# Chain Verification Models & Statuses
# =====================================================================


class ChainVerificationStatus(str, Enum):
    """Status outcomes for provenance chain verification."""

    VALID = "VALID"
    BROKEN_CHAIN = "BROKEN_CHAIN"
    SEQUENCE_VIOLATION = "SEQUENCE_VIOLATION"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    HASH_MISMATCH = "HASH_MISMATCH"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    INVALID_STRUCTURE = "INVALID_STRUCTURE"


class ChainVerificationResult(BaseModel):
    """Complete diagnostic outcome of a provenance chain verification operation."""

    model_config = ConfigDict(frozen=True)

    is_valid: bool = Field(..., description="True if the entire chain is cryptographically valid and linked")
    status: ChainVerificationStatus = Field(..., description="Overall verification status")
    verified_records_count: int = Field(default=0, description="Total records inspected")
    failed_sequence_number: Optional[int] = Field(None, description="Sequence number where failure occurred")
    error_message: Optional[str] = Field(None, description="Diagnostic reason for verification failure")
    signatures_verified_count: int = Field(default=0, description="Count of digital signatures verified")


# =====================================================================
# Genesis Record Factory
# =====================================================================


def create_genesis_record(
    project_id: str,
    signer_key_id: Optional[str] = None,
) -> ChainRecord:
    """Deterministically create the genesis record (sequence 0) for a project.

    Args:
        project_id: Non-empty project identifier.
        signer_key_id: Optional signer key ID (defaults to GENESIS_SIGNER_KEY_ID).

    Returns:
        Deterministic ChainRecord representing genesis state.

    Raises:
        InvalidProjectError: If project_id is empty or invalid.
    """
    if not project_id or not isinstance(project_id, str) or len(project_id.strip()) == 0:
        raise InvalidProjectError("Project ID must be a non-empty string.")

    nonce = compute_genesis_nonce(project_id)
    key_id = signer_key_id or GENESIS_SIGNER_KEY_ID

    record_hash = hash_provenance_payload(
        record_type=GENESIS_RECORD_TYPE,
        project_id=project_id,
        actor=GENESIS_ACTOR,
        action=GENESIS_ACTION,
        sequence_number=GENESIS_SEQUENCE_NUMBER,
        nonce=nonce,
        timestamp=GENESIS_TIMESTAMP,
        signer_key_id=key_id,
        target_type=None,
        target_id=None,
        input_hash=None,
        output_hash=None,
        model_id=None,
        model_weight_digest=None,
        config_hash=None,
        previous_record_hash=GENESIS_PREVIOUS_RECORD_HASH,
        metadata_json={"chain_genesis": True},
        schema_version=CANONICAL_SCHEMA_VERSION,
    )

    return ChainRecord(
        project_id=project_id,
        sequence_number=GENESIS_SEQUENCE_NUMBER,
        nonce=nonce,
        previous_record_hash=GENESIS_PREVIOUS_RECORD_HASH,
        record_hash=record_hash,
        signer_key_id=key_id,
        record_type=GENESIS_RECORD_TYPE,
        actor=GENESIS_ACTOR,
        action=GENESIS_ACTION,
        timestamp=GENESIS_TIMESTAMP,
        target_type=None,
        target_id=None,
        input_hash=None,
        output_hash=None,
        model_id=None,
        model_weight_digest=None,
        config_hash=None,
        metadata_json={"chain_genesis": True},
        schema_version=CANONICAL_SCHEMA_VERSION,
        signature=None,
    )


# =====================================================================
# Provenance Chain Builder & Container
# =====================================================================


class ProvenanceChain:
    """In-memory cryptographic provenance chain builder and validator.

    Maintains an ordered, hash-linked sequence of provenance records for a project,
    enforcing replay resistance, monotonic sequence numbering, and hash linkage.
    """

    def __init__(
        self,
        project_id: str,
        key_handle: Optional[Ed25519KeyHandle] = None,
    ) -> None:
        """Initialize a new ProvenanceChain anchored with a deterministic genesis record.

        Args:
            project_id: Project identifier string.
            key_handle: Optional default active Ed25519KeyHandle for signing records.

        Raises:
            InvalidProjectError: If project_id is empty or invalid.
        """
        if not project_id or not isinstance(project_id, str) or len(project_id.strip()) == 0:
            raise InvalidProjectError("Project ID must be a non-empty string.")

        self._project_id = project_id
        self._default_key_handle = key_handle

        # Replay detection indexes
        self._seen_nonces: Set[str] = set()
        self._seen_hashes: Set[str] = set()
        self._seen_sequences: Set[int] = set()
        self._records: List[ChainRecord] = []

        # Initialize deterministic genesis record at sequence 0
        signer_key_id = key_handle.key_id if key_handle is not None else None
        genesis = create_genesis_record(project_id, signer_key_id=signer_key_id)

        self._records.append(genesis)
        self._seen_nonces.add(genesis.nonce)
        self._seen_hashes.add(genesis.record_hash)
        self._seen_sequences.add(genesis.sequence_number)

    @property
    def project_id(self) -> str:
        """Project identifier for this chain."""
        return self._project_id

    @property
    def records(self) -> List[ChainRecord]:
        """All records in the chain including genesis (ordered by sequence ASC)."""
        return list(self._records)

    @property
    def genesis_record(self) -> ChainRecord:
        """The root genesis record of this chain (sequence 0)."""
        return self._records[0]

    @property
    def latest_record(self) -> ChainRecord:
        """The most recent record in this chain."""
        return self._records[-1]

    @property
    def latest_sequence_number(self) -> int:
        """Sequence number of the most recent record."""
        return self.latest_record.sequence_number

    def __len__(self) -> int:
        """Total records in the chain including genesis."""
        return len(self._records)

    def append(
        self,
        record_type: str,
        action: str,
        actor: str,
        timestamp: Optional[Union[str, datetime]] = None,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        input_hash: Optional[str] = None,
        output_hash: Optional[str] = None,
        model_id: Optional[str] = None,
        model_weight_digest: Optional[str] = None,
        config_hash: Optional[str] = None,
        metadata_json: Optional[Dict[str, Any]] = None,
        nonce: Optional[str] = None,
        signer_key_id: Optional[str] = None,
        key_handle: Optional[Ed25519KeyHandle] = None,
        sign: bool = False,
        previous_record_hash: Optional[str] = None,
        sequence_number: Optional[int] = None,
    ) -> ChainRecord:
        """Construct, validate, hash, optionally sign, and append a new provenance record.

        Args:
            record_type: Category of provenance event.
            action: Specific action performed.
            actor: Identity of actor performing action.
            timestamp: UTC ISO 8601 string or datetime (defaults to current UTC time).
            target_type: Optional target entity type.
            target_id: Optional target entity ID.
            input_hash: Optional SHA-256 hex digest of inputs.
            output_hash: Optional SHA-256 hex digest of outputs.
            model_id: Optional model identifier.
            model_weight_digest: Optional model weight SHA-256 digest.
            config_hash: Optional config SHA-256 hash.
            metadata_json: Optional supplementary metadata dictionary.
            nonce: Optional 64-character lowercase hex nonce (generated via CSPRNG if None).
            signer_key_id: Optional signer key ID.
            key_handle: Optional Ed25519KeyHandle for signing.
            sign: Whether to digitally sign the record using key_handle.
            previous_record_hash: Optional expected previous hash (must match latest record hash).
            sequence_number: Optional expected sequence number (must match latest sequence + 1).

        Returns:
            The newly appended ChainRecord.

        Raises:
            InvalidSequenceError: If sequence number is negative.
            DuplicateSequenceError / ReplayDetectedError: If sequence number is reused.
            SequenceGapError: If sequence number creates a gap.
            InvalidNonceError: If nonce format is invalid.
            DuplicateNonceError / ReplayDetectedError: If nonce was already used in this chain.
            InvalidPreviousHashError / BrokenChainError: If previous hash does not match latest record.
            DuplicateRecordError / ReplayDetectedError: If computed record hash already exists in chain.
        """
        # 1. Monotonic sequence assignment and validation
        expected_seq = self.latest_sequence_number + 1
        if sequence_number is not None:
            if not isinstance(sequence_number, int) or sequence_number < 0:
                raise InvalidSequenceError(f"Sequence number must be a non-negative integer, got {sequence_number}.")
            if sequence_number in self._seen_sequences:
                raise DuplicateSequenceError(
                    f"Sequence number {sequence_number} has already been issued in project '{self._project_id}'."
                )
            if sequence_number < expected_seq:
                raise InvalidSequenceError(
                    f"Sequence number {sequence_number} is less than expected next sequence {expected_seq}."
                )
            if sequence_number > expected_seq:
                raise SequenceGapError(
                    f"Sequence gap detected: expected {expected_seq}, received {sequence_number}."
                )
            assigned_seq = sequence_number
        else:
            assigned_seq = expected_seq

        # 2. Nonce generation and uniqueness validation
        if nonce is not None:
            validate_nonce(nonce)
            assigned_nonce = nonce
        else:
            assigned_nonce = generate_nonce()

        if assigned_nonce in self._seen_nonces:
            raise DuplicateNonceError(
                f"Replay detected: nonce '{assigned_nonce}' has already been used in project '{self._project_id}'."
            )

        # 3. Previous record hash linkage validation
        expected_prev_hash = self.latest_record.record_hash
        if previous_record_hash is not None:
            if not isinstance(previous_record_hash, str) or not is_valid_sha256(previous_record_hash):
                raise InvalidPreviousHashError(f"Invalid previous_record_hash format: '{previous_record_hash}'.")
            if previous_record_hash != expected_prev_hash:
                raise InvalidPreviousHashError(
                    f"Hash link mismatch: expected '{expected_prev_hash}', got '{previous_record_hash}'."
                )
            assigned_prev_hash = previous_record_hash
        else:
            assigned_prev_hash = expected_prev_hash

        # 4. Resolve signer identity & signing key
        active_handle = key_handle or self._default_key_handle
        if signer_key_id is not None:
            validate_key_id(signer_key_id)
            assigned_signer_key_id = signer_key_id
        elif active_handle is not None:
            assigned_signer_key_id = active_handle.key_id
        else:
            assigned_signer_key_id = "0" * 64

        # 5. Format timestamp
        if timestamp is None:
            ts_str = format_canonical_datetime(datetime.now(timezone.utc))
        elif isinstance(timestamp, datetime):
            ts_str = format_canonical_datetime(timestamp)
        elif isinstance(timestamp, str):
            ts_str = timestamp
        else:
            raise ChainError(f"Unsupported timestamp type: {type(timestamp).__name__}.")

        # 6. Compute deterministic SHA-256 record hash over canonical protected payload
        computed_hash = hash_provenance_payload(
            record_type=record_type,
            project_id=self._project_id,
            actor=actor,
            action=action,
            sequence_number=assigned_seq,
            nonce=assigned_nonce,
            timestamp=ts_str,
            signer_key_id=assigned_signer_key_id,
            target_type=target_type,
            target_id=target_id,
            input_hash=input_hash,
            output_hash=output_hash,
            model_id=model_id,
            model_weight_digest=model_weight_digest,
            config_hash=config_hash,
            previous_record_hash=assigned_prev_hash,
            metadata_json=metadata_json,
            schema_version=CANONICAL_SCHEMA_VERSION,
        )

        # 7. Check for duplicate record hash
        if computed_hash in self._seen_hashes:
            raise DuplicateRecordError(
                f"Replay detected: record hash '{computed_hash}' already exists in project '{self._project_id}'."
            )

        # 8. Digital signing (Phase 4.5) if requested
        signature_b64: Optional[str] = None
        if sign or (key_handle is not None and signer_key_id is None):
            if active_handle is None:
                raise ChainError("Digital signing was requested, but no Ed25519KeyHandle was provided.")
            sig_result: SignatureResult = sign_hash(computed_hash, active_handle)
            signature_b64 = sig_result.signature
            assigned_signer_key_id = sig_result.signer_key_id

        # 9. Create immutable ChainRecord
        record = ChainRecord(
            project_id=self._project_id,
            sequence_number=assigned_seq,
            nonce=assigned_nonce,
            previous_record_hash=assigned_prev_hash,
            record_hash=computed_hash,
            signer_key_id=assigned_signer_key_id,
            record_type=record_type,
            actor=actor,
            action=action,
            timestamp=ts_str,
            target_type=target_type,
            target_id=target_id,
            input_hash=input_hash,
            output_hash=output_hash,
            model_id=model_id,
            model_weight_digest=model_weight_digest,
            config_hash=config_hash,
            metadata_json=metadata_json,
            schema_version=CANONICAL_SCHEMA_VERSION,
            signature=signature_b64,
        )

        # 10. Update chain state and replay indexes
        self._records.append(record)
        self._seen_nonces.add(record.nonce)
        self._seen_hashes.add(record.record_hash)
        self._seen_sequences.add(record.sequence_number)

        return record

    def append_record(self, record: ChainRecord) -> None:
        """Append an externally supplied ChainRecord into this chain with full validation.

        Args:
            record: Pre-constructed ChainRecord.

        Raises:
            InvalidProjectError: If record project_id does not match chain.
            DuplicateSequenceError / InvalidSequenceError / SequenceGapError: If sequence is invalid.
            DuplicateNonceError: If nonce was already used in this chain.
            InvalidPreviousHashError: If previous hash does not match latest record.
            RecordHashMismatchError: If record's canonical hash does not match its record_hash.
            DuplicateRecordError: If record hash already exists in chain.
        """
        if not isinstance(record, ChainRecord):
            raise ChainError(f"Expected ChainRecord, got {type(record).__name__}.")

        if record.project_id != self._project_id:
            raise InvalidProjectError(
                f"Record project '{record.project_id}' does not match chain project '{self._project_id}'."
            )

        # Sequence validation
        expected_seq = self.latest_sequence_number + 1
        if record.sequence_number in self._seen_sequences:
            raise DuplicateSequenceError(f"Sequence {record.sequence_number} already exists in chain.")
        if record.sequence_number < expected_seq:
            raise InvalidSequenceError(f"Sequence {record.sequence_number} is less than expected {expected_seq}.")
        if record.sequence_number > expected_seq:
            raise SequenceGapError(f"Sequence gap: expected {expected_seq}, got {record.sequence_number}.")

        # Nonce validation
        validate_nonce(record.nonce)
        if record.nonce in self._seen_nonces:
            raise DuplicateNonceError(f"Replay detected: duplicate nonce '{record.nonce}'.")

        # Previous record hash link validation
        if record.previous_record_hash != self.latest_record.record_hash:
            raise InvalidPreviousHashError(
                f"Hash link mismatch: expected '{self.latest_record.record_hash}', got '{record.previous_record_hash}'."
            )

        # Hash integrity validation
        if not record.verify_record_hash():
            raise RecordHashMismatchError(
                f"Record hash mismatch for sequence {record.sequence_number}: "
                f"stored '{record.record_hash}' != recomputed '{record.compute_record_hash()}'."
            )

        if record.record_hash in self._seen_hashes:
            raise DuplicateRecordError(f"Replay detected: duplicate record hash '{record.record_hash}'.")

        # Update chain state
        self._records.append(record)
        self._seen_nonces.add(record.nonce)
        self._seen_hashes.add(record.record_hash)
        self._seen_sequences.add(record.sequence_number)

    def verify(
        self,
        key_manager: Optional[KeyManager] = None,
    ) -> ChainVerificationResult:
        """Verify the integrity, ordering, hash linkage, and signatures of this chain."""
        return verify_chain(
            records=self._records,
            project_id=self._project_id,
            key_manager=key_manager,
        )


# =====================================================================
# Chain Verification Engine
# =====================================================================


def verify_chain(
    records: List[ChainRecord],
    project_id: Optional[str] = None,
    key_manager: Optional[KeyManager] = None,
) -> ChainVerificationResult:
    """Verify an ordered sequence of provenance records forming a chain.

    Checks:
      1. Chain non-empty and well-structured.
      2. Project consistency across all records.
      3. Genesis record starts at sequence 0 with defined anchor.
      4. Monotonic, strictly gapless sequence ordering (0, 1, 2, 3...).
      5. Nonce format validity and per-project uniqueness.
      6. Hash continuity: record[N].previous_record_hash == record[N-1].record_hash.
      7. Recomputed canonical SHA-256 record hash matches stored record_hash.
      8. If digital signature is present, verifies signature using key_manager or public key.

    Args:
        records: List of ChainRecord instances.
        project_id: Optional expected project ID to enforce.
        key_manager: Optional KeyManager to resolve signer public keys for signatures.

    Returns:
        ChainVerificationResult with detailed diagnostic status.
    """
    if not records or len(records) == 0:
        return ChainVerificationResult(
            is_valid=False,
            status=ChainVerificationStatus.INVALID_STRUCTURE,
            error_message="Chain is empty.",
        )

    # 1. Determine project ID
    target_project_id = project_id or records[0].project_id
    if not target_project_id:
        return ChainVerificationResult(
            is_valid=False,
            status=ChainVerificationStatus.INVALID_STRUCTURE,
            error_message="Missing project ID for chain verification.",
        )

    # 2. Check Genesis record (must be sequence 0)
    genesis = records[0]
    if genesis.sequence_number != GENESIS_SEQUENCE_NUMBER:
        return ChainVerificationResult(
            is_valid=False,
            status=ChainVerificationStatus.SEQUENCE_VIOLATION,
            failed_sequence_number=genesis.sequence_number,
            error_message=(
                f"Genesis record must have sequence {GENESIS_SEQUENCE_NUMBER}, "
                f"got {genesis.sequence_number}."
            ),
        )

    if genesis.project_id != target_project_id:
        return ChainVerificationResult(
            is_valid=False,
            status=ChainVerificationStatus.INVALID_STRUCTURE,
            failed_sequence_number=genesis.sequence_number,
            error_message=f"Genesis project '{genesis.project_id}' != expected '{target_project_id}'.",
        )

    if genesis.previous_record_hash != GENESIS_PREVIOUS_RECORD_HASH:
        return ChainVerificationResult(
            is_valid=False,
            status=ChainVerificationStatus.BROKEN_CHAIN,
            failed_sequence_number=genesis.sequence_number,
            error_message=(
                f"Genesis previous_record_hash mismatch: expected '{GENESIS_PREVIOUS_RECORD_HASH}', "
                f"got '{genesis.previous_record_hash}'."
            ),
        )

    # Verify genesis record's own canonical hash
    if not genesis.verify_record_hash():
        return ChainVerificationResult(
            is_valid=False,
            status=ChainVerificationStatus.HASH_MISMATCH,
            failed_sequence_number=genesis.sequence_number,
            error_message="Genesis record hash does not match canonical recomputed hash.",
        )

    seen_nonces: Set[str] = set()
    seen_hashes: Set[str] = set()
    signatures_verified = 0

    seen_nonces.add(genesis.nonce)
    seen_hashes.add(genesis.record_hash)

    # 3. Iterate through subsequent records and verify linkage
    for i in range(1, len(records)):
        record = records[i]
        expected_seq = i

        # Check project consistency
        if record.project_id != target_project_id:
            return ChainVerificationResult(
                is_valid=False,
                status=ChainVerificationStatus.INVALID_STRUCTURE,
                failed_sequence_number=record.sequence_number,
                error_message=(
                    f"Project mismatch at sequence {record.sequence_number}: "
                    f"record project '{record.project_id}' != expected '{target_project_id}'."
                ),
            )

        # Check sequence ordering
        if record.sequence_number != expected_seq:
            return ChainVerificationResult(
                is_valid=False,
                status=ChainVerificationStatus.SEQUENCE_VIOLATION,
                failed_sequence_number=record.sequence_number,
                error_message=(
                    f"Sequence violation at index {i}: expected sequence {expected_seq}, "
                    f"got {record.sequence_number}."
                ),
            )

        # Check nonce validity and uniqueness
        if not is_valid_sha256(record.nonce):
            return ChainVerificationResult(
                is_valid=False,
                status=ChainVerificationStatus.INVALID_STRUCTURE,
                failed_sequence_number=record.sequence_number,
                error_message=f"Invalid nonce format at sequence {record.sequence_number}.",
            )

        if record.nonce in seen_nonces:
            return ChainVerificationResult(
                is_valid=False,
                status=ChainVerificationStatus.REPLAY_DETECTED,
                failed_sequence_number=record.sequence_number,
                error_message=(
                    f"Replay detected: duplicate nonce '{record.nonce}' at sequence {record.sequence_number}."
                ),
            )
        seen_nonces.add(record.nonce)

        # Check previous record hash linkage
        preceding_record = records[i - 1]
        if record.previous_record_hash != preceding_record.record_hash:
            return ChainVerificationResult(
                is_valid=False,
                status=ChainVerificationStatus.BROKEN_CHAIN,
                failed_sequence_number=record.sequence_number,
                error_message=(
                    f"Broken chain at sequence {record.sequence_number}: previous_record_hash "
                    f"'{record.previous_record_hash}' != preceding record_hash '{preceding_record.record_hash}'."
                ),
            )

        # Check recomputed canonical hash matches stored hash
        if not record.verify_record_hash():
            return ChainVerificationResult(
                is_valid=False,
                status=ChainVerificationStatus.HASH_MISMATCH,
                failed_sequence_number=record.sequence_number,
                error_message=(
                    f"Record hash mismatch at sequence {record.sequence_number}: "
                    f"stored '{record.record_hash}' != recomputed '{record.compute_record_hash()}'."
                ),
            )

        if record.record_hash in seen_hashes:
            return ChainVerificationResult(
                is_valid=False,
                status=ChainVerificationStatus.REPLAY_DETECTED,
                failed_sequence_number=record.sequence_number,
                error_message=f"Duplicate record hash '{record.record_hash}' at sequence {record.sequence_number}.",
            )
        seen_hashes.add(record.record_hash)

        # Verify signature if present and key_manager provided
        if record.signature is not None and key_manager is not None:
            sig_res: VerificationResult = key_manager.load_key(
                key_id=record.signer_key_id,
                load_private=False,
                require_active=False,
            )
            ver = verify_hash_signature(
                record_hash=record.record_hash,
                signature=record.signature,
                public_key=sig_res,
                signer_key_id=record.signer_key_id,
            )
            if not ver.is_valid:
                return ChainVerificationResult(
                    is_valid=False,
                    status=ChainVerificationStatus.SIGNATURE_INVALID,
                    failed_sequence_number=record.sequence_number,
                    error_message=(
                        f"Digital signature verification failed for record sequence {record.sequence_number}: "
                        f"{ver.error_message}"
                    ),
                    signatures_verified_count=signatures_verified,
                )
            signatures_verified += 1

    return ChainVerificationResult(
        is_valid=True,
        status=ChainVerificationStatus.VALID,
        verified_records_count=len(records),
        signatures_verified_count=signatures_verified,
        error_message=None,
    )
