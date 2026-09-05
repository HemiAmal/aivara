"""AIVARA Cryptographic Tamper Detection Engine (Phase 4.10).

Translates cryptographic verification results and diagnostic evidence into
structured, human-readable tamper assessments. Sits downstream of `verification.py`
and strictly adheres to the principle:

    VERIFICATION FAILURE != AUTOMATIC PROOF OF MALICIOUS TAMPERING

Distinguishes:
  1. Cryptographic Integrity Violation Detected (`tampering_detected = True`)
     Deterministic mathematical evidence that a record, hash, chain link, or signature
     has been modified, substituted, or corrupted.
  2. Authenticity Cannot Be Established (`tampering_detected = False`)
     Signer key is unknown or signature is missing under strict policy.
  3. Input Is Invalid / Unverifiable (`tampering_detected = False`)
     Record is structurally malformed, schema is invalid, or formats are unparseable.
  4. Clean / No Violations (`tampering_detected = False`)
     All cryptographic checks pass.

This module does NOT perform or duplicate canonicalization, hashing, signature
verification, or chain verification. It purely analyzes and classifies verification
results produced by `aivara.crypto.verification`.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Union

from pydantic import BaseModel, ConfigDict, Field

from aivara.core.exceptions import AivaraException
from aivara.crypto.chain import ChainRecord
from aivara.crypto.verification import (
    FailureCode,
    UnifiedChainVerificationResult,
    UnifiedVerificationResult,
    VerificationEvidence,
    VerificationFailure,
)


# =====================================================================
# Enums and Taxonomy
# =====================================================================


class TamperAssessmentStatus(str, Enum):
    """High-level classification of a tamper evaluation."""

    CLEAN = "clean"
    INTEGRITY_VIOLATION = "integrity_violation"
    AUTHENTICITY_UNAVAILABLE = "authenticity_unavailable"
    UNVERIFIABLE_INPUT = "unverifiable_input"


class TamperCategory(str, Enum):
    """Specific category of cryptographic integrity violation."""

    RECORD_PAYLOAD_TAMPERING = "RECORD_PAYLOAD_TAMPERING"
    RECORD_HASH_TAMPERING = "RECORD_HASH_TAMPERING"
    SIGNATURE_TAMPERING = "SIGNATURE_TAMPERING"
    CHAIN_TAMPERING = "CHAIN_TAMPERING"
    SEQUENCE_TAMPERING = "SEQUENCE_TAMPERING"
    GENESIS_TAMPERING = "GENESIS_TAMPERING"
    PROJECT_CONTEXT_TAMPERING = "PROJECT_CONTEXT_TAMPERING"


class TamperSeverity(str, Enum):
    """Deterministic severity levels for tamper findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NONE = "none"


# Mapping from FailureCode to whether it represents an established integrity violation
INTEGRITY_VIOLATION_CODES = {
    FailureCode.RECORD_HASH_MISMATCH,
    FailureCode.BROKEN_CHAIN,
    FailureCode.INVALID_SIGNATURE,
    FailureCode.GENESIS_INVALID,
    FailureCode.SEQUENCE_VIOLATION,
    FailureCode.SEQUENCE_GAP,
    FailureCode.DUPLICATE_SEQUENCE,
    FailureCode.REPLAY_DETECTED,
    FailureCode.DUPLICATE_NONCE,
    FailureCode.DUPLICATE_RECORD,
    FailureCode.PROJECT_MISMATCH,
}

AUTHENTICITY_UNAVAILABLE_CODES = {
    FailureCode.UNKNOWN_SIGNER_KEY,
    FailureCode.MISSING_SIGNATURE,
    FailureCode.SIGNER_KEY_MISMATCH,
}

UNVERIFIABLE_INPUT_CODES = {
    FailureCode.MALFORMED_INPUT,
    FailureCode.INVALID_SCHEMA,
    FailureCode.INVALID_NONCE,
    FailureCode.INVALID_HASH_FORMAT,
    FailureCode.MALFORMED_SIGNATURE,
    FailureCode.INVALID_SEQUENCE,
    FailureCode.INVALID_PROJECT,
}

SEVERITY_WEIGHTS = {
    TamperSeverity.CRITICAL: 5,
    TamperSeverity.HIGH: 4,
    TamperSeverity.MEDIUM: 3,
    TamperSeverity.LOW: 2,
    TamperSeverity.INFO: 1,
    TamperSeverity.NONE: 0,
}


# =====================================================================
# Structured Output Models
# =====================================================================


class TamperEvidence(BaseModel):
    """Preserved machine-readable cryptographic evidence of discrepancies."""

    model_config = ConfigDict(frozen=True)

    project_id: Optional[str] = None
    expected_project_id: Optional[str] = None
    sequence_number: Optional[int] = None
    expected_sequence: Optional[int] = None
    stored_record_hash: Optional[str] = None
    computed_record_hash: Optional[str] = None
    stored_previous_record_hash: Optional[str] = None
    expected_previous_record_hash: Optional[str] = None
    signer_key_id: Optional[str] = None
    key_status: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class TamperFinding(BaseModel):
    """Structured description of an individual integrity violation or anomaly."""

    model_config = ConfigDict(frozen=True)

    category: TamperCategory = Field(..., description="Tamper category classification")
    severity: TamperSeverity = Field(..., description="Deterministic severity of the finding")
    description: str = Field(..., description="Human-readable objective explanation of discrepancy")
    failure_code: FailureCode = Field(..., description="Underlying verification failure code")
    sequence_number: Optional[int] = Field(None, description="Sequence number affected")
    evidence: Optional[TamperEvidence] = Field(None, description="Preserved cryptographic evidence")


class TamperAssessment(BaseModel):
    """Deterministic tamper assessment for a single provenance record."""

    model_config = ConfigDict(frozen=True)

    tampering_detected: bool = Field(..., description="True ONLY if cryptographic integrity violation is established")
    status: TamperAssessmentStatus = Field(..., description="High-level evaluation category")
    confidence: float = Field(..., ge=0.0, le=1.0, description="1.0 for deterministic integrity violations, 0.0 otherwise")
    severity: TamperSeverity = Field(..., description="Maximum severity across detected findings (NONE if clean)")
    summary: str = Field(..., description="Human-readable objective assessment statement")
    project_id: Optional[str] = Field(None, description="Project identifier if available")
    sequence_number: Optional[int] = Field(None, description="Sequence number if available")
    categories: List[TamperCategory] = Field(default_factory=list, description="All tamper categories detected")
    findings: List[TamperFinding] = Field(default_factory=list, description="Preserved findings with evidence")
    verification_failure_codes: List[FailureCode] = Field(default_factory=list, description="All failure codes evaluated")
    evidence: Optional[TamperEvidence] = Field(None, description="Summary cryptographic evidence")


class ChainTamperAssessment(BaseModel):
    """Deterministic tamper assessment for a full hash-linked provenance chain."""

    model_config = ConfigDict(frozen=True)

    tampering_detected: bool = Field(..., description="True if any cryptographic integrity violation is established in chain")
    status: TamperAssessmentStatus = Field(..., description="Overall chain assessment status")
    confidence: float = Field(..., ge=0.0, le=1.0, description="1.0 for deterministic integrity violations, 0.0 otherwise")
    severity: TamperSeverity = Field(..., description="Maximum severity across all chain findings (NONE if clean)")
    summary: str = Field(..., description="Human-readable objective chain assessment statement")
    project_id: Optional[str] = Field(None, description="Project identifier if available")
    records_evaluated_count: int = Field(default=0, description="Total records evaluated in chain")
    affected_sequences: List[int] = Field(default_factory=list, description="Sequence numbers exhibiting violations")
    categories: List[TamperCategory] = Field(default_factory=list, description="All tamper categories detected across chain")
    findings: List[TamperFinding] = Field(default_factory=list, description="All preserved findings across chain")
    record_assessments: List[TamperAssessment] = Field(default_factory=list, description="Individual record assessments")
    verification_failure_codes: List[FailureCode] = Field(default_factory=list, description="All failure codes across chain")


# =====================================================================
# Internal Failure Classifier
# =====================================================================


def _classify_failure(
    failure: VerificationFailure,
    evidence: Optional[VerificationEvidence] = None,
) -> Optional[TamperFinding]:
    """Classify a verification failure into a TamperFinding if it represents tampering.

    Returns None if the failure does not establish an integrity violation
    (e.g., unverifiable input or unestablished authenticity).
    """
    code = failure.code
    seq = failure.sequence_number

    # Build finding-level evidence if available
    finding_evidence: Optional[TamperEvidence] = None
    if evidence is not None:
        finding_evidence = TamperEvidence(
            project_id=evidence.project_id,
            sequence_number=seq or evidence.sequence_number,
            expected_sequence=evidence.expected_sequence,
            stored_record_hash=evidence.stored_record_hash,
            computed_record_hash=evidence.computed_record_hash,
            stored_previous_record_hash=evidence.stored_previous_record_hash,
            expected_previous_record_hash=evidence.expected_previous_record_hash,
            signer_key_id=evidence.signer_key_id,
            key_status=evidence.key_status,
        )

    if code == FailureCode.RECORD_HASH_MISMATCH:
        desc = (
            f"Record payload or hash discrepancy detected at sequence {seq}: stored hash "
            f"does not match canonical recomputed hash."
        )
        return TamperFinding(
            category=TamperCategory.RECORD_PAYLOAD_TAMPERING,
            severity=TamperSeverity.HIGH,
            description=desc,
            failure_code=code,
            sequence_number=seq,
            evidence=finding_evidence,
        )

    elif code == FailureCode.INVALID_SIGNATURE:
        desc = (
            f"Digital signature verification failed at sequence {seq}: signature does not "
            f"authenticate the stored record payload for signer key."
        )
        return TamperFinding(
            category=TamperCategory.SIGNATURE_TAMPERING,
            severity=TamperSeverity.HIGH,
            description=desc,
            failure_code=code,
            sequence_number=seq,
            evidence=finding_evidence,
        )

    elif code == FailureCode.BROKEN_CHAIN:
        desc = (
            f"Hash-chain linkage broken at sequence {seq}: previous_record_hash does not match "
            f"preceding record's canonical digest."
        )
        return TamperFinding(
            category=TamperCategory.CHAIN_TAMPERING,
            severity=TamperSeverity.HIGH,
            description=desc,
            failure_code=code,
            sequence_number=seq,
            evidence=finding_evidence,
        )

    elif code in (FailureCode.SEQUENCE_VIOLATION, FailureCode.SEQUENCE_GAP, FailureCode.DUPLICATE_SEQUENCE):
        desc = (
            f"Sequence ordering manipulation detected at sequence {seq}: expected monotonic sequence "
            f"continuity was violated ({code.value})."
        )
        return TamperFinding(
            category=TamperCategory.SEQUENCE_TAMPERING,
            severity=TamperSeverity.MEDIUM,
            description=desc,
            failure_code=code,
            sequence_number=seq,
            evidence=finding_evidence,
        )

    elif code == FailureCode.GENESIS_INVALID:
        desc = (
            f"Genesis record integrity violation at sequence {seq}: genesis anchor or properties "
            f"do not conform to the required immutable genesis state."
        )
        return TamperFinding(
            category=TamperCategory.GENESIS_TAMPERING,
            severity=TamperSeverity.CRITICAL,
            description=desc,
            failure_code=code,
            sequence_number=seq,
            evidence=finding_evidence,
        )

    elif code == FailureCode.PROJECT_MISMATCH:
        desc = (
            f"Project context discrepancy at sequence {seq}: record project identifier does not "
            f"match the expected project context."
        )
        return TamperFinding(
            category=TamperCategory.PROJECT_CONTEXT_TAMPERING,
            severity=TamperSeverity.MEDIUM,
            description=desc,
            failure_code=code,
            sequence_number=seq,
            evidence=finding_evidence,
        )

    elif code in (FailureCode.REPLAY_DETECTED, FailureCode.DUPLICATE_NONCE, FailureCode.DUPLICATE_RECORD):
        desc = (
            f"Replay or duplicate record detected in chain at sequence {seq}: nonce or record hash "
            f"was reused ({code.value})."
        )
        return TamperFinding(
            category=TamperCategory.CHAIN_TAMPERING,
            severity=TamperSeverity.HIGH,
            description=desc,
            failure_code=code,
            sequence_number=seq,
            evidence=finding_evidence,
        )

    # Not an established integrity violation (e.g. UNKNOWN_SIGNER_KEY, MALFORMED_INPUT, etc.)
    return None


def _max_severity(severities: Sequence[TamperSeverity]) -> TamperSeverity:
    """Return the maximum severity among a list of severities."""
    if not severities:
        return TamperSeverity.NONE
    return max(severities, key=lambda s: SEVERITY_WEIGHTS[s])


# =====================================================================
# Single Record Tamper Assessment
# =====================================================================


def assess_record_tampering(
    verification_result: UnifiedVerificationResult,
    record: Optional[Union[ChainRecord, Dict[str, Any]]] = None,
) -> TamperAssessment:
    """Evaluate a single record's verification result for cryptographic tampering.

    Consumes the existing UnifiedVerificationResult. Never recalculates hashes,
    canonical bytes, or digital signatures.

    Distinguishes:
      - Cryptographic integrity violation detected (`tampering_detected = True`, confidence = 1.0)
      - Authenticity cannot be established (`tampering_detected = False`, confidence = 0.0)
      - Unverifiable / malformed input (`tampering_detected = False`, confidence = 0.0)
      - Clean / valid record (`tampering_detected = False`, confidence = 0.0)

    Args:
        verification_result: Pre-computed UnifiedVerificationResult from verify_record().
        record: Optional original record for extracting metadata (identifiers/project).

    Returns:
        TamperAssessment detailing deterministic findings and evidence.
    """
    evidence = verification_result.evidence
    failure_codes = verification_result.failure_codes

    # 1. Inspect failures and map to tamper findings
    findings: List[TamperFinding] = []
    has_integrity_violation = False
    has_authenticity_issue = False
    has_unverifiable_input = False

    for fail in verification_result.failures:
        code = fail.code
        if code in INTEGRITY_VIOLATION_CODES:
            has_integrity_violation = True
            finding = _classify_failure(fail, evidence)
            if finding and finding not in findings:
                findings.append(finding)
        elif code in AUTHENTICITY_UNAVAILABLE_CODES:
            has_authenticity_issue = True
        elif code in UNVERIFIABLE_INPUT_CODES:
            has_unverifiable_input = True

    # 2. Determine high-level status and tampering_detected flag
    project_id = evidence.project_id if evidence else None
    sequence_number = evidence.sequence_number if evidence else None

    # Supplement project/sequence from record dict/model if missing in evidence
    if record is not None:
        rec_dict = record.model_dump() if isinstance(record, ChainRecord) else record
        if not project_id and "project_id" in rec_dict:
            project_id = str(rec_dict["project_id"])
        if sequence_number is None and "sequence_number" in rec_dict:
            seq_val = rec_dict.get("sequence_number")
            if isinstance(seq_val, int):
                sequence_number = seq_val

    tamper_categories = sorted(list({f.category for f in findings}))

    if has_unverifiable_input:
        tampering_detected = False
        status = TamperAssessmentStatus.UNVERIFIABLE_INPUT
        confidence = 0.0
        severity = TamperSeverity.NONE
        summary = (
            "Input is structurally malformed or invalid; cryptographic integrity cannot be "
            "evaluated. Cryptographic integrity violation is not established."
        )

    elif has_integrity_violation:
        tampering_detected = True
        status = TamperAssessmentStatus.INTEGRITY_VIOLATION
        confidence = 1.0  # Deterministic mathematical certainty of discrepancy
        severity = _max_severity([f.severity for f in findings])

        cat_names = ", ".join(c.value for c in tamper_categories)
        summary = (
            f"Cryptographic integrity violation detected: record failed integrity checks "
            f"in categories [{cat_names}]."
        )

    elif has_authenticity_issue:
        tampering_detected = False
        status = TamperAssessmentStatus.AUTHENTICITY_UNAVAILABLE
        confidence = 0.0
        severity = TamperSeverity.NONE
        summary = (
            "Authenticity cannot be established: signer key is unknown or signature is "
            "unavailable. Cryptographic integrity violation is not established."
        )
        summary = (
            "Input is structurally malformed or invalid; cryptographic integrity cannot be "
            "evaluated. Cryptographic integrity violation is not established."
        )

    else:
        # Fully valid / clean
        tampering_detected = False
        status = TamperAssessmentStatus.CLEAN
        confidence = 0.0
        severity = TamperSeverity.NONE
        summary = "No cryptographic integrity violations detected."

    # Build summary evidence
    summary_evidence: Optional[TamperEvidence] = None
    if evidence:
        summary_evidence = TamperEvidence(
            project_id=project_id,
            sequence_number=sequence_number,
            expected_sequence=evidence.expected_sequence,
            stored_record_hash=evidence.stored_record_hash,
            computed_record_hash=evidence.computed_record_hash,
            stored_previous_record_hash=evidence.stored_previous_record_hash,
            expected_previous_record_hash=evidence.expected_previous_record_hash,
            signer_key_id=evidence.signer_key_id,
            key_status=evidence.key_status,
        )

    return TamperAssessment(
        tampering_detected=tampering_detected,
        status=status,
        confidence=confidence,
        severity=severity,
        summary=summary,
        project_id=project_id,
        sequence_number=sequence_number,
        categories=tamper_categories,
        findings=findings,
        verification_failure_codes=failure_codes,
        evidence=summary_evidence,
    )


# =====================================================================
# Full Chain Tamper Assessment
# =====================================================================


def assess_chain_tampering(
    chain_verification_result: UnifiedChainVerificationResult,
    records: Optional[Sequence[Union[ChainRecord, Dict[str, Any]]]] = None,
) -> ChainTamperAssessment:
    """Evaluate a full provenance chain verification result for cryptographic tampering.

    Consumes the existing UnifiedChainVerificationResult. Never recalculates hashes,
    canonical bytes, or digital signatures.

    Preserves multiple independent findings across all chain records.

    Args:
        chain_verification_result: Pre-computed result from verify_provenance_chain().
        records: Optional list of records for additional metadata resolution.

    Returns:
        ChainTamperAssessment detailing chain-wide findings and affected sequences.
    """
    chain_evidence = chain_verification_result.evidence or {}
    project_id = chain_evidence.get("project_id")
    records_count = chain_verification_result.records_verified_count

    all_findings: List[TamperFinding] = []
    affected_sequences: List[int] = []
    record_assessments: List[TamperAssessment] = []

    # 1. Assess individual records from chain_verification_result.record_results
    for idx, rec_res in enumerate(chain_verification_result.record_results):
        rec_obj = records[idx] if records and idx < len(records) else None
        rec_assessment = assess_record_tampering(rec_res, record=rec_obj)
        record_assessments.append(rec_assessment)

        if rec_assessment.tampering_detected:
            seq = rec_assessment.sequence_number if rec_assessment.sequence_number is not None else idx
            if seq not in affected_sequences:
                affected_sequences.append(seq)
            for f in rec_assessment.findings:
                if f not in all_findings:
                    all_findings.append(f)

    # 2. Check chain-level failures (from chain_verification_result.failures)
    has_chain_integrity_violation = False
    has_chain_authenticity_issue = False
    has_chain_unverifiable_input = False

    for fail in chain_verification_result.failures:
        code = fail.code
        if code in INTEGRITY_VIOLATION_CODES:
            has_chain_integrity_violation = True
            finding = _classify_failure(fail, None)
            if finding and finding not in all_findings:
                all_findings.append(finding)
            if fail.sequence_number is not None and fail.sequence_number not in affected_sequences:
                affected_sequences.append(fail.sequence_number)
        elif code in AUTHENTICITY_UNAVAILABLE_CODES:
            has_chain_authenticity_issue = True
        elif code in UNVERIFIABLE_INPUT_CODES:
            has_chain_unverifiable_input = True

    # 3. Compile overall status
    categories = sorted(list({f.category for f in all_findings}))
    affected_sequences.sort()

    if has_chain_integrity_violation or any(r.tampering_detected for r in record_assessments):
        tampering_detected = True
        status = TamperAssessmentStatus.INTEGRITY_VIOLATION
        confidence = 1.0
        severity = _max_severity([f.severity for f in all_findings])

        cat_names = ", ".join(c.value for c in categories)
        seq_str = ", ".join(str(s) for s in affected_sequences)
        summary = (
            f"Cryptographic integrity violation detected in provenance chain: violations found "
            f"at sequence(s) [{seq_str}] in categories [{cat_names}]."
        )

    elif has_chain_authenticity_issue:
        tampering_detected = False
        status = TamperAssessmentStatus.AUTHENTICITY_UNAVAILABLE
        confidence = 0.0
        severity = TamperSeverity.NONE
        summary = (
            "Authenticity cannot be established for one or more records in chain: "
            "signer keys unknown or missing. Cryptographic integrity violation is not established."
        )

    elif has_chain_unverifiable_input:
        tampering_detected = False
        status = TamperAssessmentStatus.UNVERIFIABLE_INPUT
        confidence = 0.0
        severity = TamperSeverity.NONE
        summary = (
            "Chain contains structurally malformed or invalid inputs; cryptographic integrity "
            "cannot be evaluated. Cryptographic integrity violation is not established."
        )

    else:
        tampering_detected = False
        status = TamperAssessmentStatus.CLEAN
        confidence = 0.0
        severity = TamperSeverity.NONE
        summary = "No cryptographic integrity violations detected across provenance chain."

    return ChainTamperAssessment(
        tampering_detected=tampering_detected,
        status=status,
        confidence=confidence,
        severity=severity,
        summary=summary,
        project_id=project_id,
        records_evaluated_count=records_count,
        affected_sequences=affected_sequences,
        categories=categories,
        findings=all_findings,
        record_assessments=record_assessments,
        verification_failure_codes=chain_verification_result.failure_codes,
    )


# =====================================================================
# Tamper Detector Orchestrator Class
# =====================================================================


class TamperDetector:
    """Configurable domain-layer tamper detector.

    Translates verification results into structured, deterministic tamper assessments.
    """

    def assess_record(
        self,
        verification_result: UnifiedVerificationResult,
        record: Optional[Union[ChainRecord, Dict[str, Any]]] = None,
    ) -> TamperAssessment:
        """Assess an individual provenance record for tampering."""
        return assess_record_tampering(verification_result, record=record)

    def assess_chain(
        self,
        chain_verification_result: UnifiedChainVerificationResult,
        records: Optional[Sequence[Union[ChainRecord, Dict[str, Any]]]] = None,
    ) -> ChainTamperAssessment:
        """Assess an entire provenance chain for tampering."""
        return assess_chain_tampering(chain_verification_result, records=records)
