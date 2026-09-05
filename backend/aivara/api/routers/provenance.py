"""Provenance ledger and cryptographic verification API router (Phase 4.12).

Exposes:
  - Provenance record creation with persistent replay protection.
  - Advisory replay checking prior to insertion.
  - Provenance record retrieval and chain queries.
  - Single-record and full-chain cryptographic verification.
  - Single-record and full-chain tamper assessment.
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from aivara.api.envelope import ApiResponse
from aivara.core.config import settings
from aivara.core.exceptions import NotFoundException
from aivara.crypto.keys import KeyManager
from aivara.crypto.replay import ReplayAssessment
from aivara.crypto.tamper_detection import (
    ChainTamperAssessment,
    TamperAssessment,
)
from aivara.crypto.verification import (
    UnifiedChainVerificationResult,
    UnifiedVerificationResult,
)
from aivara.database.connection import get_db
from aivara.domain.schemas import (
    ChainTamperAssessmentRequest,
    ChainVerificationRequest,
    ProvenanceRecordCreate,
    ProvenanceRecordRead,
    RecordTamperAssessmentRequest,
    RecordVerificationRequest,
    ReplayCheckRequest,
)
from aivara.services.provenance_service import ProvenanceService

router = APIRouter(prefix="/provenance", tags=["provenance"])


def get_key_manager() -> KeyManager:
    """Dependency provider resolving the local KeyManager instance."""
    return KeyManager(keys_dir=settings.keys_dir)


# ===========================================================================
# 1. Provenance Event Recording & Replay Check
# ===========================================================================

@router.post(
    "/records",
    response_model=ApiResponse[ProvenanceRecordRead],
    status_code=status.HTTP_201_CREATED,
    summary="Record a provenance event",
    description=(
        "Persist an immutable provenance record with database-enforced project-scoped "
        "sequence, nonce, and hash replay protection."
    ),
)
async def create_provenance_record(
    payload: ProvenanceRecordCreate,
    db: Session = Depends(get_db),
):
    """Create and persist a new provenance record in the assurance ledger."""
    service = ProvenanceService(db)
    record = service.record_provenance_event(payload)
    return ApiResponse(data=record)


@router.post(
    "/replay-check",
    response_model=ApiResponse[ReplayAssessment],
    status_code=status.HTTP_200_OK,
    summary="Advisory replay check",
    description=(
        "Check whether a proposed sequence number, nonce, or record hash would conflict "
        "with previously accepted records in the specified project."
    ),
)
async def check_replay(
    payload: ReplayCheckRequest,
    db: Session = Depends(get_db),
):
    """Perform an advisory replay assessment against the persistent ledger."""
    service = ProvenanceService(db)
    assessment = service.check_replay(
        project_id=payload.project_id,
        sequence_number=payload.sequence_number,
        nonce=payload.nonce,
        record_hash=payload.record_hash,
    )
    return ApiResponse(data=assessment)


# ===========================================================================
# 2. Record Retrieval & Chain Queries
# ===========================================================================

@router.get(
    "/records/{record_id}",
    response_model=ApiResponse[ProvenanceRecordRead],
    status_code=status.HTTP_200_OK,
    summary="Get provenance record",
    description="Retrieve a single provenance record by its primary key ID.",
)
async def get_provenance_record(
    record_id: str,
    db: Session = Depends(get_db),
):
    """Fetch an individual provenance record by primary key identifier."""
    service = ProvenanceService(db)
    record = service.get_record(record_id)
    if not record:
        raise NotFoundException(f"Provenance record '{record_id}' not found.")
    return ApiResponse(data=record)


@router.get(
    "/records",
    response_model=ApiResponse[List[ProvenanceRecordRead]],
    status_code=status.HTTP_200_OK,
    summary="List provenance records",
    description="List provenance records for a project ordered monotonically by sequence number.",
)
async def list_provenance_records(
    project_id: str = Query(..., description="Project identifier to query"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """List provenance records belonging to a project."""
    service = ProvenanceService(db)
    records = service.list_records(project_id, limit=limit, offset=offset)
    return ApiResponse(data=records)


@router.get(
    "/chain/{project_id}",
    response_model=ApiResponse[List[ProvenanceRecordRead]],
    status_code=status.HTTP_200_OK,
    summary="Get project provenance chain",
    description="Retrieve the sequential hash-linked provenance chain for a project.",
)
async def get_project_provenance_chain(
    project_id: str,
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """Retrieve ordered provenance chain records for a project."""
    service = ProvenanceService(db)
    records = service.list_records(project_id, limit=limit, offset=offset)
    return ApiResponse(data=records)


# ===========================================================================
# 3. Cryptographic Verification Endpoints
# ===========================================================================

@router.post(
    "/records/verify",
    response_model=ApiResponse[UnifiedVerificationResult],
    status_code=status.HTTP_200_OK,
    summary="Verify a single provenance record",
    description=(
        "Cryptographically verify a single provenance record across RFC 8785 canonical "
        "hashing, payload integrity, schema format, and Ed25519 digital signatures. "
        "Returns a structured diagnostic outcome rather than transport errors."
    ),
)
async def verify_single_record(
    payload: RecordVerificationRequest,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
):
    """Verify cryptographic integrity and signature validity of a record."""
    service = ProvenanceService(db, key_manager=key_manager)
    result = service.verify_record(
        record=payload.record,
        record_id=payload.record_id,
        expected_project_id=payload.expected_project_id,
        expected_sequence=payload.expected_sequence,
        expected_previous_record_hash=payload.expected_previous_record_hash,
        allow_unsigned=payload.allow_unsigned,
    )
    return ApiResponse(data=result)


@router.get(
    "/records/{record_id}/verify",
    response_model=ApiResponse[UnifiedVerificationResult],
    status_code=status.HTTP_200_OK,
    summary="Verify stored provenance record",
    description="Verify an existing stored provenance record retrieved from the database.",
)
async def verify_stored_record(
    record_id: str,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
):
    """Verify an existing stored provenance record by ID."""
    service = ProvenanceService(db, key_manager=key_manager)
    result = service.verify_record(record_id=record_id)
    return ApiResponse(data=result)


@router.post(
    "/chain/verify",
    response_model=ApiResponse[UnifiedChainVerificationResult],
    status_code=status.HTTP_200_OK,
    summary="Verify a provenance chain",
    description=(
        "Verify an ordered provenance chain across genesis integrity, monotonic sequence "
        "continuity, hash-linkage, nonce uniqueness, and individual signatures."
    ),
)
async def verify_provenance_chain_endpoint(
    payload: ChainVerificationRequest,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
):
    """Verify a provenance chain supplied in request body or loaded from database."""
    service = ProvenanceService(db, key_manager=key_manager)
    result = service.verify_chain(
        project_id=payload.project_id,
        records=payload.records,
        allow_unsigned=payload.allow_unsigned,
    )
    return ApiResponse(data=result)


@router.get(
    "/chain/{project_id}/verify",
    response_model=ApiResponse[UnifiedChainVerificationResult],
    status_code=status.HTTP_200_OK,
    summary="Verify stored project provenance chain",
    description="Load and verify the entire persistent provenance chain for a project.",
)
async def verify_project_chain_get(
    project_id: str,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
):
    """Load and verify a project's persistent provenance chain from the database."""
    service = ProvenanceService(db, key_manager=key_manager)
    result = service.verify_chain(project_id=project_id)
    return ApiResponse(data=result)


# ===========================================================================
# 4. Tamper Assessment Endpoints
# ===========================================================================

@router.post(
    "/records/tamper-assessment",
    response_model=ApiResponse[TamperAssessment],
    status_code=status.HTTP_200_OK,
    summary="Assess record tampering",
    description=(
        "Assess cryptographic tampering for a single provenance record. Categorizes "
        "findings into INTEGRITY_VIOLATION, AUTHENTICITY_UNAVAILABLE, UNVERIFIABLE_INPUT, "
        "or CLEAN without false positives."
    ),
)
async def assess_record_tampering_endpoint(
    payload: RecordTamperAssessmentRequest,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
):
    """Evaluate whether a provenance record exhibits cryptographic tampering."""
    service = ProvenanceService(db, key_manager=key_manager)
    assessment = service.assess_record_tampering(
        record=payload.record,
        record_id=payload.record_id,
        expected_project_id=payload.expected_project_id,
        allow_unsigned=payload.allow_unsigned,
    )
    return ApiResponse(data=assessment)


@router.get(
    "/records/{record_id}/tamper-assessment",
    response_model=ApiResponse[TamperAssessment],
    status_code=status.HTTP_200_OK,
    summary="Assess stored record tampering",
    description="Assess cryptographic tampering on an existing stored record by ID.",
)
async def assess_stored_record_tampering_get(
    record_id: str,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
):
    """Assess cryptographic tampering on an existing stored record."""
    service = ProvenanceService(db, key_manager=key_manager)
    assessment = service.assess_record_tampering(record_id=record_id)
    return ApiResponse(data=assessment)


@router.post(
    "/chain/tamper-assessment",
    response_model=ApiResponse[ChainTamperAssessment],
    status_code=status.HTTP_200_OK,
    summary="Assess chain tampering",
    description=(
        "Assess cryptographic tampering across an entire provenance chain. Evaluates "
        "chain-level integrity, sequence tampering, and genesis integrity."
    ),
)
async def assess_chain_tampering_endpoint(
    payload: ChainTamperAssessmentRequest,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
):
    """Assess cryptographic tampering across a provenance chain."""
    service = ProvenanceService(db, key_manager=key_manager)
    assessment = service.assess_chain_tampering(
        project_id=payload.project_id,
        records=payload.records,
        allow_unsigned=payload.allow_unsigned,
    )
    return ApiResponse(data=assessment)


@router.get(
    "/chain/{project_id}/tamper-assessment",
    response_model=ApiResponse[ChainTamperAssessment],
    status_code=status.HTTP_200_OK,
    summary="Assess stored chain tampering",
    description="Load and assess tampering across a project's persistent provenance chain.",
)
async def assess_stored_chain_tampering_get(
    project_id: str,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
):
    """Assess tampering across a project's persistent provenance chain in the database."""
    service = ProvenanceService(db, key_manager=key_manager)
    assessment = service.assess_chain_tampering(project_id=project_id)
    return ApiResponse(data=assessment)
