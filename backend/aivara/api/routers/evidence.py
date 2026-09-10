"""Evidence API router (Phase 5.10).

Exposes:
  - Querying and retrieval of persisted immutable Evidence records.
  - Deterministic canonical evidence hash verification (RFC 8785 + SHA-256).
"""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from aivara.api.envelope import ApiResponse
from aivara.api.schemas.evidence import (
    EvidenceItemRead,
    EvidenceVerifyRequest,
    EvidenceVerifyResponse,
)
from aivara.core.exceptions import NotFoundException
from aivara.database.connection import get_db
from aivara.database.models import EvidenceModel, FindingModel
from aivara.evidence.identity import compute_evidence_hash
from aivara.evidence.schemas import EvidenceContent
from aivara.evidence.validators import validate_project_isolation

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.get(
    "",
    response_model=ApiResponse[List[EvidenceItemRead]],
    status_code=status.HTTP_200_OK,
    summary="Query and list evidence items",
)
async def list_evidence(
    project_id: Optional[str] = Query(None, description="Filter by project ID"),
    finding_id: Optional[str] = Query(None, description="Filter by finding ID"),
    evidence_type: Optional[str] = Query(None, description="Filter by evidence type"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Retrieve paginated immutable evidence items matching query criteria."""
    query = db.query(EvidenceModel)
    if project_id:
        query = query.join(FindingModel, EvidenceModel.finding_id == FindingModel.id).filter(FindingModel.project_id == project_id)
    if finding_id:
        query = query.filter(EvidenceModel.finding_id == finding_id)
    if evidence_type:
        query = query.filter(EvidenceModel.evidence_type == evidence_type)

    total_items = query.order_by(EvidenceModel.created_at.desc()).offset(offset).limit(limit).all()

    items = [
        EvidenceItemRead(
            id=e.id,
            finding_id=e.finding_id,
            evidence_hash=e.evidence_hash,
            evidence_type=e.evidence_type,
            evidence_layer=e.evidence_layer.value if hasattr(e.evidence_layer, "value") else str(e.evidence_layer),
            title=e.title,
            description=e.description,
            confidence=e.confidence,
            measurements=e.data_json.get("measurements", {}) if isinstance(e.data_json, dict) else {},
            data_json=e.data_json or {},
            created_at=e.created_at.isoformat() if e.created_at else "",
        )
        for e in total_items
    ]
    return ApiResponse(data=items)


@router.get(
    "/{evidence_id}",
    response_model=ApiResponse[EvidenceItemRead],
    status_code=status.HTTP_200_OK,
    summary="Get single evidence record by ID",
)
async def get_evidence(
    evidence_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve a single immutable evidence item by primary key."""
    e = db.query(EvidenceModel).filter(EvidenceModel.id == evidence_id).first()
    if not e:
        raise NotFoundException(f"Evidence '{evidence_id}' not found.")

    return ApiResponse(
        data=EvidenceItemRead(
            id=e.id,
            finding_id=e.finding_id,
            evidence_hash=e.evidence_hash,
            evidence_type=e.evidence_type,
            evidence_layer=e.evidence_layer.value if hasattr(e.evidence_layer, "value") else str(e.evidence_layer),
            title=e.title,
            description=e.description,
            confidence=e.confidence,
            measurements=e.data_json.get("measurements", {}) if isinstance(e.data_json, dict) else {},
            data_json=e.data_json or {},
            created_at=e.created_at.isoformat() if e.created_at else "",
        )
    )


@router.post(
    "/verify",
    response_model=ApiResponse[EvidenceVerifyResponse],
    status_code=status.HTTP_200_OK,
    summary="Verify deterministic evidence hash",
)
async def verify_evidence_hash_endpoint(payload: EvidenceVerifyRequest):
    """Verify that an evidence payload hashes canonically to the expected SHA-256 digest."""
    computed_hash = compute_evidence_hash(payload.evidence_payload)
    is_valid = computed_hash.lower() == payload.expected_hash.lower()
    return ApiResponse(
        data=EvidenceVerifyResponse(
            is_valid=is_valid,
            computed_hash=computed_hash,
            expected_hash=payload.expected_hash,
        )
    )
