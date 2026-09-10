"""Findings API router (Phase 5.10).

Exposes:
  - Querying and retrieval of synthesized audit findings.
  - Multi-entity backward traceability graph resolution.
  - Cryptographic provenance ledger verification of finding commitments.
"""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from aivara.api.envelope import ApiResponse
from aivara.api.schemas.evidence import FindingDetailRead
from aivara.core.config import settings
from aivara.core.exceptions import NotFoundException
from aivara.crypto.keys import KeyManager
from aivara.database.connection import get_db
from aivara.database.models import FindingModel
from aivara.evidence.binding import EvidenceFindingBinder
from aivara.evidence.provenance import ProvenanceBindingAdapter
from aivara.evidence.schemas import (
    EvidenceProvenanceVerificationResult,
    TraceabilityChain,
)
from aivara.evidence.validators import validate_project_isolation

router = APIRouter(prefix="/findings", tags=["findings"])


def get_key_manager() -> KeyManager:
    """Dependency provider resolving the local KeyManager instance."""
    return KeyManager(keys_dir=settings.keys_dir)


@router.get(
    "",
    response_model=ApiResponse[List[FindingDetailRead]],
    status_code=status.HTTP_200_OK,
    summary="Query audit findings",
)
async def list_findings(
    project_id: Optional[str] = Query(None, description="Filter by project ID"),
    finding_type: Optional[str] = Query(None, description="Filter by finding type"),
    severity: Optional[str] = Query(None, description="Filter by severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Retrieve paginated findings matching query criteria."""
    query = db.query(FindingModel)
    if project_id:
        query = query.filter(FindingModel.project_id == project_id)
    if finding_type:
        query = query.filter(FindingModel.finding_type == finding_type)
    if severity:
        query = query.filter(FindingModel.severity == severity)

    total_findings = query.order_by(FindingModel.created_at.desc()).offset(offset).limit(limit).all()

    items = []
    for f in total_findings:
        meta = f.metadata_json or {}
        items.append(
            FindingDetailRead(
                id=f.id,
                project_id=f.project_id,
                finding_type=f.finding_type,
                engine_id=f.engine_id,
                title=f.title,
                description=f.description,
                severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                confidence=f.confidence,
                disposition=f.disposition.value if hasattr(f.disposition, "value") and f.disposition else None,
                affected_asset_type=f.affected_asset_type,
                affected_asset_id=f.affected_asset_id,
                primary_evidence_hashes=meta.get("primary_evidence_hashes", []),
                referenced_evidence_ids=meta.get("referenced_evidence_ids", []),
                provenance_record_id=meta.get("provenance_record_id"),
                metadata_json=meta,
                created_at=f.created_at.isoformat() if f.created_at else "",
            )
        )
    return ApiResponse(data=items)


@router.get(
    "/{finding_id}",
    response_model=ApiResponse[FindingDetailRead],
    status_code=status.HTTP_200_OK,
    summary="Get single finding by ID",
)
async def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve a single finding by ID including metadata citations."""
    f = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
    if not f:
        raise NotFoundException(f"Finding '{finding_id}' not found.")

    meta = f.metadata_json or {}
    return ApiResponse(
        data=FindingDetailRead(
            id=f.id,
            project_id=f.project_id,
            finding_type=f.finding_type,
            engine_id=f.engine_id,
            title=f.title,
            description=f.description,
            severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            confidence=f.confidence,
            disposition=f.disposition.value if hasattr(f.disposition, "value") and f.disposition else None,
            affected_asset_type=f.affected_asset_type,
            affected_asset_id=f.affected_asset_id,
            primary_evidence_hashes=meta.get("primary_evidence_hashes", []),
            referenced_evidence_ids=meta.get("referenced_evidence_ids", []),
            provenance_record_id=meta.get("provenance_record_id"),
            metadata_json=meta,
            created_at=f.created_at.isoformat() if f.created_at else "",
        )
    )


@router.get(
    "/{finding_id}/traceability",
    response_model=ApiResponse[TraceabilityChain],
    status_code=status.HTTP_200_OK,
    summary="Get backward traceability graph for finding",
)
async def get_finding_traceability(
    finding_id: str,
    project_id: str = Query(..., description="Project ID owning the finding"),
    db: Session = Depends(get_db),
):
    """Resolve the multi-entity backward traceability graph linking finding to source evidence and provenance."""
    binder = EvidenceFindingBinder(db=db)
    chain = binder.build_traceability_chain(finding_id, project_id=project_id)
    return ApiResponse(data=chain)


@router.get(
    "/{finding_id}/provenance-verification",
    response_model=ApiResponse[EvidenceProvenanceVerificationResult],
    status_code=status.HTTP_200_OK,
    summary="Verify cryptographic provenance binding for finding",
)
async def verify_finding_provenance(
    finding_id: str,
    project_id: str = Query(..., description="Project ID owning the finding"),
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
):
    """Perform cryptographic provenance verification on the sealed finding commitment."""
    adapter = ProvenanceBindingAdapter(db=db, key_manager=key_manager)
    verif_res = adapter.verify_finding_provenance(finding_id, project_id=project_id)
    return ApiResponse(data=verif_res)
