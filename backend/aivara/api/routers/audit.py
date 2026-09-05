"""FastAPI REST router for cryptographically tamper-evident audit logging (Phase 4.13).

Provides strictly read-only access to audit records and verification:
  - GET /api/v1/audit/events/{id}
  - GET /api/v1/audit/events
  - GET /api/v1/audit/chain/{project_id}
  - POST /api/v1/audit/chain/verify
  - GET /api/v1/audit/chain/{project_id}/verify

No POST/PUT/PATCH/DELETE endpoints exist for mutating audit records.
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from aivara.core.exceptions import NotFoundException
from aivara.database.connection import get_db
from aivara.domain.schemas import (
    AuditChainVerificationRequest,
    AuditEventRead,
    AuditVerificationResult,
)
from aivara.services.audit_service import AuditService

router = APIRouter(prefix="/audit", tags=["Audit Logging"])


def get_audit_service(db: Session = Depends(get_db)) -> AuditService:
    """Dependency provider for AuditService."""
    return AuditService(db)


@router.get(
    "/events/{event_id}",
    response_model=dict,
    summary="Retrieve a single audit event",
    description="Fetch a cryptographically immutable audit event by its unique UUID.",
)
def get_audit_event(
    event_id: str,
    audit_service: AuditService = Depends(get_audit_service),
):
    """Retrieve an audit event by primary key ID."""
    event = audit_service.get_event(event_id)
    if not event:
        raise NotFoundException(f"Audit event '{event_id}' not found.")
    return {
        "status": "success",
        "data": event.model_dump(),
        "meta": {"event_id": event_id},
    }


@router.get(
    "/events",
    response_model=dict,
    summary="List audit events",
    description="List ordered audit events, optionally filtered by project.",
)
def list_audit_events(
    project_id: Optional[str] = Query(None, description="Filter audit events by project ID"),
    skip: int = Query(0, ge=0, description="Offset for pagination"),
    limit: int = Query(100, ge=1, le=1000, description="Limit for pagination"),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Query audit events with optional project filtering and pagination."""
    events = audit_service.list_events(project_id=project_id, skip=skip, limit=limit)
    return {
        "status": "success",
        "data": [e.model_dump() for e in events],
        "meta": {
            "total": len(events),
            "skip": skip,
            "limit": limit,
            "project_id": project_id,
        },
    }


@router.get(
    "/chain/{project_id}",
    response_model=dict,
    summary="Retrieve full audit chain for a project",
    description="Retrieve all audit records for a project in ascending sequence order starting from genesis (sequence 0).",
)
def get_audit_chain(
    project_id: str,
    audit_service: AuditService = Depends(get_audit_service),
):
    """Retrieve all audit events forming the project's hash chain."""
    chain = audit_service.get_chain(project_id)
    return {
        "status": "success",
        "data": [e.model_dump() for e in chain],
        "meta": {
            "project_id": project_id,
            "chain_length": len(chain),
        },
    }


@router.post(
    "/chain/verify",
    response_model=dict,
    summary="Verify an audit chain array",
    description="Cryptographically verify a caller-supplied array of audit event records.",
)
def verify_audit_chain_endpoint(
    body: AuditChainVerificationRequest,
    audit_service: AuditService = Depends(get_audit_service),
):
    """Verify cryptographic integrity of a caller-supplied audit event chain."""
    result = audit_service.verify_chain(project_id=body.project_id or "", events=body.events)
    return {
        "status": "success",
        "data": result.model_dump(),
        "meta": {
            "project_id": body.project_id,
            "checked_events": result.checked_events,
            "valid": result.valid,
        },
    }


@router.get(
    "/chain/{project_id}/verify",
    response_model=dict,
    summary="Verify persisted audit chain for a project",
    description="Cryptographically verify the entire persisted audit chain stored in the database for a project.",
)
def verify_persisted_audit_chain(
    project_id: str,
    audit_service: AuditService = Depends(get_audit_service),
):
    """Verify stored audit chain directly from SQLite database."""
    result = audit_service.verify_chain(project_id=project_id)
    return {
        "status": "success",
        "data": result.model_dump(),
        "meta": {
            "project_id": project_id,
            "checked_events": result.checked_events,
            "valid": result.valid,
        },
    }
