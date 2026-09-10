"""Scan Orchestration & SSE Real-Time Progress Router (Phase 5.10).

Exposes:
  - Dataset integrity scan pipeline initiation (sync / async).
  - Scan execution status polling & summary results.
  - Cooperative scan cancellation.
  - Real-time Server-Sent Events (SSE) progress streaming.
"""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from aivara.api.envelope import ApiResponse
from aivara.api.schemas.scans import ScanCreateRequest, ScanReadResponse
from aivara.core.config import settings
from aivara.crypto.keys import KeyManager
from aivara.database.connection import get_db
from aivara.services.orchestration_service import ScanOrchestrationService, ScanTaskManager

router = APIRouter(prefix="/scans", tags=["scans"])


def get_key_manager() -> KeyManager:
    """Dependency provider resolving the local KeyManager instance."""
    return KeyManager(keys_dir=settings.keys_dir)


def get_orchestration_service(
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
) -> ScanOrchestrationService:
    """Dependency provider resolving the ScanOrchestrationService instance."""
    return ScanOrchestrationService(db=db, key_manager=key_manager)


# =====================================================================
# Scan Lifecycle Endpoints
# =====================================================================

@router.post(
    "",
    response_model=ApiResponse[ScanReadResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create and execute a dataset integrity scan",
)
async def create_scan(
    payload: ScanCreateRequest,
    async_mode: bool = Query(False, alias="async", description="Whether to execute asynchronously in background"),
    service: ScanOrchestrationService = Depends(get_orchestration_service),
):
    """Initiate a full or selective dataset integrity scan with evidence and provenance binding."""
    res = service.create_and_start_scan(payload, run_async=async_mode)
    return ApiResponse(data=res)


@router.get(
    "/{scan_id}",
    response_model=ApiResponse[ScanReadResponse],
    status_code=status.HTTP_200_OK,
    summary="Get scan status and results",
)
async def get_scan(
    scan_id: str,
    service: ScanOrchestrationService = Depends(get_orchestration_service),
):
    """Retrieve the current execution state, findings, and provenance for a scan."""
    res = service.get_scan(scan_id)
    return ApiResponse(data=res)


@router.get(
    "",
    response_model=ApiResponse[List[ScanReadResponse]],
    status_code=status.HTTP_200_OK,
    summary="List scans",
)
async def list_scans(
    project_id: Optional[str] = Query(None, description="Filter by project ID"),
    dataset_version_id: Optional[str] = Query(None, description="Filter by dataset version ID"),
    service: ScanOrchestrationService = Depends(get_orchestration_service),
):
    """List in-memory active and recent scans."""
    tasks = service.task_manager.list_tasks(
        project_id=project_id,
        dataset_version_id=dataset_version_id,
    )
    return ApiResponse(data=[t.to_read_response() for t in tasks])


@router.post(
    "/{scan_id}/cancel",
    response_model=ApiResponse[ScanReadResponse],
    status_code=status.HTTP_200_OK,
    summary="Cancel a running scan",
)
async def cancel_scan(
    scan_id: str,
    service: ScanOrchestrationService = Depends(get_orchestration_service),
):
    """Request cooperative cancellation of a running scan pipeline."""
    res = service.cancel_scan(scan_id)
    return ApiResponse(data=res)


@router.get(
    "/{scan_id}/events",
    summary="Stream scan progress via Server-Sent Events (SSE)",
    response_class=StreamingResponse,
)
async def stream_scan_events(
    scan_id: str,
    service: ScanOrchestrationService = Depends(get_orchestration_service),
):
    """Stream real-time scan progress events via SSE without sensitive data exposure."""
    return StreamingResponse(
        service.stream_scan_events(scan_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
