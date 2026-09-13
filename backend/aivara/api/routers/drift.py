"""Distribution Shift & Data Drift API Router (Phase 11.10).

Exposes asynchronous REST endpoints and Server-Sent Events (SSE) streaming for
distribution shift analysis across population datasets and models.

Endpoints:
  - POST /api/v1/projects/{project_id}/drift/analyses (202 Accepted)
  - GET  /api/v1/projects/{project_id}/drift/analyses/{analysis_id} (200 OK)
  - GET  /api/v1/projects/{project_id}/drift/analyses/{analysis_id}/result (200 OK)
  - POST /api/v1/projects/{project_id}/drift/analyses/{analysis_id}/cancel (200 OK)
  - GET  /api/v1/projects/{project_id}/drift/analyses/{analysis_id}/events (SSE)
  - GET  /api/v1/projects/{project_id}/drift/capabilities (200 OK)
"""

from __future__ import annotations

import asyncio
from typing import AsyncGenerator, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.responses import StreamingResponse

from aivara.api.envelope import ApiResponse
from aivara.api.schemas.drift import (
    DriftAnalysisCreateRequest,
    DriftAnalysisResultResponse,
    DriftCapabilitiesResponse,
    DriftTaskResponse,
)
from aivara.core.exceptions import (
    NotFoundException,
    ValidationException,
)

from aivara.services.drift_service import (
    DriftService,
    DriftTaskManager,
    get_drift_service,
    get_drift_task_manager,
)

router = APIRouter(
    tags=["Distribution Shift & Drift Analysis"],
)


@router.get(
    "/projects/{project_id}/drift/capabilities",
    summary="Get distribution shift subsystem capabilities",
    response_model=ApiResponse[DriftCapabilitiesResponse],
)
def get_drift_capabilities(
    project_id: str,
    service: DriftService = Depends(get_drift_service),
) -> ApiResponse[DriftCapabilitiesResponse]:
    """Retrieve supported analysis types, statistical methods, and resource boundaries."""
    capabilities = service.get_capabilities()
    return ApiResponse(data=capabilities)


@router.post(
    "/projects/{project_id}/drift/analyses",
    summary="Initiate asynchronous distribution shift analysis",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ApiResponse[DriftTaskResponse],
)
def create_drift_analysis(
    project_id: str,
    request: DriftAnalysisCreateRequest,
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    service: DriftService = Depends(get_drift_service),
) -> ApiResponse[DriftTaskResponse]:
    """Submit an asynchronous distribution shift analysis task.

    Returns HTTP 202 Accepted with the task identifier and initial QUEUED status.
    Supports idempotency via the `Idempotency-Key` header.
    """
    if idempotency_key and not request.idempotency_key:
        request = request.model_copy(update={"idempotency_key": idempotency_key})

    task_response, is_new = service.initiate_analysis(project_id=project_id, request=request)
    return ApiResponse(data=task_response)


@router.get(
    "/projects/{project_id}/drift/analyses/{analysis_id}",
    summary="Get drift analysis task execution status",
    response_model=ApiResponse[DriftTaskResponse],
)
def get_drift_analysis_status(
    project_id: str,
    analysis_id: str,
    service: DriftService = Depends(get_drift_service),
) -> ApiResponse[DriftTaskResponse]:
    """Poll the execution status, progress percent, and stage of an active or completed task."""
    task_response = service.get_analysis_task(project_id=project_id, task_id=analysis_id)
    return ApiResponse(data=task_response)


@router.get(
    "/projects/{project_id}/drift/analyses/{analysis_id}/result",
    summary="Get complete drift analysis result",
    response_model=ApiResponse[DriftAnalysisResultResponse],
)
def get_drift_analysis_result(
    project_id: str,
    analysis_id: str,
    service: DriftService = Depends(get_drift_service),
) -> ApiResponse[DriftAnalysisResultResponse]:
    """Retrieve full statistical drift results, findings, and assurance profile.

    Raises HTTP 409 Conflict if the task has not completed.
    """
    result = service.get_analysis_result(project_id=project_id, task_id=analysis_id)
    return ApiResponse(data=result)


@router.post(
    "/projects/{project_id}/drift/analyses/{analysis_id}/cancel",
    summary="Cancel an active drift analysis task",
    response_model=ApiResponse[DriftTaskResponse],
)
def cancel_drift_analysis(
    project_id: str,
    analysis_id: str,
    service: DriftService = Depends(get_drift_service),
) -> ApiResponse[DriftTaskResponse]:
    """Request cooperative cancellation of a queued or running task."""
    task_response = service.cancel_analysis_task(project_id=project_id, task_id=analysis_id)
    return ApiResponse(data=task_response)


@router.get(
    "/projects/{project_id}/drift/analyses/{analysis_id}/events",
    summary="Subscribe to drift task progress via Server-Sent Events (SSE)",
    response_class=StreamingResponse,
)
async def stream_drift_task_progress(
    project_id: str,
    analysis_id: str,
    last_event_id: Optional[str] = Header(None, alias="Last-Event-ID"),
    task_manager: DriftTaskManager = Depends(get_drift_task_manager),
) -> StreamingResponse:
    """Stream real-time SSE progress events for an active task.

    Supports reconnect replay via the `Last-Event-ID` header.
    """
    task = task_manager.get_task(analysis_id)
    if not task or task.project_id != project_id:
        raise NotFoundException(f"Drift analysis task '{analysis_id}' not found.")

    async def event_generator() -> AsyncGenerator[str, None]:
        queue = task_manager.subscribe_events(analysis_id, last_event_id=last_event_id)
        if queue is None:
            return
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield f"event: progress\ndata: {event.model_dump_json()}\n\n"
                    # Check terminal state
                    stage_val = event.stage.value if hasattr(event.stage, "value") else str(event.stage)
                    if stage_val in ("COMPLETED", "FAILED", "CANCELLED"):
                        break
                except asyncio.TimeoutError:
                    # Keepalive ping
                    yield ": ping\n\n"
                    cur_task = task_manager.get_task(analysis_id)
                    if not cur_task:
                        break
                    cur_status = cur_task.status.value if hasattr(cur_task.status, "value") else str(cur_task.status)
                    if cur_status in ("COMPLETED", "FAILED", "CANCELLED"):
                        break
        finally:
            task_manager.unsubscribe_events(analysis_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
