"""FastAPI REST Router for Universal Risk API and Task Integration (Phase 12.10)."""

from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncGenerator, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from fastapi.responses import StreamingResponse

from aivara.api.envelope import ApiResponse
from aivara.core.exceptions import NotFoundException, ValidationException
from aivara.universal.api.schemas import (
    UniversalAssuranceResultResponse,
    UniversalAssuranceTaskCreateRequest,
    UniversalCapabilitiesResponse,
    UniversalProgressEvent,
    UniversalTaskResponse,
)
from aivara.universal.api.service import (
    UniversalAssuranceService,
    UniversalTaskManager,
    get_universal_service,
    get_universal_task_manager,
)

router = APIRouter(
    tags=["Universal Assurance & Risk API"],
)


@router.get(
    "/projects/{project_id}/universal/capabilities",
    summary="Get Universal Assurance subsystem capabilities",
    response_model=ApiResponse[UniversalCapabilitiesResponse],
)
@router.get(
    "/universal/capabilities",
    summary="Get Universal Assurance subsystem capabilities (global)",
    response_model=ApiResponse[UniversalCapabilitiesResponse],
)
def get_universal_capabilities(
    service: UniversalAssuranceService = Depends(get_universal_service),
) -> ApiResponse[UniversalCapabilitiesResponse]:
    """Retrieve supported analysis modalities, graph resource limits, and algorithms."""
    caps = service.get_capabilities()
    return ApiResponse(data=caps)


@router.post(
    "/projects/{project_id}/universal/assurance/tasks",
    summary="Initiate asynchronous universal assurance evaluation",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ApiResponse[UniversalTaskResponse],
)
def create_universal_assurance_task(
    project_id: str,
    request: UniversalAssuranceTaskCreateRequest,
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    service: UniversalAssuranceService = Depends(get_universal_service),
) -> ApiResponse[UniversalTaskResponse]:
    """Submit an asynchronous multi-asset universal assurance task.

    Returns HTTP 202 Accepted with task identifier and initial QUEUED status.
    Supports idempotency via the `Idempotency-Key` header or request body.
    """
    task_response, _ = service.initiate_assurance_task(
        project_id=project_id,
        request=request,
        idempotency_key=idempotency_key,
    )
    return ApiResponse(data=task_response)


@router.post(
    "/universal/assurance/tasks",
    summary="Initiate asynchronous universal assurance evaluation (global route)",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ApiResponse[UniversalTaskResponse],
)
def create_universal_assurance_task_global(
    request: UniversalAssuranceTaskCreateRequest,
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    service: UniversalAssuranceService = Depends(get_universal_service),
) -> ApiResponse[UniversalTaskResponse]:
    """Submit an asynchronous universal assurance task using project_id in body."""
    if not request.project_id:
        raise ValidationException("project_id is required in request body for global task creation.")
    task_response, _ = service.initiate_assurance_task(
        project_id=request.project_id,
        request=request,
        idempotency_key=idempotency_key,
    )
    return ApiResponse(data=task_response)


@router.get(
    "/projects/{project_id}/universal/assurance/tasks/{task_id}",
    summary="Get universal assurance task execution status",
    response_model=ApiResponse[UniversalTaskResponse],
)
def get_universal_task_status(
    project_id: str,
    task_id: str,
    service: UniversalAssuranceService = Depends(get_universal_service),
) -> ApiResponse[UniversalTaskResponse]:
    """Poll execution status, progress percent, and stage of an active or completed task."""
    task_response = service.get_task_status(project_id=project_id, task_id=task_id)
    return ApiResponse(data=task_response)


@router.get(
    "/projects/{project_id}/universal/assurance/tasks/{task_id}/result",
    summary="Get complete universal assurance evaluation result",
    response_model=ApiResponse[UniversalAssuranceResultResponse],
)
def get_universal_task_result(
    project_id: str,
    task_id: str,
    service: UniversalAssuranceService = Depends(get_universal_service),
) -> ApiResponse[UniversalAssuranceResultResponse]:
    """Retrieve full 3-tier hierarchical risk evaluation, proof status, and policy disposition.

    Raises HTTP 409 Conflict if the task has not completed.
    """
    result = service.get_task_result(project_id=project_id, task_id=task_id)
    return ApiResponse(data=result)


@router.post(
    "/projects/{project_id}/universal/assurance/tasks/{task_id}/cancel",
    summary="Cancel an active universal assurance task",
    response_model=ApiResponse[UniversalTaskResponse],
)
def cancel_universal_task(
    project_id: str,
    task_id: str,
    service: UniversalAssuranceService = Depends(get_universal_service),
) -> ApiResponse[UniversalTaskResponse]:
    """Request cooperative cancellation of a queued or running task."""
    task_response = service.cancel_task(project_id=project_id, task_id=task_id)
    return ApiResponse(data=task_response)


@router.get(
    "/projects/{project_id}/universal/assurance/tasks/{task_id}/events",
    summary="Subscribe to universal assurance task progress via Server-Sent Events (SSE)",
    response_class=StreamingResponse,
)
async def stream_universal_task_progress(
    project_id: str,
    task_id: str,
    task_manager: UniversalTaskManager = Depends(get_universal_task_manager),
) -> StreamingResponse:
    """Stream real-time SSE progress events for an active task."""
    task = task_manager.get_task(task_id)
    if not task or task.project_id != project_id:
        raise NotFoundException(f"Assurance task '{task_id}' not found for project '{project_id}'.")

    async def event_generator() -> AsyncGenerator[str, None]:
        q = task.add_event_listener()
        try:
            while True:
                try:
                    event: UniversalProgressEvent = await asyncio.wait_for(q.get(), timeout=20.0)
                    yield f"event: {event.stage.value}\ndata: {event.model_dump_json()}\n\n"
                    if event.stage.value in ("COMPLETED", "FAILED", "CANCELLED"):
                        break
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            task.remove_event_listener(q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get(
    "/projects/{project_id}/universal/risk/{risk_id}",
    summary="Retrieve stored Phase 12.6 Risk Assessment by ID",
    response_model=ApiResponse[Dict[str, Any]],
)
def get_stored_risk(
    project_id: str,
    risk_id: str,
    service: UniversalAssuranceService = Depends(get_universal_service),
) -> ApiResponse[Dict[str, Any]]:
    """Retrieve stored Tier-1 risk assessment without recomputation."""
    data = service.get_stored_risk(project_id=project_id, risk_id=risk_id)
    return ApiResponse(data=data)


@router.get(
    "/projects/{project_id}/universal/decisions/{decision_id}",
    summary="Retrieve stored Phase 12.7 Policy Decision by ID",
    response_model=ApiResponse[Dict[str, Any]],
)
def get_stored_decision(
    project_id: str,
    decision_id: str,
    service: UniversalAssuranceService = Depends(get_universal_service),
) -> ApiResponse[Dict[str, Any]]:
    """Retrieve stored policy decision without recomputation."""
    data = service.get_stored_decision(project_id=project_id, decision_id=decision_id)
    return ApiResponse(data=data)


@router.get(
    "/projects/{project_id}/universal/proof/{proof_id}",
    summary="Retrieve stored Phase 12.8 Proof Assessment by ID",
    response_model=ApiResponse[Dict[str, Any]],
)
def get_stored_proof(
    project_id: str,
    proof_id: str,
    service: UniversalAssuranceService = Depends(get_universal_service),
) -> ApiResponse[Dict[str, Any]]:
    """Retrieve stored cryptographic proof assessment without recomputation."""
    data = service.get_stored_proof(project_id=project_id, proof_id=proof_id)
    return ApiResponse(data=data)


@router.get(
    "/projects/{project_id}/universal/aggregation",
    summary="Retrieve stored Phase 12.9 Project Hierarchical Risk Aggregation",
    response_model=ApiResponse[Dict[str, Any]],
)
def get_stored_aggregation(
    project_id: str,
    service: UniversalAssuranceService = Depends(get_universal_service),
) -> ApiResponse[Dict[str, Any]]:
    """Retrieve stored 3-tier project aggregation result without recomputation."""
    data = service.get_stored_aggregation(project_id=project_id)
    return ApiResponse(data=data)
