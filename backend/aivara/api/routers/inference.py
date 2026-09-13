"""Inference Verification and Assurance REST API Router (Phase 10.11).

Exposes deterministic, project-scoped REST endpoints for:
  - Synchronous & Asynchronous Inference Integrity Verification
  - In-memory Task Management, State Tracking & Cancellation
  - Real-Time Server-Sent Events (SSE) Progress Streaming
  - Sealed Inference Record Listing & Retrieval
  - Record Cryptographic Read-Back Integrity Verification
  - Controlled Replay & Consistency Verification
  - Evidence and Provenance Record Retrieval
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncGenerator, Dict, List, Optional, Union
from fastapi import APIRouter, BackgroundTasks, Depends, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from aivara.api.envelope import ApiResponse
from aivara.api.schemas.inference import (
    FindingSummaryItem,
    InferenceProgressEvent,
    InferenceRecordReadResponse,
    InferenceRecordVerifyResponse,
    InferenceReplayRequest,
    InferenceReplayResponse,
    InferenceTaskReadResponse,
    InferenceTaskStageEnum,
    InferenceVerificationRequest,
    InferenceVerificationResponse,
)
from aivara.core.config import settings
from aivara.core.exceptions import NotFoundException, ValidationException
from aivara.core.logging import get_logger
from aivara.crypto.keys import KeyManager
from aivara.database.connection import get_db
from aivara.domain.schemas import ProvenanceRecordRead
from aivara.services.inference_service import InferenceService, InferenceTaskManager, get_task_manager

logger = get_logger("aivara.api.routers.inference")

router = APIRouter(tags=["inference"])


def get_key_manager() -> KeyManager:
    """Dependency resolving the local KeyManager instance."""
    return KeyManager(keys_dir=settings.keys_dir)


def _convert_task_to_response(task: Any) -> InferenceTaskReadResponse:
    """Helper to convert an in-memory task to an API response schema."""
    if hasattr(task, "to_read_response"):
        return task.to_read_response()
    if isinstance(task, InferenceTaskReadResponse):
        return task
    return InferenceTaskReadResponse.model_validate(task)


# =====================================================================
# 1. Inference Verification (Sync & Async)
# =====================================================================

@router.post(
    "/projects/{project_id}/inference/verify",
    response_model=ApiResponse[Union[InferenceVerificationResponse, InferenceTaskReadResponse]],
    status_code=status.HTTP_200_OK,
    summary="Execute or enqueue end-to-end inference verification",
)
def verify_inference(
    project_id: str,
    request: InferenceVerificationRequest,
    async_mode: bool = Query(False, description="Whether to enqueue for asynchronous execution"),
    idempotency_key: Optional[str] = Query(None, description="Client-provided idempotency key"),
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
    task_manager: InferenceTaskManager = Depends(get_task_manager),
) -> ApiResponse[Union[InferenceVerificationResponse, InferenceTaskReadResponse]]:
    """Initiate synchronous or asynchronous inference verification pipeline."""
    service = InferenceService(db=db, key_manager=key_manager, task_manager=task_manager)
    res = service.create_and_start_verification(
        project_id=project_id,
        request=request,
        run_async=async_mode,
        idempotency_key=idempotency_key,
    )
    return ApiResponse(data=res)


# =====================================================================
# 2. Task Management & In-Memory Registry Endpoints
# =====================================================================

@router.get(
    "/projects/{project_id}/inference/tasks",
    response_model=ApiResponse[List[InferenceTaskReadResponse]],
    status_code=status.HTTP_200_OK,
    summary="List inference verification tasks",
)
def list_inference_tasks(
    project_id: str,
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status"),
    task_manager: InferenceTaskManager = Depends(get_task_manager),
) -> ApiResponse[List[InferenceTaskReadResponse]]:
    """List in-memory tasks for a project."""
    tasks = task_manager.list_tasks(project_id=project_id)
    if status_filter:
        tasks = [t for t in tasks if t.status.value.upper() == status_filter.upper()]

    return ApiResponse(data=[_convert_task_to_response(t) for t in tasks])


@router.get(
    "/projects/{project_id}/inference/tasks/{task_id}",
    response_model=ApiResponse[InferenceTaskReadResponse],
    status_code=status.HTTP_200_OK,
    summary="Get inference verification task status",
)
def get_inference_task(
    project_id: str,
    task_id: str,
    task_manager: InferenceTaskManager = Depends(get_task_manager),
) -> ApiResponse[InferenceTaskReadResponse]:
    """Retrieve an active or finished task."""
    task = task_manager.get_task(task_id)
    if not task or task.project_id != project_id:
        raise NotFoundException(f"InferenceTask '{task_id}' not found.")
    return ApiResponse(data=_convert_task_to_response(task))


@router.post(
    "/projects/{project_id}/inference/tasks/{task_id}/cancel",
    response_model=ApiResponse[InferenceTaskReadResponse],
    status_code=status.HTTP_200_OK,
    summary="Cancel inference verification task",
)
def cancel_inference_task(
    project_id: str,
    task_id: str,
    task_manager: InferenceTaskManager = Depends(get_task_manager),
) -> ApiResponse[InferenceTaskReadResponse]:
    """Cancel an active task."""
    task = task_manager.get_task(task_id)
    if not task or task.project_id != project_id:
        raise NotFoundException(f"InferenceTask '{task_id}' not found.")

    task_manager.cancel_task(task_id)
    updated_task = task_manager.get_task(task_id)
    return ApiResponse(data=_convert_task_to_response(updated_task))


@router.get(
    "/projects/{project_id}/inference/tasks/{task_id}/events",
    summary="Subscribe to task progress via Server-Sent Events (SSE)",
    response_class=StreamingResponse,
)
async def stream_task_progress(
    project_id: str,
    task_id: str,
    task_manager: InferenceTaskManager = Depends(get_task_manager),
) -> StreamingResponse:
    """Stream real-time SSE progress events for an active task."""
    task = task_manager.get_task(task_id)
    if not task or task.project_id != project_id:
        raise NotFoundException("InferenceTask", task_id)

    async def event_generator() -> AsyncGenerator[str, None]:
        queue = task_manager.subscribe_events(task_id)
        if queue is None:
            return
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield f"event: progress\ndata: {event.model_dump_json()}\n\n"
                    # Check if terminal
                    stage_val = event.stage.value if hasattr(event.stage, "value") else str(event.stage)
                    if stage_val in ("COMPLETED", "FAILED", "CANCELLED"):
                        break
                except asyncio.TimeoutError:
                    # Keepalive ping
                    yield ": ping\n\n"
                    current_task = task_manager.get_task(task_id)
                    if not current_task:
                        break
                    cur_stage = current_task.status.value if hasattr(current_task.status, "value") else str(current_task.status)
                    if cur_stage in ("COMPLETED", "FAILED", "CANCELLED"):
                        break
        finally:
            task_manager.unsubscribe_events(task_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# =====================================================================
# 3. Sealed Record Management & Read-Back Verification
# =====================================================================

@router.get(
    "/projects/{project_id}/inference/records",
    response_model=ApiResponse[List[InferenceRecordReadResponse]],
    status_code=status.HTTP_200_OK,
    summary="List sealed inference records",
)
def list_inference_records(
    project_id: str,
    model_id: Optional[str] = Query(None, description="Filter by model ID"),
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=500, description="Max records to return"),
    offset: int = Query(0, ge=0, description="Record offset"),
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
) -> ApiResponse[List[InferenceRecordReadResponse]]:
    """List persisted inference records for a project."""
    service = InferenceService(db=db, key_manager=key_manager)
    records = service.list_records(
        project_id=project_id,
        model_id=model_id,
        status=status,
        limit=limit,
        offset=offset,
    )
    return ApiResponse(data=records)


@router.get(
    "/projects/{project_id}/inference/records/{record_id}",
    response_model=ApiResponse[InferenceRecordReadResponse],
    status_code=status.HTTP_200_OK,
    summary="Get sealed inference record by ID",
)
def get_inference_record(
    project_id: str,
    record_id: str,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
) -> ApiResponse[InferenceRecordReadResponse]:
    """Retrieve a single sealed inference record."""
    service = InferenceService(db=db, key_manager=key_manager)
    record = service.get_record(project_id=project_id, record_id=record_id)
    return ApiResponse(data=record)


@router.post(
    "/projects/{project_id}/inference/records/{record_id}/verify",
    response_model=ApiResponse[InferenceRecordVerifyResponse],
    status_code=status.HTTP_200_OK,
    summary="Verify cryptographic integrity of stored inference record",
)
def verify_record_integrity(
    project_id: str,
    record_id: str,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
) -> ApiResponse[InferenceRecordVerifyResponse]:
    """Verify cryptographic integrity of stored inference record."""
    service = InferenceService(db=db, key_manager=key_manager)
    verification = service.verify_record(project_id=project_id, record_id=record_id)
    return ApiResponse(data=verification)


# =====================================================================
# 4. Controlled Replay Verification
# =====================================================================

@router.post(
    "/projects/{project_id}/inference/records/{record_id}/replay",
    response_model=ApiResponse[InferenceReplayResponse],
    status_code=status.HTTP_200_OK,
    summary="Execute controlled replay verification on stored record",
)
def replay_inference_record(
    project_id: str,
    record_id: str,
    payload: Optional[InferenceReplayRequest] = None,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
) -> ApiResponse[InferenceReplayResponse]:
    """Execute controlled replay on an existing record."""
    service = InferenceService(db=db, key_manager=key_manager)
    res = service.replay_record(
        project_id=project_id,
        record_id=record_id,
        request=payload or InferenceReplayRequest(),
    )
    return ApiResponse(data=res)


# =====================================================================
# 5. Linked Evidence & Provenance Retrieval
# =====================================================================

@router.get(
    "/projects/{project_id}/inference/records/{record_id}/evidence",
    response_model=ApiResponse[List[Any]],
    status_code=status.HTTP_200_OK,
    summary="Retrieve linked Phase 4/10 evidence items for record",
)
def get_record_evidence(
    project_id: str,
    record_id: str,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
) -> ApiResponse[List[Any]]:
    """Retrieve evidence items linked to the inference record."""
    service = InferenceService(db=db, key_manager=key_manager)
    evidence_items = service.get_record_evidence(project_id=project_id, record_id=record_id)
    return ApiResponse(data=evidence_items)


@router.get(
    "/projects/{project_id}/inference/records/{record_id}/provenance",
    response_model=ApiResponse[Optional[ProvenanceRecordRead]],
    status_code=status.HTTP_200_OK,
    summary="Retrieve linked Phase 4 provenance chain record",
)
def get_record_provenance(
    project_id: str,
    record_id: str,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
) -> ApiResponse[Optional[ProvenanceRecordRead]]:
    """Retrieve provenance record linked to the inference record."""
    service = InferenceService(db=db, key_manager=key_manager)
    provenance = service.get_record_provenance(project_id=project_id, record_id=record_id)
    return ApiResponse(data=provenance)


# =====================================================================
# 6. Global Fallback / Legacy Route
# =====================================================================

@router.get("/inference/records", response_model=ApiResponse[list], tags=["inference"])
async def list_inference_records_legacy():
    """List sealed inference records (legacy global endpoint)."""
    return ApiResponse(data=[])
