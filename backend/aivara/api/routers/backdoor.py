"""FastAPI Router for Backdoor / Trigger Analysis (Phase 9.10).

Thin router exposing endpoints under `/projects/{project_id}/backdoor`:
  - Task submission, status, cancellation, and SSE progress stream
  - Structured queries for candidate, activation, output shift, localization,
    statistical, evidence, and cryptographic provenance results.
"""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, Header, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from aivara.api.envelope import ApiResponse
from aivara.api.schemas.backdoor import (
    BackdoorActivationResponse,
    BackdoorAnalysisRequest,
    BackdoorCandidateSummaryResponse,
    BackdoorEvidenceResponse,
    BackdoorLocalizationResponse,
    BackdoorOutputShiftResponse,
    BackdoorOverallAnalysisResponse,
    BackdoorProvenanceResponse,
    BackdoorStatisticalSummaryResponse,
    BackdoorTaskReadResponse,
)
from aivara.core.config import settings
from aivara.crypto.keys import KeyManager
from aivara.database.connection import get_db
from aivara.services.backdoor_service import BackdoorService

router = APIRouter(prefix="/projects/{project_id}/backdoor", tags=["backdoor-analysis"])


def get_key_manager() -> KeyManager:
    """Dependency resolving local KeyManager instance."""
    return KeyManager(keys_dir=settings.keys_dir)


def get_backdoor_service(
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
) -> BackdoorService:
    """Dependency resolving BackdoorService with injected DB and KeyManager."""
    return BackdoorService(db=db, key_manager=key_manager)


# =====================================================================
# Task Management & SSE
# =====================================================================

@router.post(
    "/tasks",
    response_model=ApiResponse[BackdoorTaskReadResponse],
    status_code=status.HTTP_200_OK,
    summary="Submit a backdoor analysis task",
    description="Initiate a synchronous or asynchronous backdoor trigger evaluation pipeline.",
)
async def submit_task(
    project_id: str,
    payload: BackdoorAnalysisRequest,
    async_mode: bool = Query(False, alias="async", description="Whether to execute asynchronously"),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key", description="Optional client idempotency key"),
    service: BackdoorService = Depends(get_backdoor_service),
):
    """Submit a backdoor analysis task."""
    res = service.create_and_start_analysis(
        project_id=project_id,
        request=payload,
        run_async=async_mode,
        idempotency_key=idempotency_key,
    )
    return ApiResponse(data=res)


@router.get(
    "/tasks/{task_id}",
    response_model=ApiResponse[BackdoorTaskReadResponse],
    status_code=status.HTTP_200_OK,
    summary="Get task status",
    description="Retrieve execution state and progress of an active or completed task.",
)
async def get_task(
    project_id: str,
    task_id: str,
    service: BackdoorService = Depends(get_backdoor_service),
):
    """Retrieve task execution status."""
    res = service.get_task(project_id=project_id, task_id=task_id)
    return ApiResponse(data=res)


@router.get(
    "/tasks",
    response_model=ApiResponse[List[BackdoorTaskReadResponse]],
    status_code=status.HTTP_200_OK,
    summary="List backdoor tasks",
    description="List active and completed tasks for project.",
)
async def list_tasks(
    project_id: str,
    model_id: Optional[str] = Query(None, description="Filter by target model ID"),
    service: BackdoorService = Depends(get_backdoor_service),
):
    """List tasks scoped to project."""
    res = service.list_tasks(project_id=project_id, model_id=model_id)
    return ApiResponse(data=res)


@router.post(
    "/tasks/{task_id}/cancel",
    response_model=ApiResponse[BackdoorTaskReadResponse],
    status_code=status.HTTP_200_OK,
    summary="Cancel running task",
    description="Request cooperative cancellation of an in-flight analysis task.",
)
async def cancel_task(
    project_id: str,
    task_id: str,
    service: BackdoorService = Depends(get_backdoor_service),
):
    """Cancel a task."""
    res = service.cancel_task(project_id=project_id, task_id=task_id)
    return ApiResponse(data=res)


@router.get(
    "/tasks/{task_id}/events",
    summary="Stream task events via SSE",
    response_class=StreamingResponse,
    description="Stream real-time Server-Sent Events for task progress broadcasting.",
)
async def stream_task_events(
    project_id: str,
    task_id: str,
    service: BackdoorService = Depends(get_backdoor_service),
):
    """Stream real-time task progress events."""
    service.get_task(project_id=project_id, task_id=task_id)
    return StreamingResponse(
        service.stream_task_events(project_id=project_id, task_id=task_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# =====================================================================
# Analysis Results Endpoints
# =====================================================================

@router.get(
    "/analyses/{analysis_id}",
    response_model=ApiResponse[BackdoorOverallAnalysisResponse],
    status_code=status.HTTP_200_OK,
    summary="Get overall analysis summary",
    description="Retrieve comprehensive rollup of complete backdoor analysis scan.",
)
async def get_analysis(
    project_id: str,
    analysis_id: str,
    service: BackdoorService = Depends(get_backdoor_service),
):
    """Retrieve overall analysis summary."""
    res = service.get_analysis(project_id=project_id, analysis_id=analysis_id)
    return ApiResponse(data=res)


@router.get(
    "/analyses/{analysis_id}/candidates",
    response_model=ApiResponse[List[BackdoorCandidateSummaryResponse]],
    status_code=status.HTTP_200_OK,
    summary="Get candidate summaries",
    description="Retrieve evaluated candidate summaries for an analysis.",
)
async def get_candidate_summaries(
    project_id: str,
    analysis_id: str,
    service: BackdoorService = Depends(get_backdoor_service),
):
    """Retrieve candidate statistical summaries."""
    res = service.get_candidate_summaries(project_id=project_id, analysis_id=analysis_id)
    return ApiResponse(data=res)


@router.get(
    "/analyses/{analysis_id}/activation",
    response_model=ApiResponse[BackdoorActivationResponse],
    status_code=status.HTTP_200_OK,
    summary="Get activation metrics",
    description="Retrieve clean-vs-triggered activation decisions and metrics.",
)
async def get_activation_results(
    project_id: str,
    analysis_id: str,
    service: BackdoorService = Depends(get_backdoor_service),
):
    """Retrieve activation metrics."""
    res = service.get_activation_results(project_id=project_id, analysis_id=analysis_id)
    return ApiResponse(data=res)


@router.get(
    "/analyses/{analysis_id}/output-shift",
    response_model=ApiResponse[BackdoorOutputShiftResponse],
    status_code=status.HTTP_200_OK,
    summary="Get targeted output shift evaluation",
    description="Retrieve targeted misclassification and output shift metrics.",
)
async def get_output_shift_results(
    project_id: str,
    analysis_id: str,
    service: BackdoorService = Depends(get_backdoor_service),
):
    """Retrieve output shift evaluation."""
    res = service.get_output_shift_results(project_id=project_id, analysis_id=analysis_id)
    return ApiResponse(data=res)


@router.get(
    "/analyses/{analysis_id}/localization",
    response_model=ApiResponse[BackdoorLocalizationResponse],
    status_code=status.HTTP_200_OK,
    summary="Get spatial localization results",
    description="Retrieve spatial grid localization and bounding box attribution.",
)
async def get_localization_results(
    project_id: str,
    analysis_id: str,
    service: BackdoorService = Depends(get_backdoor_service),
):
    """Retrieve spatial localization results."""
    res = service.get_localization_results(project_id=project_id, analysis_id=analysis_id)
    return ApiResponse(data=res)


@router.get(
    "/analyses/{analysis_id}/statistics",
    response_model=ApiResponse[BackdoorStatisticalSummaryResponse],
    status_code=status.HTTP_200_OK,
    summary="Get statistical analysis results",
    description="Retrieve permutation testing, confidence intervals, and BH-FDR multiplicity results.",
)
async def get_statistical_results(
    project_id: str,
    analysis_id: str,
    service: BackdoorService = Depends(get_backdoor_service),
):
    """Retrieve statistical testing results."""
    res = service.get_statistical_results(project_id=project_id, analysis_id=analysis_id)
    return ApiResponse(data=res)


@router.get(
    "/analyses/{analysis_id}/evidence",
    response_model=ApiResponse[List[BackdoorEvidenceResponse]],
    status_code=status.HTTP_200_OK,
    summary="Get bound evidence items",
    description="Retrieve content-addressed sealed evidence records.",
)
async def get_evidence(
    project_id: str,
    analysis_id: str,
    service: BackdoorService = Depends(get_backdoor_service),
):
    """Retrieve sealed evidence records."""
    res = service.get_evidence(project_id=project_id, analysis_id=analysis_id)
    return ApiResponse(data=res)


@router.get(
    "/analyses/{analysis_id}/provenance",
    response_model=ApiResponse[List[BackdoorProvenanceResponse]],
    status_code=status.HTTP_200_OK,
    summary="Get cryptographic provenance records",
    description="Retrieve Ed25519-signed hash-chained provenance records and verification status.",
)
async def get_provenance(
    project_id: str,
    analysis_id: str,
    service: BackdoorService = Depends(get_backdoor_service),
):
    """Retrieve cryptographic provenance records."""
    res = service.get_provenance(project_id=project_id, analysis_id=analysis_id)
    return ApiResponse(data=res)
