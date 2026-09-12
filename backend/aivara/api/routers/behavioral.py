"""Behavioral Analysis REST API Router (Phase 8.8).

Exposes deterministic, project-scoped REST endpoints for:
  - Baseline creation, retrieval, and observation comparability checks (Phase 8.3)
  - Controlled perturbation experiments (Phase 8.4)
  - Repeatability, sensitivity, and reference output stability analysis (Phase 8.5)
  - Statistical anomaly detection with directional thresholds and explanations (Phase 8.6)
  - Evidence synthesis and cryptographic provenance sealing (Phase 8.7)
  - Provenance ledger verification with diagnostic verification vectors (Phase 4 / 8.7)
  - Integrated assessment execution, in-memory task tracking, cooperative cancellation, and SSE progress broadcasting.
"""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, Header, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from aivara.api.envelope import ApiResponse
from aivara.api.schemas.behavioral import (
    AnomalyDetectionRequest,
    AnomalyDetectionResponse,
    BaselineCompareRequest,
    BaselineCompareResponse,
    BaselineCreateRequest,
    BaselineReadResponse,
    BehavioralAssessmentRequest,
    BehavioralEvidenceBindRequest,
    BehavioralEvidenceBindResponse,
    BehavioralEvidenceReadResponse,
    BehavioralProvenanceVerificationResponse,
    BehavioralTaskReadResponse,
    PerturbationExperimentRequest,
    PerturbationExperimentResponse,
    RepeatabilityAnalysisRequest,
    RepeatabilityAnalysisResponse,
    SensitivityAnalysisRequest,
    SensitivityAnalysisResponse,
    StabilityCompareRequest,
    StabilityCompareResponse,
)
from aivara.core.config import settings
from aivara.crypto.keys import KeyManager
from aivara.database.connection import get_db
from aivara.services.behavioral_service import BehavioralService

router = APIRouter(prefix="/projects/{project_id}/behavioral", tags=["behavioral-analysis"])


def get_key_manager() -> KeyManager:
    """Dependency resolving local KeyManager instance."""
    return KeyManager(keys_dir=settings.keys_dir)


def get_behavioral_service(
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
) -> BehavioralService:
    """Dependency resolving BehavioralService with injected DB and KeyManager."""
    return BehavioralService(db=db, key_manager=key_manager)


# =====================================================================
# 1. Behavioral Baselines
# =====================================================================

@router.post(
    "/baselines",
    response_model=ApiResponse[BaselineReadResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create a behavioral baseline profile",
    description="Compute and register a deterministic behavioral reference baseline profile for a model.",
)
async def create_baseline(
    project_id: str,
    payload: BaselineCreateRequest,
    service: BehavioralService = Depends(get_behavioral_service),
):
    """Create a new deterministic baseline profile from reference observations."""
    res = service.create_baseline(project_id=project_id, request=payload)
    return ApiResponse(data=res)


@router.get(
    "/baselines/{baseline_id}",
    response_model=ApiResponse[BaselineReadResponse],
    status_code=status.HTTP_200_OK,
    summary="Retrieve a behavioral baseline profile",
    description="Retrieve a stored behavioral baseline profile by unique identifier.",
)
async def get_baseline(
    project_id: str,
    baseline_id: str,
    service: BehavioralService = Depends(get_behavioral_service),
):
    """Retrieve an existing baseline profile."""
    res = service.get_baseline(project_id=project_id, baseline_id=baseline_id)
    return ApiResponse(data=res)


@router.post(
    "/baselines/{baseline_id}/compare",
    response_model=ApiResponse[BaselineCompareResponse],
    status_code=status.HTTP_200_OK,
    summary="Compare observation against baseline",
    description="Evaluate structural and task-type compatibility between an observation and a reference baseline.",
)
async def compare_baseline(
    project_id: str,
    baseline_id: str,
    payload: BaselineCompareRequest,
    service: BehavioralService = Depends(get_behavioral_service),
):
    """Validate comparability of a candidate observation against a baseline profile."""
    res = service.compare_baseline(project_id=project_id, baseline_id=baseline_id, request=payload)
    return ApiResponse(data=res)


# =====================================================================
# 2. Controlled Perturbations
# =====================================================================

@router.post(
    "/perturbations/experiment",
    response_model=ApiResponse[PerturbationExperimentResponse],
    status_code=status.HTTP_200_OK,
    summary="Execute controlled perturbation experiment",
    description="Apply deterministic controlled perturbation (noise, blur, compression, etc.) to an input array.",
)
async def run_perturbation_experiment(
    project_id: str,
    payload: PerturbationExperimentRequest,
    service: BehavioralService = Depends(get_behavioral_service),
):
    """Run a deterministic controlled input perturbation experiment."""
    res = service.run_perturbation_experiment(project_id=project_id, request=payload)
    return ApiResponse(data=res)


# =====================================================================
# 3. Output Consistency & Stability
# =====================================================================

@router.post(
    "/stability/repeatability",
    response_model=ApiResponse[RepeatabilityAnalysisResponse],
    status_code=status.HTTP_200_OK,
    summary="Evaluate repeatability across identical executions",
    description="Measure output divergence, agreement, and bitwise determinism across multiple identical runs.",
)
async def analyze_repeatability(
    project_id: str,
    payload: RepeatabilityAnalysisRequest,
    service: BehavioralService = Depends(get_behavioral_service),
):
    """Analyze repeatability metrics across repeated executions."""
    res = service.analyze_repeatability(project_id=project_id, request=payload)
    return ApiResponse(data=res)


@router.post(
    "/stability/sensitivity",
    response_model=ApiResponse[SensitivityAnalysisResponse],
    status_code=status.HTTP_200_OK,
    summary="Evaluate perturbation sensitivity ratio",
    description="Measure output distance relative to input perturbation distance with exact zero-denominator safety.",
)
async def analyze_sensitivity(
    project_id: str,
    payload: SensitivityAnalysisRequest,
    service: BehavioralService = Depends(get_behavioral_service),
):
    """Analyze perturbation sensitivity and local Lipschitz stability."""
    res = service.analyze_sensitivity(project_id=project_id, request=payload)
    return ApiResponse(data=res)


@router.post(
    "/stability/compare",
    response_model=ApiResponse[StabilityCompareResponse],
    status_code=status.HTTP_200_OK,
    summary="Compare stability against reference model output",
    description="Evaluate output consistency and metric divergence between candidate and reference model executions.",
)
async def compare_stability(
    project_id: str,
    payload: StabilityCompareRequest,
    service: BehavioralService = Depends(get_behavioral_service),
):
    """Compare outputs between candidate and reference models."""
    res = service.compare_stability(project_id=project_id, request=payload)
    return ApiResponse(data=res)


# =====================================================================
# 4. Behavioral Anomaly Detection
# =====================================================================

@router.post(
    "/anomalies/detect",
    response_model=ApiResponse[AnomalyDetectionResponse],
    status_code=status.HTTP_200_OK,
    summary="Detect statistical behavioral anomalies",
    description="Evaluate observed measurements against a baseline using robust statistics (median, MAD, robust Z-scores).",
)
async def detect_anomalies(
    project_id: str,
    payload: AnomalyDetectionRequest,
    service: BehavioralService = Depends(get_behavioral_service),
):
    """Execute statistical anomaly analysis. Semantic invariant: ANOMALOUS != MALICIOUS."""
    res = service.detect_anomalies(project_id=project_id, request=payload)
    return ApiResponse(data=res)


@router.get(
    "/anomalies/{analysis_id}",
    response_model=ApiResponse[AnomalyDetectionResponse],
    status_code=status.HTTP_200_OK,
    summary="Retrieve behavioral anomaly analysis",
    description="Retrieve a stored behavioral anomaly analysis result by identifier.",
)
async def get_anomaly_analysis(
    project_id: str,
    analysis_id: str,
    service: BehavioralService = Depends(get_behavioral_service),
):
    """Retrieve stored anomaly analysis."""
    res = service.get_anomaly_analysis(project_id=project_id, analysis_id=analysis_id)
    return ApiResponse(data=res)


# =====================================================================
# 5. Evidence & Provenance Binding
# =====================================================================

@router.post(
    "/evidence/bind",
    response_model=ApiResponse[BehavioralEvidenceBindResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Synthesize findings and bind sealed cryptographic evidence",
    description="Synthesize finding and cryptographically bind evidence into Phase 4 hash-linked provenance ledger.",
)
async def bind_evidence(
    project_id: str,
    payload: BehavioralEvidenceBindRequest,
    service: BehavioralService = Depends(get_behavioral_service),
):
    """Bind behavioral evidence and seal provenance in ledger."""
    res = service.bind_evidence(project_id=project_id, request=payload)
    return ApiResponse(data=res)


@router.get(
    "/evidence/{evidence_id}",
    response_model=ApiResponse[BehavioralEvidenceReadResponse],
    status_code=status.HTTP_200_OK,
    summary="Retrieve sealed behavioral evidence item",
    description="Retrieve an immutable, content-addressed behavioral evidence item.",
)
async def get_evidence(
    project_id: str,
    evidence_id: str,
    service: BehavioralService = Depends(get_behavioral_service),
):
    """Retrieve sealed evidence record."""
    res = service.get_evidence(project_id=project_id, evidence_id=evidence_id)
    return ApiResponse(data=res)


# =====================================================================
# 6. Provenance Verification
# =====================================================================

@router.get(
    "/provenance/{target_id}",
    response_model=ApiResponse[BehavioralProvenanceVerificationResponse],
    status_code=status.HTTP_200_OK,
    summary="Verify cryptographic provenance of behavioral commitments",
    description="Perform Ed25519 signature, hash-linked chain, sequence, and nonce replay verification.",
)
async def verify_provenance(
    project_id: str,
    target_id: str,
    service: BehavioralService = Depends(get_behavioral_service),
):
    """Verify cryptographic provenance ledger sealing for finding or model."""
    res = service.verify_provenance(project_id=project_id, target_id=target_id)
    return ApiResponse(data=res)


# =====================================================================
# 7. Integrated Assessment, Tasks & SSE
# =====================================================================

@router.post(
    "/assessments",
    response_model=ApiResponse[BehavioralTaskReadResponse],
    status_code=status.HTTP_200_OK,
    summary="Submit integrated behavioral assessment workflow",
    description="Execute or dispatch full behavioral analysis pipeline (baseline -> anomaly -> evidence -> provenance).",
)
async def submit_assessment(
    project_id: str,
    payload: BehavioralAssessmentRequest,
    async_mode: bool = Query(False, alias="async", description="Whether to run asynchronously in background"),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key", description="Optional client idempotency key"),
    service: BehavioralService = Depends(get_behavioral_service),
):
    """Initiate synchronous or asynchronous behavioral assessment pipeline."""
    res = service.create_and_start_assessment(
        project_id=project_id,
        request=payload,
        run_async=async_mode,
        idempotency_key=idempotency_key,
    )
    return ApiResponse(data=res)


@router.get(
    "/tasks/{task_id}",
    response_model=ApiResponse[BehavioralTaskReadResponse],
    status_code=status.HTTP_200_OK,
    summary="Get behavioral task execution status",
    description="Poll current execution status and results of an in-memory behavioral task.",
)
async def get_task(
    project_id: str,
    task_id: str,
    service: BehavioralService = Depends(get_behavioral_service),
):
    """Retrieve task state."""
    res = service.get_task(project_id=project_id, task_id=task_id)
    return ApiResponse(data=res)


@router.get(
    "/tasks",
    response_model=ApiResponse[List[BehavioralTaskReadResponse]],
    status_code=status.HTTP_200_OK,
    summary="List behavioral tasks for project",
    description="List active and completed behavioral tasks scoped to project.",
)
async def list_tasks(
    project_id: str,
    model_id: Optional[str] = Query(None, description="Filter by model ID"),
    service: BehavioralService = Depends(get_behavioral_service),
):
    """List in-memory tasks."""
    res = service.list_tasks(project_id=project_id, model_id=model_id)
    return ApiResponse(data=res)


@router.post(
    "/tasks/{task_id}/cancel",
    response_model=ApiResponse[BehavioralTaskReadResponse],
    status_code=status.HTTP_200_OK,
    summary="Cancel a running behavioral task",
    description="Request cooperative cancellation of an in-flight behavioral assessment pipeline.",
)
async def cancel_task(
    project_id: str,
    task_id: str,
    service: BehavioralService = Depends(get_behavioral_service),
):
    """Request cooperative task cancellation."""
    res = service.cancel_task(project_id=project_id, task_id=task_id)
    return ApiResponse(data=res)


@router.get(
    "/tasks/{task_id}/events",
    summary="Stream task progress via Server-Sent Events (SSE)",
    response_class=StreamingResponse,
    description="Subscribe to real-time progress broadcast events for a behavioral task.",
)
async def stream_task_events(
    project_id: str,
    task_id: str,
    service: BehavioralService = Depends(get_behavioral_service),
):
    """Stream real-time SSE progress events."""
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
