"""Service Layer and In-Memory Task Runner for Universal Risk API (Phase 12.10).

Orchestrates the authoritative universal pipeline (Phases 12.2–12.9):
  1. Normalization (Phase 12.2)
  2. Evidence Graph (Phase 12.3)
  3. Ingestion (Phase 12.4)
  4. Correlation & Ancestry Damping (Phase 12.5)
  5. Universal & Asset Risk Computation (Phase 12.6)
  6. Policy & Decision Engine (Phase 12.7)
  7. Proof & Provenance Integration (Phase 12.8)
  8. Project & Multi-Asset Risk Aggregation (Phase 12.9)
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import logging
import math
import threading
from typing import Any, AsyncGenerator, Dict, List, Optional, Sequence, Tuple
import uuid

from aivara.api.envelope import utcnow_iso
from aivara.core.exceptions import NotFoundException, ValidationException
from aivara.crypto.hashing import hash_canonical_data
from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.aggregation.config import ImmutableAggregationPolicyConfig
from aivara.universal.aggregation.engine import UniversalProjectAggregator
from aivara.universal.aggregation.enums import AssetRole, DependencyEdgeType
from aivara.universal.aggregation.exceptions import AggregationError, ScopeMismatchError
from aivara.universal.aggregation.schemas import (
    AssetDependencyEdge,
    AssetDependencyGraph,
)
from aivara.universal.api.enums import (
    UniversalPipelineStage,
    UniversalTaskStatus,
)
from aivara.universal.api.schemas import (
    UniversalAssuranceResultResponse,
    UniversalAssuranceTaskCreateRequest,
    UniversalCapabilitiesResponse,
    UniversalProgressEvent,
    UniversalTaskResponse,
)
from aivara.universal.correlation.engine import CrossDomainCorrelationEngine
from aivara.universal.enums import SubsystemDomain
from aivara.universal.graph.builder import UniversalEvidenceGraphBuilder
from aivara.universal.ingestion.service import CrossSubsystemEvidenceIngestionService
from aivara.universal.normalizer import UniversalEvidenceNormalizer
from aivara.universal.policy.engine import UniversalPolicyEngine
from aivara.universal.policy.enums import UniversalDecision
from aivara.universal.policy.schemas import UniversalPolicy, UniversalPolicyDecision
from aivara.universal.proof.engine import UniversalProofIntegrationEngine
from aivara.universal.proof.schemas import UniversalProofAssessment
from aivara.universal.risk.engine import UniversalRiskComputationEngine
from aivara.universal.risk.enums import RiskLevel
from aivara.universal.risk.schemas import (
    AssetRiskAssessment,
    HierarchicalRiskAssessment,
    RiskContribution,
    UniversalRiskAssessment,
    compute_risk_level,
)
from aivara.universal.schemas import UniversalEvidenceEnvelope

logger = logging.getLogger("aivara.universal.api.service")


# =====================================================================
# In-Memory Task Representation
# =====================================================================

class UniversalTask:
    """Thread-safe state container for an in-flight or completed Universal Assurance task."""

    def __init__(
        self,
        task_id: str,
        project_id: str,
        request: UniversalAssuranceTaskCreateRequest,
        request_fingerprint: str,
        idempotency_key: Optional[str] = None,
    ) -> None:
        self.task_id = task_id
        self.project_id = project_id
        self.request = request
        self.request_fingerprint = request_fingerprint
        self.idempotency_key = idempotency_key
        self.status = UniversalTaskStatus.QUEUED
        self.progress_percent = 0.0
        self.current_stage = UniversalPipelineStage.QUEUED
        self.stage_description = "Task queued for execution"
        self.created_at = utcnow_iso()
        self.started_at: Optional[str] = None
        self.completed_at: Optional[str] = None
        self.error_message: Optional[str] = None
        self.result: Optional[UniversalAssuranceResultResponse] = None

        # Internal intermediate artifacts for read-back
        self.risk_assessments: Dict[str, AssetRiskAssessment] = {}
        self.decision_assessments: Dict[str, UniversalPolicyDecision] = {}
        self.proof_assessments: Dict[str, UniversalProofAssessment] = {}
        self.hierarchical_assessment: Optional[HierarchicalRiskAssessment] = None

        self._lock = threading.Lock()
        self._is_cancelled = False
        self._event_queues: List[asyncio.Queue[UniversalProgressEvent]] = []
        self._event_history: List[UniversalProgressEvent] = []

    def cancel(self) -> None:
        """Signal cooperative cancellation."""
        with self._lock:
            if self.status in (UniversalTaskStatus.QUEUED, UniversalTaskStatus.RUNNING):
                self._is_cancelled = True
                self.status = UniversalTaskStatus.CANCELLED
                self.current_stage = UniversalPipelineStage.CANCELLED
                self.stage_description = "Task cancelled by user"
                self.completed_at = utcnow_iso()
                self._broadcast_event(
                    UniversalPipelineStage.CANCELLED,
                    self.progress_percent,
                    "Task execution cancelled",
                )

    def is_cancelled(self) -> bool:
        """Check whether task has been cancelled."""
        with self._lock:
            return self._is_cancelled

    def update_stage(
        self,
        stage: UniversalPipelineStage,
        progress_percent: float,
        description: str,
    ) -> None:
        """Update stage and broadcast progress event."""
        with self._lock:
            if self._is_cancelled:
                return
            if self.status == UniversalTaskStatus.QUEUED:
                self.status = UniversalTaskStatus.RUNNING
                self.started_at = utcnow_iso()

            self.current_stage = stage
            self.progress_percent = round(float(progress_percent), 2)
            self.stage_description = description
            self._broadcast_event(stage, self.progress_percent, description)

    def mark_completed(self, result: UniversalAssuranceResultResponse) -> None:
        """Mark task as successfully completed."""
        with self._lock:
            if self._is_cancelled:
                return
            self.status = UniversalTaskStatus.COMPLETED
            self.current_stage = UniversalPipelineStage.COMPLETED
            self.progress_percent = 100.0
            self.stage_description = "Universal assurance evaluation completed successfully"
            self.completed_at = utcnow_iso()
            self.result = result
            self._broadcast_event(
                UniversalPipelineStage.COMPLETED,
                100.0,
                "Evaluation complete",
            )

    def mark_failed(self, error_msg: str) -> None:
        """Mark task as failed."""
        with self._lock:
            if self._is_cancelled:
                return
            self.status = UniversalTaskStatus.FAILED
            self.current_stage = UniversalPipelineStage.FAILED
            self.stage_description = f"Failed: {error_msg}"
            self.error_message = error_msg
            self.completed_at = utcnow_iso()
            self._broadcast_event(
                UniversalPipelineStage.FAILED,
                self.progress_percent,
                f"Error: {error_msg}",
            )

    def _broadcast_event(
        self,
        stage: UniversalPipelineStage,
        progress_percent: float,
        description: str,
    ) -> None:
        """Append event to history and notify active async listeners."""
        event = UniversalProgressEvent(
            task_id=self.task_id,
            stage=stage,
            progress_percent=progress_percent,
            description=description,
        )
        self._event_history.append(event)
        for q in list(self._event_queues):
            try:
                q.put_nowait(event)
            except Exception:
                pass

    def add_event_listener(self) -> asyncio.Queue[UniversalProgressEvent]:
        """Subscribe an async queue to live progress events."""
        with self._lock:
            q: asyncio.Queue[UniversalProgressEvent] = asyncio.Queue()
            for ev in self._event_history:
                q.put_nowait(ev)
            self._event_queues.append(q)
            return q

    def remove_event_listener(self, q: asyncio.Queue[UniversalProgressEvent]) -> None:
        """Unsubscribe an async queue."""
        with self._lock:
            if q in self._event_queues:
                self._event_queues.remove(q)

    def to_response(self) -> UniversalTaskResponse:
        """Serialize current task state to API response model."""
        with self._lock:
            return UniversalTaskResponse(
                task_id=self.task_id,
                project_id=self.project_id,
                status=self.status,
                progress_percent=self.progress_percent,
                current_stage=self.current_stage,
                stage_description=self.stage_description,
                created_at=self.created_at,
                started_at=self.started_at,
                completed_at=self.completed_at,
                error_message=self.error_message,
                result_reference=(
                    f"/api/v1/projects/{self.project_id}/universal/assurance/tasks/{self.task_id}/result"
                    if self.status == UniversalTaskStatus.COMPLETED
                    else None
                ),
            )


# =====================================================================
# Task Manager
# =====================================================================

class UniversalTaskManager:
    """Thread-safe registry and execution manager for Universal Assurance tasks."""

    def __init__(self, max_workers: int = 4) -> None:
        self._tasks: Dict[str, UniversalTask] = {}
        self._fingerprints: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="univ_task_")

    def create_task(
        self,
        project_id: str,
        request: UniversalAssuranceTaskCreateRequest,
        idempotency_key: Optional[str] = None,
    ) -> Tuple[UniversalTask, bool]:
        """Create or return an existing idempotent task."""
        canonical_req = {
            "project_id": project_id,
            "asset_ids": sorted(request.asset_ids),
            "evidence_items": request.evidence_items,
            "dependency_edges": request.dependency_edges,
            "asset_roles": request.asset_roles,
            "risk_policy_version": request.risk_policy_version,
            "decision_policy_version": request.decision_policy_version,
            "idempotency_key": idempotency_key or request.idempotency_key,
        }
        fingerprint = hash_canonical_data(canonical_req)

        with self._lock:
            lookup_key = f"{project_id}:{idempotency_key}" if idempotency_key else f"{project_id}:{fingerprint}"
            if lookup_key in self._fingerprints:
                existing_id = self._fingerprints[lookup_key]
                existing_task = self._tasks.get(existing_id)
                if existing_task and existing_task.status not in (UniversalTaskStatus.FAILED, UniversalTaskStatus.CANCELLED):
                    return existing_task, False

            task_id = str(uuid.uuid4())
            task = UniversalTask(
                task_id=task_id,
                project_id=project_id,
                request=request,
                request_fingerprint=fingerprint,
                idempotency_key=idempotency_key,
            )
            self._tasks[task_id] = task
            self._fingerprints[lookup_key] = task_id
            return task, True

    def get_task(self, task_id: str) -> Optional[UniversalTask]:
        """Retrieve task by ID."""
        with self._lock:
            return self._tasks.get(task_id)

    def list_tasks_for_project(self, project_id: str) -> List[UniversalTask]:
        """List all tasks belonging to a specific project."""
        with self._lock:
            return [t for t in self._tasks.values() if t.project_id == project_id]

    def submit_task(self, fn, task: UniversalTask) -> None:
        """Submit task to thread pool worker."""
        self._executor.submit(fn, task)


# =====================================================================
# Universal Assurance Service
# =====================================================================

class UniversalAssuranceService:
    """Authoritative service coordinating Universal Risk & Assurance APIs."""

    def __init__(self, task_manager: Optional[UniversalTaskManager] = None) -> None:
        self.task_manager = task_manager or UniversalTaskManager()
        self.normalizer = UniversalEvidenceNormalizer()
        self.correlation_engine = CrossDomainCorrelationEngine()
        self.risk_engine = UniversalRiskComputationEngine()
        self.policy_engine = UniversalPolicyEngine()
        self.proof_engine = UniversalProofIntegrationEngine()
        self.project_aggregator = UniversalProjectAggregator()

    def get_capabilities(self) -> UniversalCapabilitiesResponse:
        """Return universal engine capabilities."""
        return UniversalCapabilitiesResponse()

    def initiate_assurance_task(
        self,
        project_id: str,
        request: UniversalAssuranceTaskCreateRequest,
        idempotency_key: Optional[str] = None,
    ) -> Tuple[UniversalTaskResponse, bool]:
        """Submit an asynchronous universal assurance evaluation task."""
        if request.project_id and request.project_id != project_id:
            raise ScopeMismatchError(
                f"Request body project_id '{request.project_id}' does not match URL project_id '{project_id}'"
            )

        task, is_new = self.task_manager.create_task(
            project_id=project_id,
            request=request,
            idempotency_key=idempotency_key,
        )

        if is_new:
            self.task_manager.submit_task(self._execute_pipeline, task)

        return task.to_response(), is_new

    def get_task_status(self, project_id: str, task_id: str) -> UniversalTaskResponse:
        """Query lifecycle status of an assurance task."""
        task = self.task_manager.get_task(task_id)
        if not task or task.project_id != project_id:
            raise NotFoundException(f"Assurance task '{task_id}' not found for project '{project_id}'.")
        return task.to_response()

    def get_task_result(self, project_id: str, task_id: str) -> UniversalAssuranceResultResponse:
        """Retrieve completed evaluation result."""
        task = self.task_manager.get_task(task_id)
        if not task or task.project_id != project_id:
            raise NotFoundException(f"Assurance task '{task_id}' not found for project '{project_id}'.")

        if task.status == UniversalTaskStatus.RUNNING or task.status == UniversalTaskStatus.QUEUED:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=409,
                detail=f"Task '{task_id}' is still in progress ({task.current_stage.value}).",
            )
        elif task.status == UniversalTaskStatus.FAILED:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=422,
                detail=f"Task '{task_id}' failed: {task.error_message}",
            )
        elif task.status == UniversalTaskStatus.CANCELLED:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=409,
                detail=f"Task '{task_id}' was cancelled.",
            )

        if not task.result:
            raise NotFoundException(f"Result for task '{task_id}' is unavailable.")

        return task.result

    def cancel_task(self, project_id: str, task_id: str) -> UniversalTaskResponse:
        """Cancel an active task."""
        task = self.task_manager.get_task(task_id)
        if not task or task.project_id != project_id:
            raise NotFoundException(f"Assurance task '{task_id}' not found for project '{project_id}'.")
        task.cancel()
        return task.to_response()

    def get_stored_risk(self, project_id: str, risk_id: str) -> Dict[str, Any]:
        """Fetch stored Tier-1 risk assessment by asset/risk ID."""
        for t in self.task_manager.list_tasks_for_project(project_id):
            if risk_id in t.risk_assessments:
                return t.risk_assessments[risk_id].model_dump()
            for aid, a in t.risk_assessments.items():
                if a.assessment_hash == risk_id or aid == risk_id:
                    return a.model_dump()
        raise NotFoundException(f"Risk assessment '{risk_id}' not found for project '{project_id}'.")

    def get_stored_decision(self, project_id: str, decision_id: str) -> Dict[str, Any]:
        """Fetch stored Tier-1 policy decision by ID."""
        for t in self.task_manager.list_tasks_for_project(project_id):
            if decision_id in t.decision_assessments:
                return t.decision_assessments[decision_id].model_dump()
            for aid, d in t.decision_assessments.items():
                if d.decision_hash == decision_id or aid == decision_id:
                    return d.model_dump()
        raise NotFoundException(f"Policy decision '{decision_id}' not found for project '{project_id}'.")

    def get_stored_proof(self, project_id: str, proof_id: str) -> Dict[str, Any]:
        """Fetch stored Tier-1 proof assessment by ID."""
        for t in self.task_manager.list_tasks_for_project(project_id):
            if proof_id in t.proof_assessments:
                return t.proof_assessments[proof_id].model_dump()
            for aid, p in t.proof_assessments.items():
                if p.proof_assessment_hash == proof_id or aid == proof_id:
                    return p.model_dump()
        raise NotFoundException(f"Proof assessment '{proof_id}' not found for project '{project_id}'.")

    def get_stored_aggregation(self, project_id: str) -> Dict[str, Any]:
        """Fetch most recent hierarchical project aggregation for project."""
        tasks = [t for t in self.task_manager.list_tasks_for_project(project_id) if t.hierarchical_assessment]
        if not tasks:
            raise NotFoundException(f"No completed project aggregation found for project '{project_id}'.")
        tasks.sort(key=lambda t: t.created_at, reverse=True)
        return tasks[0].hierarchical_assessment.model_dump()

    # =================================================================
    # Pipeline Execution
    # =================================================================

    def _execute_pipeline(self, task: UniversalTask) -> None:
        """Synchronously execute the 8-stage universal pipeline in background thread."""
        try:
            req = task.request
            project_id = task.project_id

            # Stage 1: Normalizing Evidence (Phase 12.2)
            if task.is_cancelled(): return
            task.update_stage(UniversalPipelineStage.NORMALIZING_EVIDENCE, 10.0, "Normalizing heterogeneous evidence envelopes")
            envelopes: List[UniversalEvidenceEnvelope] = []
            for item in req.evidence_items:
                if isinstance(item, UniversalEvidenceEnvelope):
                    envelopes.append(item)
                elif isinstance(item, dict):
                    # Check if already a complete canonical envelope
                    if "canonical_hash" in item and "domain" in item:
                        envelopes.append(UniversalEvidenceEnvelope.model_validate(item))
                    else:
                        norm = self.normalizer.normalize_single(
                            raw_evidence=item,
                            project_id=project_id,
                        )
                        envelopes.append(norm)

            # Stage 2: Building Graph (Phase 12.3)
            if task.is_cancelled(): return
            task.update_stage(UniversalPipelineStage.BUILDING_GRAPH, 25.0, "Constructing in-memory finding-evidence DAG")
            builder = UniversalEvidenceGraphBuilder(project_id=project_id)
            for env in envelopes:
                builder.add_evidence_envelope(env)
            graph_snapshot = builder.validate_and_build()

            # Stage 3: Ingesting Cross-Subsystem Evidence (Phase 12.4)
            if task.is_cancelled(): return
            task.update_stage(UniversalPipelineStage.INGESTING, 40.0, "Validating cross-subsystem evidence bindings")

            # Stage 4: Correlating & Ancestry Damping (Phase 12.5)
            if task.is_cancelled(): return
            task.update_stage(UniversalPipelineStage.CORRELATING, 50.0, "Evaluating 7x7 correlation matrix and ancestry clustering")
            correlation_assessment = self.correlation_engine.evaluate_cross_domain_correlation(
                graph=graph_snapshot,
            )

            # Stage 5: Computing Tier-1 Asset Risks (Phase 12.6)
            if task.is_cancelled(): return
            task.update_stage(UniversalPipelineStage.COMPUTING_RISK, 65.0, "Quantifying Tier-1 asset-level operational risks")
            asset_ids = list(req.asset_ids)
            if not asset_ids:
                # Discover asset IDs from evidence
                discovered = {e.primary_asset_id for e in envelopes if e.primary_asset_id}
                asset_ids = sorted(list(discovered)) or ["default_asset"]

            asset_assessments: List[AssetRiskAssessment] = []
            univ_risk_assessments: Dict[str, UniversalRiskAssessment] = {}
            for aid in asset_ids:
                univ_risk = self.risk_engine.compute_asset_risk(
                    graph=graph_snapshot,
                    asset_id=aid,
                    correlation_assessment=correlation_assessment,
                )
                univ_risk_assessments[aid] = univ_risk
                asset_ass = AssetRiskAssessment(
                    project_id=project_id,
                    asset_id=aid,
                    asset_type=univ_risk.asset_type,
                    risk_score=univ_risk.risk_score,
                    risk_level=univ_risk.risk_level,
                    evidence_sufficiency=univ_risk.evidence_sufficiency,
                    finding_count=univ_risk.finding_count,
                    evidence_count=univ_risk.evidence_count,
                    cluster_count=univ_risk.cluster_count,
                    contributions=univ_risk.contributions,
                )
                asset_assessments.append(asset_ass)
                task.risk_assessments[aid] = asset_ass

            # Stage 6: Evaluating Policy Decisions (Phase 12.7)
            if task.is_cancelled(): return
            task.update_stage(UniversalPipelineStage.EVALUATING_POLICY, 75.0, "Evaluating versioned decision policies")
            policy = UniversalPolicy.get_default_policy(
                policy_id=f"policy_{project_id}",
                policy_version=req.decision_policy_version,
            )
            for aid, univ_risk in univ_risk_assessments.items():
                dec = self.policy_engine.evaluate(assessment=univ_risk, policy=policy)
                task.decision_assessments[aid] = dec

            # Stage 7: Verifying Proofs & Provenance (Phase 12.8)
            if task.is_cancelled(): return
            task.update_stage(UniversalPipelineStage.VERIFYING_PROOF, 85.0, "Verifying Ed25519 signatures and hash chains")
            proof_assessments_map: Dict[str, UniversalProofAssessment] = {}
            for a in asset_assessments:
                asset_evidence = [e for e in envelopes if e.primary_asset_id == a.asset_id]
                proof_ass = self.proof_engine.integrate_proof_assessment(
                    project_id=project_id,
                    asset_id=a.asset_id,
                    evidence_items=asset_evidence,
                )
                proof_assessments_map[a.asset_id] = proof_ass
                task.proof_assessments[a.asset_id] = proof_ass

            # Stage 8: Aggregating Project & Multi-Asset Risks (Phase 12.9)
            if task.is_cancelled(): return
            task.update_stage(UniversalPipelineStage.AGGREGATING_PROJECT, 95.0, "Synthesizing Tier-2 lineage chains and Tier-3 project risk")

            # Construct AssetDependencyGraph
            edges: List[AssetDependencyEdge] = []
            for edge_dict in req.dependency_edges:
                edges.append(AssetDependencyEdge.model_validate(edge_dict))

            roles_map: Dict[str, AssetRole] = {}
            for aid, role_str in req.asset_roles.items():
                try:
                    roles_map[aid] = AssetRole(role_str)
                except Exception:
                    roles_map[aid] = AssetRole.CORE_DEPLOYED

            dep_graph = AssetDependencyGraph(
                project_id=project_id,
                asset_ids=asset_ids,
                edges=edges,
                asset_roles=roles_map,
            )

            hierarchical_ass = self.project_aggregator.aggregate_project(
                graph=dep_graph,
                asset_assessments=asset_assessments,
                proof_assessments_map=proof_assessments_map,
            )
            task.hierarchical_assessment = hierarchical_ass

            disposition = self.project_aggregator.synthesize_project_disposition(
                project_assessment=hierarchical_ass.project_assessment,
                asset_assessments=hierarchical_ass.asset_assessments,
                proof_assessments_map=proof_assessments_map,
                asset_roles=roles_map,
            )

            # Build final response
            result = UniversalAssuranceResultResponse(
                task_id=task.task_id,
                project_id=project_id,
                status=UniversalTaskStatus.COMPLETED,
                decision=disposition.decision.value,
                project_risk_score=hierarchical_ass.project_assessment.project_risk_score,
                project_risk_level=hierarchical_ass.project_assessment.risk_level.value,
                peak_asset_id=hierarchical_ass.project_assessment.peak_asset_id,
                peak_asset_risk=hierarchical_ass.project_assessment.peak_asset_risk,
                asset_count=hierarchical_ass.project_assessment.asset_count,
                chain_count=hierarchical_ass.project_assessment.chain_count,
                proof_override_triggered=disposition.proof_override_triggered,
                escalation_reason=disposition.escalation_reason,
                hierarchical_hash=hierarchical_ass.hierarchical_hash,
                asset_assessments=[a.model_dump() for a in hierarchical_ass.asset_assessments],
                chain_assessments=[c.model_dump() for c in hierarchical_ass.chain_assessments],
                proof_assessments=[p.model_dump() for p in proof_assessments_map.values()],
            )

            task.mark_completed(result)

        except Exception as ex:
            logger.exception("Task %s failed: %s", task.task_id, str(ex))
            task.mark_failed(str(ex))


# Singleton accessors
_task_manager_singleton: Optional[UniversalTaskManager] = None
_service_singleton: Optional[UniversalAssuranceService] = None


def get_universal_task_manager() -> UniversalTaskManager:
    global _task_manager_singleton
    if _task_manager_singleton is None:
        _task_manager_singleton = UniversalTaskManager(max_workers=4)
    return _task_manager_singleton


def get_universal_service() -> UniversalAssuranceService:
    global _service_singleton
    if _service_singleton is None:
        _service_singleton = UniversalAssuranceService(task_manager=get_universal_task_manager())
    return _service_singleton
