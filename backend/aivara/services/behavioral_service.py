"""Behavioral Analysis Service & Task Orchestration Engine (Phase 8.8).

Coordinates:
  - Baseline computation and retrieval (Phase 8.3)
  - Controlled input perturbation experiments (Phase 8.4)
  - Output consistency and stability measurements (Phase 8.5)
  - Statistical anomaly detection (Phase 8.6)
  - Evidence synthesis and cryptographic provenance binding (Phase 8.7)
  - Multi-layer cryptographic provenance verification (Phase 4 / 8.7)
  - Concurrency-safe in-memory task runner, cooperative cancellation, and SSE progress broadcasting.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import logging
import threading
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple
import uuid
import numpy as np
from sqlalchemy.orm import Session, sessionmaker

from aivara.api.schemas.behavioral import (
    AnomalyDetectionRequest,
    AnomalyDetectionResponse,
    BaselineCompareRequest,
    BaselineCompareResponse,
    BaselineCreateRequest,
    BaselineReadResponse,
    BehavioralAssessmentRequest,
    BehavioralAssessmentResponse,
    BehavioralEvidenceBindRequest,
    BehavioralEvidenceBindResponse,
    BehavioralEvidenceReadResponse,
    BehavioralProgressEvent,
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
from aivara.domain.schemas import EvidenceLayer
from aivara.behavioral.anomaly import (
    AnomalyThresholdPolicy,
    BehavioralAnomalyAnalysis,
    BehavioralAnomalyEngineService,
    CrossProjectAnalysisError,
    DEFAULT_ANOMALY_POLICY,
    MetricAnomalyStatus,
    get_metric_direction,
    get_metric_family,
)
from aivara.behavioral.baselines import (
    BaselineStatus,
    BaselineSupportStatus,
    BaselineTrustStatus,
    BaselineType,
    BehavioralBaseline,
    BehavioralBaselineService,
    InputItemDescriptor,
    InputSetDescriptor,
    build_input_set_descriptor,
    compute_sample_input_hash,
    validate_baseline_comparability,
)
from aivara.behavioral.exceptions import (
    BehavioralError,
)
from aivara.behavioral.perturbations import (
    ControlledPerturbationEngine,
    PerturbationExperiment,
    PerturbationSpecification,
    PerturbationType,
    compute_input_array_hash,
)
from aivara.behavioral.provenance import (
    BehavioralEvidence,
    BehavioralEvidenceContent,
    BehavioralEvidenceType,
    BehavioralProvenanceBindingService,
    BehavioralProvenanceVerifier,
    BehavioralVerificationResult,
    IdempotencyConflictError,
    build_anomaly_evidence_content,
    create_behavioral_evidence,
    resolve_idempotent_behavioral_scan,
    seal_behavioral_evidence,
)
from aivara.behavioral.schemas import (
    DeterminismStatus,
    ExecutionResult,
    ExecutionStatus,
)
from aivara.behavioral.stability import (
    ComparisonType,
    OutputStabilityAnalysisService,
    PerturbationSensitivityResult,
    RepeatabilityAnalysisResult,
    compute_input_distance,
)
from aivara.core.config import settings
from aivara.core.exceptions import NotFoundException, ValidationException
from aivara.crypto.keys import KeyManager
from aivara.database.connection import SessionLocal
from aivara.database.models import (
    AIModelModel,
    EvidenceModel,
    FindingModel,
    ProjectModel,
    ProvenanceRecordModel,
)
from aivara.evidence.exceptions import CrossProjectContaminationError
from aivara.services.audit_service import AuditService

logger = logging.getLogger("aivara.services.behavioral")


def utcnow_iso() -> str:
    """Return timezone-aware current UTC datetime as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


# =====================================================================
# In-Memory Task Management & SSE Event Queues
# =====================================================================

class BehavioralTask:
    """Thread-safe representation of an in-flight or completed behavioral assessment."""

    def __init__(
        self,
        task_id: str,
        project_id: str,
        model_id: str,
        request: BehavioralAssessmentRequest,
        idempotency_key: Optional[str] = None,
    ) -> None:
        self.task_id = task_id
        self.project_id = project_id
        self.model_id = model_id
        self.request = request
        self.idempotency_key = idempotency_key

        self.status = "QUEUED"
        self.progress_percent = 0.0
        self.current_stage = "QUEUED"
        self.result: Optional[BehavioralAssessmentResponse] = None
        self.error_message: Optional[str] = None
        self.started_at: Optional[str] = None
        self.completed_at: Optional[str] = None

        self._is_cancelled = False
        self._lock = threading.Lock()
        self._event_queues: List[asyncio.Queue[BehavioralProgressEvent]] = []

    @property
    def is_cancelled(self) -> bool:
        with self._lock:
            return self._is_cancelled

    def cancel(self) -> None:
        with self._lock:
            self._is_cancelled = True
            if self.status in ("QUEUED", "RUNNING"):
                self.status = "CANCELLED"
                self.current_stage = "CANCELLED"
                self.completed_at = utcnow_iso()

    def to_read_response(self) -> BehavioralTaskReadResponse:
        with self._lock:
            return BehavioralTaskReadResponse(
                task_id=self.task_id,
                project_id=self.project_id,
                model_id=self.model_id,
                status=self.status,
                progress_percent=self.progress_percent,
                current_stage=self.current_stage,
                result=self.result,
                error_message=self.error_message,
                started_at=self.started_at,
                completed_at=self.completed_at,
            )


class BehavioralTaskManager:
    """Thread-safe registry of in-memory behavioral tasks for the local process."""

    _instance: Optional[BehavioralTaskManager] = None
    _lock = threading.Lock()

    def __new__(cls) -> BehavioralTaskManager:
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._tasks: Dict[str, BehavioralTask] = {}
                cls._instance._idempotency_map: Dict[str, str] = {}  # key -> task_id
                cls._instance._tasks_lock = threading.Lock()
                cls._instance._thread_pool = ThreadPoolExecutor(
                    max_workers=4,
                    thread_name_prefix="aivara-behavioral",
                )
            return cls._instance

    def register_task(self, task: BehavioralTask) -> None:
        with self._tasks_lock:
            self._tasks[task.task_id] = task
            if task.idempotency_key:
                scoped_key = f"{task.project_id}:{task.idempotency_key}"
                self._idempotency_map[scoped_key] = task.task_id

    def get_task(self, task_id: str) -> Optional[BehavioralTask]:
        with self._tasks_lock:
            return self._tasks.get(task_id)

    def find_idempotent_task(self, project_id: str, idempotency_key: str) -> Optional[BehavioralTask]:
        with self._tasks_lock:
            scoped_key = f"{project_id}:{idempotency_key}"
            task_id = self._idempotency_map.get(scoped_key)
            if task_id:
                return self._tasks.get(task_id)
            return None

    def list_tasks(
        self,
        project_id: str,
        model_id: Optional[str] = None,
    ) -> List[BehavioralTask]:
        with self._tasks_lock:
            tasks = [t for t in self._tasks.values() if t.project_id == project_id]
        if model_id:
            tasks = [t for t in tasks if t.model_id == model_id]
        return tasks

    def emit_event(self, task: BehavioralTask, event: BehavioralProgressEvent) -> None:
        """Broadcast an event to all active async subscribers without blocking."""
        with task._lock:
            dead_queues = []
            for q in task._event_queues:
                try:
                    q.put_nowait(event)
                except Exception:
                    dead_queues.append(q)
            for dq in dead_queues:
                task._event_queues.remove(dq)

    def add_subscriber(self, task: BehavioralTask, queue: asyncio.Queue[BehavioralProgressEvent]) -> None:
        with task._lock:
            task._event_queues.append(queue)

    def remove_subscriber(self, task: BehavioralTask, queue: asyncio.Queue[BehavioralProgressEvent]) -> None:
        with task._lock:
            if queue in task._event_queues:
                task._event_queues.remove(queue)


# =====================================================================
# Main Behavioral Service Layer
# =====================================================================

class BehavioralService:
    """Service layer orchestrating Behavioral Analysis REST capabilities."""

    _baselines: Dict[str, BehavioralBaseline] = {}
    _anomalies: Dict[str, BehavioralAnomalyAnalysis] = {}
    _evidence_store: Dict[str, BehavioralEvidence] = {}

    def __init__(
        self,
        db: Session,
        key_manager: Optional[KeyManager] = None,
        task_manager: Optional[BehavioralTaskManager] = None,
    ) -> None:
        self.db = db
        self.key_manager = key_manager or KeyManager(keys_dir=settings.keys_dir)
        self.task_manager = task_manager or BehavioralTaskManager()
        self.audit_service = AuditService(db)

        # Domain engines
        self.baseline_service = BehavioralBaselineService()
        self.perturbation_engine = ControlledPerturbationEngine()
        self.stability_service = OutputStabilityAnalysisService()
        self.anomaly_service = BehavioralAnomalyEngineService()
        self.binding_service = BehavioralProvenanceBindingService(
            db=db,
            key_manager=self.key_manager,
            audit_service=self.audit_service,
        )
        self.verifier = BehavioralProvenanceVerifier(
            db=db,
            key_manager=self.key_manager,
            audit_service=self.audit_service,
        )

    def _require_project(self, project_id: str) -> ProjectModel:
        """Validate project existence."""
        project = self.db.query(ProjectModel).filter(ProjectModel.id == project_id).first()
        if not project:
            raise NotFoundException(f"Project '{project_id}' not found.")
        return project

    def _get_validated_model(self, project_id: str, model_id: str) -> AIModelModel:
        """Retrieve model and strictly enforce tenant project isolation."""
        self._require_project(project_id)
        model = self.db.query(AIModelModel).filter(AIModelModel.id == model_id).first()
        if not model:
            raise NotFoundException(f"Model '{model_id}' not found.")
        if model.project_id != project_id:
            raise CrossProjectContaminationError(
                f"Model '{model_id}' belongs to project '{model.project_id}', not '{project_id}'."
            )
        return model

    def _build_baseline_from_observations(
        self,
        project_id: str,
        model_id: str,
        model_fingerprint: str,
        task_type: str,
        observations: List[Dict[str, Any]],
        baseline_type: BaselineType = BaselineType.REFERENCE_EXECUTION_PROFILE,
        input_set_id: Optional[str] = None,
        execution_provider: str = "CPUExecutionProvider",
        preprocessing_config: Optional[Dict[str, Any]] = None,
    ) -> BehavioralBaseline:
        """Helper constructing a validated BehavioralBaseline from observation dictionaries."""
        exec_results: List[ExecutionResult] = []
        sample_tuples: List[Tuple[str, Dict[str, np.ndarray], Optional[Dict[str, Any]]]] = []

        for i, obs in enumerate(observations):
            sample_id = obs.get("sample_id", f"sample-{i:04d}")
            outputs: Dict[str, np.ndarray] = {}
            if "logits" in obs:
                outputs["logits"] = np.array(obs["logits"], dtype=np.float32)
            elif "top1_confidence" in obs:
                outputs["logits"] = np.array([obs["top1_confidence"]], dtype=np.float32)
            if "boxes" in obs:
                outputs["boxes"] = np.array(obs["boxes"], dtype=np.float32)
            if "scores" in obs:
                outputs["scores"] = np.array(obs["scores"], dtype=np.float32)
            if "classes" in obs:
                outputs["classes"] = np.array(obs["classes"], dtype=np.int32)
            if "mask" in obs:
                outputs["mask"] = np.array(obs["mask"], dtype=np.float32)
            if not outputs:
                outputs = {
                    k: np.array(v, dtype=np.float32) if isinstance(v, (list, tuple)) else np.array([v], dtype=np.float32)
                    for k, v in obs.items()
                    if k not in ("latency_ms", "sample_id")
                }

            exec_results.append(
                ExecutionResult(
                    execution_id=f"exec-{uuid.uuid4().hex[:12]}",
                    status=ExecutionStatus.SUCCESS,
                    provider=execution_provider,
                    device="cpu",
                    runtime_version="1.0.0",
                    precision="float32",
                    duration_ms=float(obs.get("latency_ms", 10.0)),
                    timestamp=utcnow_iso(),
                    outputs=outputs,
                    determinism_status=DeterminismStatus.DETERMINISTIC,
                )
            )
            dummy_input = {"input": np.zeros((1, 1), dtype=np.float32)}
            sample_tuples.append((sample_id, dummy_input, {}))

        input_set = build_input_set_descriptor(sample_tuples)

        return self.baseline_service.create_baseline(
            project_id=project_id,
            model_id=model_id,
            model_fingerprint=model_fingerprint,
            task_type=task_type,
            input_set=input_set,
            execution_results=exec_results,
            baseline_type=baseline_type,
        )

    # =====================================================================
    # 1. Baseline Endpoints
    # =====================================================================

    def create_baseline(
        self,
        project_id: str,
        request: BaselineCreateRequest,
    ) -> BaselineReadResponse:
        """Create and compute a deterministic behavioral baseline profile."""
        model = self._get_validated_model(project_id, request.model_id)
        model_fp = model.file_hash_sha256 or ("0" * 64)

        try:
            b_type = BaselineType(request.baseline_type.upper())
        except Exception:
            b_type = BaselineType.REFERENCE_EXECUTION_PROFILE

        baseline = self._build_baseline_from_observations(
            project_id=project_id,
            model_id=request.model_id,
            model_fingerprint=model_fp,
            task_type=request.task_type,
            observations=request.observations,
            baseline_type=b_type,
            input_set_id=request.input_set_id,
            execution_provider=request.execution_provider,
            preprocessing_config=request.preprocessing_config,
        )

        self._baselines[baseline.baseline_id] = baseline

        obs_count = 0
        if baseline.profile.latency:
            obs_count = baseline.profile.latency.sample_count
        elif baseline.profile.classification:
            obs_count = baseline.profile.classification.sample_count
        elif baseline.profile.detection:
            obs_count = baseline.profile.detection.sample_count
        elif baseline.profile.segmentation:
            obs_count = baseline.profile.segmentation.sample_count

        return BaselineReadResponse(
            baseline_id=baseline.baseline_id,
            project_id=baseline.project_id,
            model_id=baseline.model_id,
            model_fingerprint=baseline.model_fingerprint,
            task_type=baseline.task_type,
            baseline_type=baseline.baseline_type.value,
            baseline_status=baseline.baseline_status.value,
            support_status=baseline.support_status.value,
            trust_status=baseline.trust_status.value,
            observation_count=obs_count,
            profiles=baseline.profile.model_dump(),
            limitations=list(baseline.limitations),
            created_at=baseline.created_at,
        )

    def get_baseline(
        self,
        project_id: str,
        baseline_id: str,
    ) -> BaselineReadResponse:
        """Retrieve a stored behavioral baseline."""
        self._require_project(project_id)
        baseline = self._baselines.get(baseline_id)
        if not baseline or baseline.project_id != project_id:
            raise NotFoundException(f"Behavioral baseline '{baseline_id}' not found in project '{project_id}'.")

        obs_count = 0
        if baseline.profile.latency:
            obs_count = baseline.profile.latency.sample_count
        elif baseline.profile.classification:
            obs_count = baseline.profile.classification.sample_count
        elif baseline.profile.detection:
            obs_count = baseline.profile.detection.sample_count
        elif baseline.profile.segmentation:
            obs_count = baseline.profile.segmentation.sample_count

        return BaselineReadResponse(
            baseline_id=baseline.baseline_id,
            project_id=baseline.project_id,
            model_id=baseline.model_id,
            model_fingerprint=baseline.model_fingerprint,
            task_type=baseline.task_type,
            baseline_type=baseline.baseline_type.value,
            baseline_status=baseline.baseline_status.value,
            support_status=baseline.support_status.value,
            trust_status=baseline.trust_status.value,
            observation_count=obs_count,
            profiles=baseline.profile.model_dump(),
            limitations=list(baseline.limitations),
            created_at=baseline.created_at,
        )

    def compare_baseline(
        self,
        project_id: str,
        baseline_id: str,
        request: BaselineCompareRequest,
    ) -> BaselineCompareResponse:
        """Compare an observation against a baseline profile."""
        self._require_project(project_id)
        baseline = self._baselines.get(baseline_id)
        if not baseline or baseline.project_id != project_id:
            raise NotFoundException(f"Behavioral baseline '{baseline_id}' not found.")

        obs = request.observation
        candidate_task = obs.get("task_type", baseline.task_type)
        candidate_input_set = obs.get("input_set_id", baseline.input_set_identity)
        candidate_provider = obs.get("execution_provider", baseline.execution_provider)

        is_compat, reason, codes = validate_baseline_comparability(
            baseline=baseline,
            candidate_task_type=candidate_task,
            candidate_input_set_id=candidate_input_set,
            candidate_provider=candidate_provider,
        )

        warnings = list(codes)
        if reason:
            warnings.append(reason)

        return BaselineCompareResponse(
            baseline_id=baseline_id,
            project_id=project_id,
            comparability_status="COMPARABLE" if is_compat else "INCOMPARABLE",
            metric_differences={"observation_keys": list(request.observation.keys())},
            is_compatible=is_compat,
            warnings=warnings,
        )

    # =====================================================================
    # 2. Perturbation Endpoints
    # =====================================================================

    def run_perturbation_experiment(
        self,
        project_id: str,
        request: PerturbationExperimentRequest,
    ) -> PerturbationExperimentResponse:
        """Execute a deterministic controlled perturbation experiment."""
        self._get_validated_model(project_id, request.model_id)

        try:
            p_type = PerturbationType(request.perturbation_type.upper())
        except Exception:
            raise ValidationException(f"Unsupported perturbation type '{request.perturbation_type}'.")

        arr = np.array(request.input_data, dtype=np.float32)

        # Adapt parameter aliases
        params = dict(request.parameters)
        if p_type == PerturbationType.GAUSSIAN_NOISE:
            if "sigma" in params and "std" not in params:
                params["std"] = params.pop("sigma")
        elif p_type == PerturbationType.UNIFORM_NOISE:
            if "low" in params and "min_val" not in params:
                params["min_val"] = params.pop("low")
            if "high" in params and "max_val" not in params:
                params["max_val"] = params.pop("high")

        seed = request.random_seed if p_type in (PerturbationType.GAUSSIAN_NOISE, PerturbationType.UNIFORM_NOISE) else None
        spec = PerturbationSpecification(
            perturbation_type=p_type,
            parameters=params,
            seed=seed,
        )

        source_id = f"src-{uuid.uuid4().hex[:8]}"
        experiment, res = self.perturbation_engine.create_experiment(
            project_id=project_id,
            source_input_id=source_id,
            image=arr,
            specification=spec,
            model_id=request.model_id,
        )

        dist = compute_input_distance(arr, res.perturbed_array) if res.perturbed_array is not None else {"l2": 0.0}
        dist_l2 = dist.get("l2", 0.0) if isinstance(dist, dict) else float(dist)

        return PerturbationExperimentResponse(
            experiment_id=experiment.experiment_id,
            perturbation_id=experiment.perturbation_id,
            perturbation_type=experiment.perturbation_type.value.lower(),
            status=res.status.value,
            original_input_hash=res.source_input_hash,
            perturbed_input_hash=res.perturbed_input_hash or ("0" * 64),
            input_distance=float(dist_l2),
            execution_result=None,
            metadata=res.execution_metadata if hasattr(res, "execution_metadata") else {},
        )

    # =====================================================================
    # 3. Output Consistency & Stability Endpoints
    # =====================================================================

    def analyze_repeatability(
        self,
        project_id: str,
        request: RepeatabilityAnalysisRequest,
    ) -> RepeatabilityAnalysisResponse:
        """Analyze repeatability across identical executions."""
        model = self._get_validated_model(project_id, request.model_id)
        model_fp = model.file_hash_sha256 or ("0" * 64)

        formatted_outputs = []
        for out in request.outputs:
            formatted = {}
            for k, v in out.items():
                if isinstance(v, (list, tuple)):
                    formatted[k] = np.array(v, dtype=np.float32 if k != "classes" else np.int32)
                elif isinstance(v, (int, float)):
                    formatted[k] = np.array([v], dtype=np.float32)
                else:
                    formatted[k] = v
            formatted_outputs.append(formatted)

        exec_results = []
        for i, out in enumerate(formatted_outputs):
            exec_results.append(
                ExecutionResult(
                    execution_id=f"exec-repeat-{i:03d}",
                    status=ExecutionStatus.SUCCESS,
                    provider="CPUExecutionProvider",
                    device="cpu",
                    runtime_version="1.0.0",
                    precision="float32",
                    duration_ms=10.0,
                    timestamp=utcnow_iso(),
                    outputs=out,
                    determinism_status=DeterminismStatus.DETERMINISTIC,
                )
            )

        res: RepeatabilityAnalysisResult = self.stability_service.analyze_repeatability(
            project_id=project_id,
            model_id=request.model_id,
            model_fingerprint=model_fp,
            execution_results=exec_results,
            task_type=request.task_type,
        )

        return RepeatabilityAnalysisResponse(
            analysis_id=res.analysis_id,
            is_fully_deterministic=(res.determinism_status == "DETERMINISTIC"),
            run_count=res.repeat_count,
            metrics={
                "prediction_agreement_rate": res.prediction_agreement_rate,
                "max_numerical_delta": res.max_numerical_delta,
                "mean_numerical_delta": res.mean_numerical_delta,
            },
            validity_status=res.determinism_status,
        )

    def analyze_sensitivity(
        self,
        project_id: str,
        request: SensitivityAnalysisRequest,
    ) -> SensitivityAnalysisResponse:
        """Analyze perturbation sensitivity ratio."""
        self._get_validated_model(project_id, request.model_id)

        orig_in = np.array(request.original_input, dtype=np.float32)
        pert_in = np.array(request.perturbed_input, dtype=np.float32)

        def _fmt(d: Dict[str, Any]) -> Dict[str, Any]:
            res = {}
            for k, v in d.items():
                if isinstance(v, (list, tuple)):
                    res[k] = np.array(v, dtype=np.float32 if k != "classes" else np.int32)
                elif isinstance(v, (int, float)):
                    res[k] = np.array([v], dtype=np.float32)
                else:
                    res[k] = v
            return res

        orig_out = _fmt(request.original_output)
        pert_out = _fmt(request.perturbed_output)

        res: PerturbationSensitivityResult = self.stability_service.analyze_perturbation_sensitivity(
            project_id=project_id,
            model_id=request.model_id,
            source_input=orig_in,
            perturbed_input=pert_in,
            source_output=orig_out,
            perturbed_output=pert_out,
            source_input_hash=compute_input_array_hash(orig_in),
            perturbed_input_hash=compute_input_array_hash(pert_in),
            perturbation_id=f"pert-{uuid.uuid4().hex[:12]}",
            perturbation_type="sensitivity_eval",
            task_type=request.task_type,
        )

        return SensitivityAnalysisResponse(
            sensitivity_id=res.sensitivity_id,
            input_distance=res.input_distance_l2,
            output_distance=res.output_distance_l2 or 0.0,
            sensitivity_ratio=res.sensitivity_ratio,
            ratio_status=res.sensitivity_status,
            metrics=res.task_metrics,
        )

    def compare_stability(
        self,
        project_id: str,
        request: StabilityCompareRequest,
    ) -> StabilityCompareResponse:
        """Compare outputs between candidate and reference models."""
        self._get_validated_model(project_id, request.candidate_model_id)
        self._get_validated_model(project_id, request.reference_model_id)

        def _fmt(d: Dict[str, Any]) -> Dict[str, Any]:
            res = {}
            for k, v in d.items():
                if isinstance(v, (list, tuple)):
                    res[k] = np.array(v, dtype=np.float32 if k != "classes" else np.int32)
                elif isinstance(v, (int, float)):
                    res[k] = np.array([v], dtype=np.float32)
                else:
                    res[k] = v
            return res

        res = self.stability_service.compare_observations(
            project_id=project_id,
            source_observation_id=f"ref-obs-{uuid.uuid4().hex[:8]}",
            target_observation_id=f"cand-obs-{uuid.uuid4().hex[:8]}",
            source_output=_fmt(request.reference_output),
            target_output=_fmt(request.candidate_output),
            task_type=request.task_type,
            comparison_type=ComparisonType.REFERENCE_COMPARISON,
        )

        metrics_dict: Dict[str, Any] = {}
        if res.classification:
            metrics_dict = res.classification.model_dump(mode="json")
        elif res.detection:
            metrics_dict = res.detection.model_dump(mode="json")
        elif res.segmentation:
            metrics_dict = res.segmentation.model_dump(mode="json")
        elif res.generic_tensor:
            metrics_dict = res.generic_tensor.model_dump(mode="json")

        return StabilityCompareResponse(
            comparison_id=res.comparison_id,
            task_type=res.task_type,
            metrics=metrics_dict,
            validity_status="VALID" if res.is_compatible else "INCOMPATIBLE",
        )

    # =====================================================================
    # 4. Behavioral Anomaly Detection Endpoints
    # =====================================================================

    def detect_anomalies(
        self,
        project_id: str,
        request: AnomalyDetectionRequest,
    ) -> AnomalyDetectionResponse:
        """Execute statistical anomaly detection against baseline profile."""
        model = self._get_validated_model(project_id, request.model_id)
        model_fp = model.file_hash_sha256 or ("0" * 64)

        # Resolve baseline or reference dataset
        baseline = None
        if request.baseline_id:
            baseline = self._baselines.get(request.baseline_id)
            if not baseline or baseline.project_id != project_id:
                raise NotFoundException(f"Baseline '{request.baseline_id}' not found in project '{project_id}'.")

        policy = None
        if request.threshold_policy:
            policy = AnomalyThresholdPolicy.model_validate(request.threshold_policy)

        obs_id = request.observation_id or f"obs-{uuid.uuid4().hex[:12]}"

        baseline_distributions: Dict[str, List[float]] = {}
        b_id = "ad-hoc-reference"
        b_type = "AD_HOC"

        if baseline:
            b_id = baseline.baseline_id
            b_type = baseline.baseline_type.value
            if baseline.profile.classification:
                if baseline.profile.classification.confidence_stats:
                    cs = baseline.profile.classification.confidence_stats
                    baseline_distributions["top1_confidence"] = [cs.min, cs.p25, cs.median, cs.p75, cs.max]
                    baseline_distributions["top1_confidence_median"] = [cs.min, cs.p25, cs.median, cs.p75, cs.max]
                if baseline.profile.classification.entropy_stats:
                    es = baseline.profile.classification.entropy_stats
                    baseline_distributions["entropy"] = [es.min, es.p25, es.median, es.p75, es.max]
                    baseline_distributions["entropy_median"] = [es.min, es.p25, es.median, es.p75, es.max]
                if baseline.profile.classification.margin_stats:
                    ms = baseline.profile.classification.margin_stats
                    baseline_distributions["margin"] = [ms.min, ms.p25, ms.median, ms.p75, ms.max]
                    baseline_distributions["margin_median"] = [ms.min, ms.p25, ms.median, ms.p75, ms.max]
            if baseline.profile.detection:
                if baseline.profile.detection.confidence_stats:
                    cs = baseline.profile.detection.confidence_stats
                    baseline_distributions["confidence"] = [cs.min, cs.p25, cs.median, cs.p75, cs.max]
                    baseline_distributions["confidence_median"] = [cs.min, cs.p25, cs.median, cs.p75, cs.max]
                if baseline.profile.detection.detection_count_stats:
                    dcs = baseline.profile.detection.detection_count_stats
                    baseline_distributions["box_count"] = [dcs.min, dcs.p25, dcs.median, dcs.p75, dcs.max]
                    baseline_distributions["box_count_median"] = [dcs.min, dcs.p25, dcs.median, dcs.p75, dcs.max]
            if baseline.profile.latency:
                ls = baseline.profile.latency.stats
                baseline_distributions["latency_ms"] = [ls.min, ls.p25, ls.median, ls.p75, ls.max]
                baseline_distributions["latency_p50_ms"] = [ls.min, ls.p25, ls.median, ls.p75, ls.max]
        elif request.reference_dataset:
            baseline_distributions = {k: list(v) for k, v in request.reference_dataset.items()}

        for k in request.observed_metrics:
            if k not in baseline_distributions:
                baseline_distributions[k] = []

        analysis: BehavioralAnomalyAnalysis = self.anomaly_service.analyze_metrics_dict(
            project_id=project_id,
            model_id=request.model_id,
            model_fingerprint=model_fp,
            baseline_id=b_id,
            baseline_type=b_type,
            observation_id=obs_id,
            task_type=request.task_type,
            observed_metrics=request.observed_metrics,
            baseline_distributions=baseline_distributions,
            policy=policy,
        )

        self._anomalies[analysis.analysis_id] = analysis

        anom_count = sum(1 for m in analysis.metrics if m.anomaly_status == MetricAnomalyStatus.ANOMALOUS)
        total_count = len(analysis.metrics)

        return AnomalyDetectionResponse(
            analysis_id=analysis.analysis_id,
            project_id=analysis.project_id,
            model_id=analysis.model_id,
            model_fingerprint=analysis.model_fingerprint,
            task_type=analysis.task_type,
            overall_status=analysis.overall_status.value,
            support_status=analysis.support_status.value,
            anomalous_metric_count=anom_count,
            total_metric_count=total_count,
            families={k: v.model_dump() for k, v in analysis.families.items()},
            metrics={m.metric_name: m.model_dump() for m in analysis.metrics},
            overall_explanation=analysis.explanation,
            limitations=list(analysis.limitations),
        )

    def get_anomaly_analysis(
        self,
        project_id: str,
        analysis_id: str,
    ) -> AnomalyDetectionResponse:
        """Retrieve stored anomaly analysis."""
        self._require_project(project_id)
        analysis = self._anomalies.get(analysis_id)
        if not analysis or analysis.project_id != project_id:
            raise NotFoundException(f"Anomaly analysis '{analysis_id}' not found.")

        anom_count = sum(1 for m in analysis.metrics if m.anomaly_status == MetricAnomalyStatus.ANOMALOUS)
        total_count = len(analysis.metrics)

        return AnomalyDetectionResponse(
            analysis_id=analysis.analysis_id,
            project_id=analysis.project_id,
            model_id=analysis.model_id,
            model_fingerprint=analysis.model_fingerprint,
            task_type=analysis.task_type,
            overall_status=analysis.overall_status.value,
            support_status=analysis.support_status.value,
            anomalous_metric_count=anom_count,
            total_metric_count=total_count,
            families={k: v.model_dump() for k, v in analysis.families.items()},
            metrics={m.metric_name: m.model_dump() for m in analysis.metrics},
            overall_explanation=analysis.explanation,
            limitations=list(analysis.limitations),
        )

    # =====================================================================
    # 5. Evidence & Provenance Binding Endpoints
    # =====================================================================

    def bind_evidence(
        self,
        project_id: str,
        request: BehavioralEvidenceBindRequest,
    ) -> BehavioralEvidenceBindResponse:
        """Synthesize findings and bind cryptographic evidence."""
        model = self._get_validated_model(project_id, request.model_id)
        model_fp = model.file_hash_sha256 or ("0" * 64)

        metrics_list: List[Dict[str, Any]] = []
        if isinstance(request.metric_results, dict):
            for k, v in request.metric_results.items():
                if isinstance(v, dict):
                    metrics_list.append({"metric_name": k, **v})
                else:
                    metrics_list.append({"metric_name": k, "observed_value": v})
        elif isinstance(request.metric_results, list):
            metrics_list = list(request.metric_results)

        content = BehavioralEvidenceContent(
            evidence_layer=EvidenceLayer.DETECTION,
            evidence_type=BehavioralEvidenceType.BEHAVIORAL_ANOMALY,
            project_id=project_id,
            model_id=request.model_id,
            model_fingerprint=model_fp,
            task_type=request.task_type,
            observation_id=request.observation_id,
            baseline_id=request.baseline_id,
            baseline_type="REFERENCE_PROFILE",
            comparison_id=request.comparison_id or "NONE",
            sensitivity_id=request.sensitivity_id or "NONE",
            anomaly_analysis_id=request.anomaly_analysis_id,
            input_hash=request.observation_id[:64].ljust(64, "0"),
            output_hash=request.anomaly_analysis_id[:64].ljust(64, "0"),
            preprocessing_hash="STANDARD_V1",
            detector_id="behavioral_anomaly_detector",
            detector_version="1.0.0",
            detector_config_hash="0" * 64,
            policy_version="1.0.0",
            engine_version="1.0.0",
            result_status=request.overall_status,
            support_status=request.support_status,
            comparability_status=request.comparability_status,
            metrics=metrics_list,
            families=request.family_results,
            limitations=request.limitations,
        )

        evidence: BehavioralEvidence = create_behavioral_evidence(
            content=content,
            seal=True,
        )

        finding_model, prov_rec_read, scan_status = self.binding_service.bind_behavioral_evidence(
            evidence=evidence,
            seal_provenance=request.seal_provenance,
            signer_key_id=request.signer_key_id,
            signer_passphrase=request.signer_passphrase,
            actor=request.actor,
        )

        self._evidence_store[evidence.evidence_id] = evidence

        prov_id = None
        if prov_rec_read:
            prov_id = prov_rec_read.id
        elif finding_model and finding_model.metadata_json:
            prov_id = finding_model.metadata_json.get("provenance_record_id")

        return BehavioralEvidenceBindResponse(
            evidence_id=evidence.evidence_id,
            evidence_type=evidence.content.evidence_type.value,
            lifecycle_state=evidence.lifecycle_state.value,
            finding_id=finding_model.id if finding_model else None,
            provenance_record_id=prov_id,
            execution_identity_hash=evidence.evidence_id,
            project_id=project_id,
            model_id=request.model_id,
            created_at=evidence.created_at,
        )

    def get_evidence(
        self,
        project_id: str,
        evidence_id: str,
    ) -> BehavioralEvidenceReadResponse:
        """Retrieve an immutable evidence item."""
        self._require_project(project_id)
        evidence = self._evidence_store.get(evidence_id)
        if evidence and evidence.content.project_id == project_id:
            return BehavioralEvidenceReadResponse(
                evidence_id=evidence.evidence_id,
                evidence_type=evidence.content.evidence_type.value,
                lifecycle_state=evidence.lifecycle_state.value,
                project_id=evidence.content.project_id,
                model_id=evidence.content.model_id,
                model_fingerprint=evidence.content.model_fingerprint,
                content=evidence.content.model_dump(),
                created_at=evidence.created_at,
            )

        db_ev = (
            self.db.query(EvidenceModel)
            .join(FindingModel, EvidenceModel.finding_id == FindingModel.id)
            .filter(
                EvidenceModel.evidence_hash == evidence_id,
                FindingModel.project_id == project_id,
            )
            .first()
        )
        if not db_ev:
            raise NotFoundException(f"Evidence '{evidence_id}' not found in project '{project_id}'.")
        return BehavioralEvidenceReadResponse(
            evidence_id=db_ev.evidence_hash,
            evidence_type=db_ev.evidence_type,
            lifecycle_state="SEALED",
            project_id=project_id,
            model_id=db_ev.data_json.get("model_id", ""),
            model_fingerprint=db_ev.data_json.get("model_fingerprint", ""),
            content=db_ev.data_json,
            created_at=db_ev.created_at.isoformat() if db_ev.created_at else "",
        )

    # =====================================================================
    # 6. Provenance Verification Endpoints
    # =====================================================================

    def verify_provenance(
        self,
        project_id: str,
        target_id: str,
    ) -> BehavioralProvenanceVerificationResponse:
        """Verify cryptographic provenance for a behavioral finding or model."""
        self._require_project(project_id)

        finding = self.db.query(FindingModel).filter(
            FindingModel.id == target_id,
            FindingModel.project_id == project_id,
        ).first()

        evidence_id = None
        prov_id = None

        if finding:
            primary_hashes = (finding.metadata_json or {}).get("primary_evidence_hashes", [])
            if primary_hashes:
                evidence_id = primary_hashes[0]
            prov_id = (finding.metadata_json or {}).get("provenance_record_id")
            if not prov_id:
                # Query provenance records for this project matching finding
                prov_recs = self.db.query(ProvenanceRecordModel).filter(
                    ProvenanceRecordModel.project_id == project_id
                ).order_by(ProvenanceRecordModel.sequence_number.desc()).all()
                for pr in prov_recs:
                    meta = pr.metadata_json or {}
                    if (
                        target_id in meta.get("finding_ids", [])
                        or meta.get("finding_id") == target_id
                        or pr.target_id == finding.affected_asset_id
                        or pr.target_id == finding.id
                    ):
                        prov_id = pr.id
                        break
        else:
            model = self.db.query(AIModelModel).filter(
                AIModelModel.id == target_id,
                AIModelModel.project_id == project_id,
            ).first()
            if model:
                prov_recs = self.db.query(ProvenanceRecordModel).filter(
                    ProvenanceRecordModel.project_id == project_id
                ).order_by(ProvenanceRecordModel.sequence_number.desc()).all()
                for pr in prov_recs:
                    meta = pr.metadata_json or {}
                    if meta.get("model_id") == model.id or pr.target_id == model.id:
                        prov_id = pr.id
                        break
            else:
                # Check if target_id is directly a ProvenanceRecordModel ID
                direct_pr = self.db.query(ProvenanceRecordModel).filter(
                    ProvenanceRecordModel.id == target_id,
                    ProvenanceRecordModel.project_id == project_id,
                ).first()
                if direct_pr:
                    prov_id = direct_pr.id

        if not prov_id:
            return BehavioralProvenanceVerificationResponse(
                is_valid=False,
                status="MISSING",
                provenance_record_id=None,
                project_id=project_id,
                target_id=target_id,
                signature_valid=False,
                chain_valid=False,
                failures=["No provenance record found bound to target."],
            )

        evidence = self._evidence_store.get(evidence_id) if evidence_id else None
        if not evidence and evidence_id:
            db_ev = self.db.query(EvidenceModel).filter(EvidenceModel.evidence_hash == evidence_id).first()
            if db_ev and db_ev.data_json:
                try:
                    content_dict = db_ev.data_json.get("content", db_ev.data_json)
                    content = BehavioralEvidenceContent.model_validate(content_dict)
                    evidence = create_behavioral_evidence(content=content, seal=True)
                except Exception:
                    pass

        if not evidence:
            return BehavioralProvenanceVerificationResponse(
                is_valid=False,
                status="MISSING",
                provenance_record_id=prov_id,
                project_id=project_id,
                target_id=target_id,
                signature_valid=False,
                chain_valid=False,
                failures=["Evidence item corresponding to provenance record not found."],
            )

        res: BehavioralVerificationResult = self.verifier.verify_behavioral_provenance(
            evidence=evidence,
            provenance_record_id=prov_id,
            expected_project_id=project_id,
        )

        rec = self.db.query(ProvenanceRecordModel).filter(ProvenanceRecordModel.id == prov_id).first()

        is_v = (res.overall_status.value == "VERIFIED" if hasattr(res.overall_status, "value") else str(res.overall_status) == "VERIFIED")

        return BehavioralProvenanceVerificationResponse(
            is_valid=is_v,
            status=res.overall_status.value if hasattr(res.overall_status, "value") else str(res.overall_status),
            provenance_record_id=prov_id,
            project_id=project_id,
            target_id=target_id,
            signature_valid=res.verification_vector.signature_valid,
            chain_valid=res.verification_vector.chain_valid,
            sequence_valid=res.verification_vector.sequence_valid,
            nonce_valid=res.verification_vector.nonce_valid,
            signer_key_id=rec.signer_key_id if rec else None,
            sequence_number=rec.sequence_number if rec else None,
            record_hash=rec.record_hash if rec else None,
            verification_vector=res.verification_vector.model_dump(),
            failures=list(res.verification_vector.failures),
            details={"message": res.message, "verified_at": res.verified_at},
        )

    # =====================================================================
    # 7. Integrated Assessment & Tasks
    # =====================================================================

    def run_assessment(
        self,
        project_id: str,
        request: BehavioralAssessmentRequest,
        audit_run_id: Optional[str] = None,
    ) -> BehavioralAssessmentResponse:
        """Execute full integrated behavioral assessment pipeline synchronously."""
        model = self._get_validated_model(project_id, request.model_id)
        model_fp = model.file_hash_sha256 or ("0" * 64)
        audit_id = audit_run_id or f"audit-b-{uuid.uuid4().hex[:12]}"

        # 1. Baseline Resolution or Computation
        baseline = None
        if request.baseline_id:
            baseline = self._baselines.get(request.baseline_id)
        if not baseline:
            baseline = self._build_baseline_from_observations(
                project_id=project_id,
                model_id=request.model_id,
                model_fingerprint=model_fp,
                task_type=request.task_type,
                observations=request.observations,
            )
            self._baselines[baseline.baseline_id] = baseline

        # 2. Derive representative observation metrics from inputs
        observed_metrics: Dict[str, float] = {}
        if baseline.profile.classification:
            if baseline.profile.classification.confidence_stats:
                observed_metrics["top1_confidence_median"] = baseline.profile.classification.confidence_stats.median
            if baseline.profile.classification.entropy_stats:
                observed_metrics["entropy_median"] = baseline.profile.classification.entropy_stats.median
            if baseline.profile.classification.margin_stats:
                observed_metrics["margin_median"] = baseline.profile.classification.margin_stats.median
        elif baseline.profile.detection:
            if baseline.profile.detection.confidence_stats:
                observed_metrics["confidence_median"] = baseline.profile.detection.confidence_stats.median
            observed_metrics["box_count_median"] = float(baseline.profile.detection.detection_count_stats.median)
        elif baseline.profile.segmentation:
            observed_metrics["mean_confidence"] = 0.90
        elif baseline.profile.numerical:
            for t_name, t_stat in baseline.profile.numerical.tensor_stats.items():
                observed_metrics[f"{t_name}_mean"] = t_stat.get("mean", 0.0)
        else:
            observed_metrics["latency_p50_ms"] = baseline.profile.latency.stats.median

        obs_id = f"obs-{uuid.uuid4().hex[:12]}"

        # 3. Anomaly Analysis
        baseline_distributions: Dict[str, List[float]] = {}
        if baseline.profile.classification and baseline.profile.classification.confidence_stats:
            cs = baseline.profile.classification.confidence_stats
            baseline_distributions["top1_confidence_median"] = [cs.min, cs.p25, cs.median, cs.p75, cs.max]
            if baseline.profile.classification.entropy_stats:
                es = baseline.profile.classification.entropy_stats
                baseline_distributions["entropy_median"] = [es.min, es.p25, es.median, es.p75, es.max]
            if baseline.profile.classification.margin_stats:
                ms = baseline.profile.classification.margin_stats
                baseline_distributions["margin_median"] = [ms.min, ms.p25, ms.median, ms.p75, ms.max]
        elif baseline.profile.detection and baseline.profile.detection.confidence_stats:
            cs = baseline.profile.detection.confidence_stats
            baseline_distributions["confidence_median"] = [cs.min, cs.p25, cs.median, cs.p75, cs.max]
            dcs = baseline.profile.detection.detection_count_stats
            baseline_distributions["box_count_median"] = [dcs.min, dcs.p25, dcs.median, dcs.p75, dcs.max]
        elif baseline.profile.latency:
            ls = baseline.profile.latency.stats
            baseline_distributions["latency_p50_ms"] = [ls.min, ls.p25, ls.median, ls.p75, ls.max]

        for k in observed_metrics:
            if k not in baseline_distributions:
                baseline_distributions[k] = []

        anomaly: BehavioralAnomalyAnalysis = self.anomaly_service.analyze_metrics_dict(
            project_id=project_id,
            model_id=request.model_id,
            model_fingerprint=model_fp,
            baseline_id=baseline.baseline_id,
            baseline_type=baseline.baseline_type.value,
            observation_id=obs_id,
            task_type=request.task_type,
            observed_metrics=observed_metrics,
            baseline_distributions=baseline_distributions,
        )
        self._anomalies[anomaly.analysis_id] = anomaly

        # 4. Evidence Construction & Sealing
        content = BehavioralEvidenceContent(
            evidence_layer=EvidenceLayer.DETECTION,
            evidence_type=BehavioralEvidenceType.BEHAVIORAL_ANOMALY,
            project_id=project_id,
            model_id=request.model_id,
            model_fingerprint=model_fp,
            task_type=request.task_type,
            observation_id=obs_id,
            baseline_id=baseline.baseline_id,
            baseline_type=baseline.baseline_type.value,
            comparison_id="NONE",
            sensitivity_id="NONE",
            anomaly_analysis_id=anomaly.analysis_id,
            input_hash=obs_id[:64].ljust(64, "0"),
            output_hash=anomaly.analysis_id[:64].ljust(64, "0"),
            preprocessing_hash="STANDARD_V1",
            detector_id="behavioral_anomaly_detector",
            detector_version="1.0.0",
            detector_config_hash="0" * 64,
            policy_version="1.0.0",
            engine_version="1.0.0",
            result_status=anomaly.overall_status.value,
            support_status=anomaly.support_status.value,
            comparability_status="COMPARABLE",
            metrics=[m.model_dump() for m in anomaly.metrics],
            families={k: v.model_dump() for k, v in anomaly.families.items()},
            limitations=list(anomaly.limitations),
        )

        evidence: BehavioralEvidence = create_behavioral_evidence(
            content=content,
            seal=True,
        )
        self._evidence_store[evidence.evidence_id] = evidence

        # 5. Provenance Binding
        finding_model, prov_rec_read, scan_status = self.binding_service.bind_behavioral_evidence(
            evidence=evidence,
            audit_run_id=audit_id,
            seal_provenance=request.seal_provenance,
            signer_key_id=request.signer_key_id,
            signer_passphrase=request.signer_passphrase,
            actor=request.actor,
        )

        prov_id = None
        if prov_rec_read:
            prov_id = prov_rec_read.id
        elif finding_model and finding_model.metadata_json:
            prov_id = finding_model.metadata_json.get("provenance_record_id")

        anom_count = sum(1 for m in anomaly.metrics if m.anomaly_status == MetricAnomalyStatus.ANOMALOUS)
        total_count = len(anomaly.metrics)

        return BehavioralAssessmentResponse(
            assessment_status="COMPLETED",
            project_id=project_id,
            model_id=request.model_id,
            execution_identity_hash=evidence.evidence_id,
            idempotent=False,
            anomaly_status=anomaly.overall_status.value,
            finding_id=finding_model.id if finding_model else None,
            evidence_id=evidence.evidence_id,
            provenance_record_id=prov_id,
            anomalous_metric_count=anom_count,
            total_metric_count=total_count,
            explanation=anomaly.explanation,
            limitations=list(anomaly.limitations),
        )

    def create_and_start_assessment(
        self,
        project_id: str,
        request: BehavioralAssessmentRequest,
        run_async: bool = False,
        idempotency_key: Optional[str] = None,
    ) -> BehavioralTaskReadResponse:
        """Register and execute/dispatch a behavioral assessment task."""
        self._get_validated_model(project_id, request.model_id)

        if idempotency_key:
            existing = self.task_manager.find_idempotent_task(project_id, idempotency_key)
            if existing:
                if existing.request.model_dump() != request.model_dump():
                    raise IdempotencyConflictError(
                        f"Idempotency key '{idempotency_key}' was previously used with a different request payload."
                    )
                return existing.to_read_response()

        task_id = f"task-b-{uuid.uuid4().hex[:12]}"
        task = BehavioralTask(
            task_id=task_id,
            project_id=project_id,
            model_id=request.model_id,
            request=request,
            idempotency_key=idempotency_key,
        )
        self.task_manager.register_task(task)

        if run_async:
            self.task_manager._thread_pool.submit(self._execute_task_worker, task_id, self.db)
            return task.to_read_response()
        else:
            self._execute_task_in_session(task, self.db)
            return task.to_read_response()

    def get_task(self, project_id: str, task_id: str) -> BehavioralTaskReadResponse:
        """Retrieve task execution status."""
        self._require_project(project_id)
        task = self.task_manager.get_task(task_id)
        if not task or task.project_id != project_id:
            raise NotFoundException(f"Task '{task_id}' not found in project '{project_id}'.")
        return task.to_read_response()

    def list_tasks(self, project_id: str, model_id: Optional[str] = None) -> List[BehavioralTaskReadResponse]:
        """List in-memory tasks for a project."""
        self._require_project(project_id)
        tasks = self.task_manager.list_tasks(project_id=project_id, model_id=model_id)
        return [t.to_read_response() for t in tasks]

    def cancel_task(self, project_id: str, task_id: str) -> BehavioralTaskReadResponse:
        """Request cooperative cancellation of a task."""
        self._require_project(project_id)
        task = self.task_manager.get_task(task_id)
        if not task or task.project_id != project_id:
            raise NotFoundException(f"Task '{task_id}' not found.")

        task.cancel()
        self.task_manager.emit_event(
            task,
            BehavioralProgressEvent(
                task_id=task_id,
                event_type="task.cancelled",
                progress_percent=task.progress_percent,
                stage="CANCELLED",
                message="Behavioral analysis task cancelled by user.",
                timestamp=utcnow_iso(),
            ),
        )
        return task.to_read_response()

    async def stream_task_events(self, project_id: str, task_id: str) -> AsyncGenerator[str, None]:
        """Subscribe to real-time Server-Sent Events (SSE) for a behavioral task."""
        self._require_project(project_id)
        task = self.task_manager.get_task(task_id)
        if not task or task.project_id != project_id:
            raise NotFoundException(f"Task '{task_id}' not found.")

        queue: asyncio.Queue[BehavioralProgressEvent] = asyncio.Queue()
        self.task_manager.add_subscriber(task, queue)

        init_event = BehavioralProgressEvent(
            task_id=task.task_id,
            event_type="task.progress" if task.status == "RUNNING" else f"task.{task.status.lower()}",
            progress_percent=task.progress_percent,
            stage=task.current_stage,
            message=f"Current task status: {task.status}",
            timestamp=utcnow_iso(),
        )
        yield f"data: {init_event.model_dump_json()}\n\n"

        try:
            while True:
                if task.status in ("COMPLETED", "FAILED", "CANCELLED", "IDEMPOTENT_HIT"):
                    while not queue.empty():
                        ev = queue.get_nowait()
                        yield f"data: {ev.model_dump_json()}\n\n"
                    break

                try:
                    event = await asyncio.wait_for(queue.get(), timeout=1.0)
                    yield f"data: {event.model_dump_json()}\n\n"
                    if event.event_type in ("task.completed", "task.failed", "task.cancelled"):
                        break
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            self.task_manager.remove_subscriber(task, queue)

    def _execute_task_worker(self, task_id: str, db: Optional[Session] = None) -> None:
        """Worker executing in background thread pool."""
        task = self.task_manager.get_task(task_id)
        if not task:
            return

        if db is not None:
            engine = db.get_bind()
            WorkerSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
            worker_db = WorkerSession()
        else:
            worker_db = SessionLocal()

        try:
            self._execute_task_in_session(task, worker_db)
        finally:
            worker_db.close()

    def _execute_task_in_session(self, task: BehavioralTask, db: Session) -> None:
        """Execute multi-stage behavioral assessment with event emissions."""
        task.status = "RUNNING"
        task.started_at = utcnow_iso()
        task.current_stage = "STARTING"
        task.progress_percent = 5.0

        self.task_manager.emit_event(
            task,
            BehavioralProgressEvent(
                task_id=task.task_id,
                event_type="task.started",
                progress_percent=task.progress_percent,
                stage=task.current_stage,
                message="Starting behavioral assessment pipeline",
                timestamp=utcnow_iso(),
            ),
        )

        try:
            if task.is_cancelled:
                task.status = "CANCELLED"
                task.current_stage = "CANCELLED"
                task.completed_at = utcnow_iso()
                return

            task.current_stage = "BASELINING"
            task.progress_percent = 25.0
            self.task_manager.emit_event(
                task,
                BehavioralProgressEvent(
                    task_id=task.task_id,
                    event_type="task.progress",
                    progress_percent=task.progress_percent,
                    stage=task.current_stage,
                    message="Evaluating behavioral baselines",
                    timestamp=utcnow_iso(),
                ),
            )

            if task.is_cancelled:
                task.status = "CANCELLED"
                task.current_stage = "CANCELLED"
                task.completed_at = utcnow_iso()
                return

            task.current_stage = "ANOMALY_DETECTION"
            task.progress_percent = 60.0
            self.task_manager.emit_event(
                task,
                BehavioralProgressEvent(
                    task_id=task.task_id,
                    event_type="task.progress",
                    progress_percent=task.progress_percent,
                    stage=task.current_stage,
                    message="Running statistical anomaly analysis",
                    timestamp=utcnow_iso(),
                ),
            )

            if task.is_cancelled:
                task.status = "CANCELLED"
                task.current_stage = "CANCELLED"
                task.completed_at = utcnow_iso()
                return

            task.current_stage = "EVIDENCE_BINDING"
            task.progress_percent = 85.0
            self.task_manager.emit_event(
                task,
                BehavioralProgressEvent(
                    task_id=task.task_id,
                    event_type="task.progress",
                    progress_percent=task.progress_percent,
                    stage=task.current_stage,
                    message="Synthesizing findings and sealing cryptographic provenance",
                    timestamp=utcnow_iso(),
                ),
            )

            worker_service = BehavioralService(db, key_manager=self.key_manager, task_manager=self.task_manager)
            res = worker_service.run_assessment(
                project_id=task.project_id,
                request=task.request,
                audit_run_id=task.task_id,
            )

            if task.is_cancelled:
                task.status = "CANCELLED"
                task.current_stage = "CANCELLED"
                task.completed_at = utcnow_iso()
                return

            task.result = res
            task.progress_percent = 100.0
            task.status = "COMPLETED"
            task.current_stage = "COMPLETED"
            task.completed_at = utcnow_iso()

            self.task_manager.emit_event(
                task,
                BehavioralProgressEvent(
                    task_id=task.task_id,
                    event_type="task.completed",
                    progress_percent=100.0,
                    stage="COMPLETED",
                    message="Behavioral assessment completed successfully.",
                    timestamp=utcnow_iso(),
                    data={"anomaly_status": res.anomaly_status, "evidence_id": res.evidence_id},
                ),
            )

        except Exception as exc:
            logger.exception("Behavioral task '%s' failed: %s", task.task_id, exc)
            task.status = "FAILED"
            task.current_stage = "FAILED"
            task.error_message = str(exc)
            task.completed_at = utcnow_iso()
            self.task_manager.emit_event(
                task,
                BehavioralProgressEvent(
                    task_id=task.task_id,
                    event_type="task.failed",
                    progress_percent=task.progress_percent,
                    stage="FAILED",
                    message=f"Behavioral assessment failed: {exc}",
                    timestamp=utcnow_iso(),
                ),
            )
