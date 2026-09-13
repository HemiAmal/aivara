"""Inference Verification Service and Task Orchestration Engine (Phase 10.11).

Orchestrates:
  - Phase 10.2: Safe Inference Input Boundary
  - Phase 10.3: Input / Model Binding
  - Phase 10.4: Preprocessing Contract Integrity
  - Phase 10.5: Controlled Model Execution & Raw Output
  - Phase 10.6: Output Schema & Numerical Integrity
  - Phase 10.7: Input -> Output Cryptographic Binding
  - Phase 10.8: Inference Record Persistence & Read-Back Verification
  - Phase 10.9: Deterministic Replay & Consistency Verification
  - Phase 10.10: Evidence Synthesis & Provenance Sealing
  - Concurrency-safe in-memory task runner, cooperative cancellation, and SSE progress broadcasting.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
import threading
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional, Tuple, Union
import uuid

from aivara.crypto.canonical import canonicalize

import numpy as np
from sqlalchemy import desc
from sqlalchemy.orm import Session

from aivara.api.schemas.evidence import EvidenceItemRead
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
from aivara.crypto.keys import KeyManager
from aivara.database.connection import SessionLocal
from aivara.database.models import AIModelModel, EvidenceModel, FindingModel, ProjectModel, ProvenanceRecordModel
from aivara.domain.schemas import AIModelRead, ProvenanceRecordRead
from aivara.evidence.validators import validate_project_isolation
from aivara.inference.binding.engine import create_input_model_binding
from aivara.inference.binding.models import InputModelBinding, ModelIdentityEnvelope
from aivara.inference.composite_binding.engine import create_inference_binding
from aivara.inference.composite_binding.enums import InferenceBindingStatus
from aivara.inference.composite_binding.models import InferenceBinding
from aivara.inference.comprehensive.models import ComprehensiveInferenceVerificationResult
from aivara.inference.comprehensive.service import ComprehensiveInferenceService
from aivara.inference.enums import InferenceFindingCode, InferenceIntegrityStatus, InputKind
from aivara.inference.evidence.engine import create_inference_evidence
from aivara.inference.evidence.models import InferenceEvidence
from aivara.inference.evidence.service import InferenceEvidenceService
from aivara.inference.exceptions import (
    InferenceBindingProjectMismatchError,
    InferenceError,
    InferenceRecordNotFoundError,
    InferenceRecordProjectMismatchError,
    InferenceRecordTamperedError,
    InputFileNotFoundError,
    ProjectMismatchError,
    ReplayIneligibleError,
    ReplayProjectMismatchError,
)
from aivara.inference.execution.engine import execute_inference_transaction
from aivara.inference.execution.models import ExecutionPolicy, InferenceExecution, RawExecutionOutput, RawOutputTensor
from aivara.inference.input.boundary import SafeInferenceInputBoundary, validate_inference_input
from aivara.inference.input.models import InputFinding, InputIdentity
from aivara.inference.output.engine import validate_output_integrity
from aivara.inference.output.enums import TaskType
from aivara.inference.output.models import ModelOutputContract, OutputIntegrityAssessment, OutputTensorContract
from aivara.inference.preprocessing.engine import (
    check_contract_compatibility,
    create_preprocessing_contract,
    execute_preprocessing_pipeline,
)
from aivara.inference.preprocessing.enums import PreprocessingOpType
from aivara.inference.preprocessing.models import (
    PreprocessingContract,
    PreprocessingOperation,
    TransformedInputIdentity,
)
from aivara.inference.records.enums import InferenceRecordStatus, InferenceRecordType
from aivara.inference.records.models import InferenceRecord
from aivara.inference.records.repository import InferenceRecordRepository
from aivara.inference.records.service import InferenceRecordService
from aivara.inference.replay.engine import assess_replay_eligibility, verify_replay_consistency
from aivara.inference.replay.enums import ReplayConsistencyStatus, ReplayEligibilityStatus
from aivara.inference.replay.models import ReplayPolicy, ReplayVerificationResult
from aivara.inference.replay.policy import DEFAULT_DETERMINISTIC_POLICY
from aivara.inference.replay.service import InferenceReplayService
from aivara.services.audit_service import AuditService
from aivara.services.provenance_service import ProvenanceService

logger = logging.getLogger("aivara.services.inference")


def utcnow_iso() -> str:
    """Return current timezone-aware UTC datetime formatted as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


# =====================================================================
# In-Memory Inference Task State Representation
# =====================================================================

class InferenceTask:
    """Thread-safe representation of an in-flight or completed inference verification pipeline."""

    def __init__(
        self,
        task_id: str,
        project_id: str,
        model_id: str,
        request: InferenceVerificationRequest,
        idempotency_key: Optional[str] = None,
    ) -> None:
        self.task_id = task_id
        self.project_id = project_id
        self.model_id = model_id
        self.request = request
        self.idempotency_key = idempotency_key

        self.status = InferenceTaskStageEnum.QUEUED
        self.progress_percent = 0.0
        self.current_stage = "QUEUED"
        self.record_id: Optional[str] = None
        self.result: Optional[InferenceVerificationResponse] = None
        self.error_message: Optional[str] = None
        self.started_at: Optional[str] = None
        self.completed_at: Optional[str] = None

        self._is_cancelled = False
        self._lock = threading.Lock()
        self._event_queues: List[asyncio.Queue[InferenceProgressEvent]] = []

    @property
    def is_cancelled(self) -> bool:
        with self._lock:
            return self._is_cancelled

    def cancel(self) -> None:
        with self._lock:
            self._is_cancelled = True
            if self.status not in (InferenceTaskStageEnum.COMPLETED, InferenceTaskStageEnum.FAILED):
                self.status = InferenceTaskStageEnum.CANCELLED
                self.current_stage = "CANCELLED"
                self.completed_at = utcnow_iso()

    def update_stage(
        self,
        stage: InferenceTaskStageEnum,
        progress: float,
        stage_desc: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self._lock:
            if self._is_cancelled:
                return
            self.status = stage
            self.progress_percent = progress
            self.current_stage = stage_desc
            if stage == InferenceTaskStageEnum.RUNNING and not self.started_at:
                self.started_at = utcnow_iso()
            elif stage in (
                InferenceTaskStageEnum.COMPLETED,
                InferenceTaskStageEnum.FAILED,
                InferenceTaskStageEnum.CANCELLED,
            ):
                self.completed_at = utcnow_iso()

        event = InferenceProgressEvent(
            task_id=self.task_id,
            stage=stage,
            progress_percent=progress,
            message=stage_desc,
            timestamp=utcnow_iso(),
            payload=payload,
        )
        self.broadcast_event(event)

    def broadcast_event(self, event: InferenceProgressEvent) -> None:
        with self._lock:
            dead_queues = []
            for q in list(self._event_queues):
                try:
                    q.put_nowait(event)
                except Exception:
                    dead_queues.append(q)
            for dead in dead_queues:
                if dead in self._event_queues:
                    self._event_queues.remove(dead)

    def subscribe_events(self) -> asyncio.Queue[InferenceProgressEvent]:
        q: asyncio.Queue[InferenceProgressEvent] = asyncio.Queue(maxsize=100)
        with self._lock:
            self._event_queues.append(q)
            # Replay initial state
            initial_event = InferenceProgressEvent(
                task_id=self.task_id,
                stage=self.status,
                progress_percent=self.progress_percent,
                message=self.current_stage,
                timestamp=utcnow_iso(),
            )
            try:
                q.put_nowait(initial_event)
            except Exception:
                pass
        return q

    def unsubscribe_events(self, q: asyncio.Queue[InferenceProgressEvent]) -> None:
        with self._lock:
            if q in self._event_queues:
                self._event_queues.remove(q)

    def to_read_response(self) -> InferenceTaskReadResponse:
        with self._lock:
            return InferenceTaskReadResponse(
                task_id=self.task_id,
                project_id=self.project_id,
                model_id=self.model_id,
                status=self.status,
                progress_percent=self.progress_percent,
                current_stage=self.current_stage,
                record_id=self.record_id,
                result=self.result,
                error_message=self.error_message,
                started_at=self.started_at,
                completed_at=self.completed_at,
            )


# =====================================================================
# In-Memory Task Manager
# =====================================================================

class InferenceTaskManager:
    """Thread-safe registry of in-memory inference verification tasks."""

    _instance: Optional[InferenceTaskManager] = None
    _lock = threading.Lock()

    def __new__(cls) -> InferenceTaskManager:
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._tasks: Dict[str, InferenceTask] = {}
                cls._instance._idempotency_map: Dict[str, str] = {}
                cls._instance._tasks_lock = threading.Lock()
                cls._instance._thread_pool = ThreadPoolExecutor(
                    max_workers=4,
                    thread_name_prefix="aivara-inference-worker",
                )
            return cls._instance

    def register_task(self, task: InferenceTask) -> None:
        with self._tasks_lock:
            self._tasks[task.task_id] = task
            if task.idempotency_key:
                self._idempotency_map[f"{task.project_id}:{task.idempotency_key}"] = task.task_id

    def get_task(self, task_id: str) -> Optional[InferenceTask]:
        with self._tasks_lock:
            return self._tasks.get(task_id)

    def find_by_idempotency_key(self, project_id: str, idempotency_key: str) -> Optional[InferenceTask]:
        with self._tasks_lock:
            task_id = self._idempotency_map.get(f"{project_id}:{idempotency_key}")
            if task_id:
                return self._tasks.get(task_id)
        return None

    def list_tasks(
        self,
        project_id: Optional[str] = None,
        model_id: Optional[str] = None,
    ) -> List[InferenceTask]:
        with self._tasks_lock:
            tasks = list(self._tasks.values())
        if project_id:
            tasks = [t for t in tasks if t.project_id == project_id]
        if model_id:
            tasks = [t for t in tasks if t.model_id == model_id]
        return tasks

    def create_task(
        self,
        project_id: str,
        model_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        request: Optional[InferenceVerificationRequest] = None,
    ) -> InferenceTask:
        task_id = str(uuid.uuid4())
        task = InferenceTask(
            task_id=task_id,
            project_id=project_id,
            model_id=model_id or "unknown",
            request=request or InferenceVerificationRequest(model_id=model_id or "unknown"),
            idempotency_key=idempotency_key,
        )
        self.register_task(task)
        return task

    def cancel_task(self, task_id: str) -> Optional[InferenceTask]:
        task = self.get_task(task_id)
        if task:
            task.cancel()
        return task

    def update_progress(
        self,
        task_id: str,
        stage: Any,
        progress: float,
        message: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        task = self.get_task(task_id)
        if task:
            if isinstance(stage, str):
                try:
                    stage_enum = InferenceTaskStageEnum(stage)
                except Exception:
                    stage_enum = InferenceTaskStageEnum.RUNNING
            else:
                stage_enum = stage
            task.update_stage(stage=stage_enum, progress=progress, stage_desc=message, payload=payload)

    def complete_task(self, task_id: str, result: Any) -> None:
        task = self.get_task(task_id)
        if task:
            task.result = result
            task.update_stage(stage=InferenceTaskStageEnum.COMPLETED, progress=100.0, stage_desc="Completed")

    def fail_task(self, task_id: str, error_message: str) -> None:
        task = self.get_task(task_id)
        if task:
            task.error_message = error_message
            task.update_stage(stage=InferenceTaskStageEnum.FAILED, progress=100.0, stage_desc=f"Failed: {error_message}")

    def subscribe_events(self, task_id: str) -> Optional[asyncio.Queue[InferenceProgressEvent]]:
        task = self.get_task(task_id)
        if task:
            return task.subscribe_events()
        return None

    def unsubscribe_events(self, task_id: str, q: asyncio.Queue[InferenceProgressEvent]) -> None:
        task = self.get_task(task_id)
        if task:
            task.unsubscribe_events(q)

    def clear(self) -> None:
        with self._tasks_lock:
            self._tasks.clear()
            self._idempotency_map.clear()

    def submit_background_job(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        self._thread_pool.submit(fn, *args, **kwargs)


def get_task_manager() -> InferenceTaskManager:
    """Dependency provider returning singleton InferenceTaskManager."""
    return InferenceTaskManager()



# =====================================================================
# Main Inference Service Layer
# =====================================================================

class InferenceService:
    """Service orchestrating the authoritative Phase 10 Inference Integrity verification pipeline."""

    def __init__(
        self,
        db: Optional[Session] = None,
        key_manager: Optional[KeyManager] = None,
        task_manager: Optional[InferenceTaskManager] = None,
    ) -> None:
        self.db = db
        self.key_manager = key_manager or KeyManager(keys_dir=settings.keys_dir)
        self.task_manager = task_manager or InferenceTaskManager()
        self.audit_service = AuditService(db) if db is not None else None
        self.provenance_service = (
            ProvenanceService(db=db, key_manager=self.key_manager, audit_service=self.audit_service)
            if db is not None
            else None
        )
        self.record_service = InferenceRecordService(db) if db is not None else None
        self.replay_service = InferenceReplayService()
        self.evidence_service = (
            InferenceEvidenceService(
                db=db,
                key_manager=self.key_manager,
                audit_service=self.audit_service,
                provenance_service=self.provenance_service,
            )
            if db is not None
            else None
        )
        self.comprehensive_service = ComprehensiveInferenceService(
            db=db,
            key_manager=self.key_manager,
            record_service=self.record_service,
            evidence_service=self.evidence_service,
            provenance_service=self.provenance_service,
            replay_service=self.replay_service,
            audit_service=self.audit_service,
        )

    # -----------------------------------------------------------------
    # Verification Pipeline Initiation
    # -----------------------------------------------------------------

    def create_and_start_verification(
        self,
        project_id: str,
        request: InferenceVerificationRequest,
        run_async: bool = False,
        idempotency_key: Optional[str] = None,
    ) -> Union[InferenceVerificationResponse, InferenceTaskReadResponse]:
        """Initiate synchronous or asynchronous inference verification pipeline."""
        if not project_id:
            raise ValidationException("project_id must not be empty", code="PROJECT_REQUIRED")

        # Project isolation & entity check
        if self.db is not None:
            proj = self.db.query(ProjectModel).filter(ProjectModel.id == project_id).first()
            if proj is None:
                raise NotFoundException(f"Project '{project_id}' not found.")

            model_obj = (
                self.db.query(AIModelModel)
                .filter(AIModelModel.id == request.model_id, AIModelModel.project_id == project_id)
                .first()
            )
            if model_obj is None:
                # If model not found under project, fail closed with 404
                raise NotFoundException(
                    f"Model '{request.model_id}' not found in project '{project_id}'.",
                )

        # Check idempotency
        if idempotency_key:
            existing_task = self.task_manager.find_by_idempotency_key(project_id, idempotency_key)
            if existing_task:
                if run_async:
                    return existing_task.to_read_response()
                if existing_task.result:
                    return existing_task.result

        task_id = str(uuid.uuid4())
        task = InferenceTask(
            task_id=task_id,
            project_id=project_id,
            model_id=request.model_id,
            request=request,
            idempotency_key=idempotency_key,
        )
        self.task_manager.register_task(task)

        if run_async:
            self.task_manager.submit_background_job(self._run_task_worker, task.task_id)
            return task.to_read_response()

        # Synchronous execution
        self._execute_pipeline(task)
        if task.status == InferenceTaskStageEnum.FAILED and task.error_message:
            raise InferenceError(task.error_message, details={"task_id": task.task_id})
        if task.result is None:
            raise InferenceError("Verification failed to produce result.", details={"task_id": task.task_id})
        return task.result

    def _run_task_worker(self, task_id: str) -> None:
        """Background worker thread executing the verification pipeline."""
        task = self.task_manager.get_task(task_id)
        if not task:
            return

        db_session = self.db if self.db is not None else SessionLocal()
        try:
            worker_service = InferenceService(
                db=db_session,
                key_manager=self.key_manager,
                task_manager=self.task_manager,
            )
            worker_service._execute_pipeline(task)
        except Exception as e:
            logger.exception("Error executing background inference verification task %s: %s", task_id, str(e))
            task.error_message = str(e)
            task.update_stage(InferenceTaskStageEnum.FAILED, 100.0, f"Task execution failed: {str(e)}")
        finally:
            if db_session is not self.db:
                db_session.close()

    def _execute_pipeline(self, task: InferenceTask) -> None:
        """Execute end-to-end Phase 10 verification pipeline stages sequentially with cooperative cancellation."""
        request = task.request
        project_id = task.project_id
        model_id = request.model_id
        task.update_stage(InferenceTaskStageEnum.RUNNING, 5.0, "Starting inference verification pipeline")

        try:
            # -------------------------------------------------------------
            # Stage 1: Input Validation & Boundary (Phase 10.2)
            # -------------------------------------------------------------
            if task.is_cancelled:
                return
            task.update_stage(InferenceTaskStageEnum.INPUT_VALIDATION, 15.0, "Validating input boundary and computing canonical input identity")

            # Determine input kind & payload
            input_source = request.input_payload if request.input_payload is not None else request.input_path
            if input_source is None:
                raise ValidationException("Either input_payload or input_path must be provided.", code="INPUT_REQUIRED")

            input_identity = validate_inference_input(
                data=input_source,
                kind=request.input_kind,
            )

            # -------------------------------------------------------------
            # Stage 2: Input / Model Binding (Phase 10.3)
            # -------------------------------------------------------------
            if task.is_cancelled:
                return
            task.update_stage(InferenceTaskStageEnum.INPUT_MODEL_BINDING, 25.0, "Cryptographically binding input identity to model identity")

            # Resolve model identity envelope
            model_artifact_hash = "00" * 32
            model_structural_hash = "00" * 32
            model_contract_hash = "00" * 32
            model_master_fingerprint = None

            if self.db is not None:
                model_record = (
                    self.db.query(AIModelModel)
                    .filter(AIModelModel.id == model_id, AIModelModel.project_id == project_id)
                    .first()
                )
                if model_record:
                    meta = model_record.metadata_json or {}
                    model_artifact_hash = getattr(model_record, "file_hash_sha256", None) or meta.get("artifact_hash", "00" * 32)
                    model_structural_hash = meta.get("structural_hash", "00" * 32)
                    model_contract_hash = meta.get("contract_hash", "00" * 32)
                    model_master_fingerprint = meta.get("master_fingerprint")

            if not model_master_fingerprint:
                payload = {
                    "artifact_hash": model_artifact_hash,
                    "contract_hash": model_contract_hash,
                    "schema_version": "1.0",
                    "structural_hash": model_structural_hash,
                }
                model_master_fingerprint = hashlib.sha256(canonicalize(payload)).hexdigest()

            model_envelope = ModelIdentityEnvelope(
                model_id=model_id,
                project_id=project_id,
                artifact_hash=model_artifact_hash,
                structural_hash=model_structural_hash,
                contract_hash=model_contract_hash,
                master_fingerprint=model_master_fingerprint,
            )

            input_model_binding = create_input_model_binding(
                input_identity=input_identity,
                model_identity=model_envelope,
                project_id=project_id,
                raise_on_error=True,
            )

            # -------------------------------------------------------------
            # Stage 3: Preprocessing Contract & Transformation (Phase 10.4)
            # -------------------------------------------------------------
            if task.is_cancelled:
                return
            task.update_stage(InferenceTaskStageEnum.PREPROCESSING, 40.0, "Evaluating preprocessing contract integrity and executing transformation")

            prep_contract_dict = request.preprocessing_contract or {}
            operations = []
            for op_data in prep_contract_dict.get("operations", []):
                if isinstance(op_data, dict):
                    op_type_val = op_data.get("op_type") or op_data.get("op") or "NO_OP"
                    op_type_str = str(op_type_val).upper()
                    try:
                        op_type = PreprocessingOpType(op_type_str)
                    except ValueError:
                        op_type = PreprocessingOpType.NO_OP
                    params = op_data.get("parameters")
                    if params is None:
                        params = {k: v for k, v in op_data.items() if k not in ("op", "op_type", "op_version", "description")}
                    if op_type == PreprocessingOpType.NORMALIZE:
                        if "mean" in params and isinstance(params["mean"], (int, float)):
                            params["mean"] = [float(params["mean"])]
                        if "std" in params and isinstance(params["std"], (int, float)):
                            params["std"] = [float(params["std"])]
                    operations.append(PreprocessingOperation(
                        op_type=op_type,
                        op_version=op_data.get("op_version", "1.0"),
                        parameters=params,
                        description=op_data.get("description"),
                    ))
                elif isinstance(op_data, PreprocessingOperation):
                    operations.append(op_data)

            contract_name = prep_contract_dict.get("name", "inference_default_contract")
            prep_contract = create_preprocessing_contract(
                name=contract_name,
                operations=operations,
                contract_version=prep_contract_dict.get("contract_version", "1.0"),
            )

            # Compatibility check
            compat_assessment = check_contract_compatibility(
                contract=prep_contract,
                input_identity=input_identity,
            )

            # Execute preprocessing
            raw_input_data = input_source
            if isinstance(input_source, list):
                raw_input_data = np.array(input_source, dtype=np.float32)

            preprocessed_array, transformed_identity = execute_preprocessing_pipeline(
                contract=prep_contract,
                input_array=raw_input_data,
                input_identity=input_identity,
                binding=input_model_binding,
            )

            # -------------------------------------------------------------
            # Stage 4: Controlled Model Execution & Raw Output (Phase 10.5)
            # -------------------------------------------------------------
            if task.is_cancelled:
                return
            task.update_stage(InferenceTaskStageEnum.EXECUTION, 55.0, "Executing inference transaction under controlled isolation boundary")

            exec_policy_dict = request.execution_policy or {}
            exec_policy = ExecutionPolicy(**exec_policy_dict) if exec_policy_dict else ExecutionPolicy()

            # Execute inference
            inference_execution = execute_inference_transaction(
                input_identity=input_identity,
                binding=input_model_binding,
                model_identity=model_envelope,
                preprocessing_contract=prep_contract,
                transformed_identity=transformed_identity,
                preprocessed_array=preprocessed_array,
                project_id=project_id,
                policy=exec_policy,
                cancellation_check=lambda: task.is_cancelled,
            )

            # -------------------------------------------------------------
            # Stage 5: Output Schema & Numerical Integrity (Phase 10.6)
            # -------------------------------------------------------------
            if task.is_cancelled:
                return
            task.update_stage(InferenceTaskStageEnum.OUTPUT_VALIDATION, 70.0, "Verifying output schema and numerical integrity")

            output_contract_dict = request.output_contract or {}
            if output_contract_dict:
                raw_outputs = output_contract_dict.get("outputs") or output_contract_dict.get("expected_outputs") or []
                tensor_contracts = []
                for out_item in raw_outputs:
                    if isinstance(out_item, dict):
                        vr = out_item.get("value_range")
                        min_v = out_item.get("min_value") if out_item.get("min_value") is not None else (vr[0] if isinstance(vr, (list, tuple)) and len(vr) > 0 else None)
                        max_v = out_item.get("max_value") if out_item.get("max_value") is not None else (vr[1] if isinstance(vr, (list, tuple)) and len(vr) > 1 else None)
                        tensor_contracts.append(OutputTensorContract(
                            name=out_item.get("name", "output"),
                            shape=out_item.get("shape", []),
                            dtype=out_item.get("dtype", "float32"),
                            min_value=min_v,
                            max_value=max_v,
                        ))
                    elif isinstance(out_item, OutputTensorContract):
                        tensor_contracts.append(out_item)

                task_type_str = str(output_contract_dict.get("task_type", "generic")).lower()
                try:
                    task_type_enum = TaskType(task_type_str)
                except ValueError:
                    task_type_enum = TaskType.GENERIC

                output_contract = ModelOutputContract(
                    task_type=task_type_enum,
                    outputs=tensor_contracts,
                    contract_version=output_contract_dict.get("contract_version", "1.0"),
                )
            else:
                output_contract = ModelOutputContract()

            output_assessment = validate_output_integrity(
                raw_output=inference_execution,
                contract=output_contract,
            )

            # -------------------------------------------------------------
            # Stage 6: Input -> Output Composite Binding (Phase 10.7)
            # -------------------------------------------------------------
            if task.is_cancelled:
                return
            task.update_stage(InferenceTaskStageEnum.INFERENCE_BINDING, 80.0, "Computing authoritative cryptographic inference binding")

            composite_binding = create_inference_binding(
                project_id=project_id,
                input_identity=input_identity,
                input_model_binding=input_model_binding,
                preprocessing_contract=prep_contract,
                transformed_input=transformed_identity,
                execution=inference_execution,
                output_assessment=output_assessment,
                raise_on_error=True,
            )

            # -------------------------------------------------------------
            # Stage 7: Inference Record Persistence (Phase 10.8)
            # -------------------------------------------------------------
            if task.is_cancelled:
                return
            task.update_stage(InferenceTaskStageEnum.RECORD_PERSISTENCE, 85.0, "Persisting sealed inference record and verifying read-back integrity")

            persisted_record: Optional[InferenceRecord] = None
            if self.record_service is not None and self.db is not None:
                persisted_record = self.record_service.persist_inference_record(
                    project_id=project_id,
                    binding=composite_binding,
                    record_type=InferenceRecordType.STANDARD,
                )
                task.record_id = persisted_record.record_id
            else:
                # In-memory fallback if no db provided
                from aivara.inference.records.engine import create_inference_record
                persisted_record = create_inference_record(
                    project_id=project_id,
                    binding=composite_binding,
                    record_type=InferenceRecordType.STANDARD,
                )
                task.record_id = persisted_record.record_id

            # -------------------------------------------------------------
            # Stage 8: Replay Verification (Phase 10.9 - Optional)
            # -------------------------------------------------------------
            replay_result: Optional[ReplayVerificationResult] = None
            if request.perform_replay:
                if task.is_cancelled:
                    return
                task.update_stage(InferenceTaskStageEnum.REPLAY_VERIFICATION, 90.0, "Executing deterministic replay and consistency verification")

                replay_policy = (
                    ReplayPolicy(**request.replay_policy)
                    if request.replay_policy
                    else DEFAULT_DETERMINISTIC_POLICY
                )

                replay_result = self.replay_service.orchestrate_replay(
                    record=persisted_record,
                    input_identity=input_identity,
                    binding=input_model_binding,
                    model_identity=model_envelope,
                    preprocessing_contract=prep_contract,
                    transformed_identity=transformed_identity,
                    preprocessed_array=preprocessed_array,
                    execution_policy=exec_policy,
                    replay_policy=replay_policy,
                    expected_project_id=project_id,
                    cancellation_check=lambda: task.is_cancelled,
                )

            # -------------------------------------------------------------
            # Stage 9: Evidence & Provenance Binding (Phase 10.10)
            # -------------------------------------------------------------
            if task.is_cancelled:
                return
            task.update_stage(InferenceTaskStageEnum.EVIDENCE_BINDING, 95.0, "Synthesizing Phase 5 evidence and sealing Phase 4 provenance chain")

            evidence_obj: Optional[InferenceEvidence] = None
            prov_record_id: Optional[str] = None
            prov_record_hash: Optional[str] = None

            if request.seal_provenance and self.evidence_service is not None and self.db is not None:
                key_handle = None
                if request.signer_key_id:
                    try:
                        key_handle = self.key_manager.get_private_key(
                            request.signer_key_id,
                            passphrase=request.signer_passphrase,
                        )
                    except Exception as e:
                        logger.warning("Could not unlock signer key %s: %s", request.signer_key_id, str(e))

                evidence_obj, prov_read, finding_row = self.evidence_service.seal_and_bind_evidence(
                    record=persisted_record,
                    binding=composite_binding,
                    replay_result=replay_result,
                    signer_key_id=request.signer_key_id,
                    key_handle=key_handle,
                    expected_project_id=project_id,
                )
                if prov_read:
                    prov_record_id = prov_read.id
                    prov_record_hash = prov_read.record_hash
            elif self.evidence_service is not None:
                evidence_obj = self.evidence_service.generate_inference_evidence(
                    record=persisted_record,
                    binding=composite_binding,
                    replay_result=replay_result,
                    expected_project_id=project_id,
                )
            else:
                evidence_obj = create_inference_evidence(
                    record=persisted_record,
                    binding=composite_binding,
                    replay_result=replay_result,
                )

            # -------------------------------------------------------------
            # Stage 10: Final Response Assembly
            # -------------------------------------------------------------
            all_findings: List[FindingSummaryItem] = []
            for f in composite_binding.findings:
                all_findings.append(FindingSummaryItem(
                    code=f.code if hasattr(f, "code") else str(f),
                    message=f.message if hasattr(f, "message") else str(f),
                    severity="HIGH" if composite_binding.status != InferenceBindingStatus.VERIFIED else "INFO",
                ))

            if replay_result and not replay_result.is_consistent:
                for f in replay_result.findings:
                    all_findings.append(FindingSummaryItem(
                        code=f.code if hasattr(f, "code") else str(f),
                        message=f.message if hasattr(f, "message") else str(f),
                        severity="MEDIUM",
                    ))

            response = InferenceVerificationResponse(
                task_id=task.task_id,
                record_id=persisted_record.record_id if persisted_record else None,
                project_id=project_id,
                model_id=model_id,
                verification_status=InferenceIntegrityStatus.VERIFIED.value if composite_binding.binding_status == InferenceIntegrityStatus.VERIFIED else InferenceIntegrityStatus.INVALID.value,
                binding_status=composite_binding.binding_status.value if hasattr(composite_binding.binding_status, "value") else str(composite_binding.binding_status),
                input_canonical_hash=composite_binding.input_canonical_hash,
                model_master_fingerprint=composite_binding.model_master_fingerprint,
                input_model_binding_hash=composite_binding.input_model_binding_hash,
                preprocessing_contract_hash=composite_binding.preprocessing_contract_hash,
                transformed_input_hash=composite_binding.transformed_input_hash,
                execution_identity_hash=composite_binding.execution_identity_hash,
                raw_output_hash=composite_binding.raw_output_hash,
                output_contract_hash=composite_binding.output_contract_hash,
                validated_output_identity=composite_binding.validated_output_identity,
                inference_binding_hash=composite_binding.inference_binding_hash,
                record_integrity_hash=persisted_record.record_integrity_hash if persisted_record else None,
                evidence_hash=evidence_obj.evidence_id if evidence_obj else None,
                provenance_record_id=prov_record_id,
                provenance_record_hash=prov_record_hash,
                replay_status=replay_result.consistency_status.value if (replay_result and hasattr(replay_result.consistency_status, "value")) else (str(replay_result.consistency_status) if replay_result else None),
                replay_consistency_status=replay_result.consistency_status.value if (replay_result and hasattr(replay_result.consistency_status, "value")) else (str(replay_result.consistency_status) if replay_result else None),
                findings=all_findings,
                details={
                    "schema_version": composite_binding.schema_version,
                    "binding_version": composite_binding.binding_version,
                    "input_kind": input_identity.input_kind.value if hasattr(input_identity.input_kind, "value") else str(input_identity.input_kind),
                    "element_count": transformed_identity.element_count,
                    "finite": transformed_identity.finite,
                },
                executed_at=utcnow_iso(),
            )

            task.result = response
            task.update_stage(InferenceTaskStageEnum.COMPLETED, 100.0, "Inference verification pipeline completed successfully")

        except Exception as e:
            logger.exception("Inference pipeline failed: %s", str(e))
            task.error_message = str(e)
            task.update_stage(InferenceTaskStageEnum.FAILED, 100.0, f"Inference pipeline failed: {str(e)}")
            raise

    # -----------------------------------------------------------------
    # Task Management Operations
    # -----------------------------------------------------------------

    def get_task(self, project_id: str, task_id: str) -> InferenceTaskReadResponse:
        """Retrieve task execution status with project boundary check."""
        task = self.task_manager.get_task(task_id)
        if not task:
            raise NotFoundException(f"Inference task '{task_id}' not found.")
        if task.project_id != project_id:
            raise ProjectMismatchError(
                f"Task '{task_id}' belongs to project '{task.project_id}', not '{project_id}'.",
                code="PROJECT_MISMATCH",
            )
        return task.to_read_response()

    def list_tasks(self, project_id: str, model_id: Optional[str] = None) -> List[InferenceTaskReadResponse]:
        """List tasks scoped to a project."""
        tasks = self.task_manager.list_tasks(project_id=project_id, model_id=model_id)
        return [t.to_read_response() for t in tasks]

    def cancel_task(self, project_id: str, task_id: str) -> InferenceTaskReadResponse:
        """Request cooperative cancellation of a task."""
        task = self.task_manager.get_task(task_id)
        if not task:
            raise NotFoundException(f"Inference task '{task_id}' not found.")
        if task.project_id != project_id:
            raise ProjectMismatchError(
                f"Task '{task_id}' belongs to project '{task.project_id}', not '{project_id}'.",
                code="PROJECT_MISMATCH",
            )
        task.cancel()
        return task.to_read_response()

    async def stream_task_events(self, project_id: str, task_id: str) -> AsyncGenerator[str, None]:
        """Stream real-time SSE progress events for a task."""
        task = self.task_manager.get_task(task_id)
        if not task:
            raise NotFoundException(f"Inference task '{task_id}' not found.")
        if task.project_id != project_id:
            raise ProjectMismatchError(
                f"Task '{task_id}' belongs to project '{task.project_id}', not '{project_id}'.",
                code="PROJECT_MISMATCH",
            )

        queue = task.subscribe_events()
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    # Safe serialization: no raw tensors, no keys, no secrets
                    yield f"event: progress\ndata: {event.model_dump_json()}\n\n"
                    if event.stage in (
                        InferenceTaskStageEnum.COMPLETED,
                        InferenceTaskStageEnum.FAILED,
                        InferenceTaskStageEnum.CANCELLED,
                    ):
                        break
                except asyncio.TimeoutError:
                    # Keep-alive heartbeat
                    yield f": keep-alive\n\n"
        finally:
            task.unsubscribe_events(queue)

    # -----------------------------------------------------------------
    # -----------------------------------------------------------------
    # Record Operations & Read-Back Verification
    # -----------------------------------------------------------------

    def get_record(self, project_id: str, record_id: str) -> InferenceRecordReadResponse:
        """Retrieve an immutable sealed inference record with strict project boundary enforcement."""
        if self.db is None:
            raise RuntimeError("Database session required to retrieve inference record.")

        repo = InferenceRecordRepository(self.db)
        db_rec = repo.get_by_id(record_id, project_id=project_id)
        if db_rec is None:
            # Check if record exists under different project for proper project isolation check
            any_rec = repo.get_by_id(record_id)
            if any_rec is not None:
                raise InferenceRecordProjectMismatchError(
                    f"Record '{record_id}' does not belong to project '{project_id}'.",
                    details={"record_id": record_id, "project_id": project_id},
                )
            raise NotFoundException(
                f"Inference record '{record_id}' not found for project '{project_id}'.",
                details={"record_id": record_id, "project_id": project_id},
            )

        domain_rec = repo.to_domain(db_rec)
        return InferenceRecordReadResponse(
            record_id=domain_rec.record_id,
            project_id=domain_rec.project_id,
            model_id=domain_rec.binding.model_id if domain_rec.binding else db_rec.model_id,
            record_type=domain_rec.record_type.value if hasattr(domain_rec.record_type, "value") else str(domain_rec.record_type),
            schema_version=domain_rec.schema_version,
            record_version=domain_rec.record_version,
            binding_version=domain_rec.binding_version,
            inference_binding_hash=domain_rec.inference_binding_hash,
            record_integrity_hash=domain_rec.record_integrity_hash,
            record_status=domain_rec.record_status.value if hasattr(domain_rec.record_status, "value") else str(domain_rec.record_status),
            created_at=domain_rec.created_at or (db_rec.created_at.isoformat() if db_rec.created_at else utcnow_iso()),
            input_hash=db_rec.input_hash,
            output_hash=db_rec.output_hash,
            sequence_number=db_rec.sequence_number,
            binding=domain_rec.binding.model_dump() if domain_rec.binding else None,
            findings=[
                FindingSummaryItem(code=f.code, message=f.message)
                for f in domain_rec.findings
            ],
            details=domain_rec.details,
        )

    def list_records(
        self,
        project_id: str,
        model_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[InferenceRecordReadResponse]:
        """List sealed inference records for a project."""
        if self.db is None:
            raise RuntimeError("Database session required to list inference records.")

        repo = InferenceRecordRepository(self.db)
        records = repo.list_by_project(project_id=project_id, skip=offset, limit=limit)
        results = []
        for db_rec in records:
            if model_id and db_rec.model_id != model_id:
                continue
            if status and db_rec.verification_status.upper() != status.upper():
                continue
            domain_rec = repo.to_domain(db_rec)
            results.append(InferenceRecordReadResponse(
                record_id=domain_rec.record_id,
                project_id=domain_rec.project_id,
                model_id=domain_rec.binding.model_id if domain_rec.binding else db_rec.model_id,
                record_type=domain_rec.record_type.value if hasattr(domain_rec.record_type, "value") else str(domain_rec.record_type),
                schema_version=domain_rec.schema_version,
                record_version=domain_rec.record_version,
                binding_version=domain_rec.binding_version,
                inference_binding_hash=domain_rec.inference_binding_hash,
                record_integrity_hash=domain_rec.record_integrity_hash,
                record_status=domain_rec.record_status.value if hasattr(domain_rec.record_status, "value") else str(domain_rec.record_status),
                created_at=domain_rec.created_at or (db_rec.created_at.isoformat() if db_rec.created_at else utcnow_iso()),
                input_hash=db_rec.input_hash,
                output_hash=db_rec.output_hash,
                sequence_number=db_rec.sequence_number,
                binding=domain_rec.binding.model_dump() if domain_rec.binding else None,
                findings=[],
                details=domain_rec.details,
            ))
        return results

    def verify_record(self, project_id: str, record_id: str) -> InferenceRecordVerifyResponse:
        """Verify the cryptographic integrity of a stored inference record."""
        if self.db is None or self.record_service is None:
            raise RuntimeError("Database session and record service required to verify inference record.")

        verif_result = self.record_service.get_and_verify_record(
            record_id=record_id,
            project_id=project_id,
            raise_on_tamper=False,
        )

        findings = [
            FindingSummaryItem(code=f.code, message=f.message)
            for f in verif_result.findings
        ]

        return InferenceRecordVerifyResponse(
            is_valid=verif_result.is_valid,
            status=verif_result.status.value,
            record_id=verif_result.record_id,
            project_id=verif_result.project_id,
            stored_integrity_hash=verif_result.stored_integrity_hash,
            computed_integrity_hash=verif_result.computed_integrity_hash,
            inference_binding_hash=verif_result.inference_binding_hash,
            binding_verification_status=verif_result.binding_verification_status.value,
            findings=findings,
            details=verif_result.details,
        )

    def verify_comprehensive(
        self,
        project_id: str,
        record_id: str,
    ) -> ComprehensiveInferenceVerificationResult:
        """Perform comprehensive 18-layer end-to-end verification of an inference record and its complete chain."""
        return self.comprehensive_service.verify_stored_record(
            project_id=project_id,
            record_id=record_id,
        )

    def get_record_evidence(self, project_id: str, record_id: str) -> List[Dict[str, Any]]:
        """Retrieve synthesized Phase 5 evidence items referencing this inference record."""
        if self.db is None:
            raise RuntimeError("Database session required to retrieve evidence.")

        # Verify record exists in project
        self.get_record(project_id, record_id)

        evidence_rows = (
            self.db.query(EvidenceModel)
            .join(FindingModel, EvidenceModel.finding_id == FindingModel.id)
            .filter(FindingModel.project_id == project_id)
            .all()
        )

        results = []
        for ev in evidence_rows:
            data = ev.data_json or {}
            if (
                data.get("record_id") == record_id
                or (ev.description and record_id in ev.description)
            ):
                results.append({
                    "id": ev.id,
                    "finding_id": ev.finding_id,
                    "evidence_hash": ev.evidence_hash,
                    "evidence_type": ev.evidence_type,
                    "evidence_layer": ev.evidence_layer,
                    "title": ev.title,
                    "description": ev.description,
                    "confidence": ev.confidence,
                    "data_json": data,
                    "created_at": ev.created_at.isoformat() if ev.created_at else utcnow_iso(),
                })
        return results

    def get_record_provenance(self, project_id: str, record_id: str) -> Optional[ProvenanceRecordRead]:
        """Retrieve the Phase 4 provenance chain record sealing this inference transaction."""
        if self.db is None:
            raise RuntimeError("Database session required to retrieve provenance.")

        # Verify record exists in project
        self.get_record(project_id, record_id)

        prov_rows = (
            self.db.query(ProvenanceRecordModel)
            .filter(
                ProvenanceRecordModel.project_id == project_id,
                ProvenanceRecordModel.record_type == "INFERENCE_TRANSACTION_ASSURANCE",
            )
            .order_by(desc(ProvenanceRecordModel.sequence_number))
            .all()
        )

        for p in prov_rows:
            meta = p.metadata_json or {}
            if (
                meta.get("record_id") == record_id
                or meta.get("inference_record_id") == record_id
            ):
                return ProvenanceRecordRead.model_validate(p)

        # Fallback search by record hash
        db_rec = InferenceRecordRepository(self.db).get_by_id(record_id, project_id=project_id)
        if db_rec and db_rec.record_hash:
            for p in prov_rows:
                meta = p.metadata_json or {}
                if meta.get("record_integrity_hash") == db_rec.record_hash:
                    return ProvenanceRecordRead.model_validate(p)

        return None

    def replay_record(
        self,
        project_id: str,
        record_id: str,
        request: Optional[InferenceReplayRequest] = None,
    ) -> InferenceReplayResponse:
        """Trigger controlled replay on an existing inference record and evaluate consistency."""
        if self.db is None:
            raise RuntimeError("Database session required to execute replay.")

        req = request or InferenceReplayRequest()

        repo = InferenceRecordRepository(self.db)
        db_rec = repo.get_by_id(record_id, project_id=project_id)
        if db_rec is None:
            # Project isolation check
            any_rec = repo.get_by_id(record_id)
            if any_rec is not None:
                raise ReplayProjectMismatchError(
                    f"Record '{record_id}' belongs to a different project.",
                    details={"record_id": record_id, "project_id": project_id},
                )
            raise NotFoundException(
                f"Inference record '{record_id}' not found for replay.",
                details={"record_id": record_id, "project_id": project_id},
            )

        domain_rec = repo.to_domain(db_rec)
        binding = domain_rec.binding
        if binding is None:
            raise ReplayIneligibleError("Record lacks complete composite binding descriptor for replay.")

        # Reconstruct components for replay
        input_data = req.input_payload if req.input_payload is not None else req.input_path
        if input_data is None:
            if db_rec.input_path and isinstance(db_rec.input_path, str) and (os.path.exists(db_rec.input_path) or "/" in db_rec.input_path or "\\" in db_rec.input_path):
                input_data = db_rec.input_path
            else:
                input_data = [0.0]

        input_id = validate_inference_input(
            data=input_data,
        )

        model_envelope = ModelIdentityEnvelope(
            model_id=binding.model_id,
            project_id=project_id,
            artifact_hash=binding.model_artifact_hash,
            structural_hash=binding.model_structural_hash,
            contract_hash=binding.model_contract_hash,
            master_fingerprint=binding.model_master_fingerprint,
        )

        input_model_binding = create_input_model_binding(
            input_identity=input_id,
            model_identity=model_envelope,
            project_id=project_id,
            raise_on_error=False,
        )

        prep_contract = create_preprocessing_contract(
            name="replay_preprocessing_contract",
            operations=[],
        )

        raw_array = input_data if isinstance(input_data, np.ndarray) else np.array(input_data if isinstance(input_data, list) else [0.0], dtype=np.float32)
        preprocessed_arr, transformed_id = execute_preprocessing_pipeline(
            contract=prep_contract,
            input_array=raw_array,
            input_identity=input_id,
            binding=input_model_binding,
        )

        replay_policy = (
            ReplayPolicy(**req.replay_policy)
            if req.replay_policy
            else DEFAULT_DETERMINISTIC_POLICY
        )

        exec_policy = (
            ExecutionPolicy(**req.execution_policy)
            if req.execution_policy
            else ExecutionPolicy()
        )

        replay_res = self.replay_service.orchestrate_replay(
            record=domain_rec,
            input_identity=input_id,
            binding=input_model_binding,
            model_identity=model_envelope,
            preprocessing_contract=prep_contract,
            transformed_identity=transformed_id,
            preprocessed_array=preprocessed_arr,
            execution_policy=exec_policy,
            replay_policy=replay_policy,
            expected_project_id=project_id,
        )

        findings = [
            FindingSummaryItem(code=f.code, message=f.message)
            for f in replay_res.findings
        ]

        comp_status = None
        max_abs = None
        max_rel = None
        if replay_res.comparison:
            comp_status = (
                replay_res.comparison.comparison_status.value
                if hasattr(replay_res.comparison.comparison_status, "value")
                else str(replay_res.comparison.comparison_status)
            )
            max_abs = replay_res.comparison.max_absolute_error
            max_rel = replay_res.comparison.max_relative_error

        return InferenceReplayResponse(
            record_id=record_id,
            project_id=project_id,
            status=replay_res.consistency_status.value if hasattr(replay_res.consistency_status, "value") else str(replay_res.consistency_status),
            eligibility=replay_res.eligibility_status.value if hasattr(replay_res.eligibility_status, "value") else str(replay_res.eligibility_status),
            is_consistent=replay_res.is_consistent,
            execution_identity_hash=binding.execution_identity_hash,
            replay_execution_identity_hash=replay_res.replay_execution_identity,
            original_raw_output_hash=binding.raw_output_hash,
            replay_raw_output_hash=replay_res.comparison.replay_raw_output_hash if replay_res.comparison else None,
            comparison_status=comp_status,
            max_absolute_error=max_abs,
            max_relative_error=max_rel,
            findings=findings,
            details=replay_res.details,
        )
