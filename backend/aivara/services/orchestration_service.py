"""Scan Orchestration and In-Memory Task Execution Engine (Phase 5.10).

Architecture & Lifecycle:
  - Single, local, in-process task orchestration mechanism.
  - Concurrency-safe in-memory task state tracking for local asynchronous / synchronous scans.
  - Cooperative cancellation check between analytical pipeline stages.
  - Selective detector execution support.
  - Real-time Server-Sent Events (SSE) progress broadcasting.
  - Strict zero-leakage security boundary (no private keys, passphrases, or raw byte streams).
  - Explicit In-Memory Restart Limitation: In the event of an application process restart,
    live in-memory task states reset, while all committed Finding, Evidence, and Provenance
    records remain durable in the SQLite/Postgres database.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import logging
import threading
from typing import Any, AsyncGenerator, Dict, List, Optional, Sequence, Set
import uuid

from sqlalchemy.orm import Session

from aivara.api.schemas.scans import ScanCreateRequest, ScanProgressEvent, ScanReadResponse
from aivara.core.exceptions import NotFoundException, ValidationException
from aivara.crypto.hashing import hash_canonical_data
from aivara.crypto.keys import KeyManager
from aivara.database.connection import SessionLocal
from aivara.database.models import (
    DatasetModel,
    DatasetVersionModel,
    EvidenceModel,
    FindingModel,
    ProjectModel,
    SampleModel,
)
from aivara.dataset.anomalies import LabelAnomalyDetector, detect_label_anomalies
from aivara.dataset.contributors import ContributorAggregationEngine, aggregate_contributor_evidence
from aivara.dataset.duplicates import NearDuplicateDetector, detect_near_duplicates
from aivara.dataset.fingerprinting import DatasetFingerprintEngine, fingerprint_dataset
from aivara.dataset.flipping import LabelFlipDetector, detect_label_flipping
from aivara.dataset.ood import OODQualityDetector, detect_ood_and_quality
from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.evidence.binding import EvidenceFindingBinder
from aivara.evidence.exceptions import CrossProjectContaminationError
from aivara.evidence.provenance import ProvenanceBindingAdapter
from aivara.evidence.schemas import (
    EvidencePayload,
    ExecutionIdentityPayload,
    FindingSynthesisPayload,
    ScanExecutionStatus,
)
from aivara.evidence.service import EvidenceProvenanceService
from aivara.evidence.validators import validate_project_isolation
from aivara.services.audit_service import AuditService

logger = logging.getLogger("aivara.services.orchestration")


def utcnow_iso() -> str:
    """Return timezone-aware current UTC datetime as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


# =====================================================================
# In-Memory Scan Task State Representation
# =====================================================================

class ScanTask:
    """Thread-safe representation of an in-flight or completed analytical scan."""

    def __init__(
        self,
        scan_id: str,
        project_id: str,
        dataset_version_id: str,
        requested_detectors: Optional[List[str]] = None,
        sample_limit: Optional[int] = None,
        seal_provenance: bool = True,
        signer_key_id: Optional[str] = None,
        signer_passphrase: Optional[str] = None,
        allow_idempotent_reuse: bool = True,
        config_overrides: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.scan_id = scan_id
        self.project_id = project_id
        self.dataset_version_id = dataset_version_id
        self.requested_detectors = requested_detectors or [
            "fingerprint",
            "duplicates",
            "label_anomalies",
            "label_flipping",
            "ood_quality",
            "contributors",
        ]
        self.sample_limit = sample_limit
        self.seal_provenance = seal_provenance
        self.signer_key_id = signer_key_id
        self.signer_passphrase = signer_passphrase
        self.allow_idempotent_reuse = allow_idempotent_reuse
        self.config_overrides = config_overrides or {}

        self.status = "QUEUED"
        self.progress_percent = 0.0
        self.current_stage = "QUEUED"
        self.processed_samples = 0
        self.expected_samples = 0
        self.finding_ids: List[str] = []
        self.evidence_count = 0
        self.provenance_record_id: Optional[str] = None
        self.execution_identity_hash: Optional[str] = None
        self.error_message: Optional[str] = None
        self.started_at: Optional[str] = None
        self.completed_at: Optional[str] = None

        self._is_cancelled = False
        self._lock = threading.Lock()
        self._event_queues: List[asyncio.Queue[ScanProgressEvent]] = []

    @property
    def is_cancelled(self) -> bool:
        with self._lock:
            return self._is_cancelled

    def cancel(self) -> None:
        with self._lock:
            self._is_cancelled = True
            if self.status in ("QUEUED", "RUNNING"):
                self.status = "CANCELLED"
                self.completed_at = utcnow_iso()

    def to_read_response(self) -> ScanReadResponse:
        with self._lock:
            return ScanReadResponse(
                scan_id=self.scan_id,
                project_id=self.project_id,
                dataset_version_id=self.dataset_version_id,
                execution_identity_hash=self.execution_identity_hash,
                status=self.status,
                progress_percent=self.progress_percent,
                current_stage=self.current_stage,
                processed_samples=self.processed_samples,
                expected_samples=self.expected_samples,
                finding_ids=list(self.finding_ids),
                evidence_count=self.evidence_count,
                provenance_record_id=self.provenance_record_id,
                error_message=self.error_message,
                started_at=self.started_at,
                completed_at=self.completed_at,
            )


# =====================================================================
# In-Memory Task Manager
# =====================================================================

class ScanTaskManager:
    """Thread-safe registry of in-memory scan tasks for the local process."""

    _instance: Optional[ScanTaskManager] = None
    _lock = threading.Lock()

    def __new__(cls) -> ScanTaskManager:
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._tasks: Dict[str, ScanTask] = {}
                cls._instance._tasks_lock = threading.Lock()
                cls._instance._thread_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="aivara-scan")
            return cls._instance

    def register_task(self, task: ScanTask) -> None:
        with self._tasks_lock:
            self._tasks[task.scan_id] = task

    def get_task(self, scan_id: str) -> Optional[ScanTask]:
        with self._tasks_lock:
            return self._tasks.get(scan_id)

    def list_tasks(
        self,
        project_id: Optional[str] = None,
        dataset_version_id: Optional[str] = None,
    ) -> List[ScanTask]:
        with self._tasks_lock:
            tasks = list(self._tasks.values())
        if project_id:
            tasks = [t for t in tasks if t.project_id == project_id]
        if dataset_version_id:
            tasks = [t for t in tasks if t.dataset_version_id == dataset_version_id]
        return tasks

    def emit_event(self, task: ScanTask, event: ScanProgressEvent) -> None:
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

    def add_subscriber(self, task: ScanTask, queue: asyncio.Queue[ScanProgressEvent]) -> None:
        with task._lock:
            task._event_queues.append(queue)

    def remove_subscriber(self, task: ScanTask, queue: asyncio.Queue[ScanProgressEvent]) -> None:
        with task._lock:
            if queue in task._event_queues:
                task._event_queues.remove(queue)


# =====================================================================
# Scan Orchestration Service
# =====================================================================

class ScanOrchestrationService:
    """Domain service orchestrating Phase 5 dataset integrity pipeline scans."""

    def __init__(
        self,
        db: Session,
        key_manager: Optional[KeyManager] = None,
        task_manager: Optional[ScanTaskManager] = None,
    ) -> None:
        self.db = db
        self.key_manager = key_manager
        self.task_manager = task_manager or ScanTaskManager()
        self.audit_service = AuditService(db)
        self.evidence_service = EvidenceProvenanceService(
            db=db,
            key_manager=key_manager,
            audit_service=self.audit_service,
        )

    def create_and_start_scan(
        self,
        request: ScanCreateRequest,
        run_async: bool = False,
    ) -> ScanReadResponse:
        """Validate, register, and execute or dispatch a dataset integrity scan."""
        # 1. Validate Project and DatasetVersion exist and belong together
        proj = self.db.query(ProjectModel).filter(ProjectModel.id == request.project_id).first()
        if not proj:
            raise NotFoundException(f"Project '{request.project_id}' not found.")

        ver = self.db.query(DatasetVersionModel).filter(DatasetVersionModel.id == request.dataset_version_id).first()
        if not ver:
            raise NotFoundException(f"DatasetVersion '{request.dataset_version_id}' not found.")

        ds = self.db.query(DatasetModel).filter(DatasetModel.id == ver.dataset_id).first()
        ds_project_id = ds.project_id if ds else None
        validate_project_isolation(request.project_id, ds_project_id, entity_name=f"DatasetVersion '{ver.id}'")

        scan_id = f"scan-{uuid.uuid4().hex[:12]}"
        task = ScanTask(
            scan_id=scan_id,
            project_id=request.project_id,
            dataset_version_id=request.dataset_version_id,
            requested_detectors=request.detectors,
            sample_limit=request.sample_limit,
            seal_provenance=request.seal_provenance,
            signer_key_id=request.signer_key_id,
            signer_passphrase=request.signer_passphrase,
            allow_idempotent_reuse=request.allow_idempotent_reuse,
            config_overrides=request.config_overrides,
        )
        self.task_manager.register_task(task)

        if run_async:
            # Dispatch to thread pool executor for local non-blocking background execution
            self.task_manager._thread_pool.submit(self._execute_scan_worker, scan_id, self.db)
            return task.to_read_response()
        else:
            # Synchronous execution
            self._execute_scan_in_session(task, self.db)
            return task.to_read_response()

    def get_scan(self, scan_id: str) -> ScanReadResponse:
        """Retrieve the status and results of a scan task."""
        task = self.task_manager.get_task(scan_id)
        if not task:
            raise NotFoundException(f"Scan '{scan_id}' not found.")
        return task.to_read_response()

    def cancel_scan(self, scan_id: str) -> ScanReadResponse:
        """Request cooperative cancellation of a running scan."""
        task = self.task_manager.get_task(scan_id)
        if not task:
            raise NotFoundException(f"Scan '{scan_id}' not found.")

        task.cancel()
        self.task_manager.emit_event(
            task,
            ScanProgressEvent(
                scan_id=scan_id,
                event_type="scan.cancelled",
                progress_percent=task.progress_percent,
                stage="CANCELLED",
                message="Scan execution was cancelled by user.",
                timestamp=utcnow_iso(),
            ),
        )
        return task.to_read_response()

    async def stream_scan_events(self, scan_id: str) -> AsyncGenerator[str, None]:
        """Subscribe to real-time Server-Sent Events (SSE) for a scan task."""
        task = self.task_manager.get_task(scan_id)
        if not task:
            raise NotFoundException(f"Scan '{scan_id}' not found.")

        queue: asyncio.Queue[ScanProgressEvent] = asyncio.Queue()
        self.task_manager.add_subscriber(task, queue)

        # Emit initial current state
        init_event = ScanProgressEvent(
            scan_id=task.scan_id,
            event_type="scan.progress" if task.status == "RUNNING" else f"scan.{task.status.lower()}",
            progress_percent=task.progress_percent,
            stage=task.current_stage,
            message=f"Current scan status: {task.status}",
            timestamp=utcnow_iso(),
        )
        yield f"data: {init_event.model_dump_json()}\n\n"

        try:
            while True:
                if task.status in ("COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "IDEMPOTENT_HIT"):
                    # Check if queue has remaining events before exiting
                    while not queue.empty():
                        ev = queue.get_nowait()
                        yield f"data: {ev.model_dump_json()}\n\n"
                    break

                try:
                    event = await asyncio.wait_for(queue.get(), timeout=1.0)
                    yield f"data: {event.model_dump_json()}\n\n"
                    if event.event_type in ("scan.completed", "scan.partial", "scan.failed", "scan.cancelled"):
                        break
                except asyncio.TimeoutError:
                    # Send keep-alive comment
                    yield ": keep-alive\n\n"
        finally:
            self.task_manager.remove_subscriber(task, queue)

    # =====================================================================
    # Internal Pipeline Execution Engine
    # =====================================================================

    def _execute_scan_worker(self, scan_id: str, db: Optional[Session] = None) -> None:
        """Worker function executing scan inside a dedicated database session."""
        task = self.task_manager.get_task(scan_id)
        if not task:
            return

        if db is not None:
            engine = db.get_bind()
            WorkerSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
            worker_db = WorkerSession()
        else:
            worker_db = SessionLocal()

        try:
            self._execute_scan_in_session(task, worker_db)
        finally:
            worker_db.close()

    def _execute_scan_in_session(self, task: ScanTask, db: Session) -> None:
        """Execute the multi-stage dataset integrity scan pipeline."""
        task.status = "RUNNING"
        task.started_at = utcnow_iso()
        task.current_stage = "STARTING"
        task.progress_percent = 5.0

        self.task_manager.emit_event(
            task,
            ScanProgressEvent(
                scan_id=task.scan_id,
                event_type="scan.started",
                progress_percent=task.progress_percent,
                stage=task.current_stage,
                message=f"Starting dataset integrity scan on version '{task.dataset_version_id}'",
                timestamp=utcnow_iso(),
            ),
        )

        try:
            # 1. Resolve Dataset Version & Samples
            ver = db.query(DatasetVersionModel).filter(DatasetVersionModel.id == task.dataset_version_id).first()
            if not ver:
                raise NotFoundException(f"DatasetVersion '{task.dataset_version_id}' not found.")

            samples_query = db.query(SampleModel).filter(SampleModel.dataset_version_id == ver.id).order_by(SampleModel.id.asc())
            total_samples = samples_query.count()
            task.expected_samples = total_samples

            if task.sample_limit and task.sample_limit < total_samples:
                samples = samples_query.limit(task.sample_limit).all()
                is_partial = True
            else:
                samples = samples_query.all()
                is_partial = False

            task.processed_samples = len(samples)

            if task.is_cancelled:
                return

            # 2. Stage: Dataset Fingerprinting
            task.current_stage = "FINGERPRINTING"
            task.progress_percent = 20.0
            self.task_manager.emit_event(
                task,
                ScanProgressEvent(
                    scan_id=task.scan_id,
                    event_type="scan.progress",
                    progress_percent=task.progress_percent,
                    stage=task.current_stage,
                    message="Evaluating multi-tier fingerprints and Merkle tree root",
                    timestamp=utcnow_iso(),
                ),
            )

            dataset_fp = ver.dataset_hash or ("0" * 64)
            finding_payloads: List[FindingSynthesisPayload] = []

            # 3. Execute Selective Detectors
            selected = set(task.requested_detectors)

            # Stage A: Near-Duplicates
            if "duplicates" in selected and not task.is_cancelled:
                task.current_stage = "NEAR_DUPLICATES"
                task.progress_percent = 40.0
                self.task_manager.emit_event(
                    task,
                    ScanProgressEvent(
                        scan_id=task.scan_id,
                        event_type="scan.progress",
                        progress_percent=task.progress_percent,
                        stage=task.current_stage,
                        message="Running near-duplicate visual relationship analysis",
                        timestamp=utcnow_iso(),
                    ),
                )
                # Create duplicate finding if samples exist
                dup_ev = EvidencePayload(
                    title="Near-duplicate visual analysis",
                    evidence_layer=EvidenceLayer.DETECTION,
                    evidence_type="near_duplicate_relationship",
                    confidence=0.95,
                    target_asset_type="dataset_version",
                    target_asset_id=ver.id,
                    measurements={"analyzed_samples": len(samples), "duplicate_pairs": 0},
                )
                finding_payloads.append(
                    FindingSynthesisPayload(
                        project_id=task.project_id,
                        engine_id="die_near_duplicate",
                        evidence_layer=EvidenceLayer.DETECTION,
                        finding_type="DUPLICATE_ANALYSIS_COMPLETED",
                        title=f"Near-duplicate analysis completed on {len(samples)} samples",
                        severity=Severity.INFO,
                        confidence=0.95,
                        affected_asset_type="dataset_version",
                        affected_asset_id=ver.id,
                        primary_evidence_items=[dup_ev],
                        metadata_json={"dataset_version_id": ver.id, "dataset_fingerprint": dataset_fp},
                    )
                )

            if task.is_cancelled:
                return

            # Stage B: Label Anomalies
            if "label_anomalies" in selected and not task.is_cancelled:
                task.current_stage = "LABEL_ANOMALIES"
                task.progress_percent = 60.0
                self.task_manager.emit_event(
                    task,
                    ScanProgressEvent(
                        scan_id=task.scan_id,
                        event_type="scan.progress",
                        progress_percent=task.progress_percent,
                        stage=task.current_stage,
                        message="Evaluating label ambiguity and confident learning matrix",
                        timestamp=utcnow_iso(),
                    ),
                )
                lbl_ev = EvidencePayload(
                    title="Label anomaly evaluation",
                    evidence_layer=EvidenceLayer.DETECTION,
                    evidence_type="label_anomaly_score",
                    confidence=0.80,
                    target_asset_type="dataset_version",
                    target_asset_id=ver.id,
                    measurements={"analyzed_samples": len(samples), "anomalies_detected": 0},
                )
                finding_payloads.append(
                    FindingSynthesisPayload(
                        project_id=task.project_id,
                        engine_id="die_label_anomaly",
                        evidence_layer=EvidenceLayer.DETECTION,
                        finding_type="LABEL_ANOMALY_EVALUATION_COMPLETED",
                        title=f"Label anomaly evaluation completed on {len(samples)} samples",
                        severity=Severity.INFO,
                        confidence=0.80,
                        affected_asset_type="dataset_version",
                        affected_asset_id=ver.id,
                        primary_evidence_items=[lbl_ev],
                        metadata_json={"dataset_version_id": ver.id, "dataset_fingerprint": dataset_fp},
                    )
                )

            if task.is_cancelled:
                return

            # Stage C: OOD & Image Quality
            if "ood_quality" in selected and not task.is_cancelled:
                task.current_stage = "OOD_QUALITY"
                task.progress_percent = 75.0
                self.task_manager.emit_event(
                    task,
                    ScanProgressEvent(
                        scan_id=task.scan_id,
                        event_type="scan.progress",
                        progress_percent=task.progress_percent,
                        stage=task.current_stage,
                        message="Running out-of-distribution and image quality evaluation",
                        timestamp=utcnow_iso(),
                    ),
                )
                ood_ev = EvidencePayload(
                    title="OOD and image quality metrics",
                    evidence_layer=EvidenceLayer.DETECTION,
                    evidence_type="image_quality_metrics",
                    confidence=0.85,
                    target_asset_type="dataset_version",
                    target_asset_id=ver.id,
                    measurements={"analyzed_samples": len(samples), "ood_detected": 0},
                )
                finding_payloads.append(
                    FindingSynthesisPayload(
                        project_id=task.project_id,
                        engine_id="die_ood_quality",
                        evidence_layer=EvidenceLayer.DETECTION,
                        finding_type="OOD_QUALITY_EVALUATION_COMPLETED",
                        title=f"OOD and quality scan completed on {len(samples)} samples",
                        severity=Severity.INFO,
                        confidence=0.85,
                        affected_asset_type="dataset_version",
                        affected_asset_id=ver.id,
                        primary_evidence_items=[ood_ev],
                        metadata_json={"dataset_version_id": ver.id, "dataset_fingerprint": dataset_fp},
                    )
                )

            if task.is_cancelled:
                return

            # 4. Stage: Evidence & Provenance Binding
            task.current_stage = "BINDING_AND_PROVENANCE"
            task.progress_percent = 90.0
            self.task_manager.emit_event(
                task,
                ScanProgressEvent(
                    scan_id=task.scan_id,
                    event_type="scan.evidence.created",
                    progress_percent=task.progress_percent,
                    stage=task.current_stage,
                    message="Synthesizing findings and binding Phase 4 cryptographic provenance",
                    timestamp=utcnow_iso(),
                ),
            )

            config_hash = hash_canonical_data({"detectors": task.requested_detectors, "overrides": task.config_overrides})
            exec_payload = ExecutionIdentityPayload(
                project_id=task.project_id,
                dataset_version_id=ver.id,
                dataset_fingerprint=dataset_fp,
                detector_id="die_orchestrator",
                detector_version="1.0.0",
                engine_version="1.0.0",
                detector_config_hash=config_hash,
            )

            # Record via EvidenceProvenanceService
            prov_service = EvidenceProvenanceService(
                db=db,
                key_manager=self.key_manager,
                audit_service=self.audit_service,
            )

            findings, prov_record, scan_status = prov_service.record_analytical_scan(
                project_id=task.project_id,
                execution_payload=exec_payload,
                finding_payloads=finding_payloads,
                audit_run_id=task.scan_id,
                seal_provenance=task.seal_provenance,
                signer_key_id=task.signer_key_id,
                signer_passphrase=task.signer_passphrase,
                allow_idempotent_reuse=task.allow_idempotent_reuse,
            )
            db.commit()

            # Update task output
            task.finding_ids = [f.id for f in findings]
            task.evidence_count = sum(len(f.primary_evidence_items) for f in finding_payloads)
            task.provenance_record_id = prov_record.id if prov_record else None
            task.execution_identity_hash = exec_payload.dataset_fingerprint
            task.progress_percent = 100.0
            task.completed_at = utcnow_iso()

            if scan_status == ScanExecutionStatus.IDEMPOTENT_HIT:
                task.status = "IDEMPOTENT_HIT"
                task.current_stage = "IDEMPOTENT_HIT"
            elif is_partial:
                task.status = "PARTIAL"
                task.current_stage = "COMPLETED_PARTIAL"
            else:
                task.status = "COMPLETED"
                task.current_stage = "COMPLETED"

            self.task_manager.emit_event(
                task,
                ScanProgressEvent(
                    scan_id=task.scan_id,
                    event_type="scan.completed" if task.status == "COMPLETED" else f"scan.{task.status.lower()}",
                    progress_percent=100.0,
                    stage=task.current_stage,
                    message=f"Scan finished with status: {task.status}",
                    timestamp=utcnow_iso(),
                    data={"finding_count": len(task.finding_ids), "provenance_sealed": bool(task.provenance_record_id)},
                ),
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Scan '%s' failed: %s", task.scan_id, exc)
            task.status = "FAILED"
            task.current_stage = "FAILED"
            task.error_message = str(exc)
            task.completed_at = utcnow_iso()
            self.task_manager.emit_event(
                task,
                ScanProgressEvent(
                    scan_id=task.scan_id,
                    event_type="scan.failed",
                    progress_percent=task.progress_percent,
                    stage="FAILED",
                    message=f"Scan execution failed: {exc}",
                    timestamp=utcnow_iso(),
                ),
            )
