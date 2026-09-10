"""Unified Evidence and Provenance Service for AIVARA (Phase 5.9).

Provides:
  - High-level orchestration of Evidence creation, validation, and Finding synthesis.
  - Idempotent execution recognition via ExecutionIdentityHash.
  - Cryptographic provenance sealing and verification.
  - Minimal, high-level lifecycle audit logging via AuditService (no per-sample explosion).
  - Strict separation between Detection Layer (statistical/ML) and Proof Layer (cryptographic).
  - 100% offline, air-gapped execution with zero database schema modifications.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
from sqlalchemy.orm import Session

from aivara.crypto.keys import KeyManager
from aivara.database.models import FindingModel, ProvenanceRecordModel
from aivara.domain.schemas import ProvenanceRecordRead
from aivara.evidence.binding import EvidenceFindingBinder
from aivara.evidence.exceptions import (
    CrossProjectContaminationError,
    EvidenceValidationError,
)
from aivara.evidence.identity import (
    compute_execution_identity_hash,
)
from aivara.evidence.provenance import ProvenanceBindingAdapter
from aivara.evidence.schemas import (
    EvidenceProvenanceVerificationResult,
    ExecutionIdentityPayload,
    FindingSynthesisPayload,
    ScanExecutionStatus,
    TraceabilityChain,
)
from aivara.evidence.validators import (
    validate_dataset_version_binding,
    validate_model_binding,
    validate_project_isolation,
)
from aivara.services.audit_service import AuditService
from aivara.services.provenance_service import ProvenanceService

logger = logging.getLogger("aivara.evidence.service")


class EvidenceProvenanceService:
    """Core service for managing evidence, findings synthesis, provenance binding, and audit logging."""

    def __init__(
        self,
        db: Session,
        key_manager: Optional[KeyManager] = None,
        audit_service: Optional[AuditService] = None,
        provenance_service: Optional[ProvenanceService] = None,
    ) -> None:
        """Initialize with an active database session and crypto dependencies.

        Args:
            db: Active SQLAlchemy database session.
            key_manager: Optional KeyManager instance for cryptographic operations.
            audit_service: Optional AuditService instance. Defaults to AuditService(db).
            provenance_service: Optional ProvenanceService instance.
        """
        self.db = db
        self.key_manager = key_manager
        self.audit_service = audit_service or AuditService(db)
        self.provenance_service = provenance_service or ProvenanceService(
            db=db,
            key_manager=key_manager,
            audit_service=self.audit_service,
        )
        self.binder = EvidenceFindingBinder(db)
        self.provenance_adapter = ProvenanceBindingAdapter(
            db=db,
            key_manager=key_manager,
            audit_service=self.audit_service,
            provenance_service=self.provenance_service,
        )

    def record_analytical_scan(
        self,
        *,
        project_id: str,
        execution_payload: Union[ExecutionIdentityPayload, Dict[str, Any]],
        finding_payloads: Sequence[FindingSynthesisPayload],
        audit_run_id: str,
        seal_provenance: bool = True,
        signer_key_id: Optional[str] = None,
        signer_passphrase: Optional[str] = None,
        key_handle: Optional[Any] = None,
        allow_idempotent_reuse: bool = True,
        is_partial_scan: bool = False,
        actor: str = "system:die_orchestrator",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[FindingModel], Optional[ProvenanceRecordRead], ScanExecutionStatus]:
        """Record an analytical scan execution, synthesize findings, seal provenance, and audit lifecycle.

        Args:
            project_id: Project identifier.
            execution_payload: Structured ExecutionIdentityPayload or dict.
            finding_payloads: List of finding payloads to synthesize.
            audit_run_id: Unique audit run identifier.
            seal_provenance: If True, commits findings into the provenance ledger.
            signer_key_id: Optional Ed25519 key ID for signing the provenance record.
            allow_idempotent_reuse: If True, returns prior findings if execution identity matches.
            is_partial_scan: If True, scan is marked PARTIAL_SUCCESS.
            actor: Calling system or user actor.
            metadata: Additional metadata dictionary.

        Returns:
            Tuple of (synthesized_findings, sealed_provenance_record, execution_status).
        """
        if not project_id:
            raise EvidenceValidationError("project_id is required.")

        # 1. Compute deterministic execution identity hash
        exec_hash = compute_execution_identity_hash(execution_payload)
        dataset_version_id = (
            execution_payload.dataset_version_id
            if isinstance(execution_payload, ExecutionIdentityPayload)
            else str(execution_payload["dataset_version_id"])
        )
        dataset_fingerprint = (
            execution_payload.dataset_fingerprint
            if isinstance(execution_payload, ExecutionIdentityPayload)
            else str(execution_payload["dataset_fingerprint"])
        )
        detector_id = (
            execution_payload.detector_id
            if isinstance(execution_payload, ExecutionIdentityPayload)
            else str(execution_payload["detector_id"])
        )

        model_id = (
            execution_payload.model_id
            if isinstance(execution_payload, ExecutionIdentityPayload)
            else str(execution_payload.get("model_id", "NONE"))
        )
        model_fingerprint = (
            execution_payload.model_fingerprint
            if isinstance(execution_payload, ExecutionIdentityPayload)
            else str(execution_payload.get("model_fingerprint", "NONE"))
        )

        validate_dataset_version_binding(dataset_version_id, dataset_fingerprint, self.db)
        validate_model_binding(model_id, model_fingerprint, self.db)

        # 2. Check for idempotent execution match
        if allow_idempotent_reuse:
            existing_findings = self.get_findings_by_execution_identity(exec_hash, project_id)
            if existing_findings:
                logger.info(
                    "Idempotent hit: Scan with execution hash '%s' already exists for project '%s'. Returning %d existing findings.",
                    exec_hash,
                    project_id,
                    len(existing_findings),
                )
                # Audit idempotent reuse
                self.audit_service.record_event(
                    project_id=project_id,
                    event_type="SCAN_IDEMPOTENT_HIT",
                    actor=actor,
                    action="REUSE_IDEMPOTENT_SCAN",
                    target_type="dataset_version",
                    target_id=dataset_version_id,
                    description=f"Idempotent scan match on detector '{detector_id}' with hash '{exec_hash}'.",
                    metadata_json={"execution_identity_hash": exec_hash, "finding_count": len(existing_findings)},
                )
                return existing_findings, None, ScanExecutionStatus.IDEMPOTENT_HIT

        # 3. Audit scan lifecycle start
        self.audit_service.record_event(
            project_id=project_id,
            event_type="DATASET_SCAN_STARTED",
            actor=actor,
            action="START_SCAN",
            target_type="dataset_version",
            target_id=dataset_version_id,
            description=f"Analytical scan started for detector '{detector_id}' on dataset version '{dataset_version_id}'.",
            metadata_json={
                "audit_run_id": str(audit_run_id),
                "execution_identity_hash": exec_hash,
                "detector_id": detector_id,
                "is_partial_scan": is_partial_scan,
            },
        )

        # 4. Synthesize all findings and bind evidence
        synthesized_findings: List[FindingModel] = []
        for fp in finding_payloads:
            validate_project_isolation(project_id, fp.project_id, entity_name="FindingSynthesisPayload")
            # Ensure finding metadata records the execution_identity_hash and dataset details
            f_meta = dict(fp.metadata_json) if fp.metadata_json else {}
            f_meta.setdefault("execution_identity_hash", exec_hash)
            f_meta.setdefault("dataset_version_id", dataset_version_id)
            f_meta.setdefault("dataset_fingerprint", dataset_fingerprint)
            f_meta.setdefault("is_partial_scan", is_partial_scan)

            updated_fp = FindingSynthesisPayload(
                project_id=fp.project_id,
                audit_run_id=audit_run_id,
                engine_id=fp.engine_id,
                engine_version=fp.engine_version,
                evidence_layer=fp.evidence_layer,
                finding_type=fp.finding_type,
                title=fp.title,
                description=fp.description,
                severity=fp.severity,
                confidence=fp.confidence,
                affected_asset_type=fp.affected_asset_type,
                affected_asset_id=fp.affected_asset_id,
                disposition=fp.disposition,
                analysis_mode=fp.analysis_mode,
                recommendation=fp.recommendation,
                status=fp.status,
                primary_evidence_items=fp.primary_evidence_items,
                referenced_evidence_ids=fp.referenced_evidence_ids,
                referenced_evidence_hashes=fp.referenced_evidence_hashes,
                metadata_json=f_meta,
            )

            finding = self.binder.synthesize_finding(updated_fp)
            synthesized_findings.append(finding)

        # 5. Seal into provenance ledger if requested
        sealed_record: Optional[ProvenanceRecordRead] = None
        if seal_provenance and synthesized_findings:
            sealed_record = self.provenance_adapter.seal_scan_findings(
                project_id=project_id,
                dataset_version_id=dataset_version_id,
                dataset_fingerprint=dataset_fingerprint,
                execution_identity_hash=exec_hash,
                audit_run_id=audit_run_id,
                findings=synthesized_findings,
                signer_key_id=signer_key_id,
                signer_passphrase=signer_passphrase,
                key_handle=key_handle,
                actor=actor,
                metadata=metadata,
            )

        # 6. Audit scan lifecycle completion
        status = ScanExecutionStatus.PARTIAL_SUCCESS if is_partial_scan else ScanExecutionStatus.COMPLETED
        self.audit_service.record_event(
            project_id=project_id,
            event_type="DATASET_SCAN_COMPLETED",
            actor=actor,
            action="COMPLETE_SCAN",
            target_type="dataset_version",
            target_id=dataset_version_id,
            description=f"Analytical scan completed with {len(synthesized_findings)} findings (Status: {status.value}).",
            metadata_json={
                "audit_run_id": str(audit_run_id),
                "execution_identity_hash": exec_hash,
                "finding_count": len(synthesized_findings),
                "provenance_sealed": sealed_record is not None,
                "provenance_record_id": sealed_record.id if sealed_record else None,
                "status": status.value,
            },
        )

        return synthesized_findings, sealed_record, status

    def get_findings_by_execution_identity(
        self,
        execution_identity_hash: str,
        project_id: str,
    ) -> List[FindingModel]:
        """Retrieve existing findings matching a specific execution identity hash within a project."""
        if not execution_identity_hash or not project_id:
            return []

        findings = (
            self.db.query(FindingModel)
            .filter(
                FindingModel.project_id == project_id,
            )
            .all()
        )

        matching = []
        for f in findings:
            meta = f.metadata_json or {}
            if meta.get("execution_identity_hash") == execution_identity_hash:
                matching.append(f)

        return matching

    def get_traceability_chain(
        self,
        finding_id: str,
        project_id: str,
    ) -> TraceabilityChain:
        """Trace backward from a finding to its evidence, source data assets, and provenance records."""
        return self.binder.build_traceability_chain(finding_id, project_id)

    def verify_finding_provenance(
        self,
        finding_id: str,
        project_id: str,
    ) -> EvidenceProvenanceVerificationResult:
        """Verify the cryptographic provenance record bound to a finding."""
        return self.provenance_adapter.verify_finding_provenance(finding_id, project_id)
