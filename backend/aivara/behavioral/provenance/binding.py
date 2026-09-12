"""Behavioral Evidence and Provenance Binding Service (Phase 8.7).

Coordinates:
  - Synthesis and persistence of FindingModel and EvidenceModel rows.
  - Sealing of findings into Phase 4 hash-linked ProvenanceRecordModel.
  - Ed25519 cryptographic signing and audit trail recording.
  - Strict multi-tenant project isolation and replay protection.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
from sqlalchemy.orm import Session

from aivara.crypto.canonical import format_canonical_datetime
from aivara.crypto.chain import generate_nonce
from aivara.crypto.hashing import hash_canonical_data
from aivara.crypto.keys import Ed25519KeyHandle, KeyManager
from aivara.database.models import FindingModel, ProjectModel, ProvenanceRecordModel
from aivara.domain.schemas import (
    AnalysisMode,
    Disposition,
    EvidenceLayer,
    ProvenanceRecordRead,
    Severity,
)
from aivara.evidence.binding import EvidenceFindingBinder
from aivara.evidence.provenance import ProvenanceBindingAdapter
from aivara.evidence.schemas import (
    EvidencePayload,
    FindingSynthesisPayload,
    ProvenanceStatus,
    ScanExecutionStatus,
)
from aivara.evidence.validators import validate_project_isolation
from aivara.services.audit_service import AuditService
from aivara.services.provenance_service import ProvenanceService
from aivara.behavioral.anomaly.schemas import BehavioralAnomalyAnalysis
from aivara.behavioral.provenance.enums import (
    BehavioralEvidenceType,
    BehavioralFindingStatus,
    BehavioralFindingType,
    EvidenceLifecycleState,
)
from aivara.behavioral.provenance.evidence import (
    build_anomaly_evidence_content,
    create_behavioral_evidence,
    seal_behavioral_evidence,
    to_phase5_evidence_payload,
)
from aivara.behavioral.provenance.exceptions import (
    BehavioralProvenanceError,
    CrossProjectBindingError,
)
from aivara.behavioral.provenance.identity import (
    build_behavioral_execution_payload,
    compute_behavioral_execution_identity_hash,
)
from aivara.behavioral.provenance.schemas import (
    BehavioralEvidence,
    BehavioralEvidenceContent,
)

logger = logging.getLogger("aivara.behavioral.provenance.binding")


class BehavioralProvenanceBindingService:
    """Core service for binding behavioral analytical results into cryptographic provenance."""

    def __init__(
        self,
        db: Session,
        key_manager: Optional[KeyManager] = None,
        audit_service: Optional[AuditService] = None,
        provenance_service: Optional[ProvenanceService] = None,
    ) -> None:
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

    def bind_anomaly_analysis(
        self,
        analysis: BehavioralAnomalyAnalysis,
        *,
        input_hash: str,
        output_hash: str,
        audit_run_id: Optional[str] = None,
        seal_provenance: bool = True,
        signer_key_id: Optional[str] = None,
        signer_passphrase: Optional[str] = None,
        key_handle: Optional[Ed25519KeyHandle] = None,
        allow_idempotent_reuse: bool = True,
        actor: str = "system:behavioral_orchestrator",
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[FindingModel, Optional[ProvenanceRecordRead], ScanExecutionStatus]:
        """Synthesize a Finding from an anomaly analysis, attach sealed evidence, and commit to provenance ledger."""
        project_id = analysis.project_id
        model_id = analysis.model_id

        # Validate project exists
        proj = self.db.query(ProjectModel).filter_by(id=project_id).first()
        if not proj:
            raise CrossProjectBindingError(f"Project '{project_id}' does not exist in the database.")

        # 1. Build canonical execution identity for idempotency
        exec_payload = {
            "project_id": project_id,
            "model_id": model_id,
            "model_fingerprint": analysis.model_fingerprint,
            "observation_id": analysis.observation_id,
            "baseline_id": analysis.baseline_id,
            "detector_id": "behavioral_anomaly_detector",
            "detector_version": analysis.analysis_version,
            "detector_config_hash": analysis.analysis_id,
            "policy_version": analysis.policy_version,
            "engine_version": analysis.analysis_version,
            "preprocessing_hash": "STANDARD_V1",
        }
        exec_hash = compute_behavioral_execution_identity_hash(exec_payload)

        # 2. Check Idempotency if enabled
        if allow_idempotent_reuse:
            existing_findings = (
                self.db.query(FindingModel)
                .filter(
                    FindingModel.project_id == project_id,
                    FindingModel.affected_asset_id == model_id,
                    FindingModel.finding_type == BehavioralFindingType.BEHAVIORAL_ANOMALY.value,
                )
                .all()
            )
            for f in existing_findings:
                meta = f.metadata_json or {}
                if meta.get("execution_identity_hash") == exec_hash:
                    # Idempotent match found
                    prov_record = None
                    prov_id = meta.get("provenance_record_id")
                    if prov_id:
                        prov_model = self.db.query(ProvenanceRecordModel).filter_by(id=prov_id).first()
                        if prov_model:
                            prov_record = ProvenanceRecordRead.model_validate(prov_model)
                    logger.info("Idempotent reuse hit for behavioral finding '%s'", f.id)
                    return f, prov_record, ScanExecutionStatus.IDEMPOTENT_HIT

        # 3. Build canonical evidence content and seal it
        content = build_anomaly_evidence_content(
            analysis,
            input_hash=input_hash,
            output_hash=output_hash,
            detector_id="behavioral_anomaly_detector",
            detector_config_hash=analysis.analysis_id,
        )
        evidence = create_behavioral_evidence(content, seal=True)
        evidence_payload = to_phase5_evidence_payload(evidence)

        # 4. Map anomaly status to Finding fields
        is_anomalous = (analysis.overall_status.value == "ANOMALOUS")
        severity = Severity.HIGH if is_anomalous else Severity.INFO
        disposition = Disposition.REVIEW if is_anomalous else Disposition.ACCEPT
        title = f"Behavioral Anomaly Assessment: {analysis.overall_status.value} [{analysis.task_type}]"
        desc = (
            f"Observed behavioral profile evaluated against reference baseline '{analysis.baseline_id}'. "
            f"Result: {analysis.overall_status.value}. Support: {analysis.support_status.value}."
        )

        finding_payload = FindingSynthesisPayload(
            project_id=project_id,
            audit_run_id=audit_run_id,
            engine_id="behavioral_anomaly_engine",
            engine_version=analysis.analysis_version,
            evidence_layer=EvidenceLayer.DETECTION,
            finding_type=BehavioralFindingType.BEHAVIORAL_ANOMALY.value,
            title=title,
            description=desc,
            severity=severity,
            confidence=0.95,
            affected_asset_type="model",
            affected_asset_id=model_id,
            disposition=disposition,
            analysis_mode=AnalysisMode.NOT_APPLICABLE,
            recommendation="Review statistical metric deviations against reference population." if is_anomalous else None,
            status="open",
            primary_evidence_items=[evidence_payload],
            metadata_json={
                "execution_identity_hash": exec_hash,
                "analysis_id": analysis.analysis_id,
                "model_fingerprint": analysis.model_fingerprint,
                "observation_id": analysis.observation_id,
                "baseline_id": analysis.baseline_id,
                "overall_status": analysis.overall_status.value,
                "support_status": analysis.support_status.value,
                "comparability_status": analysis.comparability_status,
                "primary_evidence_hashes": [evidence.evidence_id],
                "explanation": analysis.explanation,
                **(extra_metadata or {}),
            },
        )

        finding = self.binder.synthesize_finding(finding_payload)

        # 5. Record Audit Event: BEHAVIORAL_EVIDENCE_CREATED
        self.audit_service.record_event(
            project_id=project_id,
            event_type="BEHAVIORAL_EVIDENCE_CREATED",
            actor=actor,
            action="CREATE_EVIDENCE",
            target_type="model",
            target_id=model_id,
            outcome="SUCCESS",
            description=f"Created and sealed behavioral evidence for observation '{analysis.observation_id}'.",
            metadata_json={
                "evidence_id": evidence.evidence_id,
                "analysis_id": analysis.analysis_id,
                "model_id": model_id,
                "finding_id": finding.id,
            },
        )

        # 6. Seal into Phase 4 Provenance Ledger if requested
        prov_record_read: Optional[ProvenanceRecordRead] = None
        if seal_provenance:
            prov_record_read = self.provenance_adapter.seal_scan_findings(
                project_id=project_id,
                dataset_version_id=analysis.observation_id,
                dataset_fingerprint=input_hash,
                execution_identity_hash=exec_hash,
                audit_run_id=audit_run_id or analysis.analysis_id,
                findings=[finding],
                signer_key_id=signer_key_id,
                signer_passphrase=signer_passphrase,
                key_handle=key_handle,
                actor=actor,
                metadata={
                    "model_id": model_id,
                    "model_fingerprint": analysis.model_fingerprint,
                    "observation_id": analysis.observation_id,
                    "baseline_id": analysis.baseline_id,
                    "analysis_id": analysis.analysis_id,
                    "overall_status": analysis.overall_status.value,
                    "record_classification": "BEHAVIORAL_ASSURANCE_SEAL",
                },
            )

            # Record Audit Event: BEHAVIORAL_PROVENANCE_BOUND
            self.audit_service.record_event(
                project_id=project_id,
                event_type="BEHAVIORAL_PROVENANCE_BOUND",
                actor=actor,
                action="SEAL_PROVENANCE",
                target_type="model",
                target_id=model_id,
                outcome="SUCCESS",
                description=f"Sealed behavioral finding '{finding.id}' into provenance ledger.",
                metadata_json={
                    "provenance_record_id": prov_record_read.id,
                    "record_hash": prov_record_read.record_hash,
                    "sequence_number": prov_record_read.sequence_number,
                    "finding_id": finding.id,
                },
            )

        return finding, prov_record_read, ScanExecutionStatus.COMPLETED

    def bind_behavioral_evidence(
        self,
        evidence: BehavioralEvidence,
        *,
        audit_run_id: Optional[str] = None,
        seal_provenance: bool = True,
        signer_key_id: Optional[str] = None,
        signer_passphrase: Optional[str] = None,
        key_handle: Optional[Ed25519KeyHandle] = None,
        actor: str = "system:behavioral_orchestrator",
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[FindingModel, Optional[ProvenanceRecordRead], ScanExecutionStatus]:
        """Bind arbitrary pre-constructed sealed BehavioralEvidence into Findings and Provenance."""
        content = evidence.content
        project_id = content.project_id
        model_id = content.model_id

        # Validate project exists
        proj = self.db.query(ProjectModel).filter_by(id=project_id).first()
        if not proj:
            raise CrossProjectBindingError(f"Project '{project_id}' does not exist in the database.")

        # Seal evidence if draft
        sealed_ev = seal_behavioral_evidence(evidence)
        ev_payload = to_phase5_evidence_payload(sealed_ev)

        exec_payload = {
            "project_id": project_id,
            "model_id": model_id,
            "model_fingerprint": content.model_fingerprint,
            "observation_id": content.observation_id,
            "baseline_id": content.baseline_id,
            "detector_id": content.detector_id,
            "detector_version": content.detector_version,
            "detector_config_hash": content.detector_config_hash,
            "policy_version": content.policy_version,
            "engine_version": content.engine_version,
            "preprocessing_hash": content.preprocessing_hash,
        }
        exec_hash = compute_behavioral_execution_identity_hash(exec_payload)

        title = f"Behavioral Evidence: {content.evidence_type.value} [{content.result_status}]"
        desc = (
            f"Behavioral evidence for model '{model_id}', observation '{content.observation_id}'. "
            f"Result: {content.result_status}."
        )

        finding_payload = FindingSynthesisPayload(
            project_id=project_id,
            audit_run_id=audit_run_id,
            engine_id=content.detector_id,
            engine_version=content.detector_version,
            evidence_layer=content.evidence_layer,
            finding_type=content.evidence_type.value,
            title=title,
            description=desc,
            severity=Severity.INFO if content.result_status == "NORMAL" else Severity.MEDIUM,
            confidence=1.0 if content.evidence_layer == EvidenceLayer.PROOF else 0.95,
            affected_asset_type="model",
            affected_asset_id=model_id,
            disposition=Disposition.ACCEPT if content.result_status == "NORMAL" else Disposition.REVIEW,
            analysis_mode=AnalysisMode.NOT_APPLICABLE,
            recommendation=None,
            status="open",
            primary_evidence_items=[ev_payload],
            metadata_json={
                "execution_identity_hash": exec_hash,
                "evidence_id": sealed_ev.evidence_id,
                "model_fingerprint": content.model_fingerprint,
                "observation_id": content.observation_id,
                "baseline_id": content.baseline_id,
                "result_status": content.result_status,
                "primary_evidence_hashes": [sealed_ev.evidence_id],
                **(extra_metadata or {}),
            },
        )

        finding = self.binder.synthesize_finding(finding_payload)

        prov_record_read: Optional[ProvenanceRecordRead] = None
        if seal_provenance:
            prov_record_read = self.provenance_adapter.seal_scan_findings(
                project_id=project_id,
                dataset_version_id=content.observation_id,
                dataset_fingerprint=content.input_hash,
                execution_identity_hash=exec_hash,
                audit_run_id=audit_run_id or content.observation_id,
                findings=[finding],
                signer_key_id=signer_key_id,
                signer_passphrase=signer_passphrase,
                key_handle=key_handle,
                actor=actor,
                metadata={
                    "model_id": model_id,
                    "model_fingerprint": content.model_fingerprint,
                    "observation_id": content.observation_id,
                    "baseline_id": content.baseline_id,
                    "evidence_type": content.evidence_type.value,
                    "result_status": content.result_status,
                    "record_classification": "BEHAVIORAL_ASSURANCE_SEAL",
                },
            )

        return finding, prov_record_read, ScanExecutionStatus.COMPLETED
