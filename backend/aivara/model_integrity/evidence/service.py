"""Unified Model Integrity Evidence and Provenance Service (Phase 7.6).

Connects Phase 7 Model Integrity outputs to Phase 5.9 Evidence/Finding binding
and Phase 4 Cryptographic Provenance sealing with full idempotency, project isolation, and replay protection.
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
    build_canonical_execution_payload,
    compute_execution_identity_hash,
)
from aivara.evidence.provenance import ProvenanceBindingAdapter
from aivara.evidence.schemas import (
    EvidenceProvenanceVerificationResult,
    ExecutionIdentityPayload,
    FindingSynthesisPayload,
    ScanExecutionStatus,
)
from aivara.evidence.validators import validate_project_isolation
from aivara.model_integrity.comparison.schemas import ModelComparisonResult
from aivara.model_integrity.contract_verification.schemas import ContractVerificationResult
from aivara.model_integrity.evidence.mapping import map_model_integrity_to_findings
from aivara.model_integrity.fingerprinting.schemas import HierarchicalFingerprintResult
from aivara.model_integrity.limits import DEFAULT_LIMITS, ModelIngestionLimits
from aivara.model_integrity.schemas import ModelInspectionResult, NormalizedModelMetadata
from aivara.services.audit_service import AuditService
from aivara.services.provenance_service import ProvenanceService

logger = logging.getLogger("aivara.model_integrity.evidence")


class ModelIntegrityEvidenceService:
    """Core service managing model integrity evidence synthesis, findings persistence, and provenance binding."""

    def __init__(
        self,
        db: Session,
        key_manager: Optional[KeyManager] = None,
        audit_service: Optional[AuditService] = None,
        provenance_service: Optional[ProvenanceService] = None,
        limits: Optional[ModelIngestionLimits] = None,
    ) -> None:
        """Initialize with an active database session and crypto dependencies."""
        self.db = db
        self.key_manager = key_manager
        self.limits = limits or DEFAULT_LIMITS
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

    def record_model_assessment(
        self,
        *,
        project_id: str,
        model_id: str,
        audit_run_id: str,
        fingerprint_result: Optional[HierarchicalFingerprintResult] = None,
        contract_result: Optional[ContractVerificationResult] = None,
        comparison_result: Optional[ModelComparisonResult] = None,
        inspection_result: Optional[ModelInspectionResult] = None,
        metadata: Optional[NormalizedModelMetadata] = None,
        reference_model_id: Optional[str] = None,
        seal_provenance: bool = True,
        signer_key_id: Optional[str] = None,
        signer_passphrase: Optional[str] = None,
        key_handle: Optional[Any] = None,
        allow_idempotent_reuse: bool = True,
        actor: str = "system:model_integrity_orchestrator",
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[FindingModel], Optional[ProvenanceRecordRead], ScanExecutionStatus]:
        """Synthesize findings from model integrity results, seal into provenance chain, and enforce idempotency."""
        if not project_id:
            raise EvidenceValidationError("project_id is required for model integrity assessment.")
        if not model_id:
            raise EvidenceValidationError("model_id is required for model integrity assessment.")

        art_hash = (
            fingerprint_result.artifact_hash
            if fingerprint_result
            else (inspection_result.artifact_hash_sha256 if inspection_result else ("0" * 64))
        )
        master_fp = fingerprint_result.master_fingerprint if fingerprint_result else ("0" * 64)

        # 1. Construct canonical execution payload & hash for idempotency
        exec_payload = ExecutionIdentityPayload(
            project_id=project_id,
            dataset_version_id=model_id,
            dataset_fingerprint=art_hash,
            detector_id="model_integrity_engine",
            detector_version="1.0.0",
            engine_version="1.0.0",
            policy_version="DEFAULT",
            preprocessing_hash=contract_result.contract_hash if contract_result else "STANDARD_V1",
            model_id=model_id,
            model_fingerprint=master_fp,
            model_version="1.0.0",
            reference_dataset_id=reference_model_id or "NONE",
            reference_dataset_fingerprint="NONE",
            detector_config_hash="0" * 64,
        )
        exec_hash = compute_execution_identity_hash(exec_payload)

        # 2. Check Idempotency
        if allow_idempotent_reuse:
            existing_findings = (
                self.db.query(FindingModel)
                .filter(
                    FindingModel.project_id == project_id,
                    FindingModel.affected_asset_id == model_id,
                )
                .all()
            )
            matching_findings = [
                f
                for f in existing_findings
                if f.metadata_json and f.metadata_json.get("execution_identity_hash") == exec_hash
            ]
            if matching_findings:
                # Retrieve existing provenance record if bound
                existing_prov_id = matching_findings[0].metadata_json.get("provenance_record_id")
                existing_prov = None
                if existing_prov_id:
                    prov_model = self.db.query(ProvenanceRecordModel).filter_by(id=existing_prov_id).first()
                    if prov_model:
                        existing_prov = ProvenanceRecordRead.model_validate(prov_model)

                logger.info("Idempotency hit for execution identity '%s'", exec_hash)
                return matching_findings, existing_prov, ScanExecutionStatus.IDEMPOTENT_HIT

        # 3. Map to FindingSynthesisPayload objects
        finding_payloads = map_model_integrity_to_findings(
            project_id=project_id,
            model_id=model_id,
            audit_run_id=audit_run_id,
            fingerprint_result=fingerprint_result,
            contract_result=contract_result,
            comparison_result=comparison_result,
            inspection_result=inspection_result,
            metadata=metadata,
            reference_model_id=reference_model_id,
        )

        # 4. Bind and persist FindingModel + EvidenceModel entities
        persisted_findings: List[FindingModel] = []
        for f_payload in finding_payloads:
            # Inject execution identity hash into metadata
            meta = dict(f_payload.metadata_json)
            meta["execution_identity_hash"] = exec_hash
            meta["audit_run_id"] = audit_run_id
            payload_with_exec = f_payload.model_copy(update={"metadata_json": meta})

            f_model = self.binder.synthesize_finding(payload_with_exec)
            persisted_findings.append(f_model)

        self.db.flush()

        # 5. Seal into Phase 4 Provenance Chain if requested
        sealed_record: Optional[ProvenanceRecordRead] = None
        if seal_provenance and persisted_findings:
            sealed_record = self.provenance_adapter.seal_scan_findings(
                project_id=project_id,
                dataset_version_id=model_id,
                dataset_fingerprint=art_hash,
                execution_identity_hash=exec_hash,
                audit_run_id=audit_run_id,
                findings=persisted_findings,
                signer_key_id=signer_key_id,
                signer_passphrase=signer_passphrase,
                key_handle=key_handle,
                actor=actor,
                metadata=extra_metadata,
            )

        return persisted_findings, sealed_record, ScanExecutionStatus.COMPLETED

    def verify_finding_provenance(
        self,
        finding_id: str,
        project_id: str,
    ) -> EvidenceProvenanceVerificationResult:
        """Verify the cryptographic provenance record bound to a model integrity finding."""
        return self.provenance_adapter.verify_finding_provenance(
            finding_id=finding_id,
            project_id=project_id,
        )
