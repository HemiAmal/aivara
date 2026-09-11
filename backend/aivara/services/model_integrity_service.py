"""Model Integrity Integration and Orchestration Service (Phase 7.7).

Coordinates model registration inspection, hierarchical fingerprinting,
contract verification, reference comparison, evidence binding, and cryptographic
provenance verification under project isolation.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple
import uuid

from sqlalchemy.orm import Session

from aivara.api.schemas.evidence import EvidenceItemRead, FindingDetailRead
from aivara.api.schemas.model_integrity import (
    ModelCompareRequest,
    ModelCompareResponse,
    ModelContractVerifyRequest,
    ModelContractVerifyResponse,
    ModelFingerprintRequest,
    ModelFingerprintResponse,
    ModelInspectRequest,
    ModelInspectResponse,
    ModelIntegrityAssessmentRequest,
    ModelIntegrityAssessmentResponse,
    ModelProvenanceVerificationResponse,
)
from aivara.core.config import settings
from aivara.core.exceptions import NotFoundException
from aivara.crypto.keys import KeyManager
from aivara.crypto.verification import verify_record
from aivara.database.models import (
    AIModelModel,
    EvidenceModel,
    FindingModel,
    ModelFingerprintModel,
    ProjectModel,
    ProvenanceRecordModel,
)
from aivara.domain.schemas import ProvenanceRecordRead
from aivara.evidence.exceptions import CrossProjectContaminationError
from aivara.evidence.validators import validate_project_isolation
from aivara.model_integrity.comparison import (
    ModelComparisonResult,
    ModelComparisonService,
)
from aivara.model_integrity.contract_verification import (
    ModelContractVerificationService,
    PreprocessingDeclaration,
)
from aivara.model_integrity.contract_verification.schemas import ContractVerificationResult
from aivara.model_integrity.evidence.service import ModelIntegrityEvidenceService
from aivara.model_integrity.fingerprinting import (
    HierarchicalFingerprintResult,
    ModelFingerprintingService,
)
from aivara.model_integrity.limits import DEFAULT_LIMITS, ModelIngestionLimits
from aivara.model_integrity.schemas import (
    InspectionStatus,
    ModelInspectionResult,
    NormalizedModelMetadata,
)
from aivara.model_integrity.service import ModelIngestionService
from aivara.services.audit_service import AuditService
from aivara.services.provenance_service import ProvenanceService

logger = logging.getLogger("aivara.services.model_integrity")


class ModelIntegrityService:
    """Service layer orchestrating Model Integrity capabilities."""

    def __init__(
        self,
        db: Session,
        key_manager: Optional[KeyManager] = None,
        limits: Optional[ModelIngestionLimits] = None,
    ) -> None:
        self.db = db
        self.key_manager = key_manager or KeyManager(keys_dir=settings.keys_dir)
        self.limits = limits or DEFAULT_LIMITS
        self.ingestion_service = ModelIngestionService(limits=self.limits)
        self.fingerprinting_service = ModelFingerprintingService(limits=self.limits)
        self.contract_service = ModelContractVerificationService(limits=self.limits)
        self.comparison_service = ModelComparisonService(limits=self.limits)
        self.audit_service = AuditService(db)
        self.provenance_service = ProvenanceService(
            db=db,
            key_manager=self.key_manager,
            audit_service=self.audit_service,
        )
        self.evidence_service = ModelIntegrityEvidenceService(
            db=db,
            key_manager=self.key_manager,
            audit_service=self.audit_service,
            provenance_service=self.provenance_service,
            limits=self.limits,
        )

    def _require_project(self, project_id: str) -> ProjectModel:
        """Validate project existence."""
        project = self.db.query(ProjectModel).filter(ProjectModel.id == project_id).first()
        if not project:
            raise NotFoundException(f"Project '{project_id}' not found.")
        return project

    def _get_validated_model(self, project_id: str, model_id: str) -> AIModelModel:
        """Retrieve model and strictly enforce project isolation."""
        self._require_project(project_id)
        model = self.db.query(AIModelModel).filter(AIModelModel.id == model_id).first()
        if not model:
            raise NotFoundException(f"Model '{model_id}' not found.")
        if model.project_id != project_id:
            raise CrossProjectContaminationError(
                f"Model '{model_id}' belongs to project '{model.project_id}', not '{project_id}'."
            )
        return model

    # =====================================================================
    # 1. Safe Ingestion & Inspection
    # =====================================================================

    def inspect_model(
        self,
        project_id: str,
        model_id: str,
        request: Optional[ModelInspectRequest] = None,
    ) -> ModelInspectResponse:
        """Execute safe static model inspection without model execution."""
        model = self._get_validated_model(project_id, model_id)
        target_path = (request.file_path if request and request.file_path else model.file_path)
        allowed_dir = request.allowed_base_dir if request else None

        result: ModelInspectionResult = self.ingestion_service.inspect_artifact(
            artifact_path=target_path,
            allowed_base_dir=allowed_dir,
        )

        tensor_count = None
        input_count = None
        output_count = None
        operator_count = None

        if result.normalized_metadata:
            tensor_count = len(result.normalized_metadata.tensors)
            input_count = len(result.normalized_metadata.inputs)
            output_count = len(result.normalized_metadata.outputs)
            operator_count = len(result.normalized_metadata.operators)

        return ModelInspectResponse(
            status=result.status.value if hasattr(result.status, "value") else str(result.status),
            format=result.format.value if hasattr(result.format, "value") else str(result.format),
            policy=result.policy.value if hasattr(result.policy, "value") else str(result.policy),
            artifact_path=result.artifact_path,
            artifact_size_bytes=result.artifact_size_bytes,
            artifact_hash_sha256=result.artifact_hash_sha256,
            tensor_count=tensor_count,
            input_count=input_count,
            output_count=output_count,
            operator_count=operator_count,
            reason_codes=[r.value if hasattr(r, "value") else str(r) for r in result.reason_codes],
            warnings=result.warnings,
            details=result.details,
        )

    # =====================================================================
    # 2. Hierarchical Fingerprinting
    # =====================================================================

    def fingerprint_model(
        self,
        project_id: str,
        model_id: str,
        request: Optional[ModelFingerprintRequest] = None,
    ) -> ModelFingerprintResponse:
        """Compute or retrieve hierarchical fingerprints & weight Merkle root."""
        model = self._get_validated_model(project_id, model_id)
        allow_reuse = request.allow_idempotent_reuse if request else True

        # Check existing master fingerprint in DB if reuse allowed
        if allow_reuse:
            existing = (
                self.db.query(ModelFingerprintModel)
                .filter(
                    ModelFingerprintModel.model_id == model_id,
                    ModelFingerprintModel.fingerprint_type == "master",
                )
                .first()
            )
            if existing and existing.metadata_json:
                meta = existing.metadata_json
                return ModelFingerprintResponse(
                    model_id=model_id,
                    project_id=project_id,
                    artifact_hash=meta.get("artifact_hash", "0" * 64),
                    structural_hash=meta.get("structural_hash", "0" * 64),
                    weight_merkle_root=meta.get("weight_merkle_root", "0" * 64),
                    contract_hash=meta.get("contract_hash", "0" * 64),
                    master_fingerprint=existing.fingerprint_value,
                    tensor_count=meta.get("tensor_count", 0),
                    inspection_status=meta.get("inspection_status", InspectionStatus.SUCCESS.value),
                    details=meta.get("details", {}),
                )

        # Ingest and compute fresh fingerprints
        inspection = self.ingestion_service.inspect_artifact(model.file_path)
        fp_result: HierarchicalFingerprintResult = self.fingerprinting_service.fingerprint_model(
            artifact_path=model.file_path,
            metadata=inspection.normalized_metadata,
        )

        weight_root = fp_result.weight_merkle_root or ("0" * 64)

        # Store in DB
        meta_dict = {
            "artifact_hash": fp_result.artifact_hash,
            "structural_hash": fp_result.structural_hash,
            "weight_merkle_root": weight_root,
            "contract_hash": fp_result.contract_hash,
            "tensor_count": fp_result.tensor_count,
            "inspection_status": fp_result.status,
            "details": {},
        }
        fp_record = ModelFingerprintModel(
            model_id=model_id,
            fingerprint_type="master",
            fingerprint_version="1",
            fingerprint_value=fp_result.master_fingerprint,
            metadata_json=meta_dict,
        )
        self.db.add(fp_record)
        self.db.commit()

        return ModelFingerprintResponse(
            model_id=model_id,
            project_id=project_id,
            artifact_hash=fp_result.artifact_hash,
            structural_hash=fp_result.structural_hash,
            weight_merkle_root=weight_root,
            contract_hash=fp_result.contract_hash,
            master_fingerprint=fp_result.master_fingerprint,
            tensor_count=fp_result.tensor_count,
            inspection_status=fp_result.status,
            details={},
        )

    # =====================================================================
    # 3. Contract Verification
    # =====================================================================

    def verify_contract(
        self,
        project_id: str,
        model_id: str,
        request: Optional[ModelContractVerifyRequest] = None,
    ) -> ModelContractVerifyResponse:
        """Verify input, output, and preprocessing contracts."""
        model = self._get_validated_model(project_id, model_id)
        inspection = self.ingestion_service.inspect_artifact(model.file_path)

        declared_prep = None
        if request and request.preprocessing_declaration:
            try:
                declared_prep = PreprocessingDeclaration.model_validate(request.preprocessing_declaration)
            except Exception as e:
                logger.warning("Could not parse declared preprocessing: %s", e)

        contract_res: ContractVerificationResult = self.contract_service.verify_contract(
            metadata=inspection.normalized_metadata,
            explicit_preprocessing=declared_prep,
        )

        return ModelContractVerifyResponse(
            model_id=model_id,
            project_id=project_id,
            contract_status=contract_res.status.value if hasattr(contract_res.status, "value") else str(contract_res.status),
            completeness=contract_res.completeness.value if hasattr(contract_res.completeness, "value") else str(contract_res.completeness),
            contract_hash=contract_res.contract_hash,
            input_contract=[i.model_dump() for i in contract_res.inputs] if contract_res.inputs else None,
            output_contract=[o.model_dump() for o in contract_res.outputs] if contract_res.outputs else None,
            preprocessing_contract=contract_res.preprocessing.model_dump() if contract_res.preprocessing else None,
            finding_count=len(contract_res.findings),
            findings=[f.model_dump() for f in contract_res.findings],
            limitations=contract_res.warnings,
        )

    # =====================================================================
    # 4. Reference Model Comparison
    # =====================================================================

    def compare_models(
        self,
        project_id: str,
        candidate_model_id: str,
        request: ModelCompareRequest,
    ) -> ModelCompareResponse:
        """Compare candidate model against a trusted reference model."""
        cand_model = self._get_validated_model(project_id, candidate_model_id)
        ref_model = self._get_validated_model(project_id, request.reference_model_id)

        # Ingest both
        cand_inspect = self.ingestion_service.inspect_artifact(cand_model.file_path)
        ref_inspect = self.ingestion_service.inspect_artifact(ref_model.file_path)

        # Compare using compare_artifacts to handle leaves and full attribution
        comp_res: ModelComparisonResult = self.comparison_service.compare_artifacts(
            reference_path=ref_model.file_path,
            candidate_path=cand_model.file_path,
        )

        weight_diffs = [
            d.model_dump()
            for d in comp_res.tensor_changes
            if (d.change_type.value if hasattr(d.change_type, "value") else str(d.change_type)) != "UNCHANGED"
        ]

        return ModelCompareResponse(
            candidate_model_id=candidate_model_id,
            reference_model_id=request.reference_model_id,
            project_id=project_id,
            comparison_status=comp_res.comparison_status.value if hasattr(comp_res.comparison_status, "value") else str(comp_res.comparison_status),
            drift_classification=comp_res.drift_classification.value if hasattr(comp_res.drift_classification, "value") else str(comp_res.drift_classification),
            is_exact_match=comp_res.is_exact_master_match,
            structural_differences=[d.model_dump() for d in comp_res.structural_differences],
            contract_differences=[d.model_dump() for d in comp_res.contract_differences],
            weight_differences=weight_diffs[: request.max_tensor_changes],
            tensor_changes_summary=comp_res.tensor_summary,
            attribution_records=[d.model_dump() for d in comp_res.tensor_changes[: request.max_tensor_changes]],
        )

    # =====================================================================
    # 5. Integrated Assessment Pipeline
    # =====================================================================

    def run_integrity_assessment(
        self,
        project_id: str,
        model_id: str,
        request: Optional[ModelIntegrityAssessmentRequest] = None,
        audit_run_id: Optional[str] = None,
    ) -> ModelIntegrityAssessmentResponse:
        """Run full integrated model integrity assessment with evidence & provenance binding."""
        req = request or ModelIntegrityAssessmentRequest()
        cand_model = self._get_validated_model(project_id, model_id)
        audit_id = audit_run_id or f"audit-{uuid.uuid4()}"
        # Safe Inspection
        cand_inspect = self.ingestion_service.inspect_artifact(cand_model.file_path)

        # Fingerprinting
        cand_fp = self.fingerprinting_service.fingerprint_model(
            cand_model.file_path, metadata=cand_inspect.normalized_metadata
        )

        # Contract verification
        declared_prep = None
        if req.preprocessing_declaration:
            try:
                declared_prep = PreprocessingDeclaration.model_validate(req.preprocessing_declaration)
            except Exception as e:
                logger.warning("Could not parse declared preprocessing: %s", e)

        cand_contract = self.contract_service.verify_contract(
            metadata=cand_inspect.normalized_metadata,
            explicit_preprocessing=declared_prep,
        )

        # Optional reference comparison
        comp_res: Optional[ModelComparisonResult] = None
        comp_response: Optional[ModelCompareResponse] = None
        if req.reference_model_id:
            ref_model = self._get_validated_model(project_id, req.reference_model_id)
            ref_inspect = self.ingestion_service.inspect_artifact(ref_model.file_path)

            comp_res = self.comparison_service.compare_artifacts(
                reference_path=ref_model.file_path,
                candidate_path=cand_model.file_path,
            )
            assessment_weight_diffs = [
                d.model_dump()
                for d in comp_res.tensor_changes
                if (d.change_type.value if hasattr(d.change_type, "value") else str(d.change_type)) != "UNCHANGED"
            ]
            comp_response = ModelCompareResponse(
                candidate_model_id=model_id,
                reference_model_id=req.reference_model_id,
                project_id=project_id,
                comparison_status=comp_res.comparison_status.value if hasattr(comp_res.comparison_status, "value") else str(comp_res.comparison_status),
                drift_classification=comp_res.drift_classification.value if hasattr(comp_res.drift_classification, "value") else str(comp_res.drift_classification),
                is_exact_match=comp_res.is_exact_master_match,
                structural_differences=[d.model_dump() for d in comp_res.structural_differences],
                contract_differences=[d.model_dump() for d in comp_res.contract_differences],
                weight_differences=assessment_weight_diffs,
                tensor_changes_summary=comp_res.tensor_summary,
                attribution_records=[d.model_dump() for d in comp_res.tensor_changes],
            )

        # Evidence generation & Provenance sealing via ModelIntegrityEvidenceService
        findings_models, sealed_prov, exec_status = self.evidence_service.record_model_assessment(
            project_id=project_id,
            model_id=model_id,
            audit_run_id=audit_id,
            fingerprint_result=cand_fp,
            contract_result=cand_contract,
            comparison_result=comp_res,
            inspection_result=cand_inspect,
            metadata=cand_inspect.normalized_metadata,
            reference_model_id=req.reference_model_id,
            seal_provenance=req.seal_provenance,
            signer_key_id=req.signer_key_id,
            signer_passphrase=req.signer_passphrase,
            allow_idempotent_reuse=req.allow_idempotent_reuse,
            actor=req.actor,
            extra_metadata=req.extra_metadata,
        )

        is_idempotent = (exec_status.value == "IDEMPOTENT_HIT" if hasattr(exec_status, "value") else str(exec_status) == "IDEMPOTENT_HIT")

        # Format findings read models
        findings_read: List[FindingDetailRead] = []
        for f in findings_models:
            meta = f.metadata_json or {}
            findings_read.append(
                FindingDetailRead(
                    id=f.id,
                    project_id=f.project_id,
                    finding_type=f.finding_type,
                    engine_id=f.engine_id,
                    title=f.title,
                    description=f.description,
                    severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    confidence=f.confidence,
                    disposition=f.disposition.value if hasattr(f.disposition, "value") and f.disposition else None,
                    affected_asset_type=f.affected_asset_type,
                    affected_asset_id=f.affected_asset_id,
                    primary_evidence_hashes=meta.get("primary_evidence_hashes", []),
                    referenced_evidence_ids=meta.get("referenced_evidence_ids", []),
                    provenance_record_id=meta.get("provenance_record_id"),
                    metadata_json=meta,
                    created_at=f.created_at.isoformat() if f.created_at else "",
                )
            )

        # Retrieve execution identity hash from findings metadata
        exec_hash = "0" * 64
        if findings_models and findings_models[0].metadata_json:
            exec_hash = findings_models[0].metadata_json.get("execution_identity_hash", "0" * 64)

        weight_root = cand_fp.weight_merkle_root or ("0" * 64)
        fp_response = ModelFingerprintResponse(
            model_id=model_id,
            project_id=project_id,
            artifact_hash=cand_fp.artifact_hash,
            structural_hash=cand_fp.structural_hash,
            weight_merkle_root=weight_root,
            contract_hash=cand_fp.contract_hash,
            master_fingerprint=cand_fp.master_fingerprint,
            tensor_count=cand_fp.tensor_count,
            inspection_status=cand_fp.status,
            details={},
        )

        contract_response = ModelContractVerifyResponse(
            model_id=model_id,
            project_id=project_id,
            contract_status=cand_contract.status.value if hasattr(cand_contract.status, "value") else str(cand_contract.status),
            completeness=cand_contract.completeness.value if hasattr(cand_contract.completeness, "value") else str(cand_contract.completeness),
            contract_hash=cand_contract.contract_hash,
            input_contract=[i.model_dump() for i in cand_contract.inputs] if cand_contract.inputs else None,
            output_contract=[o.model_dump() for o in cand_contract.outputs] if cand_contract.outputs else None,
            preprocessing_contract=cand_contract.preprocessing.model_dump() if cand_contract.preprocessing else None,
            finding_count=len(cand_contract.findings),
            findings=[f.model_dump() for f in cand_contract.findings],
            limitations=cand_contract.warnings,
        )

        all_limitations = list(cand_contract.warnings)
        if cand_inspect.warnings:
            all_limitations.extend(cand_inspect.warnings)

        return ModelIntegrityAssessmentResponse(
            assessment_status=exec_status.value if hasattr(exec_status, "value") else str(exec_status),
            project_id=project_id,
            model_id=model_id,
            reference_model_id=req.reference_model_id,
            execution_identity_hash=exec_hash,
            idempotent=is_idempotent,
            fingerprint=fp_response,
            contract=contract_response,
            comparison=comp_response,
            findings_count=len(findings_read),
            findings=findings_read,
            provenance=sealed_prov,
            limitations=all_limitations,
        )

    # =====================================================================
    # 6. Evidence & Finding Retrieval
    # =====================================================================

    def list_evidence(self, project_id: str, model_id: str) -> List[EvidenceItemRead]:
        """Retrieve all immutable evidence items associated with a model's findings."""
        self._get_validated_model(project_id, model_id)
        evidences = (
            self.db.query(EvidenceModel)
            .join(FindingModel, EvidenceModel.finding_id == FindingModel.id)
            .filter(FindingModel.project_id == project_id, FindingModel.affected_asset_id == model_id)
            .order_by(EvidenceModel.created_at.desc())
            .all()
        )
        return [
            EvidenceItemRead(
                id=e.id,
                finding_id=e.finding_id,
                evidence_hash=e.evidence_hash,
                evidence_type=e.evidence_type,
                evidence_layer=e.evidence_layer.value if hasattr(e.evidence_layer, "value") else str(e.evidence_layer),
                title=e.title,
                description=e.description,
                confidence=e.confidence,
                measurements=e.data_json.get("measurements", {}) if isinstance(e.data_json, dict) else {},
                data_json=e.data_json or {},
                created_at=e.created_at.isoformat() if e.created_at else "",
            )
            for e in evidences
        ]

    def list_findings(self, project_id: str, model_id: str) -> List[FindingDetailRead]:
        """Retrieve all findings synthesized for a model."""
        self._get_validated_model(project_id, model_id)
        findings = (
            self.db.query(FindingModel)
            .filter(FindingModel.project_id == project_id, FindingModel.affected_asset_id == model_id)
            .order_by(FindingModel.created_at.desc())
            .all()
        )
        items = []
        for f in findings:
            meta = f.metadata_json or {}
            items.append(
                FindingDetailRead(
                    id=f.id,
                    project_id=f.project_id,
                    finding_type=f.finding_type,
                    engine_id=f.engine_id,
                    title=f.title,
                    description=f.description,
                    severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    confidence=f.confidence,
                    disposition=f.disposition.value if hasattr(f.disposition, "value") and f.disposition else None,
                    affected_asset_type=f.affected_asset_type,
                    affected_asset_id=f.affected_asset_id,
                    primary_evidence_hashes=meta.get("primary_evidence_hashes", []),
                    referenced_evidence_ids=meta.get("referenced_evidence_ids", []),
                    provenance_record_id=meta.get("provenance_record_id"),
                    metadata_json=meta,
                    created_at=f.created_at.isoformat() if f.created_at else "",
                )
            )
        return items

    # =====================================================================
    # 7. Provenance Verification
    # =====================================================================

    def verify_provenance(self, project_id: str, model_id: str) -> ModelProvenanceVerificationResponse:
        """Verify the cryptographic provenance record bound to model integrity commitments."""
        self._get_validated_model(project_id, model_id)

        # Check for model finding with bound provenance record
        finding = (
            self.db.query(FindingModel)
            .filter(
                FindingModel.project_id == project_id,
                FindingModel.affected_asset_id == model_id,
            )
            .order_by(FindingModel.created_at.desc())
            .first()
        )

        prov_id = None
        if finding and finding.metadata_json:
            prov_id = finding.metadata_json.get("provenance_record_id")

        if not prov_id:
            # Look up directly in provenance records by target_id
            prov_rec = (
                self.db.query(ProvenanceRecordModel)
                .filter(
                    ProvenanceRecordModel.project_id == project_id,
                    ProvenanceRecordModel.target_id == model_id,
                )
                .order_by(ProvenanceRecordModel.sequence_number.desc())
                .first()
            )
            if not prov_rec:
                return ModelProvenanceVerificationResponse(
                    is_valid=False,
                    status="MISSING",
                    provenance_record_id=None,
                    project_id=project_id,
                    model_id=model_id,
                    target_type_logical="model",
                    target_type_recorded="dataset_version",
                    signature_valid=False,
                    chain_valid=False,
                    signer_key_id=None,
                    sequence_number=None,
                    record_hash=None,
                    details={"error": "No provenance record found for this model."},
                )
            prov_id = prov_rec.id

        # Verify through EvidenceService adapter if finding exists
        if finding:
            verif_res = self.evidence_service.verify_finding_provenance(finding.id, project_id=project_id)
            record = self.db.query(ProvenanceRecordModel).filter_by(id=verif_res.provenance_record_id).first()
            return ModelProvenanceVerificationResponse(
                is_valid=verif_res.cryptographic_validity,
                status=verif_res.provenance_status.value if hasattr(verif_res.provenance_status, "value") else str(verif_res.provenance_status),
                provenance_record_id=verif_res.provenance_record_id,
                project_id=project_id,
                model_id=model_id,
                target_type_logical="model",
                target_type_recorded="dataset_version",
                signature_valid=verif_res.cryptographic_validity,
                chain_valid=verif_res.cryptographic_validity,
                signer_key_id=record.signer_key_id if record else None,
                sequence_number=record.sequence_number if record else None,
                record_hash=record.record_hash if record else None,
                details={
                    "compatibility_note": (
                        "Target type recorded in Phase 4 ledger as 'dataset_version' to maintain "
                        "backward compatibility with the frozen Phase 5.9 adapter."
                    ),
                    "evidence_count": verif_res.evidence_count,
                    "warnings": verif_res.warnings,
                    "errors": verif_res.errors,
                },
            )

        # Fallback direct record verification
        record = self.db.query(ProvenanceRecordModel).filter_by(id=prov_id).first()
        if not record:
            return ModelProvenanceVerificationResponse(
                is_valid=False,
                status="MISSING",
                provenance_record_id=prov_id,
                project_id=project_id,
                model_id=model_id,
                target_type_logical="model",
                target_type_recorded="dataset_version",
                signature_valid=False,
                chain_valid=False,
                signer_key_id=None,
                sequence_number=None,
                record_hash=None,
                details={"error": "Provenance record not found in database."},
            )

        pub_key = None
        if record.signer_key_id:
            try:
                pub_key = self.key_manager.get_public_key(record.signer_key_id)
            except Exception as e:
                logger.warning("Could not resolve public key for %s: %s", record.signer_key_id, e)

        sig_valid = False
        if pub_key:
            rec_read = ProvenanceRecordRead.model_validate(record)
            sig_valid = verify_record(rec_read, pub_key).is_valid

        chain_res = self.audit_service.verify_provenance_chain(project_id=project_id)
        is_overall_valid = sig_valid and chain_res.is_valid

        return ModelProvenanceVerificationResponse(
            is_valid=is_overall_valid,
            status="VERIFIED" if is_overall_valid else "INVALID",
            provenance_record_id=record.id,
            project_id=project_id,
            model_id=model_id,
            target_type_logical="model",
            target_type_recorded=record.target_type or "dataset_version",
            signature_valid=sig_valid,
            chain_valid=chain_res.is_valid,
            signer_key_id=record.signer_key_id,
            sequence_number=record.sequence_number,
            record_hash=record.record_hash,
            details={
                "compatibility_note": (
                    "Target type recorded in Phase 4 ledger as 'dataset_version' to maintain "
                    "backward compatibility with the frozen Phase 5.9 adapter."
                ),
            },
        )
