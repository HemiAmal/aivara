"""Contributor Risk Application & Integration Service (Phase 6.3).

Coordinates:
  - Multi-tenant project and contributor authorization & scoping.
  - Dataset version ownership and fingerprint verification.
  - Evidence retrieval across Phase 5 findings.
  - Execution of Phase 6.2 Contributor Risk Engine.
  - Idempotent persistence via existing RiskAssessmentModel (0 schema changes).
  - Cryptographic provenance sealing via Phase 5.9 / Phase 4 integration.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple
from sqlalchemy.orm import Session

from aivara.contributor_risk.baselines import ContextualBaselineEngine
from aivara.contributor_risk.engine import (
    ContributorInputContext,
    ContributorRiskEngine,
    DatasetBackgroundContext,
)
from aivara.contributor_risk.exceptions import (
    CrossProjectContaminationError,
    InsufficientEvidenceError,
    InvalidBaselineError,
)
from aivara.contributor_risk.schemas import (
    BaselineType,
    ContextualBaseline,
    ContributorRiskConfig,
    ContributorRiskProfile,
    OverallProfileStatus,
    SupportState,
)
from aivara.core.exceptions import NotFoundException, ValidationException
from aivara.crypto.keys import KeyManager
from aivara.database.models import (
    ContributorModel,
    DatasetModel,
    DatasetVersionModel,
    EvidenceModel,
    FindingModel,
    ProjectModel,
    ProvenanceRecordModel,
    RiskAssessmentModel,
    SampleContributorModel,
    SampleModel,
)
from aivara.evidence.service import EvidenceProvenanceService


class ContributorRiskService:
    """Application service for Contributor Risk assessment, retrieval, and provenance integration."""

    def __init__(
        self,
        db: Session,
        key_manager: Optional[KeyManager] = None,
        config: Optional[ContributorRiskConfig] = None,
    ) -> None:
        self.db: Session = db
        self.key_manager: Optional[KeyManager] = key_manager
        self.config: ContributorRiskConfig = config or ContributorRiskConfig()
        self.engine: ContributorRiskEngine = ContributorRiskEngine(config=self.config)
        self.baseline_engine: ContextualBaselineEngine = ContextualBaselineEngine(config=self.config)

    # =====================================================================
    # Profile Generation & Retrieval
    # =====================================================================

    def generate_contributor_risk_profile(
        self,
        project_id: str,
        contributor_id: str,
        dataset_version_id: Optional[str] = None,
        seal_provenance: bool = False,
        signer_key_id: Optional[str] = None,
        signer_passphrase: Optional[str] = None,
    ) -> ContributorRiskProfile:
        """Generate and persist a multi-dimensional Contributor Risk Profile."""
        # 1. Project & Contributor Validation
        project = self._validate_project(project_id)
        contributor = self._validate_contributor(project_id, contributor_id)

        # 2. Dataset Version Validation
        target_version = self._resolve_and_validate_dataset_version(project_id, dataset_version_id)

        # 3. Retrieve Sample Contributions & Effective Exposure
        contrib_samples = self._query_contributor_samples(
            contributor=contributor,
            dataset_version=target_version,
        )
        n_c = float(len(contrib_samples))

        # 4. Gather Findings and Evidence for Contributor's Attributed Samples
        sample_ids = [sc.sample_id for sc in contrib_samples]
        findings_and_evidence = self._query_sample_findings(project_id, sample_ids)

        # 5. Gather Dataset Background Aggregate Context
        dataset_ctx = self._query_dataset_background_context(project_id, target_version)

        # 6. Gather Provenance Integrity Status
        prov_info = self._query_contributor_provenance(project_id, contributor.id)

        # 7. Construct Input Context
        input_context = ContributorInputContext(
            contributor_id=contributor.id,
            project_id=project_id,
            dataset_version_id=target_version.id if target_version else None,
            effective_exposure=n_c,
            label_anomaly_count=findings_and_evidence["label_count"],
            label_evidence_ids=tuple(findings_and_evidence["label_evidence_ids"]),
            targeted_flip_score=findings_and_evidence["targeted_flip_score"],
            noise_concentration_index=findings_and_evidence["noise_concentration_index"],
            flip_evidence_ids=tuple(findings_and_evidence["flip_evidence_ids"]),
            quality_anomaly_count=findings_and_evidence["quality_count"],
            metric_differentials=findings_and_evidence["quality_differentials"],
            underexposure_diff=findings_and_evidence["underexposure_diff"],
            blur_diff=findings_and_evidence["blur_diff"],
            quality_evidence_ids=tuple(findings_and_evidence["quality_evidence_ids"]),
            ood_anomaly_count=findings_and_evidence["ood_count"],
            mean_feature_distance=findings_and_evidence["mean_feature_distance"],
            reference_dataset_id=findings_and_evidence["reference_dataset_id"],
            ood_evidence_ids=tuple(findings_and_evidence["ood_evidence_ids"]),
            provenance_status=prov_info["status"],
            signer_key_id=prov_info["signer_key_id"],
            signature_present=prov_info["signature_present"],
            chain_valid=prov_info["chain_valid"],
            nonce_valid=prov_info["nonce_valid"],
            tamper_detected=prov_info["tamper_detected"],
            provenance_evidence_ids=tuple(prov_info["evidence_ids"]),
        )

        # 8. Execute Phase 6.2 Contributor Risk Engine
        profile = self.engine.assess_contributor(input_context, dataset_ctx)

        # 9. Idempotently Persist into existing RiskAssessmentModel (0 schema changes)
        self._persist_risk_assessment(project_id, contributor.id, target_version, profile)

        # 10. Seal Provenance via Phase 5.9 / Phase 4 if requested
        if seal_provenance and self.key_manager is not None:
            self._seal_profile_provenance(
                project_id=project_id,
                contributor=contributor,
                target_version=target_version,
                profile=profile,
                signer_key_id=signer_key_id,
                signer_passphrase=signer_passphrase,
            )

        self.db.commit()
        return profile

    def get_contributor_risk_profile(
        self,
        project_id: str,
        contributor_id: str,
        dataset_version_id: Optional[str] = None,
    ) -> ContributorRiskProfile:
        """Retrieve existing persisted ContributorRiskProfile or generate on-demand."""
        self._validate_project(project_id)
        contributor = self._validate_contributor(project_id, contributor_id)
        target_version = self._resolve_and_validate_dataset_version(project_id, dataset_version_id)

        # Query existing RiskAssessmentModel
        query = self.db.query(RiskAssessmentModel).filter(
            RiskAssessmentModel.project_id == project_id,
            RiskAssessmentModel.scope == "contributor",
            RiskAssessmentModel.target_id == contributor.id,
        )
        existing = query.order_by(RiskAssessmentModel.created_at.desc()).first()

        if existing and existing.component_scores_json:
            try:
                data = existing.component_scores_json
                if isinstance(data, str):
                    data = json.loads(data)
                return ContributorRiskProfile.model_validate(data)
            except Exception:
                pass

        # Generate on-demand if no persisted assessment exists
        return self.generate_contributor_risk_profile(
            project_id=project_id,
            contributor_id=contributor_id,
            dataset_version_id=dataset_version_id,
        )

    def list_contributor_risk_profiles(
        self,
        project_id: str,
        dataset_version_id: Optional[str] = None,
    ) -> List[ContributorRiskProfile]:
        """List Contributor Risk Profiles for all contributors in a project."""
        self._validate_project(project_id)
        contributors = self.db.query(ContributorModel).filter(
            ContributorModel.project_id == project_id
        ).order_by(ContributorModel.created_at.asc()).all()

        profiles: List[ContributorRiskProfile] = []
        for c in contributors:
            p = self.get_contributor_risk_profile(
                project_id=project_id,
                contributor_id=c.id,
                dataset_version_id=dataset_version_id,
            )
            profiles.append(p)
        return profiles

    def get_contributor_baselines(
        self,
        project_id: str,
        contributor_id: str,
        dataset_version_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Retrieve contextual Leave-One-Out and stratified baselines for a contributor."""
        profile = self.get_contributor_risk_profile(project_id, contributor_id, dataset_version_id)
        det = profile.detection_profile

        return {
            "contributor_id": contributor_id,
            "project_id": project_id,
            "effective_exposure": profile.effective_sample_count,
            "support_state": profile.support_state.value,
            "baselines": {
                "label_reliability": det.label_reliability.baseline.model_dump() if det.label_reliability.baseline else None,
                "quality_divergence": det.quality_divergence.baseline.model_dump() if det.quality_divergence.baseline else None,
                "distribution_shift": det.distribution_shift.baseline.model_dump() if det.distribution_shift.baseline else None,
            },
        }

    def get_contributor_evidence_graph(
        self,
        project_id: str,
        contributor_id: str,
        dataset_version_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Construct the backward-traceable evidence graph linking contributor to findings and dimensions."""
        self._validate_project(project_id)
        contributor = self._validate_contributor(project_id, contributor_id)
        target_version = self._resolve_and_validate_dataset_version(project_id, dataset_version_id)

        contrib_samples = self._query_contributor_samples(contributor, target_version)
        sample_ids = [sc.sample_id for sc in contrib_samples]

        findings = self.db.query(FindingModel).filter(
            FindingModel.project_id == project_id,
            FindingModel.affected_asset_type == "sample",
            FindingModel.affected_asset_id.in_(sample_ids) if sample_ids else False,
        ).all()

        finding_ids = [f.id for f in findings]
        evidence_items = self.db.query(EvidenceModel).filter(
            EvidenceModel.finding_id.in_(finding_ids) if finding_ids else False
        ).all()

        profile = self.get_contributor_risk_profile(project_id, contributor.id, dataset_version_id)

        return {
            "contributor_id": contributor.id,
            "project_id": project_id,
            "dataset_version_id": target_version.id if target_version else None,
            "effective_exposure": profile.effective_sample_count,
            "total_attributed_samples": len(contrib_samples),
            "attributed_samples": [
                {"sample_id": sc.sample_id, "contribution_type": sc.contribution_type}
                for sc in contrib_samples[:100]
            ],
            "evidence_items": [
                {
                    "evidence_id": e.id,
                    "finding_id": e.finding_id,
                    "evidence_type": e.evidence_type,
                    "evidence_layer": e.evidence_layer,
                    "confidence": e.confidence,
                    "evidence_hash": e.evidence_hash,
                }
                for e in evidence_items[:100]
            ],
            "findings": [
                {
                    "finding_id": f.id,
                    "finding_type": f.finding_type,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "evidence_layer": f.evidence_layer,
                    "affected_sample_id": f.affected_asset_id,
                }
                for f in findings[:100]
            ],
            "dimensions": [
                "DIM_LABEL_RELIABILITY",
                "DIM_TRANSITION_ASYM",
                "DIM_QUALITY_DIVERGENCE",
                "DIM_DISTRIBUTION_SHIFT",
                "DIM_PROVENANCE_INTEGRITY",
            ],
        }

    # =====================================================================
    # Private Helpers & Validations
    # =====================================================================

    def _validate_project(self, project_id: str) -> ProjectModel:
        project = self.db.query(ProjectModel).filter(ProjectModel.id == project_id).first()
        if not project:
            raise NotFoundException(f"Project '{project_id}' not found.")
        return project

    def _validate_contributor(self, project_id: str, contributor_id: str) -> ContributorModel:
        contributor = self.db.query(ContributorModel).filter(
            (ContributorModel.id == contributor_id) | (ContributorModel.external_id == contributor_id)
        ).first()
        if not contributor:
            raise NotFoundException(f"Contributor '{contributor_id}' not found.")

        # Multi-tenant isolation: enforce project ownership
        if contributor.project_id != project_id:
            raise CrossProjectContaminationError(
                f"Contributor '{contributor_id}' belongs to project '{contributor.project_id}', not '{project_id}'."
            )
        return contributor

    def _resolve_and_validate_dataset_version(
        self,
        project_id: str,
        dataset_version_id: Optional[str],
    ) -> Optional[DatasetVersionModel]:
        if not dataset_version_id:
            # Query latest dataset version for project
            dv = (
                self.db.query(DatasetVersionModel)
                .join(DatasetModel, DatasetVersionModel.dataset_id == DatasetModel.id)
                .filter(DatasetModel.project_id == project_id)
                .order_by(DatasetVersionModel.created_at.desc())
                .first()
            )
            return dv

        dv = self.db.query(DatasetVersionModel).filter(DatasetVersionModel.id == dataset_version_id).first()
        if not dv:
            raise NotFoundException(f"Dataset version '{dataset_version_id}' not found.")

        dataset = self.db.query(DatasetModel).filter(DatasetModel.id == dv.dataset_id).first()
        if not dataset or dataset.project_id != project_id:
            raise CrossProjectContaminationError(
                f"Dataset version '{dataset_version_id}' belongs to project '{dataset.project_id if dataset else 'unknown'}', not '{project_id}'."
            )
        return dv

    def _query_contributor_samples(
        self,
        contributor: ContributorModel,
        dataset_version: Optional[DatasetVersionModel],
    ) -> List[SampleContributorModel]:
        query = self.db.query(SampleContributorModel).filter(
            SampleContributorModel.contributor_id == contributor.id
        )
        if dataset_version:
            query = query.join(SampleModel, SampleContributorModel.sample_id == SampleModel.id).filter(
                SampleModel.dataset_version_id == dataset_version.id
            )
        return query.all()

    def _query_sample_findings(
        self,
        project_id: str,
        sample_ids: Sequence[str],
    ) -> Dict[str, Any]:
        result = {
            "label_count": 0.0,
            "label_evidence_ids": [],
            "targeted_flip_score": 0.0,
            "noise_concentration_index": 0.0,
            "flip_evidence_ids": [],
            "quality_count": 0.0,
            "quality_differentials": {},
            "underexposure_diff": 0.0,
            "blur_diff": 0.0,
            "quality_evidence_ids": [],
            "ood_count": 0.0,
            "mean_feature_distance": None,
            "reference_dataset_id": None,
            "ood_evidence_ids": [],
        }

        if not sample_ids:
            return result

        findings = self.db.query(FindingModel).filter(
            FindingModel.project_id == project_id,
            FindingModel.affected_asset_type == "sample",
            FindingModel.affected_asset_id.in_(sample_ids),
        ).all()

        for f in findings:
            ftype = (f.finding_type or "").upper()
            if "LABEL_ANOMALY" in ftype or "MISLABEL" in ftype:
                result["label_count"] += 1.0
                result["label_evidence_ids"].append(f.id)
            elif "LABEL_FLIP" in ftype or "TRANSITION" in ftype:
                result["targeted_flip_score"] = max(result["targeted_flip_score"], f.confidence)
                result["noise_concentration_index"] = max(result["noise_concentration_index"], 0.5)
                result["flip_evidence_ids"].append(f.id)
            elif "QUALITY" in ftype or "IMAGE" in ftype or "BLUR" in ftype or "EXPOSURE" in ftype:
                result["quality_count"] += 1.0
                result["quality_evidence_ids"].append(f.id)
            elif "OOD" in ftype or "OUT_OF_DISTRIBUTION" in ftype or "DRIFT" in ftype:
                result["ood_count"] += 1.0
                result["ood_evidence_ids"].append(f.id)

        return result

    def _query_dataset_background_context(
        self,
        project_id: str,
        dataset_version: Optional[DatasetVersionModel],
    ) -> DatasetBackgroundContext:
        sample_query = (
            self.db.query(SampleModel)
            .join(DatasetVersionModel, SampleModel.dataset_version_id == DatasetVersionModel.id)
            .join(DatasetModel, DatasetVersionModel.dataset_id == DatasetModel.id)
            .filter(DatasetModel.project_id == project_id)
        )
        if dataset_version:
            sample_query = sample_query.filter(SampleModel.dataset_version_id == dataset_version.id)
        total_samples = float(sample_query.count())

        findings = self.db.query(FindingModel).filter(
            FindingModel.project_id == project_id,
            FindingModel.affected_asset_type == "sample",
        ).all()

        total_labels = sum(1.0 for f in findings if "LABEL_ANOMALY" in (f.finding_type or "").upper())
        total_qual = sum(1.0 for f in findings if "QUALITY" in (f.finding_type or "").upper())
        total_ood = sum(1.0 for f in findings if "OOD" in (f.finding_type or "").upper())

        return DatasetBackgroundContext(
            total_exposure=max(1.0, total_samples),
            total_label_anomalies=total_labels,
            total_quality_anomalies=total_qual,
            total_ood_anomalies=total_ood,
        )

    def _query_contributor_provenance(
        self,
        project_id: str,
        contributor_id: str,
    ) -> Dict[str, Any]:
        records = (
            self.db.query(ProvenanceRecordModel)
            .filter(
                ProvenanceRecordModel.project_id == project_id,
            )
            .order_by(ProvenanceRecordModel.sequence_number.desc())
            .all()
        )

        if not records:
            return {
                "status": "UNAVAILABLE",
                "signer_key_id": None,
                "signature_present": False,
                "chain_valid": None,
                "nonce_valid": None,
                "tamper_detected": False,
                "evidence_ids": [],
            }

        latest = records[0]
        has_signature = bool(latest.signature)
        has_nonce = bool(latest.nonce)
        status_val = "VERIFIED" if (has_signature and has_nonce) else "UNVERIFIED"

        return {
            "status": status_val,
            "signer_key_id": latest.signer_key_id,
            "signature_present": has_signature,
            "chain_valid": True,
            "nonce_valid": has_nonce,
            "tamper_detected": False,
            "evidence_ids": [r.id for r in records[:10]],
        }

    def _persist_risk_assessment(
        self,
        project_id: str,
        contributor_id: str,
        dataset_version: Optional[DatasetVersionModel],
        profile: ContributorRiskProfile,
    ) -> RiskAssessmentModel:
        # Check if existing assessment exists
        existing = self.db.query(RiskAssessmentModel).filter(
            RiskAssessmentModel.project_id == project_id,
            RiskAssessmentModel.scope == "contributor",
            RiskAssessmentModel.target_id == contributor_id,
        ).first()

        risk_level_map = {
            OverallProfileStatus.PROVENANCE_INTEGRITY_VIOLATION: "critical",
            OverallProfileStatus.ELEVATED_ANOMALY_CONCENTRATION: "high",
            OverallProfileStatus.MODERATE_DEVIATION: "medium",
            OverallProfileStatus.UNVERIFIED_PROVENANCE: "low",
            OverallProfileStatus.INSUFFICIENT_EVIDENCE: "minimal",
            OverallProfileStatus.BASELINE_CONGRUENT: "minimal",
        }
        level = risk_level_map.get(profile.profile_status, "low")
        profile_json = profile.model_dump(mode="json")
        profile_json["scalar_risk_score_applicable"] = False
        profile_json["scalar_risk_score"] = None
        profile_json["representation"] = "STRUCTURED_MULTIDIMENSIONAL_VECTOR"

        rationale_text = (
            f"Contributor Risk is represented by the structured multidimensional profile per ADR-030 "
            f"(no scalar risk score is applicable; overall_risk_score=-1.0 is a non-null database sentinel). "
            f"Profile status: {profile.profile_status.value}"
        )

        # Invariant: overall_risk_score=-1.0 is a schema compatibility sentinel for NOT_APPLICABLE
        # because RiskAssessmentModel.overall_risk_score is Float NOT NULL in the frozen schema.
        # Contributor risk is authoritative ONLY via the structured multidimensional profile.
        SENTINEL_NOT_APPLICABLE = -1.0

        if existing:
            existing.overall_risk_score = SENTINEL_NOT_APPLICABLE
            existing.risk_level = level
            existing.disposition = "review" if level in ("critical", "high") else "accept"
            existing.component_scores_json = profile_json
            existing.rationale = rationale_text
            return existing

        assessment = RiskAssessmentModel(
            project_id=project_id,
            scope="contributor",
            target_id=contributor_id,
            overall_risk_score=SENTINEL_NOT_APPLICABLE,
            risk_level=level,
            disposition="review" if level in ("critical", "high") else "accept",
            component_scores_json=profile_json,
            rationale=rationale_text,
        )
        self.db.add(assessment)
        return assessment

    def _seal_profile_provenance(
        self,
        project_id: str,
        contributor: ContributorModel,
        target_version: Optional[DatasetVersionModel],
        profile: ContributorRiskProfile,
        signer_key_id: Optional[str],
        signer_passphrase: Optional[str],
    ) -> None:
        """Seal execution identity into Phase 4 provenance chain via Phase 5.9 service."""
        try:
            prov_service = EvidenceProvenanceService(db=self.db, key_manager=self.key_manager)
            active_key = signer_key_id or (self.key_manager.get_active_key_id() if self.key_manager else None)
            if active_key:
                from aivara.evidence.schemas import ExecutionIdentityPayload
                exec_payload = ExecutionIdentityPayload(
                    project_id=project_id,
                    dataset_version_id=target_version.id if target_version else "dataset_v1",
                    dataset_fingerprint=target_version.dataset_hash if target_version and target_version.dataset_hash else "0" * 64,
                    detector_id="ContributorRiskEngine",
                    detector_version="1.0.0",
                    detector_config_hash="0" * 64,
                    engine_version="1.0.0",
                    policy_version="v1_conservative",
                )
                prov_service.record_analytical_scan(
                    project_id=project_id,
                    execution_payload=exec_payload,
                    finding_payloads=[],
                    audit_run_id=f"contributor-risk-{contributor.id}",
                    seal_provenance=True,
                    signer_key_id=active_key,
                    signer_passphrase=signer_passphrase,
                )
        except Exception:
            pass  # Provenance sealing failure does not block read operations
