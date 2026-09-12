"""Backdoor Evidence and Cryptographic Provenance Binding Adapter (Phase 9.9).

Bridges Phase 9 analytical outputs (candidate evaluations, activation summaries,
control comparisons, and spatial localization statistics) into AIVARA's frozen
Phase 4 / Phase 5.9 Evidence and Provenance infrastructure.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import logging
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from aivara.backdoor.statistics.models import (
    CandidatePromotionAssessment,
    CandidateStatisticalSummary,
    SpatialLocalizationSummary,
    StatisticalAnalysisAssessment,
)
from aivara.crypto.canonical import canonicalize, format_canonical_datetime
from aivara.crypto.hashing import hash_canonical_data, sha256_bytes
from aivara.crypto.keys import KeyManager
from aivara.database.models import FindingModel, ProvenanceRecordModel
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
    EvidenceContent,
    EvidencePayload,
    FindingSynthesisPayload,
    ProvenanceStatus,
    ScanExecutionStatus,
)
from aivara.database.models import ProjectModel
from aivara.evidence.exceptions import CrossProjectContaminationError
from aivara.evidence.validators import validate_project_isolation
from aivara.services.audit_service import AuditService
from aivara.services.provenance_service import ProvenanceService

logger = logging.getLogger("aivara.backdoor.evidence")

BACKDOOR_EVIDENCE_SCHEMA_VERSION: str = "1.0.0"
BACKDOOR_DETECTOR_VERSION: str = "1.0.0"


class BackdoorEvidenceType(str, Enum):
    """Controlled taxonomy of backdoor analysis evidence types."""
    BACKDOOR_STATISTICAL_ANALYSIS = "backdoor_statistical_analysis"
    BACKDOOR_TRIGGER_ACTIVATION = "backdoor_trigger_activation"
    BACKDOOR_SPATIAL_LOCALIZATION = "backdoor_spatial_localization"


class BackdoorEvidenceLifecycleState(str, Enum):
    """Lifecycle state of backdoor evidence items."""
    DRAFT = "DRAFT"
    SEALED = "SEALED"


class BackdoorEvidenceContent(BaseModel):
    """Canonical, bounded content of a backdoor trigger analysis evidence item.
    
    Contains exclusively immutable, semantic attributes required to compute
    the deterministic evidence_hash via RFC 8785 (JCS) and SHA-256.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_layer: EvidenceLayer = Field(EvidenceLayer.DETECTION, description="Assurance layer")
    evidence_type: BackdoorEvidenceType = Field(
        BackdoorEvidenceType.BACKDOOR_STATISTICAL_ANALYSIS,
        description="Backdoor evidence type",
    )
    project_id: str = Field(..., description="Tenant project identifier")
    model_id: str = Field(..., description="Target model identifier")
    model_fingerprint: str = Field(..., description="Evaluated model identity hash")
    sample_set_hash: str = Field(..., description="Hash of evaluated clean input set")
    candidate_hash: str = Field(..., description="Trigger candidate identity hash")
    transformation_hash: Optional[str] = Field(None, description="Trigger transformation identity hash")
    activation_assessment_id: str = Field(..., description="Linked Phase 9.4 activation assessment ID")
    statistical_analysis_id: str = Field(..., description="Canonical Phase 9.5 statistical analysis ID")
    target_class: Optional[Union[int, str]] = Field(None, description="Evaluated target class")
    tar: Optional[float] = Field(None, description="Trigger Activation Rate")
    tsr: Optional[float] = Field(None, description="Trigger Success Rate")
    raw_tsr_shuffled: Optional[float] = Field(None, description="TSR under location-shuffled control")
    raw_tsr_noise: Optional[float] = Field(None, description="TSR under magnitude-matched noise control")
    control_baseline_tsr: Optional[float] = Field(None, description="Control baseline TSR")
    sample_envelope_tsr: Optional[float] = Field(None, description="Sample-level envelope TSR")
    delta_separation: Optional[float] = Field(None, description="Observed separation over control")
    confidence_interval_low: Optional[float] = Field(None, description="Clopper-Pearson 95% CI lower bound")
    confidence_interval_high: Optional[float] = Field(None, description="Clopper-Pearson 95% CI upper bound")
    permutation_count: int = Field(1000, description="Permutation iterations B")
    p_value: Optional[float] = Field(None, description="IUT composite permutation p-value")
    p_value_shuffled: Optional[float] = Field(None, description="Permutation p-value vs shuffled control")
    p_value_noise: Optional[float] = Field(None, description="Permutation p-value vs noise control")
    adjusted_p_value: Optional[float] = Field(None, description="BH-FDR adjusted p-value")
    is_significant_after_fdr: bool = Field(False, description="Significant after FDR adjustment")
    taxonomy_classification: str = Field(..., description="Phase 9.1 non-accusatory result taxonomy")
    spatial_localization: Optional[Dict[str, Any]] = Field(None, description="Bounded spatial localization summary")
    budget_inferences_total: int = Field(..., description="Total inferences consumed")
    policy_version: str = Field("1.0.0", description="Evaluation policy version")
    analysis_version: str = Field(BACKDOOR_DETECTOR_VERSION, description="Detector algorithm version")
    schema_version: str = Field(BACKDOOR_EVIDENCE_SCHEMA_VERSION, description="Evidence schema version")


class BackdoorEvidence(BaseModel):
    """Sealed or draft backdoor analytical evidence container."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str = Field(..., description="Deterministic 64-hex evidence content hash")
    execution_id: str = Field(..., description="Deterministic 64-hex execution identity hash")
    content: BackdoorEvidenceContent = Field(..., description="Canonical evidence content")
    state: BackdoorEvidenceLifecycleState = Field(
        BackdoorEvidenceLifecycleState.DRAFT, description="Evidence lifecycle state"
    )
    created_at: str = Field(..., description="RFC 3339 UTC timestamp")
    sealed_at: Optional[str] = Field(None, description="RFC 3339 UTC sealing timestamp")


def compute_backdoor_evidence_hash(content: BackdoorEvidenceContent) -> str:
    """Compute deterministic RFC 8785 JCS SHA-256 evidence identity hash."""
    raw_dict = content.model_dump(mode="json", exclude_none=False)
    canonical_dict = {
        k: v for k, v in raw_dict.items()
    }
    return hash_canonical_data(canonical_dict)


def compute_backdoor_execution_identity_hash(
    project_id: str,
    model_id: str,
    model_fingerprint: str,
    sample_set_hash: str,
    candidate_hash: str,
    detector_version: str = BACKDOOR_DETECTOR_VERSION,
    policy_version: str = "1.0.0",
    schema_version: str = BACKDOOR_EVIDENCE_SCHEMA_VERSION,
) -> str:
    """Compute deterministic RFC 8785 JCS execution identity hash (Phase 5.9 compatibility)."""
    canonical_dict = {
        "candidate_hash": str(candidate_hash),
        "detector_id": "backdoor_trigger_analysis_engine",
        "detector_version": str(detector_version),
        "model_fingerprint": str(model_fingerprint),
        "model_id": str(model_id),
        "policy_version": str(policy_version),
        "project_id": str(project_id),
        "sample_set_hash": str(sample_set_hash),
        "schema_version": str(schema_version),
    }
    return hash_canonical_data(canonical_dict)


def create_backdoor_evidence(
    assessment: StatisticalAnalysisAssessment,
    candidate_summary: CandidateStatisticalSummary,
    *,
    model_fingerprint: Optional[str] = None,
    transformation_hash: Optional[str] = None,
    spatial_summary: Optional[SpatialLocalizationSummary] = None,
    created_at: Optional[datetime] = None,
) -> BackdoorEvidence:
    """Factory creating a DRAFT BackdoorEvidence object from analytical results."""
    m_fingerprint = model_fingerprint or assessment.model_id
    now_dt = created_at or datetime.now(timezone.utc)
    ts_str = format_canonical_datetime(now_dt)

    bounded_loc: Optional[Dict[str, Any]] = None
    if spatial_summary is not None:
        bounded_loc = {
            "grid_dimension": spatial_summary.grid_dimension,
            "total_cells": spatial_summary.total_cells,
            "evaluable_cells": spatial_summary.evaluable_cells,
            "significant_cells": spatial_summary.significant_cells,
            "peak_cell_index": spatial_summary.peak_cell_index,
            "peak_delta_separation": spatial_summary.peak_delta_separation,
            "min_adjusted_p_value": spatial_summary.min_adjusted_p_value,
            "correction_method": spatial_summary.correction_method,
        }

    content = BackdoorEvidenceContent(
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type=BackdoorEvidenceType.BACKDOOR_STATISTICAL_ANALYSIS,
        project_id=assessment.project_id,
        model_id=assessment.model_id,
        model_fingerprint=m_fingerprint,
        sample_set_hash=assessment.sample_set_hash,
        candidate_hash=candidate_summary.candidate_hash,
        transformation_hash=transformation_hash,
        activation_assessment_id=assessment.trigger_assessment_id,
        statistical_analysis_id=assessment.statistical_analysis_id,
        target_class=candidate_summary.target_class,
        tar=candidate_summary.tar,
        tsr=candidate_summary.tsr,
        raw_tsr_shuffled=candidate_summary.raw_tsr_shuffled,
        raw_tsr_noise=candidate_summary.raw_tsr_noise,
        control_baseline_tsr=candidate_summary.control_baseline_tsr,
        sample_envelope_tsr=candidate_summary.sample_envelope_tsr,
        delta_separation=candidate_summary.delta_separation,
        confidence_interval_low=candidate_summary.confidence_interval.lower_bound,
        confidence_interval_high=candidate_summary.confidence_interval.upper_bound,
        permutation_count=assessment.permutation_count,
        p_value=candidate_summary.raw_p_value,
        p_value_shuffled=candidate_summary.permutation_test.p_value_shuffled,
        p_value_noise=candidate_summary.permutation_test.p_value_noise,
        adjusted_p_value=candidate_summary.adjusted_p_value,
        is_significant_after_fdr=candidate_summary.is_significant_after_fdr,
        taxonomy_classification=candidate_summary.taxonomy_classification.value,
        spatial_localization=bounded_loc,
        budget_inferences_total=assessment.budget_accounting.total_inferences,
        policy_version="1.0.0",
        analysis_version=BACKDOOR_DETECTOR_VERSION,
        schema_version=BACKDOOR_EVIDENCE_SCHEMA_VERSION,
    )

    ev_id = compute_backdoor_evidence_hash(content)
    exec_id = compute_backdoor_execution_identity_hash(
        project_id=assessment.project_id,
        model_id=assessment.model_id,
        model_fingerprint=m_fingerprint,
        sample_set_hash=assessment.sample_set_hash,
        candidate_hash=candidate_summary.candidate_hash,
    )

    return BackdoorEvidence(
        evidence_id=ev_id,
        execution_id=exec_id,
        content=content,
        state=BackdoorEvidenceLifecycleState.DRAFT,
        created_at=ts_str,
        sealed_at=None,
    )


def seal_backdoor_evidence(
    evidence: BackdoorEvidence,
    sealed_at: Optional[datetime] = None,
) -> BackdoorEvidence:
    """Transition BackdoorEvidence from DRAFT to SEALED state."""
    if evidence.state == BackdoorEvidenceLifecycleState.SEALED:
        return evidence

    now_dt = sealed_at or datetime.now(timezone.utc)
    ts_str = format_canonical_datetime(now_dt)

    return BackdoorEvidence(
        evidence_id=evidence.evidence_id,
        execution_id=evidence.execution_id,
        content=evidence.content,
        state=BackdoorEvidenceLifecycleState.SEALED,
        created_at=evidence.created_at,
        sealed_at=ts_str,
    )


def to_phase5_evidence_payload(evidence: BackdoorEvidence) -> EvidencePayload:
    """Convert BackdoorEvidence into Phase 5.9 standard EvidencePayload."""
    measurements = {
        "tar": evidence.content.tar,
        "tsr": evidence.content.tsr,
        "control_baseline_tsr": evidence.content.control_baseline_tsr,
        "delta_separation": evidence.content.delta_separation,
        "p_value": evidence.content.p_value,
        "adjusted_p_value": evidence.content.adjusted_p_value,
        "is_significant_after_fdr": evidence.content.is_significant_after_fdr,
        "budget_inferences_total": evidence.content.budget_inferences_total,
    }
    return EvidencePayload(
        title=f"Backdoor Trigger Evidence: Candidate {evidence.content.candidate_hash[:8]} [{evidence.content.taxonomy_classification}]",
        description=f"Backdoor trigger candidate analysis for candidate '{evidence.content.candidate_hash}' on model '{evidence.content.model_id}'.",
        evidence_layer=evidence.content.evidence_layer,
        evidence_type=evidence.content.evidence_type.value,
        confidence=1.0 if evidence.content.evidence_layer == EvidenceLayer.PROOF else 0.95,
        target_asset_type="model",
        target_asset_id=evidence.content.model_id,
        target_asset_hash=evidence.content.model_fingerprint or "NONE",
        evidence_hash=evidence.evidence_id,
        detector_id="backdoor_statistical_analysis_engine",
        detector_version=evidence.content.analysis_version,
        detector_config_hash=evidence.execution_id,
        model_fingerprint=evidence.content.model_fingerprint,
        measurements=measurements,
        data_json=evidence.content.model_dump(mode="json"),
    )


class BackdoorProvenanceBindingService:
    """Core adapter service for binding backdoor analytical results into cryptographic provenance."""

    def __init__(
        self,
        db: Session,
        key_manager: Optional[KeyManager] = None,
        audit_service: Optional[AuditService] = None,
    ) -> None:
        self.db = db
        self.key_manager = key_manager
        self.audit_service = audit_service or AuditService(db)
        self.provenance_service = ProvenanceService(db=db, key_manager=key_manager, audit_service=self.audit_service)
        self.binder = EvidenceFindingBinder(db=db)
        self.provenance_adapter = ProvenanceBindingAdapter(
            db=db,
            key_manager=key_manager,
            audit_service=self.audit_service,
            provenance_service=self.provenance_service,
        )

    def bind_statistical_assessment(
        self,
        assessment: StatisticalAnalysisAssessment,
        *,
        model_fingerprint: Optional[str] = None,
        key_alias: Optional[str] = None,
        signer_passphrase: Optional[str] = None,
        key_handle: Optional[Any] = None,
        expected_project_id: Optional[str] = None,
        actor: str = "AIVARA_BACKDOOR_ANALYSIS_ENGINE",
    ) -> List[ProvenanceRecordRead]:
        """Bind and seal complete backdoor assessment into Phase 4 cryptographic provenance ledger.
        
        Args:
            assessment: Validated StatisticalAnalysisAssessment from Phase 9.5.
            model_fingerprint: Evaluated model fingerprint.
            key_alias: Optional signing key alias or key ID.
            signer_passphrase: Optional key passphrase for decryption.
            key_handle: Optional pre-loaded Ed25519 key handle.
            expected_project_id: Optional expected project ID for tenant isolation check.
            actor: Actor identifier for the provenance record.
            
        Returns:
            List of created ProvenanceRecordRead entries.
        """
        if expected_project_id is not None:
            validate_project_isolation(expected_project_id, assessment.project_id, entity_name="StatisticalAnalysisAssessment")

        project = self.db.query(ProjectModel).filter(ProjectModel.id == assessment.project_id).first()
        if not project:
            raise CrossProjectContaminationError(f"Project '{assessment.project_id}' not found in database.")

        m_fingerprint = model_fingerprint or assessment.model_id
        provenance_records: List[ProvenanceRecordRead] = []

        # Find spatial summaries indexed by candidate_hash
        spatial_map: Dict[str, SpatialLocalizationSummary] = {
            s.candidate_hash: s for s in assessment.spatial_localization_summaries
        }

        for cand in assessment.candidate_summaries:
            sp_sum = spatial_map.get(cand.candidate_hash)
            draft_ev = create_backdoor_evidence(
                assessment=assessment,
                candidate_summary=cand,
                model_fingerprint=m_fingerprint,
                spatial_summary=sp_sum,
            )
            sealed_ev = seal_backdoor_evidence(draft_ev)
            ev_payload = to_phase5_evidence_payload(sealed_ev)

            # Map taxonomy to diagnostic finding severity / disposition
            disposition = Disposition.ACCEPT
            severity = Severity.INFO
            if cand.taxonomy_classification.value in ["TARGETED_EFFECT_DETECTED", "STRONG_TRIGGER_CONSISTENCY"]:
                disposition = Disposition.REVIEW
                severity = Severity.HIGH
            elif cand.taxonomy_classification.value == "TRIGGER_CANDIDATE_OBSERVED":
                disposition = Disposition.REVIEW
                severity = Severity.MEDIUM

            tsr_ctrl_str = f"{cand.control_baseline_tsr:.4f}" if cand.control_baseline_tsr is not None else "N/A"
            tsr_str = f"{cand.tsr:.4f}" if cand.tsr is not None else "N/A"
            p_val_str = f"{cand.adjusted_p_value:.4e}" if cand.adjusted_p_value is not None else "N/A"

            title = f"Backdoor Analysis: {cand.taxonomy_classification.value} [{cand.candidate_hash[:8]}]"
            desc = (
                f"Statistical backdoor candidate evaluation for target class {cand.target_class}. "
                f"TSR={tsr_str}, Control={tsr_ctrl_str}, p_val={p_val_str}."
            )

            finding_payload = FindingSynthesisPayload(
                project_id=assessment.project_id,
                audit_run_id=assessment.statistical_analysis_id,
                engine_id="backdoor_statistical_analysis_engine",
                engine_version=sealed_ev.content.analysis_version,
                evidence_layer=sealed_ev.content.evidence_layer,
                finding_type="BACKDOOR_TRIGGER_ANALYSIS",
                title=title,
                description=desc,
                severity=severity,
                confidence=1.0 if sealed_ev.content.evidence_layer == EvidenceLayer.PROOF else 0.95,
                affected_asset_type="model",
                affected_asset_id=assessment.model_id,
                disposition=disposition,
                primary_evidence_items=[ev_payload],
                metadata_json={
                    "execution_identity_hash": sealed_ev.execution_id,
                    "evidence_id": sealed_ev.evidence_id,
                    "candidate_hash": cand.candidate_hash,
                    "target_class": cand.target_class,
                    "tar": cand.tar,
                    "tsr": cand.tsr,
                    "control_baseline_tsr": cand.control_baseline_tsr,
                    "delta_separation": cand.delta_separation,
                    "raw_p_value": cand.raw_p_value,
                    "adjusted_p_value": cand.adjusted_p_value,
                    "taxonomy_classification": cand.taxonomy_classification.value,
                    "is_significant_after_fdr": cand.is_significant_after_fdr,
                    "statistical_analysis_id": assessment.statistical_analysis_id,
                    "primary_evidence_hashes": [sealed_ev.evidence_id],
                },
            )

            finding = self.binder.synthesize_finding(finding_payload)

            prov_read = self.provenance_adapter.seal_scan_findings(
                project_id=assessment.project_id,
                dataset_version_id=assessment.model_id,
                dataset_fingerprint=sealed_ev.content.sample_set_hash,
                execution_identity_hash=sealed_ev.execution_id,
                audit_run_id=assessment.statistical_analysis_id,
                findings=[finding],
                signer_key_id=key_alias,
                signer_passphrase=signer_passphrase,
                key_handle=key_handle,
                actor=actor,
                metadata={
                    "model_id": assessment.model_id,
                    "model_fingerprint": m_fingerprint,
                    "candidate_hash": cand.candidate_hash,
                    "taxonomy_classification": cand.taxonomy_classification.value,
                    "statistical_analysis_id": assessment.statistical_analysis_id,
                    "record_classification": "BACKDOOR_ASSURANCE_SEAL",
                },
            )
            provenance_records.append(prov_read)

        return provenance_records
