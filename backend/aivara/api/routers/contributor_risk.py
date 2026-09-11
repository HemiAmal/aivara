"""REST API router for Contributor Risk Engine (Phase 6.3).

Exposes:
  - GET  /projects/{project_id}/contributors/risk-profiles
  - GET  /projects/{project_id}/contributors/{contributor_id}/risk-profile
  - POST /projects/{project_id}/contributors/risk-assessments
  - GET  /projects/{project_id}/contributors/{contributor_id}/baselines
  - GET  /projects/{project_id}/contributors/{contributor_id}/evidence-graph
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from aivara.api.envelope import ApiResponse
from aivara.api.schemas.contributor_risk import (
    BaselineInfoRead,
    ContributorEvidenceGraphRead,
    ContributorRiskAssessmentRequest,
    ContributorRiskProfileRead,
    DetectionDimensionRead,
    DetectionProfileRead,
    EvidenceFamilyRead,
    ProofDimensionRead,
    ProofProfileRead,
    RiskIndicatorRead,
)
from aivara.contributor_risk.schemas import ContributorRiskProfile
from aivara.contributor_risk.service import ContributorRiskService
from aivara.crypto.keys import KeyManager
from aivara.database.connection import get_db

router = APIRouter(prefix="/projects/{project_id}/contributors", tags=["contributor-risk"])


def _to_profile_read(profile: ContributorRiskProfile) -> ContributorRiskProfileRead:
    """Convert domain profile to public API response schema."""
    det = profile.detection_profile
    proof = profile.proof_profile

    det_read = DetectionProfileRead(
        label_reliability=DetectionDimensionRead(
            dimension_id=det.label_reliability.dimension_id.value,
            status=det.label_reliability.status.value,
            observed_rate=det.label_reliability.observed_rate,
            shrunk_rate=det.label_reliability.shrunk_rate,
            baseline=BaselineInfoRead(**det.label_reliability.baseline.model_dump()) if det.label_reliability.baseline else None,
            differential=det.label_reliability.differential,
            standard_error=det.label_reliability.standard_error,
            confidence=det.label_reliability.confidence,
            support_state=det.label_reliability.support_state.value,
            primary_evidence_ids=list(det.label_reliability.primary_evidence_ids),
            limitations=list(det.label_reliability.limitations),
            details={
                "anomalous_sample_exposure": det.label_reliability.anomalous_sample_exposure,
                "evaluated_sample_exposure": det.label_reliability.evaluated_sample_exposure,
            },
        ),
        transition_asymmetry=DetectionDimensionRead(
            dimension_id=det.transition_asymmetry.dimension_id.value,
            status=det.transition_asymmetry.status.value,
            observed_rate=det.transition_asymmetry.observed_rate,
            shrunk_rate=det.transition_asymmetry.shrunk_rate,
            differential=det.transition_asymmetry.differential,
            confidence=det.transition_asymmetry.confidence,
            support_state=det.transition_asymmetry.support_state.value,
            primary_evidence_ids=list(det.transition_asymmetry.primary_evidence_ids),
            limitations=list(det.transition_asymmetry.limitations),
            details={
                "targeted_flip_score": det.transition_asymmetry.targeted_flip_score,
                "noise_concentration_index": det.transition_asymmetry.noise_concentration_index,
                "directional_class_pairs": det.transition_asymmetry.directional_class_pairs,
            },
        ),
        quality_divergence=DetectionDimensionRead(
            dimension_id=det.quality_divergence.dimension_id.value,
            status=det.quality_divergence.status.value,
            observed_rate=det.quality_divergence.observed_rate,
            shrunk_rate=det.quality_divergence.shrunk_rate,
            baseline=BaselineInfoRead(**det.quality_divergence.baseline.model_dump()) if det.quality_divergence.baseline else None,
            differential=det.quality_divergence.differential,
            standard_error=det.quality_divergence.standard_error,
            confidence=det.quality_divergence.confidence,
            support_state=det.quality_divergence.support_state.value,
            primary_evidence_ids=list(det.quality_divergence.primary_evidence_ids),
            limitations=list(det.quality_divergence.limitations),
            details={
                "metric_differentials": det.quality_divergence.metric_differentials,
                "underexposure_differential": det.quality_divergence.underexposure_differential,
                "blur_differential": det.quality_divergence.blur_differential,
            },
        ),
        distribution_shift=DetectionDimensionRead(
            dimension_id=det.distribution_shift.dimension_id.value,
            status=det.distribution_shift.status.value,
            observed_rate=det.distribution_shift.observed_rate,
            shrunk_rate=det.distribution_shift.shrunk_rate,
            baseline=BaselineInfoRead(**det.distribution_shift.baseline.model_dump()) if det.distribution_shift.baseline else None,
            differential=det.distribution_shift.differential,
            standard_error=det.distribution_shift.standard_error,
            confidence=det.distribution_shift.confidence,
            support_state=det.distribution_shift.support_state.value,
            primary_evidence_ids=list(det.distribution_shift.primary_evidence_ids),
            limitations=list(det.distribution_shift.limitations),
            details={
                "mean_feature_distance": det.distribution_shift.mean_feature_distance,
                "reference_dataset_id": det.distribution_shift.reference_dataset_id,
            },
        ),
        effective_exposure=det.effective_exposure,
    )

    proof_read = ProofProfileRead(
        provenance_integrity=ProofDimensionRead(
            dimension_id=proof.provenance_integrity.dimension_id.value,
            evidence_layer=proof.provenance_integrity.evidence_layer,
            verification_status=proof.provenance_integrity.verification_status,
            confidence=proof.provenance_integrity.confidence,
            signer_key_id=proof.provenance_integrity.signer_key_id,
            signature_present=proof.provenance_integrity.signature_present,
            chain_valid=proof.provenance_integrity.chain_valid,
            nonce_valid=proof.provenance_integrity.nonce_valid,
            tamper_detected=proof.provenance_integrity.tamper_detected,
            primary_evidence_ids=list(proof.provenance_integrity.primary_evidence_ids),
            limitations=list(proof.provenance_integrity.limitations),
        )
    )

    families_read = [
        EvidenceFamilyRead(
            family_id=f.family_id.value,
            family_name=f.family_name,
            evidence_layer=f.evidence_layer,
            constituent_dimensions=[d.value for d in f.constituent_dimensions],
            dominant_differential=f.dominant_differential,
            dominant_dimension_id=f.dominant_dimension_id.value if f.dominant_dimension_id else None,
            evidence_count=f.evidence_count,
            is_proof_layer=f.is_proof_layer,
        )
        for f in profile.evidence_families
    ]

    indicators_read = [
        RiskIndicatorRead(
            indicator_id=ind.indicator_id,
            dimension_id=ind.dimension_id.value,
            severity=ind.severity,
            confidence=ind.confidence,
            summary=ind.summary,
            limitations=list(ind.limitations),
        )
        for ind in profile.risk_indicators
    ]

    return ContributorRiskProfileRead(
        contributor_id=profile.contributor_id,
        project_id=profile.project_id,
        dataset_version_id=profile.dataset_version_id,
        effective_sample_count=profile.effective_sample_count,
        support_state=profile.support_state.value,
        profile_status=profile.profile_status.value,
        detection_profile=det_read,
        proof_profile=proof_read,
        evidence_families=families_read,
        risk_indicators=indicators_read,
        created_at=profile.created_at.isoformat(),
    )


@router.get(
    "/risk-profiles",
    response_model=ApiResponse[List[ContributorRiskProfileRead]],
    status_code=status.HTTP_200_OK,
    summary="List all Contributor Risk Profiles for a project",
)
async def list_contributor_risk_profiles(
    project_id: str,
    dataset_version_id: Optional[str] = Query(None, description="Target dataset version UUID"),
    db: Session = Depends(get_db),
):
    """Retrieve multi-dimensional Contributor Risk Profiles for all project contributors."""
    service = ContributorRiskService(db=db)
    profiles = service.list_contributor_risk_profiles(
        project_id=project_id,
        dataset_version_id=dataset_version_id,
    )
    return ApiResponse(data=[_to_profile_read(p) for p in profiles])


@router.get(
    "/{contributor_id}/risk-profile",
    response_model=ApiResponse[ContributorRiskProfileRead],
    status_code=status.HTTP_200_OK,
    summary="Get Contributor Risk Profile by contributor ID",
)
async def get_contributor_risk_profile(
    project_id: str,
    contributor_id: str,
    dataset_version_id: Optional[str] = Query(None, description="Target dataset version UUID"),
    db: Session = Depends(get_db),
):
    """Retrieve detailed multi-dimensional risk profile for a specific contributor."""
    service = ContributorRiskService(db=db)
    profile = service.get_contributor_risk_profile(
        project_id=project_id,
        contributor_id=contributor_id,
        dataset_version_id=dataset_version_id,
    )
    return ApiResponse(data=_to_profile_read(profile))


@router.post(
    "/risk-assessments",
    response_model=ApiResponse[ContributorRiskProfileRead],
    status_code=status.HTTP_201_CREATED,
    summary="Trigger and persist on-demand Contributor Risk assessment",
)
async def create_contributor_risk_assessment(
    project_id: str,
    payload: ContributorRiskAssessmentRequest,
    db: Session = Depends(get_db),
):
    """Execute Contributor Risk Engine and persist assessment with optional cryptographic sealing."""
    service = ContributorRiskService(db=db)
    profile = service.generate_contributor_risk_profile(
        project_id=project_id,
        contributor_id=payload.contributor_id,
        dataset_version_id=payload.dataset_version_id,
        seal_provenance=payload.seal_provenance,
        signer_key_id=payload.signer_key_id,
        signer_passphrase=payload.signer_passphrase,
    )
    return ApiResponse(data=_to_profile_read(profile))


@router.get(
    "/{contributor_id}/baselines",
    response_model=ApiResponse[Dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="Get contextual reference baselines for contributor",
)
async def get_contributor_baselines(
    project_id: str,
    contributor_id: str,
    dataset_version_id: Optional[str] = Query(None, description="Target dataset version UUID"),
    db: Session = Depends(get_db),
):
    """Retrieve contextual Leave-One-Out and class-conditional baselines with population descriptions."""
    service = ContributorRiskService(db=db)
    baselines = service.get_contributor_baselines(
        project_id=project_id,
        contributor_id=contributor_id,
        dataset_version_id=dataset_version_id,
    )
    return ApiResponse(data=baselines)


@router.get(
    "/{contributor_id}/evidence-graph",
    response_model=ApiResponse[ContributorEvidenceGraphRead],
    status_code=status.HTTP_200_OK,
    summary="Get backward-traceable evidence graph for contributor",
)
async def get_contributor_evidence_graph(
    project_id: str,
    contributor_id: str,
    dataset_version_id: Optional[str] = Query(None, description="Target dataset version UUID"),
    db: Session = Depends(get_db),
):
    """Retrieve backward-traceable graph linking contributor to samples, evidence, and dimensions."""
    service = ContributorRiskService(db=db)
    graph_data = service.get_contributor_evidence_graph(
        project_id=project_id,
        contributor_id=contributor_id,
        dataset_version_id=dataset_version_id,
    )
    return ApiResponse(data=ContributorEvidenceGraphRead(**graph_data))
