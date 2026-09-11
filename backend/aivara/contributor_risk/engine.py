"""Contributor Risk Domain & Statistical Calculation Engine (Phase 6.2).

Assembles the multi-dimensional Contributor Risk Profile in accordance with:
  - ADR-030 (Multi-dimensional vector over scalar score)
  - ADR-031 (Contextual Leave-One-Out and class-conditional baselines)
  - ADR-032 (Empirical Bayes shrinkage with M_0 = 20.0)
  - ADR-033 (1/K Fractional sample exposure conservation)
  - ADR-034 (Dependency-Aware Evidence Families & proof isolation)
  - ADR-035 (Intent/culpability semantic safety)
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple
from pydantic import BaseModel, ConfigDict, Field

from aivara.contributor_risk.baselines import ContextualBaselineEngine
from aivara.contributor_risk.bayes import compute_empirical_bayes_shrinkage, determine_support_state
from aivara.contributor_risk.exceptions import CrossProjectContaminationError, SemanticSafetyViolationError
from aivara.contributor_risk.families import EvidenceFamilyEvaluator
from aivara.contributor_risk.schemas import (
    BaselineType,
    ContextualBaseline,
    ContributorRiskConfig,
    ContributorRiskIndicator,
    ContributorRiskProfile,
    DependencyAwareEvidenceFamily,
    DetectionDimension,
    DetectionProfile,
    DistributionShiftDimension,
    EvaluationStatus,
    EvidenceFamilyId,
    LabelReliabilityDimension,
    OverallProfileStatus,
    ProofProfile,
    ProvenanceIntegrityDimension,
    QualityDivergenceDimension,
    RiskDimensionId,
    SupportState,
    TransitionAsymmetryDimension,
)


# =====================================================================
# Prohibited Human-Intent Vocabulary Patterns (ADR-035)
# =====================================================================

PROHIBITED_INTENT_PATTERNS = (
    re.compile(r"\bmalicious(ly)?\b", re.IGNORECASE),
    re.compile(r"\bguilty\b", re.IGNORECASE),
    re.compile(r"\bculpab(le|ility)\b", re.IGNORECASE),
    re.compile(r"\bdeliberate(ly)?\b", re.IGNORECASE),
    re.compile(r"\bintentional(ly)?\b", re.IGNORECASE),
    re.compile(r"\bfraud(ulent)?\b", re.IGNORECASE),
    re.compile(r"\bsabot(eur|age|ing)\b", re.IGNORECASE),
    re.compile(r"\bbad\s+actor\b", re.IGNORECASE),
    re.compile(r"\bcheater\b", re.IGNORECASE),
    re.compile(r"\bcollus(ion|ive)\b", re.IGNORECASE),
)


def validate_semantic_safety(text: str) -> None:
    """Validate that text contains zero prohibited human-intent or guilt assertions (ADR-035).

    Technical security terminology (e.g. 'adversarial example', 'poisoning attack',
    'threat model') is fully permitted.
    """
    if not text:
        return

    for pattern in PROHIBITED_INTENT_PATTERNS:
        match = pattern.search(text)
        if match:
            raise SemanticSafetyViolationError(
                f"Prohibited human-intent vocabulary '{match.group(0)}' found in statement: '{text}'"
            )


class ContributorInputContext(BaseModel):
    """Normalized analytical input data for a single contributor."""

    model_config = ConfigDict(frozen=True)

    contributor_id: str
    project_id: str
    dataset_version_id: Optional[str] = None
    effective_exposure: float  # N_c

    # Detection Layer Inputs: Label Anomalies
    label_anomaly_count: float = 0.0
    label_evidence_ids: Tuple[str, ...] = Field(default_factory=tuple)

    # Detection Layer Inputs: Label Flipping
    targeted_flip_score: float = 0.0
    noise_concentration_index: float = 0.0
    directional_class_pairs: List[Dict[str, Any]] = Field(default_factory=list)
    flip_evidence_ids: Tuple[str, ...] = Field(default_factory=tuple)

    # Detection Layer Inputs: Physical Quality
    quality_anomaly_count: float = 0.0
    metric_differentials: Dict[str, float] = Field(default_factory=dict)
    underexposure_diff: float = 0.0
    blur_diff: float = 0.0
    quality_evidence_ids: Tuple[str, ...] = Field(default_factory=tuple)

    # Detection Layer Inputs: Distribution Shift
    ood_anomaly_count: float = 0.0
    mean_feature_distance: Optional[float] = None
    reference_dataset_id: Optional[str] = None
    ood_evidence_ids: Tuple[str, ...] = Field(default_factory=tuple)

    # Proof Layer Inputs: Cryptographic Provenance (STRICTLY SEPARATED)
    provenance_status: str = "UNAVAILABLE"
    signer_key_id: Optional[str] = None
    signature_present: bool = False
    chain_valid: Optional[bool] = None
    nonce_valid: Optional[bool] = None
    tamper_detected: bool = False
    provenance_evidence_ids: Tuple[str, ...] = Field(default_factory=tuple)


class DatasetBackgroundContext(BaseModel):
    """Dataset-wide baseline aggregate counts for Leave-One-Out calculations."""

    model_config = ConfigDict(frozen=True)

    total_exposure: float
    total_label_anomalies: float = 0.0
    total_quality_anomalies: float = 0.0
    total_ood_anomalies: float = 0.0


class ContributorRiskEngine:
    """Core domain and statistical engine for Contributor Risk assessment."""

    def __init__(self, config: Optional[ContributorRiskConfig] = None) -> None:
        self.config: ContributorRiskConfig = config or ContributorRiskConfig()
        self.baseline_engine = ContextualBaselineEngine(config=self.config)

    def assess_contributor(
        self,
        contributor: ContributorInputContext,
        dataset_context: DatasetBackgroundContext,
        class_stratified_baselines: Optional[Dict[str, ContextualBaseline]] = None,
    ) -> ContributorRiskProfile:
        """Construct the complete ContributorRiskProfile for a single contributor."""
        n_c = contributor.effective_exposure
        support_state = determine_support_state(n_c, self.config)

        # -----------------------------------------------------------------
        # 1. Dimension 1: Label Reliability (Detection Layer)
        # -----------------------------------------------------------------
        label_loo = self.baseline_engine.compute_leave_one_out_baseline(
            total_dataset_exposure=dataset_context.total_exposure,
            total_dataset_events=dataset_context.total_label_anomalies,
            contributor_exposure=n_c,
            contributor_events=contributor.label_anomaly_count,
            reference_description="Dataset Label Anomaly Leave-One-Out Population",
        )
        eb_label = compute_empirical_bayes_shrinkage(
            effective_count=contributor.label_anomaly_count,
            total_exposure=n_c,
            baseline_rate=label_loo.baseline_value,
            prior_weight=self.config.prior_sample_weight_m0,
            baseline_support=label_loo.support_sample_count,
            config=self.config,
        )
        label_status = self._map_support_to_status(support_state)
        dim_label = LabelReliabilityDimension(
            dimension_id=RiskDimensionId.DIM_LABEL_RELIABILITY,
            evidence_layer="detection",
            status=label_status,
            observed_rate=eb_label.raw_rate,
            shrunk_rate=eb_label.shrunk_rate,
            baseline=label_loo,
            differential=eb_label.differential,
            standard_error=eb_label.standard_error,
            confidence=eb_label.confidence,
            support_state=support_state,
            anomalous_sample_exposure=contributor.label_anomaly_count,
            evaluated_sample_exposure=n_c,
            primary_evidence_ids=contributor.label_evidence_ids,
        )

        # -----------------------------------------------------------------
        # 2. Dimension 2: Transition Asymmetry (Detection Layer)
        # -----------------------------------------------------------------
        dim_trans = TransitionAsymmetryDimension(
            dimension_id=RiskDimensionId.DIM_TRANSITION_ASYM,
            evidence_layer="detection",
            status=label_status,
            observed_rate=contributor.targeted_flip_score,
            shrunk_rate=contributor.targeted_flip_score if support_state != SupportState.UNVERIFIABLE else 0.0,
            differential=contributor.targeted_flip_score if support_state != SupportState.UNVERIFIABLE else 0.0,
            targeted_flip_score=contributor.targeted_flip_score,
            noise_concentration_index=contributor.noise_concentration_index,
            directional_class_pairs=contributor.directional_class_pairs,
            confidence=0.90 if support_state in (SupportState.MODERATE_SUPPORT, SupportState.ADEQUATE_SUPPORT) else 0.0,
            support_state=support_state,
            primary_evidence_ids=contributor.flip_evidence_ids,
        )

        # -----------------------------------------------------------------
        # 3. Dimension 3: Quality Divergence (Detection Layer)
        # -----------------------------------------------------------------
        qual_loo = self.baseline_engine.compute_leave_one_out_baseline(
            total_dataset_exposure=dataset_context.total_exposure,
            total_dataset_events=dataset_context.total_quality_anomalies,
            contributor_exposure=n_c,
            contributor_events=contributor.quality_anomaly_count,
            reference_description="Dataset Image Quality Leave-One-Out Population",
        )
        eb_qual = compute_empirical_bayes_shrinkage(
            effective_count=contributor.quality_anomaly_count,
            total_exposure=n_c,
            baseline_rate=qual_loo.baseline_value,
            prior_weight=self.config.prior_sample_weight_m0,
            baseline_support=qual_loo.support_sample_count,
            config=self.config,
        )
        dim_qual = QualityDivergenceDimension(
            dimension_id=RiskDimensionId.DIM_QUALITY_DIVERGENCE,
            evidence_layer="detection",
            status=label_status,
            observed_rate=eb_qual.raw_rate,
            shrunk_rate=eb_qual.shrunk_rate,
            baseline=qual_loo,
            differential=eb_qual.differential,
            standard_error=eb_qual.standard_error,
            confidence=eb_qual.confidence,
            support_state=support_state,
            metric_differentials=contributor.metric_differentials,
            underexposure_differential=contributor.underexposure_diff,
            blur_differential=contributor.blur_diff,
            primary_evidence_ids=contributor.quality_evidence_ids,
        )

        # -----------------------------------------------------------------
        # 4. Dimension 4: Distribution Shift (Detection Layer)
        # -----------------------------------------------------------------
        ood_loo = self.baseline_engine.compute_leave_one_out_baseline(
            total_dataset_exposure=dataset_context.total_exposure,
            total_dataset_events=dataset_context.total_ood_anomalies,
            contributor_exposure=n_c,
            contributor_events=contributor.ood_anomaly_count,
            reference_description="Dataset OOD Anomaly Leave-One-Out Population",
        )
        eb_ood = compute_empirical_bayes_shrinkage(
            effective_count=contributor.ood_anomaly_count,
            total_exposure=n_c,
            baseline_rate=ood_loo.baseline_value,
            prior_weight=self.config.prior_sample_weight_m0,
            baseline_support=ood_loo.support_sample_count,
            config=self.config,
        )
        dim_ood = DistributionShiftDimension(
            dimension_id=RiskDimensionId.DIM_DISTRIBUTION_SHIFT,
            evidence_layer="detection",
            status=label_status,
            observed_rate=eb_ood.raw_rate,
            shrunk_rate=eb_ood.shrunk_rate,
            baseline=ood_loo,
            differential=eb_ood.differential,
            standard_error=eb_ood.standard_error,
            confidence=eb_ood.confidence,
            support_state=support_state,
            mean_feature_distance=contributor.mean_feature_distance,
            reference_dataset_id=contributor.reference_dataset_id,
            primary_evidence_ids=contributor.ood_evidence_ids,
        )

        # -----------------------------------------------------------------
        # 5. Dimension 5: Provenance Integrity (Proof Layer - STRICTLY ISOLATED)
        # -----------------------------------------------------------------
        dim_prov = ProvenanceIntegrityDimension(
            dimension_id=RiskDimensionId.DIM_PROVENANCE_INTEGRITY,
            evidence_layer="proof",
            verification_status=contributor.provenance_status,
            confidence=1.0,  # ADR-028 / ADR-034: strictly 1.0 for proof layer
            signer_key_id=contributor.signer_key_id,
            signature_present=contributor.signature_present,
            chain_valid=contributor.chain_valid,
            nonce_valid=contributor.nonce_valid,
            tamper_detected=contributor.tamper_detected,
            primary_evidence_ids=contributor.provenance_evidence_ids,
        )

        # Assemble Profiles
        detection_profile = DetectionProfile(
            label_reliability=dim_label,
            transition_asymmetry=dim_trans,
            quality_divergence=dim_qual,
            distribution_shift=dim_ood,
            effective_exposure=n_c,
        )
        proof_profile = ProofProfile(provenance_integrity=dim_prov)

        # -----------------------------------------------------------------
        # 6. Dependency-Aware Evidence Families (ADR-034)
        # -----------------------------------------------------------------
        evidence_families = EvidenceFamilyEvaluator.evaluate_families(
            detection_dimensions=(dim_label, dim_trans, dim_qual, dim_ood),
            proof_dimension=dim_prov,
        )

        # -----------------------------------------------------------------
        # 7. Risk Indicators & Semantic Safety (ADR-035)
        # -----------------------------------------------------------------
        indicators: List[ContributorRiskIndicator] = []
        if support_state in (SupportState.MODERATE_SUPPORT, SupportState.ADEQUATE_SUPPORT):
            if eb_label.differential >= self.config.elevated_differential_threshold:
                summary = (
                    f"Contributor exhibits an elevated label anomaly differential of "
                    f"+{eb_label.differential * 100:.1f}% above the contextual baseline."
                )
                validate_semantic_safety(summary)
                indicators.append(
                    ContributorRiskIndicator(
                        indicator_id="IND_ELEVATED_LABEL_ANOMALY_CONCENTRATION",
                        dimension_id=RiskDimensionId.DIM_LABEL_RELIABILITY,
                        severity="medium",
                        confidence=eb_label.confidence,
                        summary=summary,
                        limitations=["Based on latent label estimates from model predictions."],
                    )
                )

            if contributor.targeted_flip_score >= self.config.elevated_differential_threshold:
                summary = (
                    f"Contributor-associated label transitions exhibit directional asymmetry "
                    f"with a targeted score of {contributor.targeted_flip_score:.2f}."
                )
                validate_semantic_safety(summary)
                indicators.append(
                    ContributorRiskIndicator(
                        indicator_id="IND_DIRECTIONAL_LABEL_TRANSITION_CONCENTRATION",
                        dimension_id=RiskDimensionId.DIM_TRANSITION_ASYM,
                        severity="medium",
                        confidence=0.90,
                        summary=summary,
                        limitations=["Directional transitions may reflect natural inter-class ambiguity."],
                    )
                )

        # -----------------------------------------------------------------
        # 8. Deterministic Profile Status Interpretation
        # -----------------------------------------------------------------
        profile_status = self._determine_overall_status(
            support_state=support_state,
            provenance_status=contributor.provenance_status,
            tamper_detected=contributor.tamper_detected,
            max_differential=max(
                filter(
                    lambda x: x is not None,
                    [dim_label.differential, dim_qual.differential, dim_ood.differential],
                ),
                default=0.0,
            ),
        )

        return ContributorRiskProfile(
            contributor_id=contributor.contributor_id,
            project_id=contributor.project_id,
            dataset_version_id=contributor.dataset_version_id,
            effective_sample_count=round(n_c, 6),
            support_state=support_state,
            profile_status=profile_status,
            detection_profile=detection_profile,
            proof_profile=proof_profile,
            evidence_families=evidence_families,
            risk_indicators=tuple(indicators),
        )

    def _determine_overall_status(
        self,
        support_state: SupportState,
        provenance_status: str,
        tamper_detected: bool,
        max_differential: float,
    ) -> OverallProfileStatus:
        """Determine deterministic status based on explicit rule ordering (not a numerical score)."""
        if provenance_status == "INVALID" or tamper_detected:
            return OverallProfileStatus.PROVENANCE_INTEGRITY_VIOLATION
        if provenance_status in ("MISSING", "UNVERIFIABLE"):
            return OverallProfileStatus.UNVERIFIED_PROVENANCE
        if support_state == SupportState.UNVERIFIABLE:
            return OverallProfileStatus.INSUFFICIENT_EVIDENCE
        if max_differential >= self.config.elevated_differential_threshold:
            return OverallProfileStatus.ELEVATED_ANOMALY_CONCENTRATION
        if max_differential >= self.config.moderate_differential_threshold:
            return OverallProfileStatus.MODERATE_DEVIATION
        return OverallProfileStatus.BASELINE_CONGRUENT

    @staticmethod
    def _map_support_to_status(support_state: SupportState) -> EvaluationStatus:
        if support_state == SupportState.UNVERIFIABLE:
            return EvaluationStatus.UNVERIFIABLE
        if support_state == SupportState.LOW_SUPPORT:
            return EvaluationStatus.LOW_SUPPORT
        if support_state == SupportState.MODERATE_SUPPORT:
            return EvaluationStatus.MODERATE_SUPPORT
        return EvaluationStatus.ADEQUATE_SUPPORT
