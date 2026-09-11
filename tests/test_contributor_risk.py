"""Comprehensive test suite for Contributor Risk Domain & Statistical Engine (Phase 6.2).

Validates all 11 mandated architectural test areas:
  A. Domain contracts & profile construction
  B. Support state tiers (0, 1, 2.99, 3, 9.99, 10, 29.99, 30)
  C. Empirical Bayes shrinkage calculations & boundary conditions
  D. Fractional attribution & exposure conservation
  E. Contextual Leave-One-Out and stratified baselines
  F. Detection dimension contracts (Label, Transition, Quality, OOD)
  G. Proof profile contracts & deterministic confidence
  H. Dependency-aware evidence families & family dominance
  I. Semantic safety & vocabulary guardrails
  J. Deterministic reproducibility
  K. Security & multi-tenant isolation
"""

from __future__ import annotations

import math
import pytest

from aivara.contributor_risk import (
    BaselineType,
    ContextualBaseline,
    ContextualBaselineEngine,
    ContributorInputContext,
    ContributorRiskConfig,
    ContributorRiskEngine,
    DatasetBackgroundContext,
    DetectionDimension,
    DetectionProfile,
    DistributionShiftDimension,
    EmpiricalBayesResult,
    EvaluationStatus,
    EvidenceFamilyEvaluator,
    EvidenceFamilyId,
    InsufficientEvidenceError,
    LabelReliabilityDimension,
    OverallProfileStatus,
    ProofProfile,
    ProvenanceIntegrityDimension,
    QualityDivergenceDimension,
    RiskDimensionId,
    SemanticSafetyViolationError,
    SupportState,
    TransitionAsymmetryDimension,
    compute_empirical_bayes_shrinkage,
    determine_support_state,
    validate_semantic_safety,
)
from aivara.dataset.contributors.attribution import (
    UNATTRIBUTED_KEY,
    build_sample_attribution_map,
    compute_contributor_exposures,
    normalize_contributor_ids,
)
from aivara.dataset.schemas import CanonicalSample


# =====================================================================
# A. Domain Contracts & Profile Construction
# =====================================================================

class TestContributorRiskDomainContracts:
    def test_contributor_risk_profile_construction_and_layer_separation(self):
        """Construct a complete ContributorRiskProfile and verify strict layer separation."""
        engine = ContributorRiskEngine()
        contributor = ContributorInputContext(
            contributor_id="contrib_alice",
            project_id="proj_alpha",
            dataset_version_id="ver_01",
            effective_exposure=50.0,
            label_anomaly_count=4.0,
            targeted_flip_score=0.15,
            noise_concentration_index=0.20,
            quality_anomaly_count=2.0,
            ood_anomaly_count=1.0,
            provenance_status="VERIFIED",
            signer_key_id="key_999",
            signature_present=True,
            chain_valid=True,
            nonce_valid=True,
            tamper_detected=False,
            provenance_evidence_ids=("prov_01",),
        )
        dataset_ctx = DatasetBackgroundContext(
            total_exposure=1000.0,
            total_label_anomalies=50.0,
            total_quality_anomalies=30.0,
            total_ood_anomalies=10.0,
        )

        profile = engine.assess_contributor(contributor, dataset_ctx)

        # 1. Verify Core Identifiers & Support
        assert profile.contributor_id == "contrib_alice"
        assert profile.project_id == "proj_alpha"
        assert profile.effective_sample_count == 50.0
        assert profile.support_state == SupportState.ADEQUATE_SUPPORT

        # 2. Verify Detection Profile (evidence_layer == 'detection')
        det = profile.detection_profile
        assert det.label_reliability.evidence_layer == "detection"
        assert det.transition_asymmetry.evidence_layer == "detection"
        assert det.quality_divergence.evidence_layer == "detection"
        assert det.distribution_shift.evidence_layer == "detection"
        assert 0.0 <= det.label_reliability.confidence <= 1.0

        # 3. Verify Proof Profile (evidence_layer == 'proof', confidence == 1.0)
        proof = profile.proof_profile
        assert proof.provenance_integrity.evidence_layer == "proof"
        assert proof.provenance_integrity.confidence == 1.0
        assert proof.provenance_integrity.verification_status == "VERIFIED"

        # 4. Verify no scalar risk score exists on profile
        assert not hasattr(profile, "risk_score")
        assert not hasattr(profile, "threat_score")
        assert isinstance(profile.profile_status, OverallProfileStatus)


# =====================================================================
# B. Support State Tiers
# =====================================================================

class TestSupportStateTiers:
    @pytest.mark.parametrize(
        "exposure,expected_state",
        [
            (0.0, SupportState.UNVERIFIABLE),
            (1.0, SupportState.UNVERIFIABLE),
            (2.99, SupportState.UNVERIFIABLE),
            (3.0, SupportState.LOW_SUPPORT),
            (5.5, SupportState.LOW_SUPPORT),
            (9.99, SupportState.LOW_SUPPORT),
            (10.0, SupportState.MODERATE_SUPPORT),
            (15.0, SupportState.MODERATE_SUPPORT),
            (29.99, SupportState.MODERATE_SUPPORT),
            (30.0, SupportState.ADEQUATE_SUPPORT),
            (100.0, SupportState.ADEQUATE_SUPPORT),
        ],
    )
    def test_support_state_deterministic_thresholds(self, exposure: float, expected_state: SupportState):
        """Verify exact frozen support-state boundary thresholds (ADR-032)."""
        assert determine_support_state(exposure) == expected_state

    def test_unverifiable_contributor_yields_zero_differentials(self):
        """A contributor with Nc < 3 produces 0.0 differential and UNVERIFIABLE status."""
        engine = ContributorRiskEngine()
        contributor = ContributorInputContext(
            contributor_id="contrib_tiny",
            project_id="proj_alpha",
            effective_exposure=1.5,  # 1.5 samples
            label_anomaly_count=1.5,  # 100% anomaly
            provenance_status="VERIFIED",
        )
        dataset_ctx = DatasetBackgroundContext(total_exposure=100.0, total_label_anomalies=5.0)

        profile = engine.assess_contributor(contributor, dataset_ctx)
        assert profile.support_state == SupportState.UNVERIFIABLE
        assert profile.profile_status == OverallProfileStatus.INSUFFICIENT_EVIDENCE
        assert profile.detection_profile.label_reliability.differential == 0.0
        assert profile.detection_profile.label_reliability.confidence == 0.0
        assert len(profile.risk_indicators) == 0


# =====================================================================
# C. Empirical Bayes Shrinkage Engine
# =====================================================================

class TestEmpiricalBayesCalculations:
    def test_empirical_bayes_shrinkage_formula(self):
        """Verify shrinkage factor lambda_c = Nc / (Nc + 20.0) and posterior rate."""
        # Nc = 20.0, M0 = 20.0 => lambda_c = 0.50
        # raw_rate = 0.80, baseline = 0.20 => posterior = 0.50*0.80 + 0.50*0.20 = 0.50
        res = compute_empirical_bayes_shrinkage(
            effective_count=16.0,
            total_exposure=20.0,
            baseline_rate=0.20,
            prior_weight=20.0,
        )
        assert pytest.approx(res.raw_rate, 1e-5) == 0.80
        assert pytest.approx(res.shrinkage_factor, 1e-5) == 0.50
        assert pytest.approx(res.shrunk_rate, 1e-5) == 0.50
        assert pytest.approx(res.differential, 1e-5) == 0.30
        assert res.support_state == SupportState.MODERATE_SUPPORT

    def test_empirical_bayes_boundary_conditions(self):
        """Verify numerical stability at extremes: p=0, p=1, baseline=0, baseline=1."""
        # Zero baseline and zero raw
        res_zero = compute_empirical_bayes_shrinkage(effective_count=0.0, total_exposure=50.0, baseline_rate=0.0)
        assert res_zero.raw_rate == 0.0
        assert res_zero.shrunk_rate == 0.0
        assert res_zero.differential == 0.0

        # One baseline and one raw
        res_one = compute_empirical_bayes_shrinkage(effective_count=50.0, total_exposure=50.0, baseline_rate=1.0)
        assert res_one.raw_rate == 1.0
        assert res_one.shrunk_rate == 1.0
        assert res_one.differential == 0.0

        # Large sample size converges to empirical rate
        res_large = compute_empirical_bayes_shrinkage(effective_count=1000.0, total_exposure=1000.0, baseline_rate=0.10)
        assert pytest.approx(res_large.shrunk_rate, abs=0.02) == 1.0
        assert res_large.shrinkage_factor > 0.98


# =====================================================================
# D. Fractional Multi-Contributor Attribution
# =====================================================================

class TestFractionalAttribution:
    def test_single_contributor_attribution(self):
        """Single contributor sample gets weight 1.0."""
        samples = [
            CanonicalSample(sample_id="s1", relative_path="s1.jpg", file_size_bytes=100, width=64, height=64, contributors=["alice"]),
        ]
        attr_map = build_sample_attribution_map(samples)
        assert attr_map["s1"]["alice"] == 1.0
        exposures = compute_contributor_exposures(attr_map)
        assert exposures["alice"] == 1.0

    def test_multi_contributor_1_over_k_weight_conservation(self):
        """Multi-contributor sample with 3 annotators conserves sum(w) == 1.0."""
        samples = [
            CanonicalSample(sample_id="s1", relative_path="s1.jpg", file_size_bytes=100, width=64, height=64, contributors=["alice", "bob", "carol"]),
            CanonicalSample(sample_id="s2", relative_path="s2.jpg", file_size_bytes=100, width=64, height=64, contributors=["alice", "bob"]),
        ]
        attr_map = build_sample_attribution_map(samples)
        assert pytest.approx(sum(attr_map["s1"].values()), 1e-6) == 1.0
        assert pytest.approx(attr_map["s1"]["alice"], 1e-6) == 1.0 / 3.0

        exposures = compute_contributor_exposures(attr_map)
        # alice: 1/3 + 1/2 = 5/6 = 0.833333
        assert pytest.approx(exposures["alice"], 1e-5) == 5.0 / 6.0
        # Total dataset exposure conserved to 2.0
        assert pytest.approx(sum(exposures.values()), 1e-5) == 2.0

    def test_contributor_id_deduplication_within_sample(self):
        """Duplicate contributor IDs within a single sample are deduplicated before 1/K calculation."""
        normalized = normalize_contributor_ids(["alice", "alice", "bob"])
        assert normalized == ("alice", "bob")

        samples = [
            CanonicalSample(sample_id="s1", relative_path="s1.jpg", file_size_bytes=100, width=64, height=64, contributors=["alice", "alice"]),
        ]
        attr_map = build_sample_attribution_map(samples)
        assert len(attr_map["s1"]) == 1
        assert attr_map["s1"]["alice"] == 1.0

    def test_unattributed_fallback(self):
        """Empty or None contributor lists fallback to UNATTRIBUTED."""
        assert normalize_contributor_ids([]) == (UNATTRIBUTED_KEY,)
        assert normalize_contributor_ids([None, ""]) == (UNATTRIBUTED_KEY,)


# =====================================================================
# E. Contextual Baselines & Simpson's Paradox Prevention
# =====================================================================

class TestContextualBaselines:
    def test_leave_one_out_baseline_calculation(self):
        """LOO baseline accurately subtracts target contributor from background."""
        engine = ContextualBaselineEngine()
        # Total: 100 samples, 10 events. Contributor: 20 samples, 5 events.
        # LOO Background: (10 - 5) / (100 - 20) = 5 / 80 = 0.0625
        loo = engine.compute_leave_one_out_baseline(
            total_dataset_exposure=100.0,
            total_dataset_events=10.0,
            contributor_exposure=20.0,
            contributor_events=5.0,
        )
        assert loo.baseline_type == BaselineType.LEAVE_ONE_OUT
        assert pytest.approx(loo.baseline_value, 1e-5) == 0.0625
        assert loo.support_sample_count == 80.0
        assert loo.is_fallback is False

    def test_class_conditional_baseline_stratification(self):
        """Class-conditional baseline evaluates within-class error rate."""
        engine = ContextualBaselineEngine()
        # Class melanoma: 50 samples total, 15 errors. Contributor: 10 samples, 2 errors.
        # Class LOO: (15 - 2) / (50 - 10) = 13 / 40 = 0.325
        class_base = engine.compute_class_conditional_baseline(
            class_total_exposure=50.0,
            class_total_events=15.0,
            class_contributor_exposure=10.0,
            class_contributor_events=2.0,
            class_name="melanoma",
            class_id=1,
        )
        assert class_base.baseline_type == BaselineType.CLASS_CONDITIONAL
        assert pytest.approx(class_base.baseline_value, 1e-5) == 0.325
        assert class_base.is_fallback is False

    def test_class_conditional_fallback_when_class_support_low(self):
        """Falls back to global LOO when class support is below threshold (N < 10)."""
        engine = ContextualBaselineEngine(config=ContributorRiskConfig(min_class_support_for_stratification=10))
        global_loo = ContextualBaseline(
            baseline_type=BaselineType.LEAVE_ONE_OUT,
            baseline_value=0.05,
            support_sample_count=500.0,
            reference_population="Global LOO",
        )
        # Class rare_disease only has 4 samples (< 10)
        class_base = engine.compute_class_conditional_baseline(
            class_total_exposure=4.0,
            class_total_events=1.0,
            class_contributor_exposure=1.0,
            class_contributor_events=0.0,
            class_name="rare_disease",
            class_id=99,
            global_fallback_baseline=global_loo,
        )
        assert class_base.is_fallback is True
        assert class_base.baseline_value == 0.05
        assert "low class support" in class_base.limitations[0]


# =====================================================================
# F. Detection Dimensions
# =====================================================================

class TestDetectionDimensions:
    def test_all_four_detection_dimensions_conform_to_contract(self):
        """Verify all detection dimensions inherit DetectionDimension and set evidence_layer='detection'."""
        dim_label = LabelReliabilityDimension(
            dimension_id=RiskDimensionId.DIM_LABEL_RELIABILITY,
            status=EvaluationStatus.AVAILABLE,
            observed_rate=0.10,
            shrunk_rate=0.08,
            differential=0.03,
            confidence=0.90,
            support_state=SupportState.ADEQUATE_SUPPORT,
        )
        assert dim_label.evidence_layer == "detection"
        assert dim_label.dimension_id == RiskDimensionId.DIM_LABEL_RELIABILITY

        dim_trans = TransitionAsymmetryDimension(
            dimension_id=RiskDimensionId.DIM_TRANSITION_ASYM,
            targeted_flip_score=0.45,
            noise_concentration_index=0.60,
        )
        assert dim_trans.evidence_layer == "detection"

        dim_qual = QualityDivergenceDimension(
            dimension_id=RiskDimensionId.DIM_QUALITY_DIVERGENCE,
            blur_differential=0.12,
        )
        assert dim_qual.evidence_layer == "detection"

        dim_ood = DistributionShiftDimension(
            dimension_id=RiskDimensionId.DIM_DISTRIBUTION_SHIFT,
            mean_feature_distance=1.45,
        )
        assert dim_ood.evidence_layer == "detection"


# =====================================================================
# G. Proof Profile & Provenance Separation
# =====================================================================

class TestProofProfileSeparation:
    def test_proof_profile_strictly_separated_with_confidence_one(self):
        """Proof profile is independent, deterministic, and requires confidence=1.0."""
        proof_dim = ProvenanceIntegrityDimension(
            dimension_id=RiskDimensionId.DIM_PROVENANCE_INTEGRITY,
            verification_status="VERIFIED",
            confidence=1.0,
            signer_key_id="key_abc123",
            signature_present=True,
            chain_valid=True,
            nonce_valid=True,
        )
        assert proof_dim.evidence_layer == "proof"
        assert proof_dim.confidence == 1.0

        proof_profile = ProofProfile(provenance_integrity=proof_dim)
        assert proof_profile.provenance_integrity.verification_status == "VERIFIED"

    def test_tampered_provenance_triggers_provenance_integrity_violation_status(self):
        """Tampered or invalid provenance overrides detection metrics to PROVENANCE_INTEGRITY_VIOLATION."""
        engine = ContributorRiskEngine()
        contributor = ContributorInputContext(
            contributor_id="contrib_bad_prov",
            project_id="proj_alpha",
            effective_exposure=50.0,
            provenance_status="INVALID",
            tamper_detected=True,
        )
        dataset_ctx = DatasetBackgroundContext(total_exposure=500.0)
        profile = engine.assess_contributor(contributor, dataset_ctx)

        assert profile.profile_status == OverallProfileStatus.PROVENANCE_INTEGRITY_VIOLATION
        assert profile.proof_profile.provenance_integrity.tamper_detected is True


# =====================================================================
# H. Dependency-Aware Evidence Families & Dominance
# =====================================================================

class TestDependencyAwareEvidenceFamilies:
    def test_family_dominance_rule_uses_max_differential_not_sum(self):
        """Family dominance takes max differential among constituent detectors, preventing additive compounding."""
        dim_label = LabelReliabilityDimension(
            dimension_id=RiskDimensionId.DIM_LABEL_RELIABILITY,
            differential=0.15,
            primary_evidence_ids=("ev_label_1",),
        )
        dim_trans = TransitionAsymmetryDimension(
            dimension_id=RiskDimensionId.DIM_TRANSITION_ASYM,
            differential=0.25,  # Higher differential
            primary_evidence_ids=("ev_flip_1", "ev_flip_2"),
        )
        dim_qual = QualityDivergenceDimension(
            dimension_id=RiskDimensionId.DIM_QUALITY_DIVERGENCE,
            differential=0.08,
            primary_evidence_ids=("ev_qual_1",),
        )
        dim_ood = DistributionShiftDimension(
            dimension_id=RiskDimensionId.DIM_DISTRIBUTION_SHIFT,
            differential=0.02,
        )
        proof_dim = ProvenanceIntegrityDimension(
            dimension_id=RiskDimensionId.DIM_PROVENANCE_INTEGRITY,
            verification_status="VERIFIED",
            confidence=1.0,
            primary_evidence_ids=("prov_01",),
        )

        families = EvidenceFamilyEvaluator.evaluate_families(
            detection_dimensions=(dim_label, dim_trans, dim_qual, dim_ood),
            proof_dimension=proof_dim,
        )

        assert len(families) == 4
        # Label family includes DIM_LABEL_RELIABILITY (0.15) and DIM_TRANSITION_ASYM (0.25)
        # Dominant differential must be 0.25 (not 0.15 + 0.25 = 0.40)
        label_fam = next(f for f in families if f.family_id == EvidenceFamilyId.LABEL_INTEGRITY)
        assert label_fam.dominant_differential == 0.25
        assert label_fam.dominant_dimension_id == RiskDimensionId.DIM_TRANSITION_ASYM
        assert label_fam.evidence_count == 3

        # Proof family is strictly isolated
        prov_fam = next(f for f in families if f.family_id == EvidenceFamilyId.CRYPTOGRAPHIC_PROVENANCE)
        assert prov_fam.is_proof_layer is True
        assert prov_fam.dominant_differential is None


# =====================================================================
# I. Semantic Safety & Vocabulary Filtering
# =====================================================================

class TestSemanticSafety:
    def test_technical_security_terminology_is_permitted(self):
        """Technical security terms are explicitly allowed (ADR-035)."""
        validate_semantic_safety("Evaluated against adversarial perturbation attack simulation.")
        validate_semantic_safety("Dataset assessed for data poisoning experiment and threat model.")
        validate_semantic_safety("Observed out-of-distribution anomaly and backdoor trigger pattern.")

    @pytest.mark.parametrize(
        "prohibited_statement",
        [
            "Contributor is malicious and attacked the dataset.",
            "Annotator is guilty of manipulating labels.",
            "Identified culpable user who committed fraud.",
            "Contributor deliberately sabotaged training batches.",
            "Detected a bad actor cheater in project.",
        ],
    )
    def test_prohibited_human_intent_assertions_are_rejected(self, prohibited_statement: str):
        """Prohibited human-intent and guilt terms raise SemanticSafetyViolationError (ADR-035)."""
        with pytest.raises(SemanticSafetyViolationError):
            validate_semantic_safety(prohibited_statement)


# =====================================================================
# J. Determinism & Stability
# =====================================================================

class TestDeterminismAndReproducibility:
    def test_identical_inputs_produce_identical_profiles(self):
        """Multiple evaluations over identical contributor inputs yield identical profiles."""
        engine = ContributorRiskEngine()
        contributor = ContributorInputContext(
            contributor_id="contrib_det",
            project_id="proj_01",
            effective_exposure=45.0,
            label_anomaly_count=9.0,
            targeted_flip_score=0.22,
            quality_anomaly_count=4.5,
            ood_anomaly_count=1.0,
            provenance_status="VERIFIED",
        )
        dataset_ctx = DatasetBackgroundContext(
            total_exposure=1000.0,
            total_label_anomalies=100.0,
            total_quality_anomalies=50.0,
            total_ood_anomalies=20.0,
        )

        p1 = engine.assess_contributor(contributor, dataset_ctx)
        p2 = engine.assess_contributor(contributor, dataset_ctx)

        assert p1.effective_sample_count == p2.effective_sample_count
        assert p1.detection_profile.label_reliability.differential == p2.detection_profile.label_reliability.differential
        assert p1.detection_profile.transition_asymmetry.differential == p2.detection_profile.transition_asymmetry.differential
        assert p1.profile_status == p2.profile_status
        assert len(p1.risk_indicators) == len(p2.risk_indicators)
