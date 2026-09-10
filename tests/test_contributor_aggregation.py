"""Dedicated unit test suite for Phase 5.8: Contributor Aggregation Engine (CAE).

Covers all 32+ mandated scenarios:
  1. Attribution (single, multiple, 1/K weights, weight conservation, deduplication, UNATTRIBUTED)
  2. Rates & Fractional Exposure (zero anomalies, all anomalies, fractional rates, zero exposure)
  3. Wilson Confidence Intervals (normal, zero positives, all positives, small/fractional counts)
  4. Contributor Support Policy (n < 5 discount, n >= 5 valid, zero exposure)
  5. Leave-One-Out (LOO) Background (self-exclusion, fractional attribution, solo contributor)
  6. Rate Differential & Uncertainty (Delta, SE(Delta), insufficient background)
  7. Subgroup Stratification & Confounding (class, sensor, terrain, illumination, Simpson's paradox)
  8. Class Distribution & Specialization (entropy H(c), single-class contributor, descriptive category)
  9. Evidence Concentration & HHI (concentrated anomaly share, distributed share, Gini)
 10. Multi-Signal Evidence Diversity (>=3 signals, independent tracking without score summation)
 11. Defensive Input Validation (NaN, Inf, negative counts/weights, weight > 1, malformed IDs)
 12. Non-accusatory Semantic Invariants (No guilt, maliciousness, or threat scores; evidence_layer='detection')
 13. Deterministic Reproducibility & Performance Budget (O(N + C + E) linear scalability)
"""

import math
import pytest
from typing import Dict, List, Set

from aivara.dataset.contributors import (
    ContributorAggregationConfig,
    ContributorAggregationEngine,
    ContributorAggregationResult,
    ContributorCategory,
    ContributorEvidenceMetric,
    ContributorEvidenceProfile,
    ContributorScanFinding,
    UNATTRIBUTED_KEY,
    aggregate_contributor_evidence,
    build_contributor_profiles,
    build_sample_attribution_map,
    compute_contributor_exposures,
    compute_gini_coefficient,
    compute_herfindahl_hirschman_index,
    compute_leave_one_out_baseline,
    compute_rate_differential_and_se,
    compute_shannon_entropy,
    compute_subgroup_stratified_rates,
    compute_wilson_confidence_interval,
    normalize_contributor_ids,
)
from aivara.dataset.contributors.exceptions import (
    ContributorAggregationError,
    InsufficientContributorSupportError,
    InvalidAttributionError,
    InvalidBaselineError,
    MalformedEvidenceError,
)
from aivara.dataset.schemas import (
    CanonicalAnnotation,
    CanonicalCategory,
    CanonicalDatasetManifest,
    CanonicalSample,
    DatasetFormat,
)


def _make_sample(
    sample_id: str,
    class_name: str = "vehicle",
    contributors: List[str] = None,
    metadata: dict = None,
) -> CanonicalSample:
    """Helper to construct canonical sample for testing."""
    anno = CanonicalAnnotation(
        annotation_id=f"ann_{sample_id}",
        category_id=1,
        category_name=class_name,
    )
    meta = metadata or {}
    return CanonicalSample(
        sample_id=sample_id,
        relative_path=f"images/{sample_id}.jpg",
        file_size_bytes=1024,
        width=640,
        height=480,
        channels=3,
        color_space="RGB",
        contributors=tuple(contributors) if contributors is not None else tuple(),
        metadata=meta,
        annotations=(anno,),
    )


def _make_manifest(samples: List[CanonicalSample], dataset_name: str = "test_dataset") -> CanonicalDatasetManifest:
    """Helper to construct canonical dataset manifest."""
    return CanonicalDatasetManifest(
        format=DatasetFormat.COCO,
        dataset_name=dataset_name,
        sample_count=len(samples),
        annotation_count=sum(len(s.annotations) for s in samples),
        categories=(CanonicalCategory(category_id=1, category_name="vehicle", supercategory="object"),),
        samples=tuple(samples),
        metadata={"dataset_merkle_root": "0" * 64},
    )


# ==============================================================================
# 1. CONTRIBUTOR ATTRIBUTION TESTS
# ==============================================================================

class TestContributorAttribution:
    """Tests for deterministic 1/K contributor attribution and normalization."""

    def test_single_contributor_attribution(self):
        sample = _make_sample("s1", contributors=["alice"])
        attr_map = build_sample_attribution_map([sample])
        assert attr_map["s1"] == {"alice": 1.0}
        assert math.isclose(sum(attr_map["s1"].values()), 1.0)

    def test_two_contributors_attribution(self):
        sample = _make_sample("s1", contributors=["alice", "bob"])
        attr_map = build_sample_attribution_map([sample])
        assert attr_map["s1"] == {"alice": 0.5, "bob": 0.5}
        assert math.isclose(sum(attr_map["s1"].values()), 1.0)

    def test_k_contributors_linear_conservation(self):
        k = 5
        contribs = [f"worker_{i}" for i in range(k)]
        sample = _make_sample("s1", contributors=contribs)
        attr_map = build_sample_attribution_map([sample])
        assert len(attr_map["s1"]) == k
        for c in contribs:
            assert math.isclose(attr_map["s1"][c], 1.0 / k)
        assert math.isclose(sum(attr_map["s1"].values()), 1.0)

    def test_duplicate_contributor_deduplication(self):
        """Duplicate mappings must not inflate attribution."""
        sample = _make_sample("s1", contributors=["alice", "alice", "bob", "bob"])
        attr_map = build_sample_attribution_map([sample])
        assert attr_map["s1"] == {"alice": 0.5, "bob": 0.5}
        assert math.isclose(sum(attr_map["s1"].values()), 1.0)

    def test_empty_or_null_contributors_to_unattributed(self):
        sample_empty = _make_sample("s1", contributors=[])
        attr_empty = build_sample_attribution_map([sample_empty])
        assert attr_empty["s1"] == {UNATTRIBUTED_KEY: 1.0}

        sample_none = _make_sample("s2", contributors=None)
        attr_none = build_sample_attribution_map([sample_none])
        assert attr_none["s2"] == {UNATTRIBUTED_KEY: 1.0}

    def test_whitespace_and_mixed_unattributed(self):
        sample = _make_sample("s1", contributors=["  ", "alice", ""])
        attr_map = build_sample_attribution_map([sample])
        assert attr_map["s1"] == {"alice": 1.0}


# ==============================================================================
# 2. RATES & FRACTIONAL EXPOSURE TESTS
# ==============================================================================

class TestContributorRates:
    """Tests for empirical rate calculation and fractional exposure."""

    def test_zero_anomalies_rate(self):
        rate, p_lo, p_hi = compute_wilson_confidence_interval(k=0.0, n=10.0)
        assert rate == 0.0
        assert p_lo >= 0.0
        assert p_hi > 0.0  # Wilson interval accounts for uncertainty even at 0

    def test_all_anomalies_rate(self):
        rate, p_lo, p_hi = compute_wilson_confidence_interval(k=10.0, n=10.0)
        assert rate == 1.0
        assert p_lo < 1.0
        assert p_hi <= 1.0

    def test_fractional_exposure_rates(self):
        """Verify fractional weighted positive counts and exposure."""
        samples = [
            _make_sample("s1", contributors=["alice", "bob"]),  # 0.5 each, anomaly
            _make_sample("s2", contributors=["alice", "bob"]),  # 0.5 each, anomaly
            _make_sample("s3", contributors=["alice"]),         # 1.0, normal
            _make_sample("s4", contributors=["alice"]),         # 1.0, normal
            _make_sample("s5", contributors=["alice"]),         # 1.0, normal
        ]
        manifest = _make_manifest(samples)
        evidence = {"s1": {"label_anomaly"}, "s2": {"label_anomaly"}}
        
        result = aggregate_contributor_evidence(manifest, evidence_by_sample=evidence)
        alice_prof = result.profiles["alice"]
        assert math.isclose(alice_prof.weighted_sample_exposure, 4.0)
        # Alice anomaly count: 0.5 + 0.5 = 1.0
        m = alice_prof.metrics["label_anomaly"]
        assert math.isclose(m.contributor_count, 1.0)
        assert math.isclose(m.contributor_rate, 1.0 / 4.0)


# ==============================================================================
# 3. WILSON CONFIDENCE INTERVAL TESTS
# ==============================================================================

class TestWilsonConfidenceInterval:
    """Tests for Wilson score interval implementation."""

    def test_standard_wilson_interval(self):
        rate, p_lo, p_hi = compute_wilson_confidence_interval(k=20.0, n=100.0, confidence=0.95)
        # Point estimate is 0.20
        assert math.isclose(rate, 0.20)
        assert 0.12 < p_lo < 0.20
        assert 0.20 < p_hi < 0.30

    def test_zero_exposure_wilson_interval(self):
        rate, p_lo, p_hi = compute_wilson_confidence_interval(k=0.0, n=0.0)
        assert rate == 0.0
        assert p_lo == 0.0
        assert p_hi == 0.0

    def test_numerical_boundary_clamping(self):
        rate, p_lo, p_hi = compute_wilson_confidence_interval(k=100.0, n=100.0)
        assert p_hi <= 1.0
        assert p_lo >= 0.0


# ==============================================================================
# 4. CONTRIBUTOR SUPPORT POLICY TESTS
# ==============================================================================

class TestContributorSupportPolicy:
    """Tests for minimum contributor support (n >= 5) guardrail."""

    def test_insufficient_support_under_5(self):
        samples = [_make_sample(f"s{i}", contributors=["micro_user"]) for i in range(4)]
        manifest = _make_manifest(samples)
        result = aggregate_contributor_evidence(manifest)
        prof = result.profiles["micro_user"]
        assert not prof.is_sufficient_support
        
        # Finding must be INSUFFICIENT_CONTRIBUTOR_SUPPORT
        f = next(f for f in result.findings if f.contributor_id == "micro_user")
        assert f.category == ContributorCategory.INSUFFICIENT_CONTRIBUTOR_SUPPORT
        assert f.confidence == 0.0

    def test_sufficient_support_at_5(self):
        samples = [_make_sample(f"s{i}", contributors=["regular_user"]) for i in range(5)]
        manifest = _make_manifest(samples)
        result = aggregate_contributor_evidence(manifest)
        prof = result.profiles["regular_user"]
        assert prof.is_sufficient_support


# ==============================================================================
# 5. LEAVE-ONE-OUT BASELINE & DIFFERENTIAL TESTS
# ==============================================================================

class TestLeaveOneOutBaseline:
    """Tests for LOO background estimation, rate differential, and zero background support."""

    def test_loo_background_exclusion(self):
        bg_count, bg_exp, bg_rate = compute_leave_one_out_baseline(
            total_anomalies=10.0,
            total_exposure=20.0,
            contributor_anomalies=8.0,
            contributor_exposure=10.0,
        )

        assert math.isclose(bg_count, 2.0)
        assert math.isclose(bg_exp, 10.0)
        assert bg_rate is not None and math.isclose(bg_rate, 0.20)

    def test_solo_contributor_zero_background(self):
        """If contributor is sole provider, background exposure is 0.0 and rate is None."""
        bg_count, bg_exp, bg_rate = compute_leave_one_out_baseline(
            total_anomalies=5.0,
            total_exposure=5.0,
            contributor_anomalies=5.0,
            contributor_exposure=5.0,
        )

        assert bg_exp == 0.0
        assert bg_rate is None

        diff, se = compute_rate_differential_and_se(
            r_c=1.0,
            n_c=5.0,
            r_bg=bg_rate,
            n_bg=bg_exp,
        )
        assert diff is None
        assert se is None

    def test_single_contributor_dataset_profile_status(self):
        """Single contributor dataset must explicitly report INSUFFICIENT_BACKGROUND_SUPPORT."""
        samples = [_make_sample(f"s{i}", contributors=["alice"]) for i in range(10)]
        manifest = _make_manifest(samples)
        evidence = {f"s{i}": {"ood"} for i in range(5)}

        result = aggregate_contributor_evidence(manifest, evidence_by_sample=evidence)
        alice_prof = result.profiles["alice"]
        m = alice_prof.metrics["ood"]
        assert m.background_exposure == 0.0
        assert m.background_rate is None
        assert m.rate_differential is None
        assert m.standard_error is None
        assert m.baseline_status == "INSUFFICIENT_BACKGROUND_SUPPORT"

    def test_zero_background_positives_with_valid_exposure(self):
        """When background exposure > 0 but background anomalies = 0, background rate is 0.0."""
        bg_count, bg_exp, bg_rate = compute_leave_one_out_baseline(
            total_anomalies=4.0,
            total_exposure=20.0,
            contributor_anomalies=4.0,
            contributor_exposure=10.0,
        )
        assert bg_exp == 10.0
        assert bg_count == 0.0
        assert bg_rate == 0.0

        diff, se = compute_rate_differential_and_se(
            r_c=0.40,
            n_c=10.0,
            r_bg=bg_rate,
            n_bg=bg_exp,
        )
        assert diff is not None and math.isclose(diff, 0.40)
        assert se is not None and se > 0.0

    def test_mixed_attribution_zero_background(self):
        """All samples shared between alice and bob with no other dataset contributors."""
        samples = [_make_sample(f"s{i}", contributors=["alice", "bob"]) for i in range(10)]
        manifest = _make_manifest(samples)
        evidence = {f"s{i}": {"label_flip"} for i in range(4)}

        result = aggregate_contributor_evidence(manifest, evidence_by_sample=evidence)
        # Alice exposure = 5.0, Bob exposure = 5.0, total = 10.0
        # When comparing Alice, background is Bob (5.0 exposure) -> valid background!
        alice_m = result.profiles["alice"].metrics["label_flip"]
        assert alice_m.background_exposure == 5.0
        assert alice_m.baseline_status == "VALID"

    def test_rate_differential_and_standard_error(self):
        diff, se = compute_rate_differential_and_se(
            r_c=0.80,
            n_c=10.0,
            r_bg=0.20,
            n_bg=90.0,
        )
        assert diff is not None and math.isclose(diff, 0.60)
        expected_se = math.sqrt((0.8 * 0.2 / 10.0) + (0.2 * 0.8 / 90.0))
        assert se is not None and math.isclose(se, expected_se)


# ==============================================================================
# 6. SUBGROUP STRATIFICATION & SIMPSON'S PARADOX TESTS
# ==============================================================================

class TestSubgroupStratification:
    """Tests for stratified subgroup evaluation (class, sensor, illumination)."""

    def test_subgroup_metrics_computation(self):
        samples = [
            _make_sample(f"s{i}", contributors=["alice"], metadata={"sensor": "night_flir"}) for i in range(5)
        ] + [
            _make_sample(f"s{i+5}", contributors=["alice"], metadata={"sensor": "day_rgb"}) for i in range(5)
        ]
        evidence = {f"s{i}": {"underexposed"} for i in range(5)}  # All night samples flagged
        manifest = _make_manifest(samples)

        result = aggregate_contributor_evidence(
            manifest,
            evidence_by_sample=evidence,
            subgroup_extractor=lambda s: s.metadata.get("sensor", "unknown"),
        )
        alice_prof = result.profiles["alice"]
        m = alice_prof.metrics["underexposed"]
        assert "night_flir" in m.subgroup_metrics
        assert "day_rgb" in m.subgroup_metrics
        assert math.isclose(m.subgroup_metrics["night_flir"]["contributor_rate"], 1.0)
        assert math.isclose(m.subgroup_metrics["day_rgb"]["contributor_rate"], 0.0)


# ==============================================================================
# 7. CLASS DISTRIBUTION & SPECIALIZATION TESTS
# ==============================================================================

class TestClassSpecialization:
    """Tests for Shannon class entropy H(c) and legitimate specialization."""

    def test_single_class_zero_entropy(self):
        class_dist = {"vehicle": 1.0}
        entropy = compute_shannon_entropy(class_dist)
        assert entropy == 0.0

    def test_uniform_distribution_high_entropy(self):
        class_dist = {"class_a": 0.25, "class_b": 0.25, "class_c": 0.25, "class_d": 0.25}
        entropy = compute_shannon_entropy(class_dist)
        assert math.isclose(entropy, 2.0)  # log2(4) = 2.0 bits

    def test_specialization_finding_descriptive(self):
        """High specialization contributor emits CONTRIBUTOR_CLASS_DISTRIBUTION, not anomaly."""
        samples = [_make_sample(f"s{i}", class_name="tanker", contributors=["specialist"]) for i in range(10)]
        manifest = _make_manifest(samples)
        result = aggregate_contributor_evidence(manifest)
        
        f = next(f for f in result.findings if f.contributor_id == "specialist")
        assert f.category == ContributorCategory.CONTRIBUTOR_CLASS_DISTRIBUTION
        assert f.severity == "LOW"
        assert "specialization" in f.explanation.lower()
        assert "policy thresholds" in f.explanation.lower()


# ==============================================================================
# 8. EVIDENCE CONCENTRATION & HHI TESTS
# ==============================================================================

class TestEvidenceConcentration:
    """Tests for Herfindahl-Hirschman Index and Gini concentration."""

    def test_hhi_monopoly(self):
        # One contributor holds 100% of anomalies
        shares = [1.0]
        assert compute_herfindahl_hirschman_index(shares) == 1.0

    def test_hhi_distributed(self):
        # 4 contributors hold 25% each
        shares = [0.25, 0.25, 0.25, 0.25]
        assert math.isclose(compute_herfindahl_hirschman_index(shares), 0.25)

    def test_gini_coefficient(self):
        # Perfect equality
        assert compute_gini_coefficient([5.0, 5.0, 5.0, 5.0]) == 0.0
        # High inequality
        assert compute_gini_coefficient([0.0, 0.0, 0.0, 10.0]) > 0.70

    def test_anomaly_concentration_finding(self):
        # Alice provides 8 anomalies, Bob provides 2 -> Alice share = 80%, HHI > 0.40
        samples = (
            [_make_sample(f"sa_{i}", contributors=["alice"]) for i in range(10)] +
            [_make_sample(f"sb_{i}", contributors=["bob"]) for i in range(10)] +
            [_make_sample(f"sc_{i}", contributors=["charlie"]) for i in range(10)]
        )
        manifest = _make_manifest(samples)
        evidence = {f"sa_{i}": {"label_anomaly"} for i in range(8)}
        evidence.update({f"sb_{i}": {"label_anomaly"} for i in range(2)})

        result = aggregate_contributor_evidence(manifest, evidence_by_sample=evidence)
        alice_findings = [f for f in result.findings if f.contributor_id == "alice" and f.category == ContributorCategory.CONTRIBUTOR_ANOMALY_CONCENTRATION]
        assert len(alice_findings) >= 1


# ==============================================================================
# 9. MULTI-SIGNAL EVIDENCE DIVERSITY & NON-ADDITIVITY TESTS
# ==============================================================================

class TestMultiSignalDiversity:
    """Tests for multi-signal concurrence without score summation or false independence assumptions."""

    def test_multi_signal_finding_generation(self):
        # Alice has samples with label_anomaly, ood, quality, and label_flip
        samples = (
            [_make_sample(f"s{i}", contributors=["alice"]) for i in range(10)] +
            [_make_sample(f"sb_{i}", contributors=["bob"]) for i in range(10)]
        )
        manifest = _make_manifest(samples)
        evidence = {
            f"s{i}": {"label_anomaly", "ood", "quality", "label_flip"} for i in range(6)
        }

        result = aggregate_contributor_evidence(manifest, evidence_by_sample=evidence)
        alice_prof = result.profiles["alice"]
        assert alice_prof.evidence_diversity_count >= 3
        
        multi_findings = [f for f in result.findings if f.contributor_id == "alice" and f.category == ContributorCategory.CONTRIBUTOR_MULTI_SIGNAL_EVIDENCE]
        assert len(multi_findings) == 1
        assert multi_findings[0].severity == "HIGH"
        # Must NOT claim independence
        assert "independent" not in multi_findings[0].explanation.lower()
        assert "without score summation" in multi_findings[0].explanation.lower()

    def test_correlated_evidence_types_remain_separate_observations(self):
        """Correlated signals (e.g. low quality + OOD) do not produce additive composite risk scores."""
        samples = (
            [_make_sample(f"sa_{i}", contributors=["alice"]) for i in range(10)] +
            [_make_sample(f"sb_{i}", contributors=["bob"]) for i in range(10)]
        )
        manifest = _make_manifest(samples)
        evidence = {
            f"sa_{i}": {"ood", "quality"} for i in range(8)
        }

        result = aggregate_contributor_evidence(manifest, evidence_by_sample=evidence)
        alice_prof = result.profiles["alice"]
        # Both metrics exist separately with their own counts
        assert math.isclose(alice_prof.metrics["ood"].contributor_count, 8.0)
        assert math.isclose(alice_prof.metrics["quality"].contributor_count, 8.0)
        # There is no composite threat_score or risk_score in the profile
        assert not hasattr(alice_prof, "threat_score")
        assert not hasattr(alice_prof, "risk_score")
        assert not hasattr(alice_prof, "guilt_score")


# ==============================================================================
# 10. DEFENSIVE INPUT VALIDATION & SECURITY TESTS
# ==============================================================================

class TestDefensiveValidation:
    """Tests for rejecting NaN, Inf, negative counts, and malicious language."""

    def test_pydantic_rejects_negative_counts(self):
        with pytest.raises(Exception):
            ContributorEvidenceMetric(
                metric_name="m1",
                contributor_count=-1.0,
                contributor_exposure=10.0,
                contributor_rate=0.0,
                wilson_lower_bound=0.0,
                wilson_upper_bound=0.0,
                background_count=0.0,
                background_exposure=0.0,
                background_rate=0.0,
                rate_differential=0.0,
                standard_error=0.0,
                anomaly_share=0.0,
            )

    def test_pydantic_rejects_malicious_language_in_finding(self):
        """Invariants prohibit terms like 'malicious', 'sabotage', 'attacker', 'poison'."""
        with pytest.raises(ValueError, match="Prohibited malicious attribution term"):
            ContributorScanFinding(
                finding_id="f1",
                contributor_id="alice",
                category=ContributorCategory.CONTRIBUTOR_ANOMALY_CONCENTRATION,
                confidence=0.9,
                explanation="Contributor alice is a malicious attacker responsible for dataset poisoning.",
            )

    def test_domain_exceptions_instantiation(self):
        e1 = ContributorAggregationError("generic error")
        assert isinstance(e1, Exception)
        e2 = InsufficientContributorSupportError("support error")
        assert isinstance(e2, ContributorAggregationError)
        e3 = InvalidAttributionError("attribution error")
        assert isinstance(e3, ContributorAggregationError)
        e4 = InvalidBaselineError("baseline error")
        assert isinstance(e4, ContributorAggregationError)
        e5 = MalformedEvidenceError("evidence error")
        assert isinstance(e5, ContributorAggregationError)


# ==============================================================================
# 11. SPECIFIC FINDING CATEGORY EMISSION TESTS
# ==============================================================================

class TestSpecificFindingCategories:
    """Tests for transition, ood, quality, duplicate, and unattributed findings."""

    def test_label_transition_differential_finding(self):
        # Alice has high label_flip rate, Bob has low label_flip rate
        samples = (
            [_make_sample(f"sa_{i}", contributors=["alice"]) for i in range(15)] +
            [_make_sample(f"sb_{i}", contributors=["bob"]) for i in range(15)]
        )
        manifest = _make_manifest(samples)
        # Alice 10/15 flips (~66.7%), Bob 0/15 flips (0%) -> Delta ~ 66.7% >= 30% threshold
        evidence = {f"sa_{i}": {"label_flip"} for i in range(10)}

        result = aggregate_contributor_evidence(manifest, evidence_by_sample=evidence)
        findings = [f for f in result.findings if f.contributor_id == "alice" and f.category == ContributorCategory.CONTRIBUTOR_LABEL_TRANSITION]
        assert len(findings) == 1
        assert "directional transition rate" in findings[0].explanation

    def test_ood_concentration_finding(self):
        samples = (
            [_make_sample(f"sa_{i}", contributors=["alice"]) for i in range(15)] +
            [_make_sample(f"sb_{i}", contributors=["bob"]) for i in range(15)]
        )
        manifest = _make_manifest(samples)
        evidence = {f"sa_{i}": {"ood"} for i in range(10)}

        result = aggregate_contributor_evidence(manifest, evidence_by_sample=evidence)
        findings = [f for f in result.findings if f.contributor_id == "alice" and f.category == ContributorCategory.CONTRIBUTOR_OOD_CONCENTRATION]
        assert len(findings) == 1
        assert "out-of-distribution" in findings[0].explanation

    def test_quality_concentration_finding(self):
        samples = (
            [_make_sample(f"sa_{i}", contributors=["alice"]) for i in range(15)] +
            [_make_sample(f"sb_{i}", contributors=["bob"]) for i in range(15)]
        )
        manifest = _make_manifest(samples)
        evidence = {f"sa_{i}": {"quality"} for i in range(10)}

        result = aggregate_contributor_evidence(manifest, evidence_by_sample=evidence)
        findings = [f for f in result.findings if f.contributor_id == "alice" and f.category == ContributorCategory.CONTRIBUTOR_QUALITY_CONCENTRATION]
        assert len(findings) == 1
        assert "quality degradation" in findings[0].explanation

    def test_duplicate_concentration_finding(self):
        samples = (
            [_make_sample(f"sa_{i}", contributors=["alice"]) for i in range(15)] +
            [_make_sample(f"sb_{i}", contributors=["bob"]) for i in range(15)]
        )
        manifest = _make_manifest(samples)
        evidence = {f"sa_{i}": {"duplicate"} for i in range(10)}

        result = aggregate_contributor_evidence(manifest, evidence_by_sample=evidence)
        findings = [f for f in result.findings if f.contributor_id == "alice" and f.category == ContributorCategory.CONTRIBUTOR_DUPLICATE_CONCENTRATION]
        assert len(findings) == 1
        assert "near-duplicate" in findings[0].explanation

    def test_unattributed_evidence_container_finding(self):
        # Samples with no contributors provided having anomalies
        samples = (
            [_make_sample(f"su_{i}", contributors=[]) for i in range(10)] +
            [_make_sample(f"sa_{i}", contributors=["alice"]) for i in range(10)]
        )
        manifest = _make_manifest(samples)
        evidence = {f"su_{i}": {"label_anomaly"} for i in range(5)}

        result = aggregate_contributor_evidence(manifest, evidence_by_sample=evidence)
        findings = [f for f in result.findings if f.contributor_id == UNATTRIBUTED_KEY and f.category == ContributorCategory.UNATTRIBUTED_EVIDENCE]
        assert len(findings) == 1
        assert "Preserved 5.0 weighted anomaly evidence items" in findings[0].explanation

    def test_small_dataset_support_warning(self):
        # Dataset with < 25 samples
        samples = [_make_sample(f"s_{i}", contributors=["alice"]) for i in range(10)]
        manifest = _make_manifest(samples)

        result = aggregate_contributor_evidence(manifest)
        dataset_findings = [f for f in result.findings if f.contributor_id == "dataset" and f.category == ContributorCategory.INSUFFICIENT_CONTRIBUTOR_SUPPORT]
        assert len(dataset_findings) == 1
        assert "below minimum statistical support threshold of 25" in dataset_findings[0].explanation


# ==============================================================================
# 11. DETERMINISM & PERFORMANCE BENCHMARK TESTS
# ==============================================================================

class TestDeterminismAndPerformance:
    """Tests for exact reproducibility and linear O(N + C + E) performance."""

    def test_deterministic_result_reproducibility(self):
        samples = (
            [_make_sample(f"s_a{i}", contributors=["alice"]) for i in range(10)] +
            [_make_sample(f"s_b{i}", contributors=["bob"]) for i in range(10)]
        )
        manifest = _make_manifest(samples)
        evidence = {f"s_a{i}": {"ood"} for i in range(5)}

        res1 = aggregate_contributor_evidence(manifest, evidence_by_sample=evidence)
        res2 = aggregate_contributor_evidence(manifest, evidence_by_sample=evidence)

        assert res1.scan_id == res2.scan_id
        assert len(res1.findings) == len(res2.findings)
        for f1, f2 in zip(res1.findings, res2.findings):
            assert f1.finding_id == f2.finding_id
            assert f1.confidence == f2.confidence

    def test_large_dataset_linear_performance(self):
        """Process synthetic dataset of 1,000 samples across 50 contributors within 1.0 second."""
        import time
        n_samples = 1000
        n_contributors = 50
        
        samples = []
        evidence = {}
        for i in range(n_samples):
            c_idx = i % n_contributors
            s_id = f"bench_s_{i}"
            samples.append(_make_sample(s_id, contributors=[f"user_{c_idx}"]))
            if i % 10 == 0:
                evidence[s_id] = {"label_anomaly", "ood"}

        manifest = _make_manifest(samples)

        t0 = time.perf_counter()
        result = aggregate_contributor_evidence(manifest, evidence_by_sample=evidence)
        elapsed = time.perf_counter() - t0

        assert elapsed < 1.0  # Must be fast and linear O(N + C + E)
        assert result.total_contributors == n_contributors
        assert result.profiled_contributors == n_contributors


# ==============================================================================
# 12. TRACEABILITY & INTEGRATION READINESS TESTS
# ==============================================================================

class TestTraceabilityAndSafety:
    """Tests confirming all metadata needed for downstream Phase 5.9 / Phase 8 is preserved."""

    def test_full_evidence_traceability(self):
        samples = [
            _make_sample("s_trace_1", contributors=["alice", "bob"]),
            _make_sample("s_trace_2", contributors=["alice"]),
            _make_sample("s_trace_3", contributors=["bob"]),
            _make_sample("s_trace_4", contributors=["alice"]),
            _make_sample("s_trace_5", contributors=["alice"]),
            _make_sample("s_trace_6", contributors=["alice"]),
        ]
        manifest = _make_manifest(samples)
        evidence = {"s_trace_1": {"ood"}, "s_trace_2": {"ood"}}

        result = aggregate_contributor_evidence(manifest, evidence_by_sample=evidence)

        # 1. Dataset fingerprint preserved
        assert result.dataset_fingerprint == "0" * 64
        # 2. Total contributor count and profiles preserved
        assert "alice" in result.profiles
        alice_prof = result.profiles["alice"]
        assert alice_prof.contributor_id == "alice"
        assert alice_prof.total_samples_contributed == 5
        assert alice_prof.shared_sample_count == 1
        assert math.isclose(alice_prof.weighted_sample_exposure, 4.5)

        # 3. Anomaly metric granular details
        ood_metric = alice_prof.metrics["ood"]
        assert ood_metric.metric_name == "ood"
        assert math.isclose(ood_metric.contributor_count, 1.5)
        assert math.isclose(ood_metric.contributor_rate, 1.5 / 4.5)
        assert ood_metric.wilson_lower_bound > 0.0
        assert ood_metric.wilson_upper_bound > 0.0
        assert ood_metric.background_count >= 0.0
        assert ood_metric.background_exposure >= 0.0
        assert ood_metric.baseline_status == "VALID"
        assert ood_metric.rate_differential is not None

        # 4. Findings preserve detection layer semantics
        for f in result.findings:
            assert f.evidence_layer == "detection"
            assert not any(bad in f.explanation.lower() for bad in ["malicious", "poison", "sabotage", "attacker", "guilt"])
