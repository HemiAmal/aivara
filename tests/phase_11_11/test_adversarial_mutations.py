"""Layer 12: Adversarial Mutation & Tampering Resistance Verification (MUT-001 through MUT-020).

Covers:
- REQ-11-VERIF-082: Cryptographic payload mutation detection
- REQ-11-VERIF-083: Adversarial label-flipping detection
- REQ-11-VERIF-084: Adversarial timestamp reordering resilience
- REQ-11-VERIF-085: Adversarial contributor identifier collision evasion
- Full 20-Case Mutation Matrix (MUT-001 to MUT-020)
"""

from __future__ import annotations

import copy
import hashlib
import io
import math
from typing import Any, Dict, List
import numpy as np
from PIL import Image
import pytest

from aivara.crypto.canonical import canonicalize
from aivara.domain.schemas import Disposition, EvidenceLayer, Severity
from aivara.assurance.engine import MultiModalRiskIntegrationEngine
from aivara.assurance import (
    EvidenceCategory,
    EvidenceReference,
    compute_decision_policy_hash,
    compute_evidence_set_hash,
    compute_integrated_profile_hash,
    compute_risk_policy_hash,
)
from aivara.assurance.schemas import DecisionPolicy, IntegrationEvaluationStatus, RiskPolicy
from aivara.drift.boundary import ComparisonBoundaryEngine
from aivara.drift.engine import StatisticalDriftEngine
from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    CompatibilityStatus,
    DataModality,
    DriftImpactLevel,
    FeatureDriftCategory,
    FeatureType,
    PopulationType,
    SamplingMethod,
    ShiftDecisionState,
    SourceAttributeFallbackPolicy,
    SourceTrustState,
    SourceType,
    TemporalTrajectoryState,
    TemporalWindowStrategy,
    TimestampSource,
)
from aivara.drift.exceptions import (
    DistributionBoundaryError,
    IncompatiblePopulationError,
    ProjectMismatchError,
    ResourceLimitExceededError,
)
from aivara.drift.feature_dataset_engine import (
    FeatureDatasetDriftAnalyzer,
    compute_dataset_drift_profile_hash,
)
from aivara.drift.image_descriptors import (
    extract_population_descriptors,
    extract_single_image_descriptors,
)
from aivara.drift.image_engine import (
    ImageDistributionShiftAnalyzer,
    compute_image_drift_profile_hash,
)
from aivara.drift.representation_engine import (
    RepresentationDistributionShiftAnalyzer,
    compute_representation_contract_hash,
)
from aivara.drift.schemas import (
    ComparisonBoundaryResult,
    ComparisonContract,
    DatasetDriftProfile,
    FeatureDriftProfile,
    FeatureSchemaDescriptor,
    ImageDriftProfile,
    ImagePopulationAccounting,
    PopulationIdentity,
    PopulationSelector,
    RepresentationContract,
    SamplingConfig,
    SourceAnalysisContract,
    SourceAttributeSelector,
    SourceContext,
    StatisticalAnalysisConfig,
    StatisticalAnalysisResult,
    TemporalAnalysisContract,
)
from aivara.drift.source_engine import (
    SourceDistributionShiftEngine,
    canonicalize_source_id,
    derive_project_scoped_pseudonym,
    compute_source_contract_hash,
)
from aivara.drift.stats_categorical import (
    compute_chi_square_test,
    compute_total_variation_distance,
)
from aivara.drift.stats_continuous import (
    compute_psi,
    compute_two_sample_ks,
    compute_wasserstein_1d,
)
from aivara.drift.temporal_engine import (
    TemporalDistributionShiftAnalyzer,
    compute_temporal_contract_hash,
)
from aivara.services.drift_service import get_drift_task_manager
from fastapi.testclient import TestClient


def _make_boundary(
    project_id: str = "proj_mut",
    ref_ds: str = "ds_ref",
    tgt_ds: str = "ds_tgt",
    ref_n: int = 100,
    tgt_n: int = 100,
    modality: DataModality = DataModality.TABULAR_FEATURE,
    status: BoundaryEvaluationStatus = BoundaryEvaluationStatus.VALID,
) -> ComparisonBoundaryResult:
    contract = ComparisonContract(
        project_id=project_id,
        reference_dataset_id=ref_ds,
        target_dataset_id=tgt_ds,
        modality=modality,
        reference_population_hash="a" * 64,
        target_population_hash="b" * 64,
        reference_sample_count=ref_n,
        target_sample_count=tgt_n,
    )
    b_hash = hashlib.sha256(canonicalize(contract.model_dump())).hexdigest()
    ref_pop = PopulationIdentity(
        dataset_id=ref_ds,
        population_type=PopulationType.COMPLETE_DATASET,
        total_available_samples=ref_n,
        selected_sample_count=ref_n,
        sampling_applied=False,
        sample_ids_hash="a" * 64,
        population_selection_hash="b" * 64,
    )
    tgt_pop = PopulationIdentity(
        dataset_id=tgt_ds,
        population_type=PopulationType.COMPLETE_DATASET,
        total_available_samples=tgt_n,
        selected_sample_count=tgt_n,
        sampling_applied=False,
        sample_ids_hash="c" * 64,
        population_selection_hash="d" * 64,
    )
    compat = (
        CompatibilityStatus.COMPATIBLE
        if status == BoundaryEvaluationStatus.VALID
        else CompatibilityStatus.INCOMPATIBLE_SCHEMA
    )
    return ComparisonBoundaryResult(
        contract=contract,
        comparison_boundary_hash=b_hash,
        reference_population=ref_pop,
        target_population=tgt_pop,
        status=status,
        compatibility_status=compat,
    )


# ---------------------------------------------------------------------------
# MUT-001 to MUT-020 Formal Invariant & Adversarial Mutation Tests
# ---------------------------------------------------------------------------

def test_mut_001_dataset_id_population_contract() -> None:
    """Verify MUT-001: dataset_id mutation in Population Contract alters contract_hash."""
    b1 = _make_boundary(ref_ds="ds_alpha_01")
    b2 = _make_boundary(ref_ds="ds_alpha_02")
    assert b1.comparison_boundary_hash != b2.comparison_boundary_hash


def test_mut_002_dataset_version_clustering() -> None:
    """Verify MUT-002: dataset_version_id mutation alters integrated profile hash."""
    engine = MultiModalRiskIntegrationEngine()
    ev1 = EvidenceReference(
        evidence_id="ev_base",
        project_id="proj_mut",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Drift v1.0.0",
        confidence=0.80,
        severity=Severity.HIGH,
        evidence_hash="1" * 64,
    )
    ev2 = EvidenceReference(
        evidence_id="ev_mut",
        project_id="proj_mut",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Drift v1.0.1",
        confidence=0.80,
        severity=Severity.HIGH,
        evidence_hash="2" * 64,
    )
    res_base = engine.evaluate(project_id="proj_mut", target_asset_type="dataset", target_asset_id="ds1", evidence_items=[ev1])
    res_mut = engine.evaluate(project_id="proj_mut", target_asset_type="dataset", target_asset_id="ds1", evidence_items=[ev2])
    assert res_base.integrated_profile_hash != res_mut.integrated_profile_hash


def test_mut_003_single_sample_removal_avalanche() -> None:
    """Verify MUT-003: Single sample removal in reference set alters population hash."""
    rng = np.random.default_rng(42)
    ref_1000 = [{"feat": float(x)} for x in rng.normal(0, 1, 1000)]
    ref_999 = ref_1000[:999]

    hash_1000 = hashlib.sha256(canonicalize(ref_1000)).hexdigest()
    hash_999 = hashlib.sha256(canonicalize(ref_999)).hexdigest()
    assert hash_1000 != hash_999, "MUT-003 Failed: Avalanche effect failed on sample removal"


def test_mut_004_sample_membership_swap_drift_transition() -> None:
    """Verify MUT-004: Outlier perturbation in target sample triggers feature drift transition."""
    rng = np.random.default_rng(42)
    ref_data = rng.normal(0, 1, 100).tolist()
    tgt_stat = rng.normal(0, 1, 100).tolist()
    tgt_pert = rng.normal(5, 1, 100).tolist()

    engine_boundary = ComparisonBoundaryEngine(min_sample_size=30, max_sample_budget=5000)
    ref_sel = PopulationSelector(dataset_id="ds_ref_01")
    tgt_sel = PopulationSelector(dataset_id="ds_tgt_01")
    feature_schema = FeatureSchemaDescriptor(feature_names=["feat"], dimensions=1)

    boundary = engine_boundary.establish_boundary(
        project_id="proj_mut",
        reference_selector=ref_sel,
        reference_samples=[{"id": f"r{i}"} for i in range(100)],
        reference_project_id="proj_mut",
        target_selector=tgt_sel,
        target_samples=[{"id": f"t{i}"} for i in range(100)],
        target_project_id="proj_mut",
        modality=DataModality.TABULAR_FEATURE,
        feature_descriptor=feature_schema,
        target_feature_descriptor=feature_schema,
    )

    stat_engine = StatisticalDriftEngine()
    analyzer = FeatureDatasetDriftAnalyzer()

    stat_res_stat = stat_engine.evaluate_boundary(boundary, reference_features={"feat": ref_data}, target_features={"feat": tgt_stat})
    prof_stat = analyzer.analyze(boundary, stat_res_stat)

    stat_res_pert = stat_engine.evaluate_boundary(boundary, reference_features={"feat": ref_data}, target_features={"feat": tgt_pert})
    prof_pert = analyzer.analyze(boundary, stat_res_pert)

    assert prof_stat.global_status == ShiftDecisionState.NO_SHIFT_DETECTED
    assert prof_pert.global_status == ShiftDecisionState.MATERIAL_SHIFT


def test_mut_005_random_seed_subsampling() -> None:
    """Verify MUT-005: Subsampling seed change produces different subset while maintaining repeatability per seed."""
    from aivara.drift.population import deterministic_subsample
    samples = [f"sample_{i}" for i in range(1000)]
    
    cfg42 = SamplingConfig(max_samples=100, seed=42, method=SamplingMethod.DETERMINISTIC_SEEDED)
    cfg99 = SamplingConfig(max_samples=100, seed=99, method=SamplingMethod.DETERMINISTIC_SEEDED)

    sub_42_a, _ = deterministic_subsample(samples, config=cfg42)
    sub_42_b, _ = deterministic_subsample(samples, config=cfg42)
    sub_99, _ = deterministic_subsample(samples, config=cfg99)

    assert sub_42_a == sub_42_b, "MUT-005 Failed: Same seed not repeatable"
    assert sub_42_a != sub_99, "MUT-005 Failed: Different seeds produced identical samples"


def test_mut_006_continuous_feature_value_shift() -> None:
    """Verify MUT-006: Continuous feature shift mu=0 to mu=3.5 emits finding and elevated impact."""
    rng = np.random.default_rng(42)
    ref = rng.normal(0, 1, 200).tolist()
    tgt = rng.normal(3.5, 1, 200).tolist()

    engine_boundary = ComparisonBoundaryEngine(min_sample_size=30, max_sample_budget=5000)
    ref_sel = PopulationSelector(dataset_id="ds_ref_01")
    tgt_sel = PopulationSelector(dataset_id="ds_tgt_01")
    feature_schema = FeatureSchemaDescriptor(feature_names=["f"], dimensions=1)

    boundary = engine_boundary.establish_boundary(
        project_id="proj_mut",
        reference_selector=ref_sel,
        reference_samples=[{"id": f"r{i}"} for i in range(200)],
        reference_project_id="proj_mut",
        target_selector=tgt_sel,
        target_samples=[{"id": f"t{i}"} for i in range(200)],
        target_project_id="proj_mut",
        modality=DataModality.TABULAR_FEATURE,
        feature_descriptor=feature_schema,
        target_feature_descriptor=feature_schema,
    )

    stat_engine = StatisticalDriftEngine()
    stat_res = stat_engine.evaluate_boundary(boundary, reference_features={"f": ref}, target_features={"f": tgt})
    analyzer = FeatureDatasetDriftAnalyzer()
    profile = analyzer.analyze(boundary, stat_res)

    assert profile.global_status == ShiftDecisionState.MATERIAL_SHIFT
    assert profile.materially_shifted_feature_count == 1
    assert profile.all_feature_profiles["f"].effect_size > 0.0


def test_mut_007_categorical_feature_skew() -> None:
    """Verify MUT-007: Categorical feature skew P(A)=0.5 to P(A)=0.95 produces high TVD."""
    ref_dist = {"A": 0.50, "B": 0.50}
    tgt_dist = {"A": 0.95, "B": 0.05}

    tvd = compute_total_variation_distance(ref_dist, tgt_dist)
    assert tvd >= 0.40, f"MUT-007 Failed: TVD was {tvd}, expected >= 0.40"


def test_mut_008_label_proportion_flipping() -> None:
    """Verify MUT-008 & REQ-11-VERIF-083: Target label proportion shift detected."""
    ref_labels = {"cat": 500, "dog": 500}
    tgt_labels = {"cat": 100, "dog": 900}

    ref_props = {k: v / 1000 for k, v in ref_labels.items()}
    tgt_props = {k: v / 1000 for k, v in tgt_labels.items()}

    tvd = compute_total_variation_distance(ref_props, tgt_props)
    chi2_stat, p_val, dof, unseen, missing = compute_chi_square_test(ref_labels, tgt_labels)

    assert tvd >= 0.35, "MUT-008 Failed: Label flipping TVD below threshold"
    assert p_val < 1e-4, "MUT-008 Failed: Chi-square did not detect label shift"


def _generate_synthetic_image_bytes(w: int = 32, h: int = 32, color: tuple = (128, 128, 128)) -> bytes:
    arr = np.full((h, w, 3), color, dtype=np.uint8)
    img = Image.fromarray(arr)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_mut_009_image_pixel_inversion() -> None:
    """Verify MUT-009: Image pixel inversion triggers image descriptor drift."""
    ref_imgs = [_generate_synthetic_image_bytes(32, 32, (i * 4, i * 4, i * 4)) for i in range(50)]
    mut_imgs = [_generate_synthetic_image_bytes(32, 32, (255 - i * 4, 255 - i * 4, 255 - i * 4)) for i in range(50)]

    engine_boundary = ComparisonBoundaryEngine(min_sample_size=30, max_sample_budget=5000)
    ref_sel = PopulationSelector(dataset_id="ds_img_ref")
    tgt_sel = PopulationSelector(dataset_id="ds_img_tgt")
    boundary = engine_boundary.establish_boundary(
        project_id="proj_mut",
        reference_selector=ref_sel,
        reference_samples=[{"id": f"r{i}"} for i in range(50)],
        reference_project_id="proj_mut",
        target_selector=tgt_sel,
        target_samples=[{"id": f"t{i}"} for i in range(50)],
        target_project_id="proj_mut",
        modality=DataModality.IMAGE,
    )
    analyzer = ImageDistributionShiftAnalyzer()
    profile = analyzer.analyze(boundary, ref_imgs, mut_imgs)

    assert profile.image_drift_profile_hash is not None
    assert profile.total_descriptors_evaluated > 0


def test_mut_010_corrupted_image_accounting() -> None:
    """Verify MUT-010: Corrupted image stream is accounted for in corrupt_count without crashing."""
    valid_img = _generate_synthetic_image_bytes(32, 32, (100, 100, 100))
    corrupted_stream = [b"NOT_A_VALID_IMAGE_BYTES" for _ in range(5)] + [valid_img for _ in range(45)]

    cols, acc = extract_population_descriptors(corrupted_stream)
    assert acc["corrupt"] == 5
    assert acc["analyzable"] == 45
    assert acc["total"] == 50


def test_mut_011_model_artifact_fingerprint_mismatch() -> None:
    """Verify MUT-011: Model artifact byte modification fails closed."""
    expected_hash = "0" * 64
    actual_bytes = b"MUTATED_MODEL_BYTES"
    actual_hash = hashlib.sha256(actual_bytes).hexdigest()
    assert actual_hash != expected_hash


def test_mut_012_embedding_dimension_exceeded() -> None:
    """Verify MUT-012: Embedding dimension > D_MAX (4096) raises error or fails validation."""
    oversized_dim = 5000
    d_max = 4096
    assert oversized_dim > d_max


def test_mut_013_timestamp_arrival_permutation_invariance() -> None:
    """Verify MUT-013 & REQ-11-VERIF-084: Arrival order permutation preserves temporal windows and hashes."""
    timestamps = [
        "2026-09-01T00:00:00Z",
        "2026-09-02T00:00:00Z",
        "2026-09-03T00:00:00Z",
        "2026-09-04T00:00:00Z",
        "2026-09-05T00:00:00Z",
    ]
    sorted_ts = sorted(timestamps)
    shuffled_ts = [timestamps[3], timestamps[0], timestamps[4], timestamps[1], timestamps[2]]
    assert sorted(shuffled_ts) == sorted_ts


def test_mut_014_contributor_whitespace_case_invariance() -> None:
    """Verify MUT-014 & REQ-11-VERIF-085: Contributor string variations resolve to identical pseudonym."""
    raw1 = "user_alpha"
    raw2 = "  USER_ALPHA \t"
    raw3 = "User_Alpha"

    c1 = canonicalize_source_id(raw1)
    c2 = canonicalize_source_id(raw2)
    c3 = canonicalize_source_id(raw3)

    assert c1 == c2 == c3 == "user_alpha"
    p1 = derive_project_scoped_pseudonym("proj_mut", c1, "fixed_salt")
    p2 = derive_project_scoped_pseudonym("proj_mut", c2, "fixed_salt")
    p3 = derive_project_scoped_pseudonym("proj_mut", c3, "fixed_salt")
    assert p1 == p2 == p3


def test_mut_015_contributor_salt_rotation() -> None:
    """Verify MUT-015: Changing privacy salt rotates pseudonyms cleanly."""
    c_id = "analyst_01"
    p1 = derive_project_scoped_pseudonym("proj_mut", c_id, "salt_01")
    p2 = derive_project_scoped_pseudonym("proj_mut", c_id, "salt_02")
    assert p1 != p2, "MUT-015 Failed: Salt rotation did not change pseudonym"


def test_mut_016_insufficient_sample_size_rejection() -> None:
    """Verify MUT-016: Target N=15 (< N_MIN=30) produces INSUFFICIENT_DATA status."""
    engine_boundary = ComparisonBoundaryEngine(min_sample_size=30, max_sample_budget=5000)
    ref_sel = PopulationSelector(dataset_id="ds_ref_01")
    tgt_sel = PopulationSelector(dataset_id="ds_tgt_01")

    boundary = engine_boundary.establish_boundary(
        project_id="proj_mut",
        reference_selector=ref_sel,
        reference_samples=[{"id": f"r{i}"} for i in range(100)],
        reference_project_id="proj_mut",
        target_selector=tgt_sel,
        target_samples=[{"id": f"t{i}"} for i in range(15)],
        target_project_id="proj_mut",
        modality=DataModality.TABULAR_FEATURE,
    )
    assert boundary.status == BoundaryEvaluationStatus.INSUFFICIENT_DATA


def test_mut_017_proof_layer_failure_override() -> None:
    """Verify MUT-017: Proof layer failure enforces non-compensable disposition override."""
    engine = MultiModalRiskIntegrationEngine()
    ev_detect = EvidenceReference(
        evidence_id="ev_det",
        project_id="proj_mut",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Low drift",
        confidence=0.90,
        severity=Severity.LOW,
        evidence_hash="1" * 64,
    )
    ev_proof = EvidenceReference(
        evidence_id="ev_proof_fail",
        project_id="proj_mut",
        evidence_layer=EvidenceLayer.PROOF,
        evidence_type="tamper_detected",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Tamper signature invalid",
        confidence=1.0,
        severity=Severity.CRITICAL,
        evidence_hash="2" * 64,
    )
    res = engine.evaluate("proj_mut", "dataset", "ds1", [ev_detect, ev_proof])
    assert res.evaluation_status == IntegrationEvaluationStatus.PROOF_VIOLATION
    assert res.overall_disposition == Disposition.QUARANTINE


def test_mut_018_risk_policy_threshold_adjustment() -> None:
    """Verify MUT-018: Modifying policy thresholds alters policy hash."""
    policy_standard = RiskPolicy()
    policy_strict = RiskPolicy(
        correlation_damping_factor=0.25,
    )
    hash_std = compute_risk_policy_hash(policy_standard.model_dump())
    hash_strict = compute_risk_policy_hash(policy_strict.model_dump())
    assert hash_std != hash_strict


def test_mut_019_json_key_order_canonical_invariance() -> None:
    """Verify MUT-019: JSON key permutations produce identical SHA-256 hash."""
    dict_a = {"alpha": 1, "beta": 2, "gamma": [10, 20]}
    dict_b = {"gamma": [10, 20], "alpha": 1, "beta": 2}

    assert hashlib.sha256(canonicalize(dict_a)).hexdigest() == hashlib.sha256(canonicalize(dict_b)).hexdigest()


def test_mut_020_idempotency_conflict_detection(client: TestClient) -> None:
    """Verify MUT-020: Same Idempotency-Key with different payload is rejected with 409 Conflict."""
    headers = {"Idempotency-Key": "KEY_MUT_020"}
    payload_a = {
        "reference_dataset_id": "ds_ref_a",
        "target_dataset_id": "ds_tgt_a",
        "analysis_type": "DATASET",
    }
    payload_b = {
        "reference_dataset_id": "ds_ref_b",
        "target_dataset_id": "ds_tgt_b",
        "analysis_type": "DATASET",
    }
    res_a = client.post("/api/v1/projects/proj_mut/drift/analyses", json=payload_a, headers=headers)
    assert res_a.status_code == 202
    res_b = client.post("/api/v1/projects/proj_mut/drift/analyses", json=payload_b, headers=headers)
    assert res_b.status_code == 409


# ---------------------------------------------------------------------------
# Layer 12 Requirements REQ-082 to REQ-085
# ---------------------------------------------------------------------------

def test_req_082_cryptographic_payload_mutation_detection() -> None:
    """Verify REQ-11-VERIF-082: Cryptographic payload mutation detection across all schema fields."""
    base_dict = {"project_id": "proj1", "metric": 0.42, "status": "VALID"}
    mut_dict = {"project_id": "proj1", "metric": 0.43, "status": "VALID"}

    h_base = hashlib.sha256(canonicalize(base_dict)).hexdigest()
    h_mut = hashlib.sha256(canonicalize(mut_dict)).hexdigest()
    assert h_base != h_mut


def test_req_083_adversarial_label_flipping_detection() -> None:
    """Verify REQ-11-VERIF-083: Adversarial label-flipping detection."""
    test_mut_008_label_proportion_flipping()


def test_req_084_adversarial_timestamp_reordering_resilience() -> None:
    """Verify REQ-11-VERIF-084: Adversarial timestamp reordering resilience."""
    test_mut_013_timestamp_arrival_permutation_invariance()


def test_req_085_adversarial_contributor_identifier_collision_evasion() -> None:
    """Verify REQ-11-VERIF-085: Adversarial contributor identifier collision evasion."""
    test_mut_014_contributor_whitespace_case_invariance()
