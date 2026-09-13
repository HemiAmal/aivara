"""Layer 2: Component Integration Verification.

Covers:
- REQ-11-VERIF-011: Feature dataset drift engine statistical delegation
- REQ-11-VERIF-012: Image drift analyzer descriptor extraction integration
- REQ-11-VERIF-013: Representation drift analyzer embedding pipeline
- REQ-11-VERIF-014: Temporal analyzer window partitioning & dual topology
- REQ-11-VERIF-015: Temporal trajectory classification state machine
- REQ-11-VERIF-016: Contributor source engine 5-stage canonicalization
- REQ-11-VERIF-017: Contributor project-scoped pseudonymization
- REQ-11-VERIF-018: Contributor source engine O(G) linear topology
- REQ-11-VERIF-019: Simpson's paradox & label confounding safeguard
- REQ-11-VERIF-020: Multi-modal risk engine ancestry clustering
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List
import numpy as np
import pytest

from aivara.drift.engine import StatisticalDriftEngine
from aivara.drift.feature_dataset_engine import FeatureDatasetDriftAnalyzer
from aivara.drift.image_engine import ImageDistributionShiftAnalyzer
from aivara.drift.image_descriptors import extract_population_descriptors
from aivara.drift.representation_engine import (
    RepresentationDistributionShiftAnalyzer,
    apply_l2_normalization,
    compute_representation_contract_hash,
)
from aivara.drift.temporal_engine import (
    TemporalDistributionShiftAnalyzer,
    compute_temporal_contract_hash,
)
from aivara.drift.source_engine import (
    SourceDistributionShiftEngine,
    canonicalize_source_id,
    derive_project_scoped_pseudonym,
)
from aivara.assurance.engine import MultiModalRiskIntegrationEngine
from aivara.drift.boundary import ComparisonBoundaryEngine
from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    CompatibilityStatus,
    DataModality,
    PopulationType,
    ShiftDecisionState,
    SourceAttributeFallbackPolicy,
    SourceTrustState,
    SourceType,
    TemporalTrajectoryState,
    TemporalWindowStrategy,
    TimestampSource,
)
from aivara.drift.schemas import (
    ComparisonBoundaryResult,
    ComparisonContract,
    FeatureSchemaDescriptor,
    ImagePopulationAccounting,
    PopulationIdentity,
    PopulationSelector,
    RepresentationContract,
    SourceAnalysisContract,
    SourceAttributeSelector,
    SourceContext,
    StatisticalAnalysisConfig,
    TemporalAnalysisContract,
)
from aivara.assurance.schemas import (
    DecisionPolicy,
    EvidenceCategory,
    EvidenceReference,
    ModalityCluster,
    RiskPolicy,
    SynthesizedFinding,
)
from aivara.domain.schemas import Disposition, EvidenceLayer, Severity


def _make_dummy_boundary(
    project_id: str = "proj_alpha",
    ref_ds: str = "ds_ref",
    tgt_ds: str = "ds_tgt",
    modality: DataModality = DataModality.TABULAR_FEATURE,
    ref_n: int = 100,
    tgt_n: int = 100,
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
    ref_pop = PopulationIdentity(
        dataset_id=ref_ds,
        population_type=PopulationType.COMPLETE_DATASET,
        total_available_samples=ref_n,
        selected_sample_count=ref_n,
        sampling_applied=False,
        sample_ids_hash="c" * 64,
        population_selection_hash="d" * 64,
    )
    tgt_pop = PopulationIdentity(
        dataset_id=tgt_ds,
        population_type=PopulationType.COMPLETE_DATASET,
        total_available_samples=tgt_n,
        selected_sample_count=tgt_n,
        sampling_applied=False,
        sample_ids_hash="e" * 64,
        population_selection_hash="f" * 64,
    )
    return ComparisonBoundaryResult(
        contract=contract,
        comparison_boundary_hash="0" * 64,
        reference_population=ref_pop,
        target_population=tgt_pop,
        status=status,
        compatibility_status=CompatibilityStatus.COMPATIBLE,
    )


def test_req_011_feature_engine_statistical_delegation(synthetic_tabular_data: Dict[str, Any]) -> None:
    """Verify REQ-11-VERIF-011: Feature engine delegates two-sample testing to StatisticalDriftEngine."""
    stat_engine = StatisticalDriftEngine()
    ref_data = synthetic_tabular_data["reference"]
    tgt_data = synthetic_tabular_data["target_shifted"]

    b_res = _make_dummy_boundary(
        modality=DataModality.TABULAR_FEATURE,
        ref_n=len(ref_data["num_1"]),
        tgt_n=len(tgt_data["num_1"]),
    )

    stat_res = stat_engine.evaluate_boundary(
        b_res,
        reference_features={"num_1": ref_data["num_1"], "num_2": ref_data["num_2"]},
        target_features={"num_1": tgt_data["num_1"], "num_2": tgt_data["num_2"]},
    )
    assert len(stat_res.feature_results) == 2
    assert stat_res.feature_results["num_1"].is_statistically_significant is True
    assert stat_res.feature_results["num_1"].status == ShiftDecisionState.MATERIAL_SHIFT

    analyzer = FeatureDatasetDriftAnalyzer()
    profile = analyzer.analyze(b_res, stat_res)
    assert profile.global_status == ShiftDecisionState.MATERIAL_SHIFT
    assert profile.materially_shifted_feature_count >= 1


def test_req_012_image_descriptor_extraction(synthetic_image_batches: Dict[str, List[bytes]]) -> None:
    """Verify REQ-11-VERIF-012: Image descriptor extraction across dimension, pixel, and quality families."""
    ref_images = synthetic_image_batches["reference"]
    descriptors, accounting = extract_population_descriptors(image_items=ref_images)
    assert accounting["total"] == 10
    assert accounting["analyzable"] == 10
    assert "mean_intensity" in descriptors
    assert "rms_contrast" in descriptors
    assert len(descriptors["mean_intensity"]) == 10


def test_req_013_representation_engine_pipeline(synthetic_representation_embeddings: Dict[str, np.ndarray]) -> None:
    """Verify REQ-11-VERIF-013: Representation drift pipeline verifies L2 unit normalization and MMD/Energy testing."""
    ref_emb = synthetic_representation_embeddings["reference"]
    tgt_emb = synthetic_representation_embeddings["target_shifted"]

    normed_ref = apply_l2_normalization(ref_emb)
    normed_tgt = apply_l2_normalization(tgt_emb)
    assert np.allclose(np.linalg.norm(normed_ref, axis=1), 1.0, atol=1e-5)

    contract_desc = {
        "batch_size": 32,
        "contract_version": "1.0",
        "embedding_dimension": 64,
        "execution_device_policy": "CPU",
        "modality": "image",
        "model_artifact_hash": "m" * 64,
        "model_format": "ONNX",
        "model_id": "test_model",
        "model_master_fingerprint": "f" * 64,
        "normalization_policy": "L2",
        "numerical_precision": "float32",
        "preprocessing_contract_hash": "p" * 64,
        "representation_id": "rep_test_01",
        "representation_layer": "norm",
        "runtime_framework": "onnxruntime",
        "schema_version": "1.0",
    }
    c_hash = compute_representation_contract_hash(contract_desc)
    rep_contract = RepresentationContract(
        representation_id="rep_test_01",
        modality=DataModality.IMAGE,
        model_id="test_model",
        model_master_fingerprint="f" * 64,
        model_artifact_hash="m" * 64,
        model_format="ONNX",
        runtime_framework="onnxruntime",
        representation_layer="norm",
        embedding_dimension=64,
        preprocessing_contract_hash="p" * 64,
        normalization_policy="L2",
        numerical_precision="float32",
        execution_device_policy="CPU",
        batch_size=32,
        representation_contract_hash=c_hash,
    )

    b_res = _make_dummy_boundary(
        modality=DataModality.IMAGE,
        ref_n=len(ref_emb),
        tgt_n=len(tgt_emb),
    )

    rep_engine = RepresentationDistributionShiftAnalyzer()
    res = rep_engine.analyze(b_res, rep_contract, normed_ref, normed_tgt)
    assert res.global_status == ShiftDecisionState.MATERIAL_SHIFT
    assert res.multivariate_result is not None
    assert res.multivariate_result.is_statistically_significant is True


def test_req_014_temporal_window_partitioning_and_dual_topology() -> None:
    """Verify REQ-11-VERIF-014: Temporal analyzer dual topology (Baseline W0 <-> Wk and Adjacent Wk-1 <-> Wk)."""
    rng = np.random.RandomState(42)
    raw_obs = []
    for i in range(40):
        raw_obs.append({"event_time": "2026-09-01T12:10:00Z", "payload": rng.normal(0.0, 1.0, 8), "id": f"w0_{i}"})
    for i in range(40):
        raw_obs.append({"event_time": "2026-09-01T13:10:00Z", "payload": rng.normal(0.0, 1.0, 8), "id": f"w1_{i}"})
    for i in range(40):
        raw_obs.append({"event_time": "2026-09-01T14:10:00Z", "payload": rng.normal(3.0, 1.0, 8), "id": f"w2_{i}"})

    contract_dict = {
        "baseline_policy": "first_window",
        "comparison_topology": "dual_topology",
        "contract_version": "1.0",
        "declared_seasonality_period_seconds": -1.0,
        "max_window_samples": 5000,
        "max_windows": 50,
        "min_window_samples": 30,
        "schema_version": "1.0",
        "step_size_seconds": -1.0,
        "temporal_analysis_id": "temp_01",
        "timestamp_field": "event_time",
        "timezone_policy": "UTC",
        "window_size_seconds": 3600.0,
        "window_strategy": "fixed_interval",
    }
    c_hash = compute_temporal_contract_hash(contract_dict)
    temp_contract = TemporalAnalysisContract(
        temporal_analysis_id="temp_01",
        timestamp_field=TimestampSource.EVENT_TIME,
        timezone_policy="UTC",
        window_strategy=TemporalWindowStrategy.FIXED_INTERVAL,
        window_size_seconds=3600.0,
        max_windows=50,
        min_window_samples=30,
        temporal_contract_hash=c_hash,
    )
    b_res = _make_dummy_boundary(ref_n=120, tgt_n=120)

    temp_engine = TemporalDistributionShiftAnalyzer()
    profile = temp_engine.analyze(b_res, temp_contract, raw_obs)
    assert len(profile.windows) == 3
    assert len(profile.baseline_comparisons) == 2
    assert len(profile.adjacent_comparisons) == 2


def test_req_015_temporal_trajectory_state_machine() -> None:
    """Verify REQ-11-VERIF-015: Classification into deterministic trajectory states."""
    temp_engine = TemporalDistributionShiftAnalyzer()
    raw_obs_stat = []
    for i in range(40):
        raw_obs_stat.append({"event_time": "2026-09-01T12:00:00Z", "payload": [0.1] * 4, "id": f"w0_{i}"})
    for i in range(40):
        raw_obs_stat.append({"event_time": "2026-09-01T13:00:00Z", "payload": [0.1] * 4, "id": f"w1_{i}"})

    contract_dict = {
        "baseline_policy": "first_window",
        "comparison_topology": "dual_topology",
        "contract_version": "1.0",
        "declared_seasonality_period_seconds": -1.0,
        "max_window_samples": 5000,
        "max_windows": 50,
        "min_window_samples": 30,
        "schema_version": "1.0",
        "step_size_seconds": -1.0,
        "temporal_analysis_id": "temp_stat",
        "timestamp_field": "event_time",
        "timezone_policy": "UTC",
        "window_size_seconds": 3600.0,
        "window_strategy": "fixed_interval",
    }
    c_hash = compute_temporal_contract_hash(contract_dict)
    temp_contract = TemporalAnalysisContract(
        temporal_analysis_id="temp_stat",
        timestamp_field=TimestampSource.EVENT_TIME,
        timezone_policy="UTC",
        window_strategy=TemporalWindowStrategy.FIXED_INTERVAL,
        window_size_seconds=3600.0,
        max_windows=50,
        min_window_samples=30,
        temporal_contract_hash=c_hash,
    )
    b_res = _make_dummy_boundary(ref_n=80, tgt_n=80)
    profile = temp_engine.analyze(b_res, temp_contract, raw_obs_stat)
    assert profile.global_trajectory_status == TemporalTrajectoryState.NO_MATERIAL_SHIFT


def test_req_016_source_5stage_canonicalization() -> None:
    """Verify REQ-11-VERIF-016: 5-stage canonicalization (NFKC, control chars, whitespace, lower, length)."""
    c1 = canonicalize_source_id("  Alpha_Contributor \t")
    c2 = canonicalize_source_id("ALPHA_CONTRIBUTOR")
    c3 = canonicalize_source_id("alpha_contributor")
    assert c1 == c2 == c3 == "alpha_contributor"


def test_req_017_source_project_scoped_pseudonymization() -> None:
    """Verify REQ-11-VERIF-017: Project-scoped pseudonymization uniqueness across projects."""
    p1 = derive_project_scoped_pseudonym(
        project_id="project_A",
        canonical_source_id="user_alpha",
        salt="salt_123",
    )
    p2 = derive_project_scoped_pseudonym(
        project_id="project_B",
        canonical_source_id="user_alpha",
        salt="salt_123",
    )
    assert p1 != p2
    assert len(p1) == 16
    assert len(p2) == 16


def test_req_018_source_linear_og_topology() -> None:
    """Verify REQ-11-VERIF-018: Source engine executes linear O(G) comparisons against reference."""
    engine = SourceDistributionShiftEngine()
    rng = np.random.RandomState(42)
    ref_obs = [{"sample_id": f"r_{i}", "contributor_id": "ref_source", "payload": rng.normal(0, 1, 4).tolist()} for i in range(100)]
    tgt_obs_1 = [{"sample_id": f"t1_{i}", "contributor_id": "src_1", "payload": rng.normal(0, 1, 4).tolist()} for i in range(40)]
    tgt_obs_2 = [{"sample_id": f"t2_{i}", "contributor_id": "src_2", "payload": rng.normal(2, 1, 4).tolist()} for i in range(40)]
    tgt_obs_3 = [{"sample_id": f"t3_{i}", "contributor_id": "src_3", "payload": rng.normal(0, 1, 4).tolist()} for i in range(40)]

    contract = SourceAnalysisContract(
        source_analysis_id="contract_og",
        min_group_samples=30,
    )
    profile = engine.analyze(
        observations=ref_obs + tgt_obs_1 + tgt_obs_2 + tgt_obs_3,
        contract=contract,
        project_id="proj_alpha",
    )
    assert len(profile.comparisons) == 3


def test_req_019_simpsons_paradox_safeguard() -> None:
    """Verify REQ-11-VERIF-019: Automated label confounding advisory finding on class TVD >= 0.15."""
    engine = SourceDistributionShiftEngine()
    ref_obs = [{"sample_id": f"r_{i}", "contributor_id": "ref", "label": "A", "payload": [1.0]} for i in range(50)] + \
              [{"sample_id": f"r2_{i}", "contributor_id": "ref", "label": "B", "payload": [1.0]} for i in range(50)]

    # Confounded source: contributes only class B
    tgt_obs = [{"sample_id": f"t_{i}", "contributor_id": "src_confounded", "label": "B", "payload": [1.0]} for i in range(50)]

    contract = SourceAnalysisContract(
        source_analysis_id="contract_confounding",
        min_group_samples=30,
        enable_label_confounding_check=True,
    )
    profile = engine.analyze(
        observations=ref_obs + tgt_obs,
        contract=contract,
        project_id="proj_alpha",
    )
    assert any(c.potential_label_confounding for c in profile.comparisons)


def test_req_020_multimodal_ancestry_clustering() -> None:
    """Verify REQ-11-VERIF-020: Ancestry-based clustering on shared dataset asset lineage."""
    engine = MultiModalRiskIntegrationEngine()
    ancestry = {"dataset_version_id": "v_2.0"}
    ev1 = EvidenceReference(
        evidence_id="e1",
        project_id="proj_alpha",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift1",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Shift 1",
        confidence=0.80,
        severity=Severity.HIGH,
        ancestry_keys=ancestry,
        evidence_hash="a1" * 32,
    )
    ev2 = EvidenceReference(
        evidence_id="e2",
        project_id="proj_alpha",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift2",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Shift 2",
        confidence=0.60,
        severity=Severity.HIGH,
        ancestry_keys=ancestry,
        evidence_hash="a2" * 32,
    )
    profile = engine.evaluate(
        project_id="proj_alpha",
        target_asset_type="dataset",
        target_asset_id="ds_main",
        evidence_items=[ev1, ev2],
    )
    assert len(profile.clusters) == 1
    assert len(profile.clusters[0].evidence_ids) == 2
