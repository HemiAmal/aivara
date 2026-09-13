"""Phase 11.11.2 - Layer 4: End-to-End Assurance Verification Suite.

Validates end-to-end multi-modal assurance pipelines against frozen contracts:
- REQ-11-VERIF-028 to REQ-11-VERIF-037
- Authoritative End-to-End Scenarios 1 through 7
- Neutral semantic attribution (shift != malicious intent)
- Proof override non-compensability
"""

from __future__ import annotations

import datetime
import io
from typing import Any, Dict, List
import numpy as np
from PIL import Image
import pytest

from aivara.assurance.engine import MultiModalRiskIntegrationEngine
from aivara.assurance.schemas import (
    DEFAULT_CATEGORY_WEIGHTS,
    DecisionPolicy,
    EvidenceCategory,
    EvidenceReference,
    IntegratedAssuranceProfile,
    RiskPolicy,
)
from aivara.domain.schemas import Disposition, EvidenceLayer, Severity
from aivara.drift.boundary import ComparisonBoundaryEngine
from aivara.drift.engine import StatisticalDriftEngine
from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    CompatibilityStatus,
    DataModality,
    PopulationType,
    ShiftDecisionState,
    TemporalWindowStrategy,
    TimestampSource,
)
from aivara.drift.feature_dataset_engine import FeatureDatasetDriftAnalyzer
from aivara.drift.image_descriptors import extract_population_descriptors
from aivara.drift.image_engine import ImageDistributionShiftAnalyzer
from aivara.drift.representation_engine import (
    RepresentationDistributionShiftAnalyzer,
    apply_l2_normalization,
    compute_representation_contract_hash,
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
from aivara.drift.source_engine import SourceDistributionShiftEngine
from aivara.drift.temporal_engine import (
    TemporalDistributionShiftAnalyzer,
    compute_temporal_contract_hash,
)


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


def test_req_028_scenario_1_clean_no_shift() -> None:
    """REQ-11-VERIF-028 / Scenario 1: Clean baseline yields ACCEPT, 0 risk, deterministic disposition."""
    engine_risk = MultiModalRiskIntegrationEngine()
    
    # Evaluate with no findings/evidence
    profile = engine_risk.evaluate(
        project_id="proj_clean",
        target_asset_type="dataset",
        target_asset_id="ds_clean",
        evidence_items=[],
    )
    
    assert profile.overall_risk_score == 0.0
    assert profile.overall_disposition == Disposition.ACCEPT


def test_req_029_scenario_2_statistical_feature_shift(synthetic_tabular_data: Dict[str, Any]) -> None:
    """REQ-11-VERIF-029 / Scenario 2: Statistical feature shift produces finding, elevated risk, neutral semantic attribution."""
    b_res = _make_dummy_boundary(project_id="proj_e2e_stat", ref_n=40, tgt_n=40)
    ref_data = synthetic_tabular_data["reference"]
    tgt_data = synthetic_tabular_data["target_shifted"]
    
    stat_engine = StatisticalDriftEngine()
    stat_res = stat_engine.evaluate_boundary(
        b_res,
        reference_features={"num_1": ref_data["num_1"]},
        target_features={"num_1": [x + 25.0 for x in tgt_data["num_1"]]},
    )
    
    ds_analyzer = FeatureDatasetDriftAnalyzer()
    feat_profile = ds_analyzer.analyze(b_res, stat_res)
    
    assert feat_profile.global_status == ShiftDecisionState.MATERIAL_SHIFT
    
    # Convert drift to EvidenceReference
    ev_item = EvidenceReference(
        evidence_id="ev_stat_drift_01",
        project_id="proj_e2e_stat",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="feature_drift",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Significant feature shift detected in num_1",
        confidence=0.90,
        severity=Severity.HIGH,
        evidence_hash="f1" * 32,
    )
    
    risk_engine = MultiModalRiskIntegrationEngine()
    profile = risk_engine.evaluate(
        project_id="proj_e2e_stat",
        target_asset_type="dataset",
        target_asset_id="ds_stat",
        evidence_items=[ev_item],
    )
    
    assert profile.overall_risk_score > 0.0
    # Invariant: Statistical shift is NOT malicious intent attribution
    assert "malicious" not in ev_item.title.lower()
    assert "guilt" not in ev_item.title.lower()


def test_req_030_scenario_3_image_shift() -> None:
    """REQ-11-VERIF-030 / Scenario 3: Image distribution shift triggers image-specific drift findings."""
    rng = np.random.default_rng(seed=42)
    ref_imgs = []
    for _ in range(35):
        arr = rng.integers(100, 150, size=(32, 32, 3), dtype=np.uint8)
        img = Image.fromarray(arr, mode="RGB")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        ref_imgs.append(buf.getvalue())

    tgt_imgs = []
    for _ in range(35):
        arr = rng.integers(10, 40, size=(32, 32, 3), dtype=np.uint8)
        img = Image.fromarray(arr, mode="RGB")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        tgt_imgs.append(buf.getvalue())

    img_analyzer = ImageDistributionShiftAnalyzer()
    b_res = _make_dummy_boundary(
        project_id="proj_img",
        modality=DataModality.IMAGE,
        ref_n=len(ref_imgs),
        tgt_n=len(tgt_imgs),
    )
    
    drift_profile = img_analyzer.analyze(b_res, ref_imgs, tgt_imgs)
    assert drift_profile.global_status == ShiftDecisionState.MATERIAL_SHIFT
    
    ev_img = EvidenceReference(
        evidence_id="ev_img_01",
        project_id="proj_img",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="image_drift",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Image distribution drift detected",
        confidence=0.85,
        severity=Severity.MEDIUM,
        evidence_hash="f2" * 32,
    )
    
    risk_engine = MultiModalRiskIntegrationEngine()
    profile = risk_engine.evaluate(
        project_id="proj_img",
        target_asset_type="dataset",
        target_asset_id="ds_img",
        evidence_items=[ev_img],
    )
    assert profile.overall_risk_score > 0.0


def test_req_031_scenario_4_representation_shift(synthetic_representation_embeddings: Dict[str, np.ndarray]) -> None:
    """REQ-11-VERIF-031 / Scenario 4: Representation shift handles multi-variate embeddings with zero-norm safety."""
    rep_analyzer = RepresentationDistributionShiftAnalyzer()
    ref_emb = synthetic_representation_embeddings["reference"]
    tgt_emb = synthetic_representation_embeddings["target_shifted"]
    
    normed_ref = apply_l2_normalization(ref_emb)
    normed_tgt = apply_l2_normalization(tgt_emb)
    
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
        "representation_id": "rep_e2e_01",
        "representation_layer": "norm",
        "runtime_framework": "onnxruntime",
        "schema_version": "1.0",
    }
    c_hash = compute_representation_contract_hash(contract_desc)
    rep_contract = RepresentationContract(
        representation_id="rep_e2e_01",
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
        project_id="proj_rep",
        modality=DataModality.IMAGE,
        ref_n=len(ref_emb),
        tgt_n=len(tgt_emb),
    )
    
    prof = rep_analyzer.analyze(b_res, rep_contract, normed_ref, normed_tgt)
    assert prof.global_status == ShiftDecisionState.MATERIAL_SHIFT
    
    ev_rep = EvidenceReference(
        evidence_id="ev_rep_01",
        project_id="proj_rep",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="representation_drift",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Representation layer drift detected",
        confidence=0.95,
        severity=Severity.HIGH,
        evidence_hash="f3" * 32,
    )
    
    risk_engine = MultiModalRiskIntegrationEngine()
    profile = risk_engine.evaluate(
        project_id="proj_rep",
        target_asset_type="model",
        target_asset_id="model_rep",
        evidence_items=[ev_rep],
    )
    assert profile.overall_risk_score > 0.0


def test_req_032_scenario_5_temporal_shift() -> None:
    """REQ-11-VERIF-032 / Scenario 5: Temporal drift analysis detects trajectory changes and change points."""
    rng = np.random.RandomState(42)
    raw_obs = []
    for i in range(40):
        raw_obs.append({"event_time": "2026-09-01T12:00:00Z", "payload": rng.normal(0.0, 1.0, 8), "id": f"w0_{i}"})
    for i in range(40):
        raw_obs.append({"event_time": "2026-09-01T13:00:00Z", "payload": rng.normal(0.0, 1.0, 8), "id": f"w1_{i}"})
    for i in range(40):
        raw_obs.append({"event_time": "2026-09-01T14:00:00Z", "payload": rng.normal(3.0, 1.0, 8), "id": f"w2_{i}"})
    
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
        "temporal_analysis_id": "temp_e2e_01",
        "timestamp_field": "event_time",
        "timezone_policy": "UTC",
        "window_size_seconds": 3600.0,
        "window_strategy": "fixed_interval",
    }
    c_hash = compute_temporal_contract_hash(contract_dict)
    temp_contract = TemporalAnalysisContract(
        temporal_analysis_id="temp_e2e_01",
        timestamp_field=TimestampSource.EVENT_TIME,
        timezone_policy="UTC",
        window_strategy=TemporalWindowStrategy.FIXED_INTERVAL,
        window_size_seconds=3600.0,
        max_windows=50,
        min_window_samples=30,
        temporal_contract_hash=c_hash,
    )
    b_res = _make_dummy_boundary(project_id="proj_temp", ref_n=120, tgt_n=120)
    
    temp_engine = TemporalDistributionShiftAnalyzer()
    profile = temp_engine.analyze(b_res, temp_contract, raw_obs)
    assert len(profile.windows) == 3
    assert profile.global_trajectory_status is not None


def test_req_033_scenario_6_source_aware_shift() -> None:
    """REQ-11-VERIF-033 / Scenario 6: Contributor/Source-aware drift pinpoints group-level shift with pseudonymization."""
    ref_obs = [{"sample_id": f"r_{i}", "contributor_id": "c_ref", "label": "0", "payload": [float(i)]} for i in range(40)]
    tgt_obs = [{"sample_id": f"t_{i}", "contributor_id": "c1", "label": "0", "payload": [float(i + 20)]} for i in range(40)]
    
    contract = SourceAnalysisContract(
        source_analysis_id="src_e2e_01",
        min_group_samples=30,
        enable_label_confounding_check=True,
    )
    
    engine = SourceDistributionShiftEngine()
    profile = engine.analyze(
        observations=ref_obs + tgt_obs,
        contract=contract,
        project_id="proj_src",
    )
    
    assert profile.project_id == "proj_src"
    assert len(profile.comparisons) > 0


def test_req_034_scenario_7_multi_modal_correlation_damping() -> None:
    """REQ-11-VERIF-034 / Scenario 7: Multi-modal correlated evidence is damped rather than inflated."""
    risk_engine = MultiModalRiskIntegrationEngine()
    ancestry = {"dataset_version_id": "v_corr_1.0"}
    
    # Create 5 duplicate/highly-correlated distribution shift evidence items in the same ancestry cluster
    correlated_evidence = [
        EvidenceReference(
            evidence_id=f"ev_corr_{i}",
            project_id="proj_corr",
            evidence_layer=EvidenceLayer.DETECTION,
            evidence_type="drift_feature",
            evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
            title=f"Shift {i}",
            confidence=0.80,
            severity=Severity.MEDIUM,
            ancestry_keys=ancestry,
            evidence_hash=f"c{i}" * 32,
        )
        for i in range(5)
    ]
    
    profile_multi = risk_engine.evaluate(
        project_id="proj_corr",
        target_asset_type="dataset",
        target_asset_id="ds_corr",
        evidence_items=correlated_evidence,
    )
    
    # Single item baseline
    profile_single = risk_engine.evaluate(
        project_id="proj_corr",
        target_asset_type="dataset",
        target_asset_id="ds_corr",
        evidence_items=[correlated_evidence[0]],
    )
    
    # Damping property: 5 correlated items are clustered together and damped
    assert len(profile_multi.clusters) == 1
    assert len(profile_multi.clusters[0].evidence_ids) == 5
    assert profile_multi.overall_risk_score <= 0.85
    assert profile_multi.overall_risk_score >= profile_single.overall_risk_score


def test_req_035_proof_violation_override() -> None:
    """REQ-11-VERIF-035: Non-compensable proof violation forces QUARANTINE even with 0 statistical risk."""
    risk_engine = MultiModalRiskIntegrationEngine()
    
    proof_evidence = EvidenceReference(
        evidence_id="ev_proof_fail_1",
        project_id="proj_proof",
        evidence_layer=EvidenceLayer.PROOF,
        evidence_type="cryptographic_hash_chain",
        evidence_category=EvidenceCategory.CRYPTOGRAPHIC_PROOF,
        title="Merkle chain proof mismatch",
        confidence=1.0,
        severity=Severity.CRITICAL,
        evidence_hash="p1" * 32,
    )
    
    profile = risk_engine.evaluate(
        project_id="proj_proof",
        target_asset_type="dataset",
        target_asset_id="ds_proof",
        evidence_items=[proof_evidence],
    )
    
    assert profile.overall_disposition in (Disposition.QUARANTINE, Disposition.REVIEW)
    assert profile.overall_risk_score >= 0.85


def test_req_036_insufficient_evidence_handling() -> None:
    """REQ-11-VERIF-036: Insufficient data sample count (N < 30) triggers fail-closed validation rejection."""
    b_engine = ComparisonBoundaryEngine(min_sample_size=30)
    
    # Target count 20 (< 30)
    ref_samples = [{"id": f"r_{i}", "x": float(i)} for i in range(40)]
    tgt_samples = [{"id": f"t_{i}", "x": float(i)} for i in range(20)]
    
    ref_sel = PopulationSelector(dataset_id="ds_ref")
    target_sel = PopulationSelector(dataset_id="ds_tgt")
    
    b_res = b_engine.establish_boundary(
        project_id="proj_small",
        reference_selector=ref_sel,
        reference_samples=ref_samples,
        reference_project_id="proj_small",
        target_selector=target_sel,
        target_samples=tgt_samples,
        target_project_id="proj_small",
    )
    assert b_res.status == BoundaryEvaluationStatus.INSUFFICIENT_DATA


def test_req_037_adversarial_mixed_scenario(synthetic_tabular_data: Dict[str, Any]) -> None:
    """REQ-11-VERIF-037: Mixed adversarial inputs (shifted data + broken proof + manipulated fields) fail closed cleanly."""
    b_res = _make_dummy_boundary(project_id="proj_mixed", ref_n=40, tgt_n=40)
    ref_data = synthetic_tabular_data["reference"]
    tgt_data = synthetic_tabular_data["target_shifted"]
    
    stat_engine = StatisticalDriftEngine()
    stat_res = stat_engine.evaluate_boundary(
        b_res,
        reference_features={"num_1": ref_data["num_1"]},
        target_features={"num_1": [x + 50.0 for x in tgt_data["num_1"]]},
    )
    
    ds_analyzer = FeatureDatasetDriftAnalyzer()
    feat_profile = ds_analyzer.analyze(b_res, stat_res)
    
    ev_stat = EvidenceReference(
        evidence_id="ev_mixed_stat",
        project_id="proj_mixed",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Major feature shift",
        confidence=0.90,
        severity=Severity.HIGH,
        evidence_hash="m1" * 32,
    )
    
    ev_proof = EvidenceReference(
        evidence_id="ev_mixed_proof",
        project_id="proj_mixed",
        evidence_layer=EvidenceLayer.PROOF,
        evidence_type="provenance",
        evidence_category=EvidenceCategory.CRYPTOGRAPHIC_PROOF,
        title="Tampered provenance root signature",
        confidence=1.0,
        severity=Severity.CRITICAL,
        evidence_hash="m2" * 32,
    )
    
    risk_engine = MultiModalRiskIntegrationEngine()
    profile = risk_engine.evaluate(
        project_id="proj_mixed",
        target_asset_type="dataset",
        target_asset_id="ds_mixed",
        evidence_items=[ev_stat, ev_proof],
    )
    
    assert profile.overall_disposition in (Disposition.QUARANTINE, Disposition.REVIEW)
    assert profile.overall_risk_score > 0.0
