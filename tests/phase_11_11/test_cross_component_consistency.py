"""Layer 3: Cross-Component Consistency Verification.

Covers:
- REQ-11-VERIF-021: Cross-engine population count reconciliation
- REQ-11-VERIF-022: Population contract digest immutability across engines
- REQ-11-VERIF-023: Schema definition symmetry across engines
- REQ-11-VERIF-024: Consistent dual-gating threshold application
- REQ-11-VERIF-025: Descriptive finding type taxonomy consistency
- REQ-11-VERIF-026: Consistent evidence layer categorization
- REQ-11-VERIF-027: Zero duplicate statistical engine instances
"""

from __future__ import annotations

import ast
import glob
import os
from typing import Any, Dict, List
import pytest

from aivara.drift.boundary import ComparisonBoundaryEngine
from aivara.drift.engine import StatisticalDriftEngine
from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    CompatibilityStatus,
    DataModality,
    PopulationType,
    ShiftDecisionState,
)
from aivara.drift.feature_dataset_engine import FeatureDatasetDriftAnalyzer
from aivara.drift.schemas import (
    ComparisonBoundaryResult,
    ComparisonContract,
    FeatureSchemaDescriptor,
    PopulationIdentity,
    PopulationSelector,
    StatisticalAnalysisConfig,
)
from aivara.domain.schemas import EvidenceLayer


def test_req_021_cross_engine_population_count_reconciliation(synthetic_tabular_data: Dict[str, Any]) -> None:
    """Verify REQ-11-VERIF-021: Reference and target sample counts match exactly between boundary, stats, and feature profiles."""
    ref_data = synthetic_tabular_data["reference"]["num_1"]
    tgt_data = synthetic_tabular_data["target_shifted"]["num_1"]

    contract = ComparisonContract(
        project_id="proj_alpha",
        reference_dataset_id="ds_ref",
        target_dataset_id="ds_tgt",
        modality=DataModality.TABULAR_FEATURE,
        reference_population_hash="a" * 64,
        target_population_hash="b" * 64,
        reference_sample_count=len(ref_data),
        target_sample_count=len(tgt_data),
    )
    b_res = ComparisonBoundaryResult(
        contract=contract,
        comparison_boundary_hash="0" * 64,
        reference_population=PopulationIdentity(
            dataset_id="ds_ref",
            population_type=PopulationType.COMPLETE_DATASET,
            total_available_samples=len(ref_data),
            selected_sample_count=len(ref_data),
            sampling_applied=False,
            sample_ids_hash="c" * 64,
            population_selection_hash="d" * 64,
        ),
        target_population=PopulationIdentity(
            dataset_id="ds_tgt",
            population_type=PopulationType.COMPLETE_DATASET,
            total_available_samples=len(tgt_data),
            selected_sample_count=len(tgt_data),
            sampling_applied=False,
            sample_ids_hash="e" * 64,
            population_selection_hash="f" * 64,
        ),
        status=BoundaryEvaluationStatus.VALID,
        compatibility_status=CompatibilityStatus.COMPATIBLE,
    )

    stat_engine = StatisticalDriftEngine()
    stat_res = stat_engine.evaluate_boundary(
        b_res,
        reference_features={"num_1": ref_data},
        target_features={"num_1": tgt_data},
    )

    feat_analyzer = FeatureDatasetDriftAnalyzer()
    feat_profile = feat_analyzer.analyze(b_res, stat_res)

    assert b_res.contract.reference_sample_count == len(ref_data)
    assert b_res.contract.target_sample_count == len(tgt_data)
    assert stat_res.feature_results["num_1"].reference_sample_count == len(ref_data)
    assert stat_res.feature_results["num_1"].target_sample_count == len(tgt_data)
    assert feat_profile.all_feature_profiles["num_1"].reference_count == len(ref_data)
    assert feat_profile.all_feature_profiles["num_1"].target_count == len(tgt_data)


def test_req_022_population_contract_digest_immutability(synthetic_tabular_data: Dict[str, Any]) -> None:
    """Verify REQ-11-VERIF-022: comparison_boundary_hash is propagated immutably across downstream profiles."""
    ref_data = synthetic_tabular_data["reference"]["num_1"]
    tgt_data = synthetic_tabular_data["target_shifted"]["num_1"]

    boundary_engine = ComparisonBoundaryEngine()
    contract = ComparisonContract(
        project_id="proj_alpha",
        reference_dataset_id="ds_ref",
        target_dataset_id="ds_tgt",
        modality=DataModality.TABULAR_FEATURE,
        reference_population_hash="a" * 64,
        target_population_hash="b" * 64,
        reference_sample_count=len(ref_data),
        target_sample_count=len(tgt_data),
    )
    b_hash = boundary_engine.compute_boundary_hash(contract)
    b_res = ComparisonBoundaryResult(
        contract=contract,
        comparison_boundary_hash=b_hash,
        reference_population=PopulationIdentity(
            dataset_id="ds_ref",
            population_type=PopulationType.COMPLETE_DATASET,
            total_available_samples=len(ref_data),
            selected_sample_count=len(ref_data),
            sampling_applied=False,
            sample_ids_hash="c" * 64,
            population_selection_hash="d" * 64,
        ),
        target_population=PopulationIdentity(
            dataset_id="ds_tgt",
            population_type=PopulationType.COMPLETE_DATASET,
            total_available_samples=len(tgt_data),
            selected_sample_count=len(tgt_data),
            sampling_applied=False,
            sample_ids_hash="e" * 64,
            population_selection_hash="f" * 64,
        ),
        status=BoundaryEvaluationStatus.VALID,
        compatibility_status=CompatibilityStatus.COMPATIBLE,
    )

    stat_engine = StatisticalDriftEngine()
    stat_res = stat_engine.evaluate_boundary(
        b_res,
        reference_features={"num_1": ref_data},
        target_features={"num_1": tgt_data},
    )
    feat_analyzer = FeatureDatasetDriftAnalyzer()
    feat_profile = feat_analyzer.analyze(b_res, stat_res)

    assert stat_res.comparison_boundary_hash == b_hash
    assert feat_profile.comparison_boundary_hash == b_hash


def test_req_023_schema_definition_symmetry(synthetic_tabular_data: Dict[str, Any]) -> None:
    """Verify REQ-11-VERIF-023: Feature names and count symmetry across boundary and feature profiles."""
    ref_features = {
        "num_1": synthetic_tabular_data["reference"]["num_1"],
        "num_2": synthetic_tabular_data["reference"]["num_2"],
    }
    tgt_features = {
        "num_1": synthetic_tabular_data["target_shifted"]["num_1"],
        "num_2": synthetic_tabular_data["target_shifted"]["num_2"],
    }

    contract = ComparisonContract(
        project_id="proj_alpha",
        reference_dataset_id="ds_ref",
        target_dataset_id="ds_tgt",
        modality=DataModality.TABULAR_FEATURE,
        reference_population_hash="a" * 64,
        target_population_hash="b" * 64,
        reference_sample_count=len(ref_features["num_1"]),
        target_sample_count=len(tgt_features["num_1"]),
    )
    b_res = ComparisonBoundaryResult(
        contract=contract,
        comparison_boundary_hash="0" * 64,
        reference_population=PopulationIdentity(
            dataset_id="ds_ref",
            population_type=PopulationType.COMPLETE_DATASET,
            total_available_samples=100,
            selected_sample_count=100,
            sampling_applied=False,
            sample_ids_hash="c" * 64,
            population_selection_hash="d" * 64,
        ),
        target_population=PopulationIdentity(
            dataset_id="ds_tgt",
            population_type=PopulationType.COMPLETE_DATASET,
            total_available_samples=100,
            selected_sample_count=100,
            sampling_applied=False,
            sample_ids_hash="e" * 64,
            population_selection_hash="f" * 64,
        ),
        status=BoundaryEvaluationStatus.VALID,
        compatibility_status=CompatibilityStatus.COMPATIBLE,
    )

    stat_engine = StatisticalDriftEngine()
    stat_res = stat_engine.evaluate_boundary(b_res, reference_features=ref_features, target_features=tgt_features)
    feat_analyzer = FeatureDatasetDriftAnalyzer()
    feat_profile = feat_analyzer.analyze(b_res, stat_res)

    assert set(feat_profile.all_feature_profiles.keys()) == set(ref_features.keys())
    assert feat_profile.total_features_evaluated == 2


def test_req_024_consistent_dual_gating_threshold_application(synthetic_tabular_data: Dict[str, Any]) -> None:
    """Verify REQ-11-VERIF-024: Shift decision requires BOTH statistical significance and physical effect."""
    stat_engine = StatisticalDriftEngine()
    # Continuous feature evaluation
    ref = synthetic_tabular_data["reference"]["num_1"]
    tgt = synthetic_tabular_data["target_shifted"]["num_1"]

    contract = ComparisonContract(
        project_id="proj_alpha",
        reference_dataset_id="ds_ref",
        target_dataset_id="ds_tgt",
        modality=DataModality.TABULAR_FEATURE,
        reference_population_hash="a" * 64,
        target_population_hash="b" * 64,
        reference_sample_count=len(ref),
        target_sample_count=len(tgt),
    )
    b_res = ComparisonBoundaryResult(
        contract=contract,
        comparison_boundary_hash="0" * 64,
        reference_population=PopulationIdentity(
            dataset_id="ds_ref",
            population_type=PopulationType.COMPLETE_DATASET,
            total_available_samples=len(ref),
            selected_sample_count=len(ref),
            sampling_applied=False,
            sample_ids_hash="c" * 64,
            population_selection_hash="d" * 64,
        ),
        target_population=PopulationIdentity(
            dataset_id="ds_tgt",
            population_type=PopulationType.COMPLETE_DATASET,
            total_available_samples=len(tgt),
            selected_sample_count=len(tgt),
            sampling_applied=False,
            sample_ids_hash="e" * 64,
            population_selection_hash="f" * 64,
        ),
        status=BoundaryEvaluationStatus.VALID,
        compatibility_status=CompatibilityStatus.COMPATIBLE,
    )

    res = stat_engine.evaluate_boundary(b_res, reference_features={"num_1": ref}, target_features={"num_1": tgt})
    feat_res = res.feature_results["num_1"]
    # Dual gate assert
    assert (feat_res.status == ShiftDecisionState.MATERIAL_SHIFT) == (
        feat_res.is_statistically_significant and feat_res.is_practically_significant
    )


def test_req_025_descriptive_finding_type_taxonomy(synthetic_tabular_data: Dict[str, Any]) -> None:
    """Verify REQ-11-VERIF-025: Standardized descriptive finding type taxonomy across findings."""
    stat_engine = StatisticalDriftEngine()
    ref_features = {"num_1": synthetic_tabular_data["reference"]["num_1"]}
    tgt_features = {"num_1": synthetic_tabular_data["target_shifted"]["num_1"]}

    contract = ComparisonContract(
        project_id="proj_alpha",
        reference_dataset_id="ds_ref",
        target_dataset_id="ds_tgt",
        modality=DataModality.TABULAR_FEATURE,
        reference_population_hash="a" * 64,
        target_population_hash="b" * 64,
        reference_sample_count=100,
        target_sample_count=100,
    )
    b_res = ComparisonBoundaryResult(
        contract=contract,
        comparison_boundary_hash="0" * 64,
        reference_population=PopulationIdentity(
            dataset_id="ds_ref",
            population_type=PopulationType.COMPLETE_DATASET,
            total_available_samples=100,
            selected_sample_count=100,
            sampling_applied=False,
            sample_ids_hash="c" * 64,
            population_selection_hash="d" * 64,
        ),
        target_population=PopulationIdentity(
            dataset_id="ds_tgt",
            population_type=PopulationType.COMPLETE_DATASET,
            total_available_samples=100,
            selected_sample_count=100,
            sampling_applied=False,
            sample_ids_hash="e" * 64,
            population_selection_hash="f" * 64,
        ),
        status=BoundaryEvaluationStatus.VALID,
        compatibility_status=CompatibilityStatus.COMPATIBLE,
    )

    stat_res = stat_engine.evaluate_boundary(b_res, reference_features=ref_features, target_features=tgt_features)
    analyzer = FeatureDatasetDriftAnalyzer()
    profile = analyzer.analyze(b_res, stat_res)

    for finding in profile.findings:
        assert finding["finding_type"] in (
            "dataset_distribution_shift",
            "feature_distribution_shift",
            "feature_dataset_drift",
            "label_distribution_shift",
            "insufficient_data",
        )


def test_req_026_evidence_layer_categorization(synthetic_tabular_data: Dict[str, Any]) -> None:
    """Verify REQ-11-VERIF-026: All distribution shift evidence records are explicitly labeled detection."""
    stat_engine = StatisticalDriftEngine()
    ref_features = {"num_1": synthetic_tabular_data["reference"]["num_1"]}
    tgt_features = {"num_1": synthetic_tabular_data["target_shifted"]["num_1"]}

    contract = ComparisonContract(
        project_id="proj_alpha",
        reference_dataset_id="ds_ref",
        target_dataset_id="ds_tgt",
        modality=DataModality.TABULAR_FEATURE,
        reference_population_hash="a" * 64,
        target_population_hash="b" * 64,
        reference_sample_count=100,
        target_sample_count=100,
    )
    b_res = ComparisonBoundaryResult(
        contract=contract,
        comparison_boundary_hash="0" * 64,
        reference_population=PopulationIdentity(
            dataset_id="ds_ref",
            population_type=PopulationType.COMPLETE_DATASET,
            total_available_samples=100,
            selected_sample_count=100,
            sampling_applied=False,
            sample_ids_hash="c" * 64,
            population_selection_hash="d" * 64,
        ),
        target_population=PopulationIdentity(
            dataset_id="ds_tgt",
            population_type=PopulationType.COMPLETE_DATASET,
            total_available_samples=100,
            selected_sample_count=100,
            sampling_applied=False,
            sample_ids_hash="e" * 64,
            population_selection_hash="f" * 64,
        ),
        status=BoundaryEvaluationStatus.VALID,
        compatibility_status=CompatibilityStatus.COMPATIBLE,
    )

    stat_res = stat_engine.evaluate_boundary(b_res, reference_features=ref_features, target_features=tgt_features)
    analyzer = FeatureDatasetDriftAnalyzer()
    profile = analyzer.analyze(b_res, stat_res)

    for ev in profile.evidence_records:
        assert ev.get("evidence_layer") == "detection" or ev.get("evidence_layer") == EvidenceLayer.DETECTION.value


def test_req_027_zero_duplicate_statistical_engines() -> None:
    """Verify REQ-11-VERIF-027: AST scan verifies zero unauthorized scipy.stats imports outside engine modules."""
    backend_drift_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../backend/aivara/drift"))
    python_files = glob.glob(os.path.join(backend_drift_path, "*.py"))

    unauthorized_modules = []
    for filepath in python_files:
        filename = os.path.basename(filepath)
        # Stats are only implemented in stats_continuous.py, stats_categorical.py, stats_multivariate.py, engine.py
        with open(filepath, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=filename)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "scipy.stats" in alias.name:
                        unauthorized_modules.append(filename)
            elif isinstance(node, ast.ImportFrom):
                if node.module and "scipy.stats" in node.module:
                    unauthorized_modules.append(filename)

    assert len(unauthorized_modules) == 0, f"Found unauthorized scipy.stats in: {unauthorized_modules}"
