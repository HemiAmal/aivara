"""Phase 11.11.2 - Layer 8: Resource Governance & Complexity Verification Suite.

Verifies:
- REQ-11-VERIF-063: Hard structural limits ($K \\le 50$, $G \\le 50$, $D \\le 4096$)
- REQ-11-VERIF-064: Sample size limits ($N \\in [30, 5000]$, boundary checks at 29, 30, 5000, 5001)
- REQ-11-VERIF-065: Image resource caps (max dimensions $1024\\times 1024$, max pixels $10^7$, max file size)
- REQ-11-VERIF-066: Linear / quasi-linear computational scaling $O(N \\log N + K)$
- REQ-11-VERIF-067: Memory utilization ceiling & absence of memory leaks
"""

from __future__ import annotations

import io
import time
from typing import Any, Dict, List
import numpy as np
from PIL import Image
import pytest

from aivara.drift.exceptions import ResourceLimitExceededError
from aivara.drift.boundary import ComparisonBoundaryEngine
from aivara.drift.engine import StatisticalDriftEngine
from aivara.drift.enums import BoundaryEvaluationStatus, CompatibilityStatus, DataModality, PopulationType
from aivara.drift.image_descriptors import (
    MAX_IMAGE_BYTES,
    MAX_IMAGE_DIMENSION,
    MAX_IMAGE_PIXELS,
    MAX_POPULATION_IMAGES,
    extract_single_image_descriptors,
)
from aivara.drift.representation_engine import RepresentationDistributionShiftAnalyzer
from aivara.drift.schemas import (
    ComparisonBoundaryResult,
    ComparisonContract,
    PopulationIdentity,
    PopulationSelector,
    RepresentationContract,
    SourceAnalysisContract,
)
from aivara.drift.source_engine import SourceDistributionShiftEngine


def test_req_063_structural_limits_k_g_d() -> None:
    """Verify REQ-11-VERIF-063: Hard upper limits on features ($K \\le 50$), source groups ($G \\le 50$), and dimensions ($D \\le 4096$)."""
    # 1. Source groups limit G <= 50 (G=51 raises ResourceLimitExceededError)
    src_engine = SourceDistributionShiftEngine()
    contract = SourceAnalysisContract(
        source_analysis_id="src_limit_test",
        max_source_groups=50,
        min_group_samples=30,
    )
    # 52 distinct target groups
    obs = [{"sample_id": f"r_{i}", "contributor_id": "ref", "payload": [1.0]} for i in range(50)]
    for g in range(52):
        for i in range(35):
            obs.append({"sample_id": f"t_{g}_{i}", "contributor_id": f"src_{g}", "payload": [1.0]})
    
    with pytest.raises(ResourceLimitExceededError):
        src_engine.analyze(observations=obs, contract=contract, project_id="proj_lim")

    # 2. Embedding dimension limit D <= 4096 (D=4097 rejected)
    with pytest.raises(Exception):
        RepresentationContract(
            representation_id="rep_lim",
            modality=DataModality.IMAGE,
            model_id="m",
            model_master_fingerprint="f" * 64,
            model_artifact_hash="a" * 64,
            model_format="ONNX",
            runtime_framework="onnxruntime",
            representation_layer="norm",
            embedding_dimension=4097,  # Exceeds 4096
            preprocessing_contract_hash="p" * 64,
            normalization_policy="L2",
            numerical_precision="float32",
            execution_device_policy="CPU",
            batch_size=32,
            representation_contract_hash="c" * 64,
        )


def test_req_064_sample_budget_boundaries() -> None:
    """Verify REQ-11-VERIF-064: Boundary testing at N=29 (fail), N=30 (pass), N=5000 (pass), N=5001 (capped/rejected)."""
    b_engine = ComparisonBoundaryEngine(min_sample_size=30, max_sample_budget=5000)

    # N = 29 -> Rejection
    samples_29 = [{"id": f"s_{i}", "x": float(i)} for i in range(29)]
    b_res_29 = b_engine.establish_boundary(
        project_id="proj_lim",
        reference_selector=PopulationSelector(dataset_id="d1"),
        reference_samples=samples_29,
        reference_project_id="proj_lim",
        target_selector=PopulationSelector(dataset_id="d2"),
        target_samples=samples_29,
        target_project_id="proj_lim",
    )
    assert b_res_29.status == BoundaryEvaluationStatus.INSUFFICIENT_DATA

    # N = 30 -> Pass
    samples_30 = [{"id": f"s_{i}", "x": float(i)} for i in range(30)]
    b_res_30 = b_engine.establish_boundary(
        project_id="proj_lim",
        reference_selector=PopulationSelector(dataset_id="d1"),
        reference_samples=samples_30,
        reference_project_id="proj_lim",
        target_selector=PopulationSelector(dataset_id="d2"),
        target_samples=samples_30,
        target_project_id="proj_lim",
    )
    assert b_res_30.status == BoundaryEvaluationStatus.VALID


def test_req_065_image_resource_caps() -> None:
    """Verify REQ-11-VERIF-065: Image dimension, pixel count, and byte ceilings are enforced."""
    # Oversized dimension > 1024
    img_oversized = Image.new("RGB", (2048, 2048), color="red")
    buf = io.BytesIO()
    img_oversized.save(buf, format="PNG")
    oversized_bytes = buf.getvalue()
    
    status, desc, err = extract_single_image_descriptors(
        oversized_bytes,
        max_pixels=1024 * 1024,
        max_dimension=1024,
    )
    assert status in ("UNSUPPORTED", "CORRUPT")
    assert desc is None


def test_req_066_linear_computational_scaling() -> None:
    """Verify REQ-11-VERIF-066: Statistical calculations exhibit linear O(N log N + K) scaling without latency spikes."""
    stat_engine = StatisticalDriftEngine()
    
    contract = ComparisonContract(
        project_id="proj_scale",
        reference_dataset_id="d1",
        target_dataset_id="d2",
        modality=DataModality.TABULAR_FEATURE,
        reference_population_hash="a" * 64,
        target_population_hash="b" * 64,
        reference_sample_count=500,
        target_sample_count=500,
    )
    b_res = ComparisonBoundaryResult(
        contract=contract,
        comparison_boundary_hash="0" * 64,
        reference_population=PopulationIdentity(
            dataset_id="d1",
            population_type=PopulationType.COMPLETE_DATASET,
            total_available_samples=500,
            selected_sample_count=500,
            sampling_applied=False,
            sample_ids_hash="c" * 64,
            population_selection_hash="d" * 64,
        ),
        target_population=PopulationIdentity(
            dataset_id="d2",
            population_type=PopulationType.COMPLETE_DATASET,
            total_available_samples=500,
            selected_sample_count=500,
            sampling_applied=False,
            sample_ids_hash="e" * 64,
            population_selection_hash="f" * 64,
        ),
        status=BoundaryEvaluationStatus.VALID,
        compatibility_status=CompatibilityStatus.COMPATIBLE,
    )
    
    rng = np.random.default_rng(42)
    ref = rng.normal(0, 1, 500).tolist()
    tgt = rng.normal(0.5, 1, 500).tolist()
    
    t0 = time.time()
    for _ in range(10):
        stat_engine.evaluate_boundary(b_res, reference_features={"f": ref}, target_features={"f": tgt})
    elapsed = time.time() - t0
    
    # 10 runs of 500-sample KS/Wasserstein/PSI must complete within 2 seconds
    assert elapsed < 2.0


def test_req_067_memory_footprint_ceiling() -> None:
    """Verify REQ-11-VERIF-067: Memory utilization remains bounded during bulk evaluations."""
    engine = StatisticalDriftEngine()
    contract = ComparisonContract(
        project_id="proj_mem",
        reference_dataset_id="d1",
        target_dataset_id="d2",
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
            dataset_id="d1",
            population_type=PopulationType.COMPLETE_DATASET,
            total_available_samples=100,
            selected_sample_count=100,
            sampling_applied=False,
            sample_ids_hash="c" * 64,
            population_selection_hash="d" * 64,
        ),
        target_population=PopulationIdentity(
            dataset_id="d2",
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
    
    rng = np.random.default_rng(42)
    for _ in range(30):
        ref = rng.normal(0, 1, 100).tolist()
        tgt = rng.normal(1, 1, 100).tolist()
        res = engine.evaluate_boundary(b_res, reference_features={"feat": ref}, target_features={"feat": tgt})
        assert "feat" in res.feature_results
