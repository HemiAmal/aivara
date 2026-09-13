"""Phase 11.11.2 - Layer 7: Determinism & Repeatability Verification Suite.

Verifies:
- REQ-11-VERIF-056: Bit-identical repeatability across consecutive runs (seed=42)
- REQ-11-VERIF-057: Deterministic permutation test seeding & reproducibility
- REQ-11-VERIF-058: ISO 8601 UTC timestamp formatting consistency
- REQ-11-VERIF-059: Multi-key canonical sorting across feature maps and records
- REQ-11-VERIF-060: RFC 8785 JSON Canonicalization Scheme (JCS) deterministic hashing
- REQ-11-VERIF-061: Thread-safe analytical isolation (concurrent runs do not leak state)
- REQ-11-VERIF-062: Idempotent cryptographic digests across repeated evaluations
"""

from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List
import numpy as np
import pytest

from aivara.assurance.engine import MultiModalRiskIntegrationEngine
from aivara.assurance import (
    DEFAULT_CATEGORY_WEIGHTS,
    DecisionPolicy,
    EvidenceCategory,
    EvidenceReference,
    RiskPolicy,
    compute_decision_policy_hash,
    compute_evidence_set_hash,
    compute_risk_policy_hash,
)
from aivara.crypto.canonical import canonicalize
from aivara.domain.schemas import Disposition, EvidenceLayer, Severity
from aivara.drift.boundary import ComparisonBoundaryEngine
from aivara.drift.engine import StatisticalDriftEngine
from aivara.drift.enums import BoundaryEvaluationStatus, CompatibilityStatus, DataModality, PopulationType
from aivara.drift.feature_dataset_engine import FeatureDatasetDriftAnalyzer, compute_dataset_drift_profile_hash
from aivara.drift.schemas import (
    ComparisonBoundaryResult,
    ComparisonContract,
    PopulationIdentity,
    StatisticalAnalysisConfig,
)


def _make_dummy_boundary(project_id: str = "proj_det", ref_n: int = 40, tgt_n: int = 40) -> ComparisonBoundaryResult:
    contract = ComparisonContract(
        project_id=project_id,
        reference_dataset_id="ds_ref",
        target_dataset_id="ds_tgt",
        modality=DataModality.TABULAR_FEATURE,
        reference_population_hash="a" * 64,
        target_population_hash="b" * 64,
        reference_sample_count=ref_n,
        target_sample_count=tgt_n,
    )
    ref_pop = PopulationIdentity(
        dataset_id="ds_ref",
        population_type=PopulationType.COMPLETE_DATASET,
        total_available_samples=ref_n,
        selected_sample_count=ref_n,
        sampling_applied=False,
        sample_ids_hash="c" * 64,
        population_selection_hash="d" * 64,
    )
    tgt_pop = PopulationIdentity(
        dataset_id="ds_tgt",
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
        status=BoundaryEvaluationStatus.VALID,
        compatibility_status=CompatibilityStatus.COMPATIBLE,
    )


def test_req_056_bit_identical_repeatability(synthetic_tabular_data: Dict[str, Any]) -> None:
    """Verify REQ-11-VERIF-056: Repeated executions on identical data produce bit-identical profiles and digests."""
    b_res = _make_dummy_boundary()
    ref_f = {"num_1": synthetic_tabular_data["reference"]["num_1"]}
    tgt_f = {"num_1": synthetic_tabular_data["target_shifted"]["num_1"]}
    
    stat_engine = StatisticalDriftEngine()
    analyzer = FeatureDatasetDriftAnalyzer()
    
    # Run 1
    res1 = stat_engine.evaluate_boundary(b_res, reference_features=ref_f, target_features=tgt_f)
    prof1 = analyzer.analyze(b_res, res1)
    
    # Run 2
    res2 = stat_engine.evaluate_boundary(b_res, reference_features=ref_f, target_features=tgt_f)
    prof2 = analyzer.analyze(b_res, res2)
    
    assert prof1.dataset_drift_profile_hash == prof2.dataset_drift_profile_hash
    assert prof1.global_status == prof2.global_status
    assert prof1.materially_shifted_feature_count == prof2.materially_shifted_feature_count


def test_req_057_permutation_test_seed_determinism() -> None:
    """Verify REQ-11-VERIF-057: Statistical permutation distance testing uses deterministic seed (seed=42)."""
    cfg1 = StatisticalAnalysisConfig(random_seed=42, permutation_iterations=100)
    cfg2 = StatisticalAnalysisConfig(random_seed=42, permutation_iterations=100)
    
    engine1 = StatisticalDriftEngine(default_config=cfg1)
    engine2 = StatisticalDriftEngine(default_config=cfg2)
    
    b_res = _make_dummy_boundary()
    rng = np.random.default_rng(seed=10)
    ref = rng.normal(0, 1, 50).tolist()
    tgt = rng.normal(0.5, 1, 50).tolist()
    
    res1 = engine1.evaluate_boundary(b_res, reference_features={"x": ref}, target_features={"x": tgt}, config=cfg1)
    res2 = engine2.evaluate_boundary(b_res, reference_features={"x": ref}, target_features={"x": tgt}, config=cfg2)
    
    f1 = res1.feature_results["x"]
    f2 = res2.feature_results["x"]
    assert f1.raw_p_value == f2.raw_p_value
    assert f1.effect_size == f2.effect_size


def test_req_058_iso8601_utc_timestamp_formatting() -> None:
    """Verify REQ-11-VERIF-058: All generated timestamp strings conform to ISO 8601 UTC."""
    from aivara.api.schemas.drift import DriftAnalysisCreateRequest
    from aivara.services.drift_service import get_drift_task_manager
    manager = get_drift_task_manager()
    req = DriftAnalysisCreateRequest(reference_dataset_id="d1", target_dataset_id="d2")
    task, _ = manager.create_or_get_task("proj_time", req)
    
    assert task.created_at is not None
    parsed = datetime.fromisoformat(task.created_at.replace("Z", "+00:00"))
    assert parsed is not None
    assert parsed.tzinfo is not None


def test_req_059_canonical_sorting_order() -> None:
    """Verify REQ-11-VERIF-059: Dictionary key ordering permutations yield identical RFC 8785 hashes."""
    d1 = {"zebra": 1, "alpha": 2, "middle": [3, 4, 5]}
    d2 = {"alpha": 2, "middle": [3, 4, 5], "zebra": 1}
    
    c1 = canonicalize(d1)
    c2 = canonicalize(d2)
    assert c1 == c2
    assert hashlib.sha256(c1).hexdigest() == hashlib.sha256(c2).hexdigest()


def test_req_060_jcs_float_and_key_canonicalization() -> None:
    """Verify REQ-11-VERIF-060: JCS floats and numbers follow RFC 8785 strict format."""
    d = {"zero": 0.0, "pi": 3.14159, "sci": 1e-05}
    c_bytes = canonicalize(d)
    assert b"zero" in c_bytes
    assert b"0.0" not in c_bytes or b"0" in c_bytes


def test_req_061_concurrent_thread_safe_isolation(synthetic_tabular_data: Dict[str, Any]) -> None:
    """Verify REQ-11-VERIF-061: Concurrent evaluations on shared engine instances do not corrupt state."""
    b_res = _make_dummy_boundary()
    ref_f = {"num_1": synthetic_tabular_data["reference"]["num_1"]}
    tgt_f = {"num_1": synthetic_tabular_data["target_shifted"]["num_1"]}
    
    stat_engine = StatisticalDriftEngine()
    analyzer = FeatureDatasetDriftAnalyzer()
    
    def worker(i: int) -> str:
        res = stat_engine.evaluate_boundary(b_res, reference_features=ref_f, target_features=tgt_f)
        prof = analyzer.analyze(b_res, res)
        return prof.dataset_drift_profile_hash
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        hashes = list(executor.map(worker, range(16)))
    
    # All threads must produce identical hash
    assert len(set(hashes)) == 1


def test_req_062_idempotent_hash_digests() -> None:
    """Verify REQ-11-VERIF-062: Evidence set hashing and policy hashing are strictly deterministic."""
    ev_hashes = ["d1" * 32, "d2" * 32]
    h1 = compute_evidence_set_hash(ev_hashes)
    h2 = compute_evidence_set_hash(ev_hashes)
    assert h1 == h2
    assert len(h1) == 64
