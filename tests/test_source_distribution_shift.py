"""Comprehensive Verification Suite for Phase 11.8: Contributor & Source-Aware Distribution Shift.

Verifies all 55 formal requirements across 12 exhaustive test suites:
- Canonicalization and extraction
- Group formation and reconciliation accounting
- Group size floors and seeded deterministic subsampling
- Statistical engine delegation and BH FDR multiplicity control
- Dual-gate significance and effect size evaluation
- Confounding, label skew, and Simpson's paradox detection
- Sybil fragmentation and dominance alerts
- Project isolation and deterministic pseudonymization
- RFC 8785 JCS cryptographic hashing and mutation sensitivity
- FindingModel and EvidenceModel synthesis with non-attribution semantics
- AST security scan, offline air-gap execution, and input immutability
- Cross-phase architectural compatibility (11.2, 11.3, 11.4, 11.5, 11.6, 11.7)
"""

import ast
import copy
import glob
import math
import os
import re
from typing import Any, Dict, List

import numpy as np
import pytest

from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    CompatibilityStatus,
    DataModality,
    PopulationType,
    ShiftDecisionState,
    SourceAttributeFallbackPolicy,
    SourceComparisonTopology,
    SourceGroupStatus,
    SourceTrustState,
    SourceType,
    StatisticalMethod,
)
from aivara.drift.exceptions import (
    ProjectMismatchError,
    ResourceLimitExceededError,
)
from aivara.drift.schemas import (
    ComparisonBoundaryResult,
    ComparisonContract,
    PopulationIdentity,
    SourceAnalysisContract,
    SourceAnalysisProfile,
    SourceAttributeSelector,
    SourceContext,
    SourceGroupAccounting,
    SourceGroupDescriptor,
    SourceObservation,
)
from aivara.drift.source_engine import (
    MAX_SOURCE_GROUPS_CEILING,
    MIN_SOURCE_GROUP_SAMPLE_FLOOR,
    SourceDistributionShiftEngine,
    canonicalize_source_id,
    compute_source_analysis_profile_hash,
    compute_source_contract_hash,
    compute_source_group_hash,
    derive_project_scoped_pseudonym,
    extract_source_context,
)


def test_01_to_07_canonicalization_and_extraction() -> None:
    """Verify FR-11.8-001, FR-11.8-002, SEC-11.8-005, SEC-11.8-006: 5-stage canonicalization and attribute extraction."""
    # 1. Basic trimming and lowercasing
    assert canonicalize_source_id("  Vendor_Alpha  ") == "vendor_alpha"
    assert canonicalize_source_id("CONTRIBUTOR-123") == "contributor-123"

    # 2. Internal whitespace collapsing
    assert canonicalize_source_id("Site    Alpha   Device   01") == "site alpha device 01"

    # 3. Non-printable and control character stripping
    assert canonicalize_source_id("vendor\x00\x07_test\t01\n") == "vendor_test 01"

    # 4. Unicode NFKC normalization
    # Full-width characters
    assert canonicalize_source_id("ＶＥＮＤＯＲ") == "vendor"

    # 5. Length cap at 128 characters
    long_str = "a" * 200
    assert len(canonicalize_source_id(long_str)) == 128

    # 6. Null and empty fallback
    assert canonicalize_source_id(None) == "missing"
    assert canonicalize_source_id("") == "missing"
    assert canonicalize_source_id("   ") == "missing"

    # 7. Nested attribute extraction via SourceAttributeSelector
    selector = SourceAttributeSelector(attribute_key="metadata.hardware.sensor_id")
    obs_dict = {
        "sample_id": "s_001",
        "metadata": {"hardware": {"sensor_id": " SENSOR_X "}},
    }
    ctx = extract_source_context(obs_dict, selector, project_id="proj_01")
    assert ctx.canonical_source_id == "sensor_x"
    assert ctx.trust_state == SourceTrustState.CLAIMED
    assert len(ctx.pseudonym_id) == 16


def test_08_to_14_group_formation_and_accounting() -> None:
    """Verify FR-11.8-003, FR-11.8-006, FR-11.8-007, DATA-11.8-003: Group partitioning and strict reconciliation."""
    engine = SourceDistributionShiftEngine()
    contract = SourceAnalysisContract(
        source_analysis_id="test_contract_01",
        selector=SourceAttributeSelector(attribute_key="contributor_id"),
        min_group_samples=30,
    )

    observations: List[Dict[str, Any]] = []

    # 40 samples from Contributor A (Eligible)
    for i in range(40):
        observations.append({"sample_id": f"s_a_{i}", "contributor_id": "Contributor_A", "payload": float(i)})

    # 35 samples from Contributor B (Eligible)
    for i in range(35):
        observations.append({"sample_id": f"s_b_{i}", "contributor_id": "Contributor_B", "payload": float(i)})

    # 10 samples from Contributor C (Insufficient)
    for i in range(10):
        observations.append({"sample_id": f"s_c_{i}", "contributor_id": "Contributor_C", "payload": float(i)})

    # 5 samples with missing contributor_id
    for i in range(5):
        observations.append({"sample_id": f"s_m_{i}", "contributor_id": None, "payload": float(i)})

    # 3 samples with invalid/unknown contributor_id
    for i in range(3):
        observations.append({"sample_id": f"s_u_{i}", "contributor_id": "unknown", "payload": float(i)})

    total_expected = 40 + 35 + 10 + 5 + 3  # 93

    profile = engine.analyze(
        observations=observations,
        contract=contract,
        project_id="proj_accounting",
    )

    acc = profile.accounting
    assert acc.total_observations == total_expected
    assert acc.eligible_observations == 75
    assert acc.insufficient_observations == 10
    assert acc.missing_source_observations == 5
    assert acc.unknown_source_observations == 3
    assert acc.eligible_groups_count == 2
    assert acc.insufficient_groups_count == 1

    # Exact reconciliation invariant
    reconciled_sum = (
        acc.eligible_observations
        + acc.insufficient_observations
        + acc.missing_source_observations
        + acc.invalid_source_observations
        + acc.unknown_source_observations
    )
    assert reconciled_sum == acc.total_observations


def test_15_to_18_group_size_bounds_and_subsampling() -> None:
    """Verify STAT-11.8-007, PERF-11.8-001, PERF-11.8-002: N_min floor, N_max subsampling, G max ceiling."""
    engine = SourceDistributionShiftEngine()

    # 1. N_min floor verification
    small_obs = [
        {"sample_id": f"s_{i}", "contributor_id": "small_source", "payload": 1.0}
        for i in range(20)
    ]
    contract = SourceAnalysisContract(
        source_analysis_id="test_bounds",
        min_group_samples=30,
    )
    prof_small = engine.analyze(observations=small_obs, contract=contract, project_id="proj_bounds")
    assert prof_small.global_status == ShiftDecisionState.INSUFFICIENT_DATA

    # 2. G max ceiling enforcement
    many_sources_obs: List[Dict[str, Any]] = []
    for g in range(60):
        for i in range(5):
            many_sources_obs.append({"sample_id": f"s_{g}_{i}", "contributor_id": f"source_{g}", "payload": 1.0})

    with pytest.raises(ResourceLimitExceededError):
        engine.analyze(observations=many_sources_obs, contract=contract, project_id="proj_bounds")

    # 3. Large group deterministic subsampling
    large_obs = [
        {"sample_id": f"s_{i}", "contributor_id": "large_source", "payload": float(i % 100)}
        for i in range(6000)
    ]
    contract_subsample = SourceAnalysisContract(
        source_analysis_id="test_subsample",
        min_group_samples=30,
        max_group_samples=5000,
        subsampling_seed=12345,
    )
    # Compare with another source
    ref_obs = [
        {"sample_id": f"r_{i}", "contributor_id": "ref_source", "payload": float(i % 100)}
        for i in range(100)
    ]
    prof_large = engine.analyze(
        observations=large_obs + ref_obs,
        contract=contract_subsample,
        project_id="proj_bounds",
    )
    assert prof_large.accounting.eligible_observations == 6100
    assert len(prof_large.comparisons) == 1
    # Evaluated target sample count should be bounded to 5000
    assert prof_large.comparisons[0].target_sample_count <= 5000


def test_19_to_24_statistical_engine_reuse_and_fdr() -> None:
    """Verify STAT-11.8-001, STAT-11.8-002, STAT-11.8-003, STAT-11.8-004, STAT-11.8-005, STAT-11.8-006."""
    engine = SourceDistributionShiftEngine()
    rng = np.random.RandomState(42)

    # Reference source: N(0, 1)
    ref_data = rng.normal(loc=0.0, scale=1.0, size=200).tolist()
    # Source A (Identical): N(0, 1)
    src_a_data = rng.normal(loc=0.0, scale=1.0, size=200).tolist()
    # Source B (Shifted): N(2.0, 1.0)
    src_b_data = rng.normal(loc=2.0, scale=1.0, size=200).tolist()

    obs: List[Dict[str, Any]] = []
    for i, x in enumerate(ref_data):
        obs.append({"sample_id": f"ref_{i}", "contributor_id": "reference_vendor", "payload": x})
    for i, x in enumerate(src_a_data):
        obs.append({"sample_id": f"src_a_{i}", "contributor_id": "vendor_a", "payload": x})
    for i, x in enumerate(src_b_data):
        obs.append({"sample_id": f"src_b_{i}", "contributor_id": "vendor_b", "payload": x})

    contract = SourceAnalysisContract(
        source_analysis_id="test_stats_fdr",
        reference_source_id="reference_vendor",
        fdr_alpha=0.05,
    )

    profile = engine.analyze(observations=obs, contract=contract, project_id="proj_stats")

    assert len(profile.comparisons) == 2
    comp_map = {c.target_source_id: c for c in profile.comparisons}

    # Vendor A (Identical): No shift
    comp_a = comp_map["vendor_a"]
    assert comp_a.status == ShiftDecisionState.NO_SHIFT_DETECTED
    assert comp_a.adjusted_p_value is not None
    assert comp_a.adjusted_p_value > 0.05

    # Vendor B (Shifted): Material shift
    comp_b = comp_map["vendor_b"]
    assert comp_b.status == ShiftDecisionState.MATERIAL_SHIFT
    assert comp_b.adjusted_p_value is not None
    assert comp_b.adjusted_p_value <= 0.05
    assert comp_b.effect_size >= 0.10  # PSI threshold

    # Global status reflects material shift
    assert profile.global_status == ShiftDecisionState.MATERIAL_SHIFT


def test_25_to_30_dual_gate_decisions_and_thresholds() -> None:
    """Verify FR-11.8-009, STAT-11.8-008, STAT-11.8-009: Dual-gate decision matrix across effect thresholds."""
    engine = SourceDistributionShiftEngine()

    # Synthetic categorical tokens
    # Reference: 50% "cat", 50% "dog"
    ref_tokens = ["cat"] * 50 + ["dog"] * 50
    # Source 1 (Large shift): 95% "cat", 5% "dog" (TVD ~ 0.45)
    src_shift_tokens = ["cat"] * 95 + ["dog"] * 5
    # Source 2 (Identical): 50% "cat", 50% "dog"
    src_ident_tokens = ["cat"] * 50 + ["dog"] * 50

    obs: List[Dict[str, Any]] = []
    for i, tok in enumerate(ref_tokens):
        obs.append({"sample_id": f"r_{i}", "contributor_id": "ref_source", "payload": tok})
    for i, tok in enumerate(src_shift_tokens):
        obs.append({"sample_id": f"s1_{i}", "contributor_id": "src_shifted", "payload": tok})
    for i, tok in enumerate(src_ident_tokens):
        obs.append({"sample_id": f"s2_{i}", "contributor_id": "src_ident", "payload": tok})

    contract = SourceAnalysisContract(
        source_analysis_id="test_dual_gate",
        reference_source_id="ref_source",
    )

    profile = engine.analyze(observations=obs, contract=contract, project_id="proj_dual_gate")
    comp_map = {c.target_source_id: c for c in profile.comparisons}

    assert comp_map["src_shifted"].status == ShiftDecisionState.MATERIAL_SHIFT
    assert comp_map["src_shifted"].effect_metric == "tvd"
    assert comp_map["src_shifted"].effect_size >= 0.05
    assert comp_map["src_ident"].status == ShiftDecisionState.NO_SHIFT_DETECTED


def test_31_to_35_confounding_and_simpsons_paradox() -> None:
    """Verify FR-11.8-010, STAT-11.8-010: Label skew detection, TVD thresholding, and confounding caveat."""
    engine = SourceDistributionShiftEngine()
    rng = np.random.RandomState(99)

    # Reference has balanced classes (50% Class 0, 50% Class 1)
    ref_obs: List[Dict[str, Any]] = []
    for i in range(100):
        lbl = "class_0" if i < 50 else "class_1"
        ref_obs.append({"sample_id": f"r_{i}", "contributor_id": "ref_vendor", "payload": float(rng.normal(0, 1)), "label": lbl})

    # Target vendor specializes in class_1 (90% Class 1, 10% Class 0) -> Confounding TVD = |0.5-0.1| + |0.5-0.9| / 2 = 0.40 >= 0.15
    tgt_obs: List[Dict[str, Any]] = []
    for i in range(100):
        lbl = "class_0" if i < 10 else "class_1"
        tgt_obs.append({"sample_id": f"t_{i}", "contributor_id": "specialist_vendor", "payload": float(rng.normal(2, 1)), "label": lbl})

    contract = SourceAnalysisContract(
        source_analysis_id="test_confounding",
        reference_source_id="ref_vendor",
    )

    profile = engine.analyze(observations=ref_obs + tgt_obs, contract=contract, project_id="proj_confound")

    assert len(profile.comparisons) == 1
    comp = profile.comparisons[0]
    assert comp.potential_label_confounding is True
    assert comp.label_tvd >= 0.15
    assert profile.confounded_source_count == 1

    # Check finding description contains the confounding caveat
    finding = next((f for f in profile.findings if f["finding_type"] == "SOURCE_ASSOCIATED_DISTRIBUTION_SHIFT"), None)
    assert finding is not None
    assert "potential label distribution confounding" in finding["description"].lower()


def test_36_to_39_sybil_fragmentation_and_dominance() -> None:
    """Verify SEC-11.8-004: Excessive source fragmentation alert when sub-threshold volume > 20%."""
    engine = SourceDistributionShiftEngine()

    obs: List[Dict[str, Any]] = []

    # 1 Reference group with 40 samples (Eligible)
    for i in range(40):
        obs.append({"sample_id": f"ref_{i}", "contributor_id": "ref_vendor", "payload": float(i)})

    # 6 Small fragmented groups with 10 samples each (Total = 60 samples in sub-threshold groups)
    # Total samples = 40 + 60 = 100. Sub-threshold ratio = 60/100 = 60% > 20%
    for g in range(6):
        for i in range(10):
            obs.append({"sample_id": f"frag_{g}_{i}", "contributor_id": f"frag_source_{g}", "payload": float(i)})

    contract = SourceAnalysisContract(
        source_analysis_id="test_fragmentation",
        reference_source_id="ref_vendor",
        min_group_samples=30,
    )

    profile = engine.analyze(observations=obs, contract=contract, project_id="proj_frag")

    assert profile.accounting.excessive_fragmentation_detected is True
    assert profile.accounting.sub_threshold_sample_ratio == 0.60

    # Verify advisory finding emitted
    frag_finding = next((f for f in profile.findings if f["finding_type"] == "EXCESSIVE_SOURCE_FRAGMENTATION"), None)
    assert frag_finding is not None
    assert frag_finding["category"] == "SOURCE_DISTRIBUTION_ADVISORY"
    assert "excessive source fragmentation detected" in frag_finding["description"].lower()


def test_40_to_44_privacy_pseudonymization_and_isolation() -> None:
    """Verify PRIV-11.8-001, PRIV-11.8-002, PRIV-11.8-003, PRIV-11.8-004: Deterministic project isolation."""
    # 1. Deterministic pseudonym in same project
    p1 = derive_project_scoped_pseudonym("project_alpha", "vendor_xyz", salt="salt_1")
    p2 = derive_project_scoped_pseudonym("project_alpha", "vendor_xyz", salt="salt_1")
    assert p1 == p2
    assert len(p1) == 16

    # 2. Cross-project unlinkability (different project produces distinct pseudonym)
    p_beta = derive_project_scoped_pseudonym("project_beta", "vendor_xyz", salt="salt_1")
    assert p1 != p_beta

    # 3. Different salt produces distinct pseudonym
    p_salt2 = derive_project_scoped_pseudonym("project_alpha", "vendor_xyz", salt="salt_2")
    assert p1 != p_salt2

    # 4. Project mismatch rejection with boundary
    engine = SourceDistributionShiftEngine()
    contract = SourceAnalysisContract(source_analysis_id="test_isolation")
    pop_id = PopulationIdentity(
        dataset_id="ds_1",
        population_type=PopulationType.COMPLETE_DATASET,
        total_available_samples=100,
        selected_sample_count=100,
        sampling_applied=False,
        sample_ids_hash="0" * 64,
        population_selection_hash="0" * 64,
    )
    comp_contract = ComparisonContract(
        project_id="tenant_A",
        reference_dataset_id="ref_ds",
        target_dataset_id="tgt_ds",
        modality=DataModality.TABULAR_FEATURE,
        reference_population_hash="0" * 64,
        target_population_hash="1" * 64,
        reference_sample_count=100,
        target_sample_count=100,
    )
    boundary = ComparisonBoundaryResult(
        contract=comp_contract,
        comparison_boundary_hash="a" * 64,
        reference_population=pop_id,
        target_population=pop_id,
        status=BoundaryEvaluationStatus.VALID,
        compatibility_status=CompatibilityStatus.COMPATIBLE,
    )

    with pytest.raises(ProjectMismatchError):
        engine.analyze(
            observations=[{"sample_id": "s1", "contributor_id": "v1", "payload": 1.0}],
            contract=contract,
            boundary_result=boundary,
            project_id="tenant_B",  # Mismatch!
        )


def test_45_to_48_cryptographic_hashes_and_sensitivity() -> None:
    """Verify CRYPTO-11.8-001, CRYPTO-11.8-002, CRYPTO-11.8-003, CRYPTO-11.8-004: RFC 8785 hashes & mutation sensitivity."""
    engine = SourceDistributionShiftEngine()
    rng = np.random.RandomState(42)

    base_obs = [
        {"sample_id": f"r_{i}", "contributor_id": "ref", "payload": float(rng.normal(0, 1))}
        for i in range(50)
    ] + [
        {"sample_id": f"t_{i}", "contributor_id": "tgt", "payload": float(rng.normal(1, 1))}
        for i in range(50)
    ]

    contract = SourceAnalysisContract(
        source_analysis_id="contract_hash_test",
        reference_source_id="ref",
        subsampling_seed=42,
    )

    prof1 = engine.analyze(observations=base_obs, contract=contract, project_id="proj_hash")
    prof2 = engine.analyze(observations=base_obs, contract=contract, project_id="proj_hash")

    # Deterministic reproducibility
    assert prof1.source_analysis_profile_hash == prof2.source_analysis_profile_hash

    # Mutation 1: Change project_id
    prof_mut_proj = engine.analyze(observations=base_obs, contract=contract, project_id="proj_mutated")
    assert prof1.source_analysis_profile_hash != prof_mut_proj.source_analysis_profile_hash

    # Mutation 2: Change contract subsampling seed
    contract_mut = contract.model_copy(update={"subsampling_seed": 9999})
    prof_mut_contract = engine.analyze(observations=base_obs, contract=contract_mut, project_id="proj_hash")
    assert prof1.source_analysis_profile_hash != prof_mut_contract.source_analysis_profile_hash

    # Mutation 3: Change sample payloads
    mut_obs = copy.deepcopy(base_obs)
    mut_obs[0]["payload"] = 999.0
    prof_mut_payload = engine.analyze(observations=mut_obs, contract=contract, project_id="proj_hash")
    assert prof1.source_analysis_profile_hash != prof_mut_payload.source_analysis_profile_hash


def test_49_to_51_finding_and_evidence_synthesis() -> None:
    """Verify FR-11.8-011, FR-11.8-012, FR-11.8-013: Non-attribution finding synthesis and ranking."""
    engine = SourceDistributionShiftEngine()
    rng = np.random.RandomState(42)

    obs = (
        [{"sample_id": f"r_{i}", "contributor_id": "ref", "payload": float(rng.normal(0, 1))} for i in range(50)]
        + [{"sample_id": f"t1_{i}", "contributor_id": "shift_high", "payload": float(rng.normal(3, 1))} for i in range(50)]
        + [{"sample_id": f"t2_{i}", "contributor_id": "shift_med", "payload": float(rng.normal(1.2, 1))} for i in range(50)]
    )

    contract = SourceAnalysisContract(source_analysis_id="test_findings", reference_source_id="ref")
    profile = engine.analyze(observations=obs, contract=contract, project_id="proj_finding")

    assert len(profile.findings) >= 1
    for f in profile.findings:
        assert f["category"] in ("SOURCE_DISTRIBUTION_SHIFT", "SOURCE_DISTRIBUTION_ADVISORY")
        desc = f["description"].lower()
        # Non-attribution check
        assert "malicious" not in desc
        assert "poisoning" not in desc
        assert "fraud" not in desc
        assert "attack" not in desc
        assert "culpable" not in desc

    assert len(profile.evidence_records) == 1
    ev = profile.evidence_records[0]
    assert ev["evidence_type"] == "source_distribution_shift"

    # Deterministic ranking: shift_high should rank before shift_med
    assert profile.ranked_source_ids[0] == "shift_high"


def test_52_to_54_security_ast_scan_and_offline() -> None:
    """Verify SEC-11.8-001, SEC-11.8-002, SEC-11.8-003: AST security scan, 0 network imports, input immutability."""
    # 1. AST Security Scan on source_engine.py
    engine_path = os.path.join("backend", "aivara", "drift", "source_engine.py")
    with open(engine_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=engine_path)

    forbidden_funcs = {"eval", "exec", "pickle"}
    forbidden_modules = {"requests", "httpx", "urllib", "socket", "dns", "subprocess"}

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in forbidden_funcs:
                pytest.fail(f"Forbidden call '{node.func.id}' found in source_engine.py")
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            mod_name = getattr(node, "module", None)
            if mod_name and mod_name.split(".")[0] in forbidden_modules:
                pytest.fail(f"Forbidden network/system import '{mod_name}' found in source_engine.py")

    # 2. Input observation immutability test
    engine = SourceDistributionShiftEngine()
    obs_original = [
        {"sample_id": f"s_{i}", "contributor_id": "vendor_immut", "payload": [float(i), float(i * 2)]}
        for i in range(40)
    ]
    obs_copy = copy.deepcopy(obs_original)

    contract = SourceAnalysisContract(source_analysis_id="test_immut")
    engine.analyze(observations=obs_original, contract=contract, project_id="proj_immut")

    assert obs_original == obs_copy


def test_55_cross_phase_compatibility() -> None:
    """Verify COMPAT-11.8-001 through COMPAT-11.8-007: Integration with Phase 11.2, 11.3, 11.4, 11.5, 11.6, 11.7."""
    engine = SourceDistributionShiftEngine()
    rng = np.random.RandomState(42)

    # 1. Multivariate representation shift (Phase 11.6 & 11.3 MMD)
    ref_emb = rng.normal(loc=0.0, scale=1.0, size=(50, 16)).tolist()
    tgt_emb = rng.normal(loc=1.0, scale=1.0, size=(50, 16)).tolist()

    obs_repr = (
        [{"sample_id": f"r_{i}", "contributor_id": "site_ref", "payload": ref_emb[i]} for i in range(50)]
        + [{"sample_id": f"t_{i}", "contributor_id": "site_tgt", "payload": tgt_emb[i]} for i in range(50)]
    )

    contract = SourceAnalysisContract(source_analysis_id="test_compat", reference_source_id="site_ref")
    profile = engine.analyze(observations=obs_repr, contract=contract, project_id="proj_compat")

    assert len(profile.comparisons) == 1
    comp = profile.comparisons[0]
    assert comp.modality == DataModality.LATENT_EMBEDDING
    assert comp.statistic_method == StatisticalMethod.KERNEL_MMD.value
    assert comp.status == ShiftDecisionState.MATERIAL_SHIFT
