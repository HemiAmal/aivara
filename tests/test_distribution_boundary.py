"""Comprehensive test suite for Phase 11.2 Reference & Target Distribution Boundary.

Validates project isolation, population selection, deterministic subsampling,
compatibility validation, RFC 8785 canonical hash derivation, mutation sensitivity,
immutability, and security bounds.
"""

import copy
import hashlib
import pytest
from pydantic import ValidationError

from aivara.crypto.canonical import InvalidNumberError, canonicalize
from aivara.dataset.exceptions import PathTraversalError
from aivara.dataset.path_security import normalize_relative_path
from aivara.drift.boundary import ComparisonBoundaryEngine
from aivara.drift.compatibility import (
    compute_feature_descriptor_hash,
    compute_label_descriptor_hash,
    compute_representation_descriptor_hash,
    validate_feature_compatibility,
    validate_image_compatibility,
    validate_label_compatibility,
    validate_representation_compatibility,
)
from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    CompatibilityStatus,
    DataModality,
    PopulationType,
    SamplingMethod,
)
from aivara.drift.exceptions import (
    IncompatiblePopulationError,
    InsufficientDataError,
    InvalidPopulationError,
    ProjectMismatchError,
    ResourceLimitExceededError,
)
from aivara.drift.population import (
    compute_population_selection_hash,
    compute_sample_ids_hash,
    deterministic_subsample,
    filter_sample_records,
    resolve_population_identity,
)
from aivara.drift.schemas import (
    ComparisonBoundaryResult,
    ComparisonContract,
    FeatureSchemaDescriptor,
    ImageSchemaDescriptor,
    LabelSchemaDescriptor,
    PopulationIdentity,
    PopulationSelector,
    RepresentationDescriptor,
    SamplingConfig,
)


# =====================================================================
# Fixtures & Helpers
# =====================================================================

def make_dummy_samples(count: int, prefix: str = "sample", category: str = "cat", contributor: str = "contrib_1"):
    """Generate mock sample records."""
    samples = []
    for i in range(count):
        samples.append({
            "id": f"{prefix}_{i:05d}",
            "contributor_id": contributor,
            "created_at": f"2026-01-01T{i%24:02d}:00:00Z",
            "label_json": {"category": category},
            "metadata_json": {"contributor_id": contributor},
        })
    return samples


# =====================================================================
# 1. Basic Boundary & Validity Tests
# =====================================================================

def test_valid_reference_target_pair():
    engine = ComparisonBoundaryEngine()
    ref_samples = make_dummy_samples(50, prefix="ref")
    target_samples = make_dummy_samples(60, prefix="target")

    ref_sel = PopulationSelector(dataset_id="ds_ref_01")
    target_sel = PopulationSelector(dataset_id="ds_target_01")

    result = engine.establish_boundary(
        project_id="proj_01",
        reference_selector=ref_sel,
        reference_samples=ref_samples,
        reference_project_id="proj_01",
        target_selector=target_sel,
        target_samples=target_samples,
        target_project_id="proj_01",
    )

    assert result.status == BoundaryEvaluationStatus.VALID
    assert result.compatibility_status == CompatibilityStatus.COMPATIBLE
    assert result.reference_population.selected_sample_count == 50
    assert result.target_population.selected_sample_count == 60
    assert len(result.comparison_boundary_hash) == 64
    assert len(result.contract.reference_population_hash) == 64
    assert len(result.contract.target_population_hash) == 64


def test_same_dataset_different_versions():
    engine = ComparisonBoundaryEngine()
    v1_samples = make_dummy_samples(40, prefix="v1")
    v2_samples = make_dummy_samples(45, prefix="v2")

    ref_sel = PopulationSelector(dataset_id="ds_main", dataset_version_id="ver_01")
    target_sel = PopulationSelector(dataset_id="ds_main", dataset_version_id="ver_02")

    result = engine.establish_boundary(
        project_id="proj_01",
        reference_selector=ref_sel,
        reference_samples=v1_samples,
        reference_project_id="proj_01",
        target_selector=target_sel,
        target_samples=v2_samples,
        target_project_id="proj_01",
    )

    assert result.status == BoundaryEvaluationStatus.VALID
    assert result.contract.reference_dataset_version_id == "ver_01"
    assert result.contract.target_dataset_version_id == "ver_02"
    assert result.contract.reference_dataset_id == result.contract.target_dataset_id


# =====================================================================
# 2. Project Isolation Tests
# =====================================================================

def test_project_mismatch_reference():
    engine = ComparisonBoundaryEngine()
    ref_samples = make_dummy_samples(50)
    target_samples = make_dummy_samples(50)

    with pytest.raises(ProjectMismatchError):
        engine.establish_boundary(
            project_id="proj_01",
            reference_selector=PopulationSelector(dataset_id="ds_ref"),
            reference_samples=ref_samples,
            reference_project_id="proj_02",  # Mismatched!
            target_selector=PopulationSelector(dataset_id="ds_target"),
            target_samples=target_samples,
            target_project_id="proj_01",
        )


def test_project_mismatch_target():
    engine = ComparisonBoundaryEngine()
    ref_samples = make_dummy_samples(50)
    target_samples = make_dummy_samples(50)

    with pytest.raises(ProjectMismatchError):
        engine.establish_boundary(
            project_id="proj_01",
            reference_selector=PopulationSelector(dataset_id="ds_ref"),
            reference_samples=ref_samples,
            reference_project_id="proj_01",
            target_selector=PopulationSelector(dataset_id="ds_target"),
            target_samples=target_samples,
            target_project_id="proj_other",  # Mismatched!
        )


# =====================================================================
# 3. Sample Size Floor & Ceilings (N_min = 30, N_max = 5000)
# =====================================================================

def test_empty_reference_population():
    engine = ComparisonBoundaryEngine()
    ref_samples = []
    target_samples = make_dummy_samples(50)

    result = engine.establish_boundary(
        project_id="proj_01",
        reference_selector=PopulationSelector(dataset_id="ds_ref"),
        reference_samples=ref_samples,
        reference_project_id="proj_01",
        target_selector=PopulationSelector(dataset_id="ds_target"),
        target_samples=target_samples,
        target_project_id="proj_01",
    )

    assert result.status == BoundaryEvaluationStatus.INSUFFICIENT_DATA
    assert any("Reference population sample size" in w for w in result.warnings)


def test_insufficient_sample_size_below_30():
    engine = ComparisonBoundaryEngine()
    ref_samples = make_dummy_samples(29)  # 29 < 30
    target_samples = make_dummy_samples(50)

    result = engine.establish_boundary(
        project_id="proj_01",
        reference_selector=PopulationSelector(dataset_id="ds_ref"),
        reference_samples=ref_samples,
        reference_project_id="proj_01",
        target_selector=PopulationSelector(dataset_id="ds_target"),
        target_samples=target_samples,
        target_project_id="proj_01",
    )

    assert result.status == BoundaryEvaluationStatus.INSUFFICIENT_DATA
    assert result.reference_population.selected_sample_count == 29


def test_exact_boundary_at_30():
    engine = ComparisonBoundaryEngine()
    ref_samples = make_dummy_samples(30)
    target_samples = make_dummy_samples(30)

    result = engine.establish_boundary(
        project_id="proj_01",
        reference_selector=PopulationSelector(dataset_id="ds_ref"),
        reference_samples=ref_samples,
        reference_project_id="proj_01",
        target_selector=PopulationSelector(dataset_id="ds_target"),
        target_samples=target_samples,
        target_project_id="proj_01",
    )

    assert result.status == BoundaryEvaluationStatus.VALID
    assert result.reference_population.selected_sample_count == 30
    assert result.target_population.selected_sample_count == 30


def test_large_population_subsampling_at_5000():
    engine = ComparisonBoundaryEngine()
    # 6000 samples > max 5000
    ref_samples = make_dummy_samples(6000, prefix="large_ref")
    target_samples = make_dummy_samples(50, prefix="target")

    result = engine.establish_boundary(
        project_id="proj_01",
        reference_selector=PopulationSelector(dataset_id="ds_ref"),
        reference_samples=ref_samples,
        reference_project_id="proj_01",
        target_selector=PopulationSelector(dataset_id="ds_target"),
        target_samples=target_samples,
        target_project_id="proj_01",
    )

    assert result.status == BoundaryEvaluationStatus.VALID
    assert result.reference_population.total_available_samples == 6000
    assert result.reference_population.selected_sample_count == 5000
    assert result.reference_population.sampling_applied is True
    assert result.target_population.sampling_applied is False


# =====================================================================
# 4. Deterministic Sampling & Seed Reproducibility
# =====================================================================

def test_deterministic_sampling_reproducibility():
    sample_ids = [f"id_{i:04d}" for i in range(100)]
    config = SamplingConfig(max_samples=20, seed=12345)

    sel_1, applied_1 = deterministic_subsample(sample_ids, config)
    sel_2, applied_2 = deterministic_subsample(sample_ids, config)

    assert applied_1 is True
    assert applied_2 is True
    assert sel_1 == sel_2
    assert len(sel_1) == 20


def test_sampling_seed_changes_selection():
    sample_ids = [f"id_{i:04d}" for i in range(100)]
    config_a = SamplingConfig(max_samples=20, seed=111)
    config_b = SamplingConfig(max_samples=20, seed=222)

    sel_a, _ = deterministic_subsample(sample_ids, config_a)
    sel_b, _ = deterministic_subsample(sample_ids, config_b)

    assert sel_a != sel_b


def test_hash_ranking_sampling():
    sample_ids = [f"id_{i:04d}" for i in range(100)]
    config = SamplingConfig(method=SamplingMethod.HASH_RANKING, max_samples=25, seed=42)

    sel_1, _ = deterministic_subsample(sample_ids, config, dataset_context_seed="salt_1")
    sel_2, _ = deterministic_subsample(sample_ids, config, dataset_context_seed="salt_1")
    sel_diff_salt, _ = deterministic_subsample(sample_ids, config, dataset_context_seed="salt_2")

    assert sel_1 == sel_2
    assert sel_1 != sel_diff_salt


# =====================================================================
# 5. Compatibility Validation Tests
# =====================================================================

def test_feature_compatibility_valid():
    ref_f = FeatureSchemaDescriptor(
        feature_names=["f1", "f2", "f3"],
        feature_types={"f1": "float", "f2": "float", "f3": "float"},
        dimensions=3,
    )
    target_f = FeatureSchemaDescriptor(
        feature_names=["f1", "f2", "f3"],
        feature_types={"f1": "float", "f2": "float", "f3": "float"},
        dimensions=3,
    )
    status, warns = validate_feature_compatibility(ref_f, target_f)
    assert status == CompatibilityStatus.COMPATIBLE
    assert len(warns) == 0


def test_feature_dimension_mismatch():
    ref_f = FeatureSchemaDescriptor(feature_names=["f1", "f2"], dimensions=2)
    target_f = FeatureSchemaDescriptor(feature_names=["f1", "f2", "f3"], dimensions=3)

    status, warns = validate_feature_compatibility(ref_f, target_f)
    assert status == CompatibilityStatus.INCOMPATIBLE_DIMENSIONS
    assert any("dimensions mismatch" in w for w in warns)


def test_feature_name_mismatch():
    ref_f = FeatureSchemaDescriptor(feature_names=["f1", "f2"], dimensions=2)
    target_f = FeatureSchemaDescriptor(feature_names=["f1", "other"], dimensions=2)

    status, warns = validate_feature_compatibility(ref_f, target_f)
    assert status == CompatibilityStatus.INCOMPATIBLE_SCHEMA
    assert any("Feature names mismatch" in w for w in warns)


def test_label_compatibility_unseen_classes():
    ref_l = LabelSchemaDescriptor(class_names=["cat", "dog"], num_classes=2)
    target_l = LabelSchemaDescriptor(class_names=["cat", "dog", "bird"], num_classes=3)

    status, warns = validate_label_compatibility(ref_l, target_l)
    assert status == CompatibilityStatus.UNSEEN_CLASSES_PRESENT
    assert any("unseen classes" in w for w in warns)


def test_image_compatibility_channel_mismatch():
    ref_img = ImageSchemaDescriptor(channels=3, color_space="RGB")
    target_img = ImageSchemaDescriptor(channels=1, color_space="GRAYSCALE")

    status, warns = validate_image_compatibility(ref_img, target_img)
    assert status == CompatibilityStatus.INCOMPATIBLE_MODALITY


def test_representation_model_mismatch():
    ref_rep = RepresentationDescriptor(
        modality=DataModality.LATENT_EMBEDDING,
        model_id="model_v1",
        embedding_dim=512,
    )
    target_rep = RepresentationDescriptor(
        modality=DataModality.LATENT_EMBEDDING,
        model_id="model_v2",  # Different model!
        embedding_dim=512,
    )
    status, warns = validate_representation_compatibility(ref_rep, target_rep)
    assert status == CompatibilityStatus.INCOMPATIBLE_REPRESENTATION


# =====================================================================
# 6. Population Filtering Tests (Contributor, Time, Class)
# =====================================================================

def test_filter_by_contributor():
    samples = [
        {"id": "s1", "contributor_id": "c1"},
        {"id": "s2", "contributor_id": "c2"},
        {"id": "s3", "contributor_id": "c1"},
    ]
    selector = PopulationSelector(
        population_type=PopulationType.CONTRIBUTOR_SUBSET,
        dataset_id="ds_1",
        contributor_id="c1",
    )
    filtered = filter_sample_records(samples, selector)
    assert len(filtered) == 2
    assert {s["id"] for s in filtered} == {"s1", "s3"}


def test_filter_by_time_window():
    samples = [
        {"id": "s1", "created_at": "2026-01-01T10:00:00Z"},
        {"id": "s2", "created_at": "2026-01-02T10:00:00Z"},
        {"id": "s3", "created_at": "2026-01-03T10:00:00Z"},
    ]
    selector = PopulationSelector(
        population_type=PopulationType.TEMPORAL_WINDOW,
        dataset_id="ds_1",
        time_start="2026-01-01T12:00:00Z",
        time_end="2026-01-02T12:00:00Z",
    )
    filtered = filter_sample_records(samples, selector)
    assert len(filtered) == 1
    assert filtered[0]["id"] == "s2"


def test_filter_by_class():
    samples = [
        {"id": "s1", "label_json": {"category": "cat"}},
        {"id": "s2", "label_json": {"category": "dog"}},
        {"id": "s3", "label_json": {"category": "bird"}},
    ]
    selector = PopulationSelector(
        population_type=PopulationType.CLASS_SUBSET,
        dataset_id="ds_1",
        class_filter=["cat", "dog"],
    )
    filtered = filter_sample_records(samples, selector)
    assert len(filtered) == 2
    assert {s["id"] for s in filtered} == {"s1", "s2"}


# =====================================================================
# 7. Canonical Hash Determinism & Mutation Matrix
# =====================================================================

def test_canonical_hash_determinism():
    engine = ComparisonBoundaryEngine()
    ref_samples = make_dummy_samples(40, prefix="ref")
    target_samples = make_dummy_samples(40, prefix="target")

    ref_sel = PopulationSelector(dataset_id="ds_ref")
    target_sel = PopulationSelector(dataset_id="ds_target")

    res_1 = engine.establish_boundary(
        project_id="proj_01",
        reference_selector=ref_sel,
        reference_samples=ref_samples,
        reference_project_id="proj_01",
        target_selector=target_sel,
        target_samples=target_samples,
        target_project_id="proj_01",
    )

    res_2 = engine.establish_boundary(
        project_id="proj_01",
        reference_selector=ref_sel,
        reference_samples=ref_samples,
        reference_project_id="proj_01",
        target_selector=target_sel,
        target_samples=target_samples,
        target_project_id="proj_01",
    )

    assert res_1.comparison_boundary_hash == res_2.comparison_boundary_hash
    assert res_1.reference_population.population_selection_hash == res_2.reference_population.population_selection_hash
    assert res_1.target_population.population_selection_hash == res_2.target_population.population_selection_hash


def test_boundary_hash_mutation_matrix():
    """Verify that mutating any field in ComparisonContract changes comparison_boundary_hash."""
    engine = ComparisonBoundaryEngine()
    base_contract = ComparisonContract(
        project_id="proj_01",
        reference_dataset_id="ds_ref",
        reference_dataset_version_id="v1",
        target_dataset_id="ds_target",
        target_dataset_version_id="v2",
        modality=DataModality.IMAGE,
        reference_population_hash="a" * 64,
        target_population_hash="b" * 64,
        reference_sample_count=50,
        target_sample_count=60,
        sampling_method="none",
        max_samples_budget=5000,
        sampling_seed=42,
        feature_descriptor_hash="c" * 64,
        label_descriptor_hash="d" * 64,
        representation_descriptor_hash="e" * 64,
        resource_policy_version="1.0",
    )

    base_hash = engine.compute_boundary_hash(base_contract)

    mutations = [
        {"project_id": "proj_mutated"},
        {"reference_dataset_id": "ds_ref_mutated"},
        {"reference_dataset_version_id": "v1_mutated"},
        {"target_dataset_id": "ds_target_mutated"},
        {"target_dataset_version_id": "v2_mutated"},
        {"modality": DataModality.TABULAR_FEATURE},
        {"reference_population_hash": "f" * 64},
        {"target_population_hash": "0" * 64},
        {"reference_sample_count": 51},
        {"target_sample_count": 61},
        {"sampling_method": "deterministic_seeded"},
        {"max_samples_budget": 4999},
        {"sampling_seed": 43},
        {"feature_descriptor_hash": "1" * 64},
        {"label_descriptor_hash": "2" * 64},
        {"representation_descriptor_hash": "3" * 64},
        {"schema_version": "1.1"},
        {"analysis_version": "1.1"},
        {"resource_policy_version": "1.1"},
    ]

    for mut in mutations:
        d = base_contract.model_dump()
        d.update(mut)
        mutated_contract = ComparisonContract(**d)
        mutated_hash = engine.compute_boundary_hash(mutated_contract)
        assert mutated_hash != base_hash, f"Mutation {mut} failed to change comparison_boundary_hash!"


# =====================================================================
# 8. Security & Path Traversal Tests
# =====================================================================

def test_path_traversal_rejection():
    dangerous_paths = [
        "../secret.txt",
        "images/../../etc/passwd",
        "\\\\network\\unc\\path",
        "//unc/forward/path",
        "C:\\Windows\\System32",
        "",
    ]
    for path in dangerous_paths:
        with pytest.raises(PathTraversalError):
            normalize_relative_path(path)


def test_nan_infinity_rejected_in_canonical():
    with pytest.raises(InvalidNumberError):
        canonicalize({"value": float("nan")})

    with pytest.raises(InvalidNumberError):
        canonicalize({"value": float("inf")})

    with pytest.raises(InvalidNumberError):
        canonicalize({"value": float("-inf")})


def test_schema_immutability():
    config = SamplingConfig(max_samples=100)
    with pytest.raises(ValidationError):
        config.max_samples = 200  # Frozen model raises on mutation


def test_explicit_sample_ids_filter():
    samples = make_dummy_samples(20, prefix="s")
    selector = PopulationSelector(
        population_type=PopulationType.EXPLICIT_SAMPLES,
        dataset_id="ds_explicit",
        sample_ids=["s_00002", "s_00005", "s_00008"],
    )
    filtered = filter_sample_records(samples, selector)
    assert len(filtered) == 3
    assert [s["id"] for s in filtered] == ["s_00002", "s_00005", "s_00008"]


def test_combined_contributor_and_class_filter():
    samples = [
        {"id": "s1", "contributor_id": "c1", "label_json": {"category": "cat"}},
        {"id": "s2", "contributor_id": "c2", "label_json": {"category": "cat"}},
        {"id": "s3", "contributor_id": "c1", "label_json": {"category": "dog"}},
        {"id": "s4", "contributor_id": "c1", "label_json": {"category": "cat"}},
    ]
    selector = PopulationSelector(
        population_type=PopulationType.CONTRIBUTOR_SUBSET,
        dataset_id="ds_comb",
        contributor_id="c1",
        class_filter=["cat"],
    )
    filtered = filter_sample_records(samples, selector)
    assert len(filtered) == 2
    assert {s["id"] for s in filtered} == {"s1", "s4"}


def test_feature_dimensions_exceed_limit():
    engine = ComparisonBoundaryEngine(max_feature_dim=4096)
    ref_samples = make_dummy_samples(50)
    target_samples = make_dummy_samples(50)

    # 4097 dimensions exceeds 4096 limit
    oversized_features = [f"f_{i}" for i in range(4097)]
    with pytest.raises(ValidationError):
        FeatureSchemaDescriptor(feature_names=oversized_features, dimensions=4097)


def test_duplicate_class_names_rejected():
    with pytest.raises(ValidationError):
        LabelSchemaDescriptor(class_names=["cat", "dog", "cat"], num_classes=3)


def test_label_num_classes_mismatch():
    with pytest.raises(ValidationError):
        LabelSchemaDescriptor(class_names=["cat", "dog"], num_classes=3)


def test_duplicate_sample_ids_in_selector_rejected():
    with pytest.raises(ValidationError):
        PopulationSelector(
            dataset_id="ds_1",
            sample_ids=["s1", "s2", "s1"],
        )


def test_sampling_budget_exceeds_frozen_max():
    with pytest.raises(ValidationError):
        SamplingConfig(max_samples=5001)


def test_unseen_classes_emits_finding():
    engine = ComparisonBoundaryEngine()
    ref_samples = make_dummy_samples(50)
    target_samples = make_dummy_samples(50)

    ref_labels = LabelSchemaDescriptor(class_names=["cat", "dog"], num_classes=2)
    target_labels = LabelSchemaDescriptor(class_names=["cat", "dog", "lion"], num_classes=3)

    result = engine.establish_boundary(
        project_id="proj_01",
        reference_selector=PopulationSelector(dataset_id="ds_ref"),
        reference_samples=ref_samples,
        reference_project_id="proj_01",
        target_selector=PopulationSelector(dataset_id="ds_target"),
        target_samples=target_samples,
        target_project_id="proj_01",
        label_descriptor=ref_labels,
        target_label_descriptor=target_labels,
    )

    assert result.compatibility_status == CompatibilityStatus.UNSEEN_CLASSES_PRESENT
    assert any(f["finding_type"] == "unseen_classes_detected" for f in result.findings)


def test_insufficient_data_emits_findings():
    engine = ComparisonBoundaryEngine()
    ref_samples = make_dummy_samples(10)  # 10 < 30
    target_samples = make_dummy_samples(50)

    result = engine.establish_boundary(
        project_id="proj_01",
        reference_selector=PopulationSelector(dataset_id="ds_ref"),
        reference_samples=ref_samples,
        reference_project_id="proj_01",
        target_selector=PopulationSelector(dataset_id="ds_target"),
        target_samples=target_samples,
        target_project_id="proj_01",
    )

    assert result.status == BoundaryEvaluationStatus.INSUFFICIENT_DATA
    assert any(f["finding_type"] == "insufficient_reference_population" for f in result.findings)


def test_incompatible_schema_marks_boundary_status():
    engine = ComparisonBoundaryEngine()
    ref_samples = make_dummy_samples(50)
    target_samples = make_dummy_samples(50)

    ref_f = FeatureSchemaDescriptor(feature_names=["f1", "f2"], dimensions=2)
    target_f = FeatureSchemaDescriptor(feature_names=["f1", "f_other"], dimensions=2)

    result = engine.establish_boundary(
        project_id="proj_01",
        reference_selector=PopulationSelector(dataset_id="ds_ref"),
        reference_samples=ref_samples,
        reference_project_id="proj_01",
        target_selector=PopulationSelector(dataset_id="ds_target"),
        target_samples=target_samples,
        target_project_id="proj_01",
        feature_descriptor=ref_f,
        target_feature_descriptor=target_f,
    )

    assert result.status == BoundaryEvaluationStatus.INCOMPATIBLE_INPUTS
    assert result.compatibility_status == CompatibilityStatus.INCOMPATIBLE_SCHEMA


def test_descriptor_hashes_none_handling():
    assert compute_feature_descriptor_hash(None) is None
    assert compute_label_descriptor_hash(None) is None
    assert compute_representation_descriptor_hash(None) is None
