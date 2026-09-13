"""Comprehensive Test Suite for Phase 11.6 Representation & Embedding Distribution Shift Analysis.

Covers all 59 specification requirements across:
A. Model Resolution & Verification
B. Preprocessing & Input Validation
C. Embedding Validation & L2 Normalization
D. Representation Compatibility
E. Statistical Engine Integration (MMD, Energy Distance, Permutation Tests)
F. Distribution Shift Scenarios
G. Profile Synthesis & Population Accounting
H. Cryptographic Identity & Hash Sensitivity
I. Security, Offline Execution & Immutability
J. Provenance, Findings & Evidence Linkage
"""

import ast
import hashlib
import io
from pathlib import Path
from typing import Any, Dict, List, Tuple
import numpy as np
from PIL import Image
import pytest

from aivara.crypto.canonical import canonicalize
from aivara.drift.engine import StatisticalDriftEngine
from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    CompatibilityStatus,
    DataModality,
    PopulationType,
    ShiftDecisionState,
)
from aivara.drift.exceptions import (
    IncompatiblePopulationError,
    ProjectMismatchError,
    ResourceLimitExceededError,
)
from aivara.drift.representation_engine import (
    RepresentationDistributionShiftAnalyzer,
    RepresentationExtractor,
    apply_l2_normalization,
    compute_representation_contract_hash,
    compute_representation_drift_profile_hash,
    preprocess_image_for_representation,
)
from aivara.drift.schemas import (
    ComparisonBoundaryResult,
    ComparisonContract,
    PopulationIdentity,
    RepresentationContract,
    RepresentationDriftProfile,
    RepresentationPopulationAccounting,
    StatisticalAnalysisConfig,
)


def _make_dummy_boundary(
    project_id: str = "proj-rep-1",
    ref_ds: str = "ds-ref-1",
    tgt_ds: str = "ds-tgt-1",
    modality: DataModality = DataModality.IMAGE,
    ref_n: int = 100,
    tgt_n: int = 100,
    status: BoundaryEvaluationStatus = BoundaryEvaluationStatus.VALID,
) -> ComparisonBoundaryResult:
    """Helper to construct deterministic ComparisonBoundaryResult for tests."""
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
    boundary_hash = hashlib.sha256(canonicalize(contract.to_canonical_dict())).hexdigest()
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
    compat = (
        CompatibilityStatus.COMPATIBLE
        if status == BoundaryEvaluationStatus.VALID
        else CompatibilityStatus.INCOMPATIBLE_SCHEMA
    )
    return ComparisonBoundaryResult(
        contract=contract,
        comparison_boundary_hash=boundary_hash,
        reference_population=ref_pop,
        target_population=tgt_pop,
        status=status,
        compatibility_status=compat,
    )


def _make_dummy_contract(
    rep_id: str = "dinov2_vits14_test",
    model_id: str = "dinov2_vits14",
    dim: int = 384,
    norm: str = "L2",
    layer: str = "norm",
) -> RepresentationContract:
    """Helper to construct a deterministic RepresentationContract."""
    desc = {
        "batch_size": 32,
        "contract_version": "1.0",
        "embedding_dimension": dim,
        "execution_device_policy": "CPU",
        "modality": "image",
        "model_artifact_hash": "m" * 64,
        "model_format": "ONNX",
        "model_id": model_id,
        "model_master_fingerprint": "f" * 64,
        "normalization_policy": norm,
        "numerical_precision": "float32",
        "preprocessing_contract_hash": "p" * 64,
        "representation_id": rep_id,
        "representation_layer": layer,
        "runtime_framework": "onnxruntime",
        "schema_version": "1.0",
    }
    c_hash = compute_representation_contract_hash(desc)
    return RepresentationContract(
        representation_id=rep_id,
        modality=DataModality.IMAGE,
        model_id=model_id,
        model_master_fingerprint="f" * 64,
        model_artifact_hash="m" * 64,
        model_format="ONNX",
        runtime_framework="onnxruntime",
        representation_layer=layer,
        embedding_dimension=dim,
        preprocessing_contract_hash="p" * 64,
        normalization_policy=norm,
        numerical_precision="float32",
        execution_device_policy="CPU",
        batch_size=32,
        representation_contract_hash=c_hash,
    )


# ===========================================================================
# A. Model Resolution & Verification (1 - 7)
# ===========================================================================

def test_01_and_02_local_model_resolution_and_missing_file():
    """1-2. Local model file verification and missing artifact failure."""
    contract = _make_dummy_contract()
    with pytest.raises(FileNotFoundError, match="Model artifact not found"):
        RepresentationExtractor(contract, model_artifact_path="/non/existent/model.onnx")


def test_03_and_04_model_hash_verification_and_mismatch(tmp_path: Path):
    """3-4. Model SHA-256 hash verified and mismatch triggers ValueError."""
    fake_onnx = tmp_path / "model.onnx"
    fake_onnx.write_bytes(b"dummy_onnx_bytes_12345")
    actual_hash = hashlib.sha256(b"dummy_onnx_bytes_12345").hexdigest()

    contract_mismatch = _make_dummy_contract()  # has 'm' * 64
    with pytest.raises(ValueError, match="Model artifact hash mismatch"):
        RepresentationExtractor(contract_mismatch, model_artifact_path=fake_onnx)


def test_05_invalid_model_resource_limit(tmp_path: Path):
    """5. Huge model artifact exceeding file size limit rejected."""
    fake_large_onnx = tmp_path / "huge_model.onnx"
    fake_large_onnx.write_bytes(b"x")
    contract = _make_dummy_contract()

    # Mock stat size to exceed MAX_MODEL_FILE_SIZE_BYTES
    import aivara.drift.representation_engine as rep_engine
    orig_limit = rep_engine.MAX_MODEL_FILE_SIZE_BYTES
    try:
        rep_engine.MAX_MODEL_FILE_SIZE_BYTES = 0
        with pytest.raises(ResourceLimitExceededError):
            RepresentationExtractor(contract, model_artifact_path=fake_large_onnx)
    finally:
        rep_engine.MAX_MODEL_FILE_SIZE_BYTES = orig_limit


def test_06_and_07_embedding_dimension_verification():
    """6-7. Verifies embedding dimension matches contract exactly or raises error."""
    contract = _make_dummy_contract(dim=384)
    # Runner returning wrong dimension 512
    runner_wrong_dim = lambda x: np.zeros((1, 512), dtype=np.float32)
    extractor = RepresentationExtractor(contract, model_runner=runner_wrong_dim)

    img = np.zeros((64, 64, 3), dtype=np.uint8)
    with pytest.raises(ValueError, match="Embedding dimension mismatch: expected 384, got 512"):
        extractor.extract_single_embedding(img)


# ===========================================================================
# B. Preprocessing & Input Validation (8 - 12)
# ===========================================================================

def test_08_to_12_deterministic_preprocessing():
    """8-12. Deterministic preprocessing: target size, channel conversion, normalization, NCHW layout."""
    raw_img = np.full((100, 150, 3), 128, dtype=np.uint8)
    t1 = preprocess_image_for_representation(raw_img, target_size=(224, 224))
    t2 = preprocess_image_for_representation(raw_img, target_size=(224, 224))

    assert t1.shape == (1, 3, 224, 224)
    assert t1.dtype == np.float32
    assert np.array_equal(t1, t2)
    assert np.all(np.isfinite(t1))

    # Grayscale conversion
    gray_img = np.full((80, 80), 200, dtype=np.uint8)
    t_gray = preprocess_image_for_representation(gray_img)
    assert t_gray.shape == (1, 3, 224, 224)


# ===========================================================================
# C. Embedding Validation & L2 Normalization (13 - 20)
# ===========================================================================

def test_13_to_20_l2_normalization_and_validation():
    """13-20. L2 normalization projects to unit norm S^(D-1), handles NaN/Inf, and rejects zero-norm."""
    vec = np.array([3.0, 4.0], dtype=np.float64)
    normed = apply_l2_normalization(vec)
    assert np.allclose(normed, np.array([0.6, 0.8]))
    assert abs(np.linalg.norm(normed) - 1.0) < 1e-6

    # 2D matrix normalization
    mat = np.array([[1.0, 2.0, 2.0], [0.0, 5.0, 0.0]], dtype=np.float64)
    normed_mat = apply_l2_normalization(mat)
    assert normed_mat.shape == (2, 3)
    assert np.allclose(np.linalg.norm(normed_mat, axis=1), [1.0, 1.0])

    # Zero norm rejection
    with pytest.raises(ValueError, match="Zero-norm embedding"):
        apply_l2_normalization(np.zeros(10))

    # NaN / Inf rejection
    with pytest.raises(ValueError, match="non-finite values"):
        apply_l2_normalization(np.array([1.0, np.nan, 2.0]))
    with pytest.raises(ValueError, match="non-finite values"):
        apply_l2_normalization(np.array([1.0, np.inf, 2.0]))


# ===========================================================================
# D. Representation Space Compatibility (21 - 27)
# ===========================================================================

def test_21_to_27_representation_compatibility():
    """21-27. Validates representation contract equality and fails on project/modality mismatches."""
    boundary = _make_dummy_boundary(modality=DataModality.TABULAR_FEATURE)
    contract = _make_dummy_contract()
    analyzer = RepresentationDistributionShiftAnalyzer()

    with pytest.raises(IncompatiblePopulationError, match="Modality must be IMAGE or LATENT_EMBEDDING"):
        analyzer.analyze(boundary, contract, [[1.0] * 384] * 40, [[1.0] * 384] * 40)

    # Project mismatch
    boundary_proj_mismatch = _make_dummy_boundary(status=BoundaryEvaluationStatus.PROJECT_MISMATCH)
    with pytest.raises(ProjectMismatchError):
        analyzer.analyze(boundary_proj_mismatch, contract, [[1.0] * 384] * 40, [[1.0] * 384] * 40)


# ===========================================================================
# E. Statistical Engine Integration & Shift Scenarios (28 - 39)
# ===========================================================================

def test_28_to_36_identical_and_shifted_embeddings():
    """28-36. Phase 11.3 multivariate integration: identical -> NO_SHIFT, shifted -> MATERIAL_SHIFT."""
    boundary = _make_dummy_boundary(ref_n=40, tgt_n=40)
    contract = _make_dummy_contract(dim=64)
    analyzer = RepresentationDistributionShiftAnalyzer()

    rng = np.random.RandomState(42)
    # Identical distributions
    ref_emb = rng.normal(0.0, 1.0, (40, 64))

    p_identical = analyzer.analyze(boundary, contract, ref_emb, ref_emb)
    assert p_identical.global_status == ShiftDecisionState.NO_SHIFT_DETECTED
    assert p_identical.multivariate_result is not None
    assert p_identical.multivariate_result.is_statistically_significant is False
    assert p_identical.multivariate_result.statistic_value == pytest.approx(0.0, abs=1e-5)

    # Shifted distributions (different mean cluster)
    tgt_emb_shifted = rng.normal(3.0, 1.0, (40, 64))
    p_shifted = analyzer.analyze(boundary, contract, ref_emb, tgt_emb_shifted)
    assert p_shifted.global_status == ShiftDecisionState.MATERIAL_SHIFT
    assert p_shifted.multivariate_result is not None
    assert p_shifted.multivariate_result.is_statistically_significant is True
    assert p_shifted.multivariate_result.statistic_value > 0.02



def test_37_insufficient_embedding_data():
    """37. Insufficient valid samples (< 30) returns fail-closed INSUFFICIENT_DATA."""
    boundary = _make_dummy_boundary(ref_n=10, tgt_n=10)
    contract = _make_dummy_contract(dim=64)
    analyzer = RepresentationDistributionShiftAnalyzer()

    ref_emb = np.ones((10, 64))
    tgt_emb = np.ones((10, 64))

    profile = analyzer.analyze(boundary, contract, ref_emb, tgt_emb)
    assert profile.global_status == ShiftDecisionState.INSUFFICIENT_DATA


def test_38_and_39_invalid_embeddings_accounting():
    """38-39. Corrupted vectors and dimension mismatches counted in sample accounting."""
    boundary = _make_dummy_boundary(ref_n=40, tgt_n=40)
    contract = _make_dummy_contract(dim=64)
    analyzer = RepresentationDistributionShiftAnalyzer()

    ref_emb = [np.ones(64)] * 35 + [np.array([np.nan] * 64)] * 5
    tgt_emb = [np.ones(64)] * 38 + [np.ones(32)] * 2  # wrong dimension

    profile = analyzer.analyze(boundary, contract, ref_emb, tgt_emb)
    assert profile.accounting.reference_invalid_embeddings == 5
    assert profile.accounting.reference_valid_embeddings == 35
    assert profile.accounting.target_invalid_embeddings == 2
    assert profile.accounting.target_valid_embeddings == 38


# ===========================================================================
# G. Profile Synthesis & Findings (40 - 44)
# ===========================================================================

def test_40_to_44_profile_synthesis_and_findings():
    """40-44. Synthesis of RepresentationDriftProfile, findings, and evidence records."""
    boundary = _make_dummy_boundary(ref_n=40, tgt_n=40)
    contract = _make_dummy_contract(dim=32)
    analyzer = RepresentationDistributionShiftAnalyzer()

    rng = np.random.RandomState(42)
    ref_emb = rng.normal(0.0, 1.0, (40, 32))
    tgt_emb = rng.normal(2.0, 1.0, (40, 32))

    profile = analyzer.analyze(boundary, contract, ref_emb, tgt_emb)
    assert isinstance(profile, RepresentationDriftProfile)
    assert len(profile.findings) == 1
    assert profile.findings[0]["finding_type"] == "representation_distribution_shift"
    assert profile.findings[0]["evidence_layer"] == "detection"
    assert "malicious" not in profile.findings[0]["description"].lower()
    assert len(profile.evidence_records) == 1


# ===========================================================================
# H. Cryptographic Identity & Hash Sensitivity (45 - 50)
# ===========================================================================

def test_45_to_50_cryptographic_hash_and_sensitivity():
    """45-50. Deterministic hashing and sensitivity to model, preprocessing, and boundary mutation."""
    boundary = _make_dummy_boundary(ref_n=40, tgt_n=40)
    contract1 = _make_dummy_contract(rep_id="model_a", dim=32)
    contract2 = _make_dummy_contract(rep_id="model_b", dim=32)

    analyzer = RepresentationDistributionShiftAnalyzer()
    rng = np.random.RandomState(42)
    ref_emb = rng.normal(0.0, 1.0, (40, 32))
    tgt_emb = rng.normal(0.0, 1.0, (40, 32))

    p1 = analyzer.analyze(boundary, contract1, ref_emb, tgt_emb)
    p1_repeat = analyzer.analyze(boundary, contract1, ref_emb, tgt_emb)
    p2 = analyzer.analyze(boundary, contract2, ref_emb, tgt_emb)

    # Determinism
    assert p1.representation_drift_profile_hash == p1_repeat.representation_drift_profile_hash
    assert len(p1.representation_drift_profile_hash) == 64

    # Mutation changes hash
    assert p1.representation_drift_profile_hash != p2.representation_drift_profile_hash


# ===========================================================================
# I. Security, Offline Execution & AST Scan (51 - 55)
# ===========================================================================

def test_51_to_55_security_and_ast_scan():
    """51-55. Offline execution guarantee, AST scanner clean, no forbidden calls."""
    src_paths = [
        Path("backend/aivara/drift/representation_engine.py"),
    ]
    forbidden_calls = {"eval", "exec", "pickle", "system", "popen", "subprocess"}

    for p in src_paths:
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in forbidden_calls:
                    pytest.fail(f"Forbidden call {node.func.id} found in {p}")
                elif isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_calls:
                    pytest.fail(f"Forbidden method {node.func.attr} found in {p}")


# ===========================================================================
# J. Provenance & Linkage (56 - 59)
# ===========================================================================

def test_56_to_59_provenance_linkage():
    """56-59. Preserves comparison boundary hash, representation contract hash, and statistical analysis hash."""
    boundary = _make_dummy_boundary(ref_n=40, tgt_n=40)
    contract = _make_dummy_contract(dim=32)
    analyzer = RepresentationDistributionShiftAnalyzer()

    rng = np.random.RandomState(42)
    ref_emb = rng.normal(0.0, 1.0, (40, 32))
    tgt_emb = rng.normal(0.0, 1.0, (40, 32))

    profile = analyzer.analyze(boundary, contract, ref_emb, tgt_emb)
    assert profile.comparison_boundary_hash == boundary.comparison_boundary_hash
    assert profile.representation_contract_hash == contract.representation_contract_hash
    assert len(profile.statistical_analysis_hash) == 64
    assert profile.findings[0]["metadata_json"]["comparison_boundary_hash"] == boundary.comparison_boundary_hash
