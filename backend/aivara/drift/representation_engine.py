"""Authoritative Representation & Embedding Distribution Shift Engine.

Executes deterministic image preprocessing, verified local model inference (ONNX),
L2 hypersphere normalization, and multivariate statistical distribution shift analysis (Kernel MMD,
Energy Distance, Permutation Testing) via Phase 11.3 StatisticalDriftEngine.
"""

from __future__ import annotations

import hashlib
import io
import math
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

import numpy as np
from PIL import Image, ImageOps

from aivara.crypto.canonical import canonicalize
from aivara.drift.engine import StatisticalDriftEngine
from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    DataModality,
    ShiftDecisionState,
)
from aivara.drift.exceptions import (
    DistributionBoundaryError,
    IncompatiblePopulationError,
    ProjectMismatchError,
    ResourceLimitExceededError,
)
from aivara.drift.schemas import (
    ComparisonBoundaryResult,
    MultivariateDriftResult,
    RepresentationContract,
    RepresentationDriftProfile,
    RepresentationPopulationAccounting,
    StatisticalAnalysisConfig,
    StatisticalAnalysisResult,
)

# Standard visual representation limits
MAX_MODEL_FILE_SIZE_BYTES: int = 500 * 1024 * 1024  # 500 MB
MAX_EMBEDDING_POPULATION_SIZE: int = 5000
MAX_EMBEDDING_DIMENSION: int = 4096


def compute_representation_contract_hash(canonical_dict: Dict[str, Any]) -> str:
    """Compute cryptographic SHA-256 digest over canonical RFC 8785 representation contract descriptor."""
    canonical_bytes = canonicalize(canonical_dict)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_representation_drift_profile_hash(canonical_dict: Dict[str, Any]) -> str:
    """Compute cryptographic SHA-256 digest over canonical RFC 8785 representation drift profile descriptor."""
    canonical_bytes = canonicalize(canonical_dict)
    return hashlib.sha256(canonical_bytes).hexdigest()


def apply_l2_normalization(embeddings: np.ndarray, eps: float = 1e-12) -> np.ndarray:
    """Apply deterministic L2 normalization projecting embeddings onto the unit hypersphere S^(D-1).

    Raises:
        ValueError: If array contains NaNs, Infinities, or zero-norm vectors.
    """
    arr = np.asarray(embeddings, dtype=np.float64)
    if not np.all(np.isfinite(arr)):
        raise ValueError("Embedding array contains non-finite values (NaN or Infinity).")

    if arr.ndim == 1:
        norm = float(np.linalg.norm(arr))
        if norm <= eps:
            raise ValueError(f"Zero-norm embedding vector detected (norm={norm}).")
        return (arr / norm).astype(np.float64)
    elif arr.ndim == 2:
        norms = np.linalg.norm(arr, axis=1, keepdims=True)
        if np.any(norms <= eps):
            zero_indices = np.where(norms.ravel() <= eps)[0].tolist()
            raise ValueError(f"Zero-norm embedding vector(s) detected at indices: {zero_indices[:5]}.")
        return (arr / norms).astype(np.float64)
    else:
        raise ValueError(f"Expected 1D or 2D embedding array, got ndim={arr.ndim}.")


def preprocess_image_for_representation(
    image_input: Union[Path, str, bytes, np.ndarray, Image.Image],
    target_size: Tuple[int, int] = (224, 224),
    mean: Tuple[float, float, float] = (0.485, 0.456, 0.406),
    std: Tuple[float, float, float] = (0.229, 0.224, 0.225),
) -> np.ndarray:
    """Execute deterministic image preprocessing (Resize, Center Crop, Normalization, NCHW layout).

    Returns:
        np.ndarray with shape (1, 3, target_height, target_width) and dtype float32.
    """
    if isinstance(image_input, (str, Path)):
        path_obj = Path(image_input)
        if not path_obj.exists() or not path_obj.is_file():
            raise FileNotFoundError(f"Image file not found: {path_obj.name}")
        with Image.open(path_obj) as raw_img:
            img = ImageOps.exif_transpose(raw_img) or raw_img
            if img.mode != "RGB":
                img = img.convert("RGB")
            img.load()
            canonical_img = img.copy()
    elif isinstance(image_input, bytes):
        with Image.open(io.BytesIO(image_input)) as raw_img:
            img = ImageOps.exif_transpose(raw_img) or raw_img
            if img.mode != "RGB":
                img = img.convert("RGB")
            img.load()
            canonical_img = img.copy()
    elif isinstance(image_input, Image.Image):
        img = ImageOps.exif_transpose(image_input) or image_input
        if img.mode != "RGB":
            canonical_img = img.convert("RGB")
        else:
            canonical_img = img
    elif isinstance(image_input, np.ndarray):
        arr = image_input
        if arr.ndim == 2:
            arr = np.stack([arr] * 3, axis=-1)
        elif arr.ndim == 3 and arr.shape[2] == 1:
            arr = np.concatenate([arr] * 3, axis=-1)
        elif arr.ndim == 3 and arr.shape[2] == 4:
            arr = arr[:, :, :3]
        if arr.dtype != np.uint8:
            arr = np.clip(arr, 0, 255).astype(np.uint8)
        canonical_img = Image.fromarray(arr)
    else:
        raise ValueError(f"Unsupported image input type: {type(image_input)}")

    # 1. Deterministic Resize & Center Crop to target_size
    w, h = canonical_img.size
    target_w, target_h = target_size
    if w < 1 or h < 1:
        raise ValueError(f"Invalid image dimensions: {w}x{h}")

    # Resize preserving aspect ratio (shorter side resized to target)
    scale = max(target_w / w, target_h / h)
    new_w = int(math.ceil(w * scale))
    new_h = int(math.ceil(h * scale))
    resized = canonical_img.resize((new_w, new_h), Image.Resampling.BILINEAR)

    # Center crop
    left = (new_w - target_w) // 2
    top = (new_h - target_h) // 2
    cropped = resized.crop((left, top, left + target_w, top + target_h))

    # 2. Convert to float32 [0.0, 1.0] and Normalize
    arr_rgb = np.array(cropped, dtype=np.float32) / 255.0
    mean_arr = np.array(mean, dtype=np.float32)
    std_arr = np.array(std, dtype=np.float32)
    normalized = (arr_rgb - mean_arr) / std_arr

    # 3. Transpose to NCHW layout: (1, 3, H, W)
    nchw = np.transpose(normalized, (2, 0, 1))[np.newaxis, :, :, :]
    return np.ascontiguousarray(nchw, dtype=np.float32)


class RepresentationExtractor:
    """Safe, offline, local representation model evaluator (ONNX / Callable)."""

    def __init__(
        self,
        contract: RepresentationContract,
        model_artifact_path: Optional[Union[Path, str]] = None,
        model_runner: Optional[Callable[[np.ndarray], np.ndarray]] = None,
    ) -> None:
        self.contract = contract
        self.model_artifact_path = Path(model_artifact_path) if model_artifact_path else None
        self._runner = model_runner
        self._session = None

        if self._runner is None and self.model_artifact_path is not None:
            self._init_onnx_session()

    def _init_onnx_session(self) -> None:
        """Verify model artifact on disk and initialize ONNX Runtime session."""
        if not self.model_artifact_path.exists() or not self.model_artifact_path.is_file():
            raise FileNotFoundError(f"Model artifact not found at {self.model_artifact_path}")

        file_size = self.model_artifact_path.stat().st_size
        if file_size > MAX_MODEL_FILE_SIZE_BYTES:
            raise ResourceLimitExceededError(
                f"Model file size {file_size} exceeds maximum {MAX_MODEL_FILE_SIZE_BYTES} bytes."
            )

        # Hash verification if expected hash is declared
        if self.contract.model_artifact_hash:
            actual_hash = hashlib.sha256(self.model_artifact_path.read_bytes()).hexdigest()
            if actual_hash.lower() != self.contract.model_artifact_hash.lower():
                raise ValueError(
                    f"Model artifact hash mismatch: expected {self.contract.model_artifact_hash}, "
                    f"got {actual_hash}."
                )

        import onnxruntime as ort

        # Enforce CPU execution for deterministic reproducibility
        opts = ort.SessionOptions()
        opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        opts.intra_op_num_threads = 1
        opts.inter_op_num_threads = 1

        self._session = ort.InferenceSession(
            str(self.model_artifact_path),
            sess_options=opts,
            providers=["CPUExecutionProvider"],
        )

    def extract_single_embedding(self, image_input: Any) -> np.ndarray:
        """Extract L2-normalized embedding vector for a single image."""
        tensor = preprocess_image_for_representation(image_input)

        if self._runner is not None:
            raw_out = self._runner(tensor)
        elif self._session is not None:
            input_name = self._session.get_inputs()[0].name
            outputs = self._session.run(None, {input_name: tensor})
            raw_out = outputs[0]
        else:
            raise RuntimeError("RepresentationExtractor has no valid model runner or ONNX session.")

        emb = np.asarray(raw_out, dtype=np.float64).ravel()
        if len(emb) != self.contract.embedding_dimension:
            raise ValueError(
                f"Embedding dimension mismatch: expected {self.contract.embedding_dimension}, "
                f"got {len(emb)}."
            )

        if not np.all(np.isfinite(emb)):
            raise ValueError("Model output contains non-finite values (NaN or Inf).")

        if self.contract.normalization_policy == "L2":
            return apply_l2_normalization(emb)
        return emb


class RepresentationDistributionShiftAnalyzer:
    """Authoritative domain analyzer for learned representation & embedding distribution shift."""

    def __init__(
        self,
        statistical_engine: Optional[StatisticalDriftEngine] = None,
        extractor: Optional[RepresentationExtractor] = None,
    ) -> None:
        self.statistical_engine = statistical_engine or StatisticalDriftEngine()
        self.extractor = extractor

    def analyze(
        self,
        boundary_result: ComparisonBoundaryResult,
        representation_contract: RepresentationContract,
        reference_data: Sequence[Any],
        target_data: Sequence[Any],
        *,
        model_artifact_path: Optional[Union[Path, str]] = None,
        model_runner: Optional[Callable[[np.ndarray], np.ndarray]] = None,
        config: Optional[StatisticalAnalysisConfig] = None,
    ) -> RepresentationDriftProfile:
        """Execute representation and embedding distribution shift evaluation.

        Supports both raw image populations (extracted via local ONNX model) and precomputed embeddings.
        """
        contract = boundary_result.contract

        # 1. Modality & Boundary Validation
        if contract.modality not in (DataModality.IMAGE, DataModality.LATENT_EMBEDDING):
            raise IncompatiblePopulationError(
                f"Modality must be IMAGE or LATENT_EMBEDDING, found '{contract.modality.value}'."
            )

        if boundary_result.status != BoundaryEvaluationStatus.VALID:
            if boundary_result.status == BoundaryEvaluationStatus.PROJECT_MISMATCH:
                raise ProjectMismatchError("Cannot analyze representation drift across mismatched projects.")
            return self._create_fail_closed_profile(
                boundary_result=boundary_result,
                representation_contract=representation_contract,
                status=ShiftDecisionState.INVALID,
                accounting=RepresentationPopulationAccounting(
                    reference_total_images=len(reference_data),
                    target_total_images=len(target_data),
                ),
                warnings=[f"Boundary status is {boundary_result.status.value}."],
            )

        active_config = config or self.statistical_engine.default_config
        warnings: List[str] = list(boundary_result.warnings)
        limitations: List[str] = []

        # 2. Resolve & Verify Extractor if image inputs are provided
        extractor = self.extractor
        if extractor is None and (model_artifact_path is not None or model_runner is not None):
            try:
                extractor = RepresentationExtractor(
                    contract=representation_contract,
                    model_artifact_path=model_artifact_path,
                    model_runner=model_runner,
                )
            except Exception as exc:
                return self._create_fail_closed_profile(
                    boundary_result=boundary_result,
                    representation_contract=representation_contract,
                    status=ShiftDecisionState.INVALID,
                    accounting=RepresentationPopulationAccounting(
                        reference_total_images=len(reference_data),
                        target_total_images=len(target_data),
                    ),
                    warnings=[f"Failed to initialize representation extractor: {str(exc)}"],
                )

        # 3. Ingest or Extract Embeddings
        ref_embeddings, ref_acc = self._process_population_data(
            reference_data, representation_contract, extractor
        )
        tgt_embeddings, tgt_acc = self._process_population_data(
            target_data, representation_contract, extractor
        )

        accounting = RepresentationPopulationAccounting(
            reference_total_images=ref_acc["total"],
            reference_valid_embeddings=ref_acc["valid"],
            reference_extraction_failures=ref_acc["failures"],
            reference_invalid_embeddings=ref_acc["invalid"],
            target_total_images=tgt_acc["total"],
            target_valid_embeddings=tgt_acc["valid"],
            target_extraction_failures=tgt_acc["failures"],
            target_invalid_embeddings=tgt_acc["invalid"],
        )

        if ref_acc["failures"] > 0 or tgt_acc["failures"] > 0:
            warnings.append(
                f"Extraction failures: {ref_acc['failures']} reference, {tgt_acc['failures']} target."
            )
        if ref_acc["invalid"] > 0 or tgt_acc["invalid"] > 0:
            warnings.append(
                f"Invalid/corrupted embeddings: {ref_acc['invalid']} reference, {tgt_acc['invalid']} target."
            )

        # 4. Check for Sufficient Valid Samples
        if (
            len(ref_embeddings) < active_config.min_sample_size
            or len(tgt_embeddings) < active_config.min_sample_size
        ):
            return self._create_fail_closed_profile(
                boundary_result=boundary_result,
                representation_contract=representation_contract,
                status=ShiftDecisionState.INSUFFICIENT_DATA,
                accounting=accounting,
                warnings=warnings
                + [
                    f"Valid embedding count below minimum {active_config.min_sample_size}: "
                    f"reference={len(ref_embeddings)}, target={len(tgt_embeddings)}."
                ],
            )

        # 5. Enforce High-Dimensional Resource Bounds
        if len(ref_embeddings) > MAX_EMBEDDING_POPULATION_SIZE:
            ref_embeddings = ref_embeddings[:MAX_EMBEDDING_POPULATION_SIZE]
            warnings.append(f"Capped reference embeddings to {MAX_EMBEDDING_POPULATION_SIZE}.")
        if len(tgt_embeddings) > MAX_EMBEDDING_POPULATION_SIZE:
            tgt_embeddings = tgt_embeddings[:MAX_EMBEDDING_POPULATION_SIZE]
            warnings.append(f"Capped target embeddings to {MAX_EMBEDDING_POPULATION_SIZE}.")

        # 6. Execute Phase 11.3 Multivariate Statistical Evaluation
        statistical_result: StatisticalAnalysisResult = self.statistical_engine.evaluate_boundary(
            boundary_result=boundary_result,
            reference_embeddings=ref_embeddings,
            target_embeddings=tgt_embeddings,
            config=active_config,
        )

        multivariate_res: Optional[MultivariateDriftResult] = statistical_result.multivariate_results
        global_status = statistical_result.global_status

        # 7. Synthesize Findings and Evidence
        findings, evidence_records = self._generate_findings_and_evidence(
            boundary_result=boundary_result,
            representation_contract=representation_contract,
            statistical_result=statistical_result,
            multivariate_res=multivariate_res,
            accounting=accounting,
            global_status=global_status,
        )

        # 8. Cryptographic Digest
        rep_contract_hash = (
            representation_contract.representation_contract_hash
            or compute_representation_contract_hash(representation_contract.to_canonical_dict())
        )

        descriptor_for_hash = {
            "accounting": accounting.to_canonical_dict(),
            "analysis_version": "1.0",
            "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
            "embedding_dimension": representation_contract.embedding_dimension,
            "global_status": global_status.value,
            "multivariate_statistic_present": multivariate_res is not None,
            "normalization_policy": representation_contract.normalization_policy,
            "project_id": contract.project_id,
            "reference_dataset_id": contract.reference_dataset_id,
            "representation_contract_hash": rep_contract_hash,
            "schema_version": "1.0",
            "statistical_analysis_hash": statistical_result.analysis_result_hash,
            "target_dataset_id": contract.target_dataset_id,
        }
        profile_hash = compute_representation_drift_profile_hash(descriptor_for_hash)

        return RepresentationDriftProfile(
            schema_version="1.0",
            analysis_version="1.0",
            comparison_boundary_hash=boundary_result.comparison_boundary_hash,
            representation_contract_hash=rep_contract_hash,
            statistical_analysis_hash=statistical_result.analysis_result_hash,
            representation_drift_profile_hash=profile_hash,
            project_id=contract.project_id,
            reference_dataset_id=contract.reference_dataset_id,
            target_dataset_id=contract.target_dataset_id,
            global_status=global_status,
            accounting=accounting,
            multivariate_result=multivariate_res,
            embedding_dimension=representation_contract.embedding_dimension,
            normalization_policy=representation_contract.normalization_policy,
            warnings=sorted(list(set(warnings))),
            limitations=limitations,
            findings=findings,
            evidence_records=evidence_records,
        )

    def _process_population_data(
        self,
        data_items: Sequence[Any],
        contract: RepresentationContract,
        extractor: Optional[RepresentationExtractor],
    ) -> Tuple[List[List[float]], Dict[str, int]]:
        """Process either precomputed embedding vectors or raw image inputs safely."""
        total = len(data_items)
        valid_list: List[List[float]] = []
        failures = 0
        invalid = 0

        for item in data_items:
            try:
                # Case A: Item is already a numerical embedding vector
                if isinstance(item, (np.ndarray, list, tuple)):
                    arr = np.asarray(item, dtype=np.float64).ravel()
                    if len(arr) != contract.embedding_dimension:
                        invalid += 1
                        continue
                    if not np.all(np.isfinite(arr)):
                        invalid += 1
                        continue
                    if contract.normalization_policy == "L2":
                        normed = apply_l2_normalization(arr)
                    else:
                        normed = arr
                    valid_list.append(normed.tolist())
                # Case B: Item is an image requiring extraction
                elif extractor is not None:
                    emb = extractor.extract_single_embedding(item)
                    valid_list.append(emb.tolist())
                else:
                    failures += 1
            except Exception:
                failures += 1

        accounting_dict = {
            "total": total,
            "valid": len(valid_list),
            "failures": failures,
            "invalid": invalid,
        }
        return valid_list, accounting_dict

    def _create_fail_closed_profile(
        self,
        boundary_result: ComparisonBoundaryResult,
        representation_contract: RepresentationContract,
        status: ShiftDecisionState,
        accounting: RepresentationPopulationAccounting,
        warnings: List[str],
    ) -> RepresentationDriftProfile:
        """Create fail-closed profile on boundary invalidity, model error, or insufficient data."""
        contract = boundary_result.contract
        rep_contract_hash = (
            representation_contract.representation_contract_hash
            or compute_representation_contract_hash(representation_contract.to_canonical_dict())
        )
        dummy_stat_hash = "0" * 64

        descriptor_for_hash = {
            "accounting": accounting.to_canonical_dict(),
            "analysis_version": "1.0",
            "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
            "embedding_dimension": representation_contract.embedding_dimension,
            "global_status": status.value,
            "multivariate_statistic_present": False,
            "normalization_policy": representation_contract.normalization_policy,
            "project_id": contract.project_id,
            "reference_dataset_id": contract.reference_dataset_id,
            "representation_contract_hash": rep_contract_hash,
            "schema_version": "1.0",
            "statistical_analysis_hash": dummy_stat_hash,
            "target_dataset_id": contract.target_dataset_id,
        }
        profile_hash = compute_representation_drift_profile_hash(descriptor_for_hash)

        return RepresentationDriftProfile(
            schema_version="1.0",
            analysis_version="1.0",
            comparison_boundary_hash=boundary_result.comparison_boundary_hash,
            representation_contract_hash=rep_contract_hash,
            statistical_analysis_hash=dummy_stat_hash,
            representation_drift_profile_hash=profile_hash,
            project_id=contract.project_id,
            reference_dataset_id=contract.reference_dataset_id,
            target_dataset_id=contract.target_dataset_id,
            global_status=status,
            accounting=accounting,
            embedding_dimension=representation_contract.embedding_dimension,
            normalization_policy=representation_contract.normalization_policy,
            warnings=warnings,
            limitations=["Representation distribution shift analysis aborted due to fail-closed state."],
            findings=[],
            evidence_records=[],
        )

    def _generate_findings_and_evidence(
        self,
        boundary_result: ComparisonBoundaryResult,
        representation_contract: RepresentationContract,
        statistical_result: StatisticalAnalysisResult,
        multivariate_res: Optional[MultivariateDriftResult],
        accounting: RepresentationPopulationAccounting,
        global_status: ShiftDecisionState,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Synthesize standard FindingModel and EvidenceModel records without mutating schemas."""
        contract = boundary_result.contract
        findings: List[Dict[str, Any]] = []
        evidence_records: List[Dict[str, Any]] = []

        affected_asset_id = contract.target_dataset_version_id or contract.target_dataset_id
        affected_asset_type = "dataset_version" if contract.target_dataset_version_id else "dataset"

        if global_status == ShiftDecisionState.MATERIAL_SHIFT:
            severity = "high"
            disposition = "review"
            confidence = 0.95
        elif global_status == ShiftDecisionState.SIGNIFICANT_SHIFT:
            severity = "medium"
            disposition = "review"
            confidence = 0.85
        elif global_status == ShiftDecisionState.SHIFT_DETECTED:
            severity = "low"
            disposition = "review"
            confidence = 0.75
        else:
            severity = "info"
            disposition = "accept"
            confidence = 0.99

        mmd_val = multivariate_res.statistic_value if multivariate_res is not None else 0.0
        p_val = multivariate_res.permutation_p_value if multivariate_res is not None else 1.0

        finding = {
            "project_id": contract.project_id,
            "engine_id": "representation_distribution_shift_analyzer",
            "engine_version": "1.0",
            "evidence_layer": "detection",
            "finding_type": "representation_distribution_shift",
            "title": f"Representation Distribution Shift Analysis: {global_status.value}",
            "description": (
                f"Learned representation distribution shift evaluated in {representation_contract.representation_id} "
                f"space ({representation_contract.embedding_dimension}-dim) across "
                f"{accounting.reference_valid_embeddings} reference and {accounting.target_valid_embeddings} target samples: "
                f"status={global_status.value}, Kernel MMD²={mmd_val:.6f}, permutation p={p_val:.4f}."
            ),
            "severity": severity,
            "confidence": confidence,
            "affected_asset_type": affected_asset_type,
            "affected_asset_id": affected_asset_id,
            "disposition": disposition,
            "analysis_mode": "multivariate_kernel_mmd",
            "recommendation": (
                "Review high-dimensional latent distribution divergence metrics and evaluate downstream model "
                "generalization across shifted representation clusters. "
                "Note: Representation distribution shift measures latent topological divergence and is NOT proof of "
                "malicious manipulation, dataset poisoning, or model backdoor compromise."
            ),
            "metadata_json": {
                "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
                "statistical_analysis_hash": statistical_result.analysis_result_hash,
                "representation_id": representation_contract.representation_id,
                "model_id": representation_contract.model_id,
                "embedding_dimension": representation_contract.embedding_dimension,
                "global_status": global_status.value,
                "mmd_squared": mmd_val,
                "permutation_p_value": p_val,
                "reference_valid_count": accounting.reference_valid_embeddings,
                "target_valid_count": accounting.target_valid_embeddings,
            },
        }
        findings.append(finding)

        evidence_data = {
            "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
            "statistical_analysis_hash": statistical_result.analysis_result_hash,
            "representation_id": representation_contract.representation_id,
            "model_id": representation_contract.model_id,
            "embedding_dimension": representation_contract.embedding_dimension,
            "normalization_policy": representation_contract.normalization_policy,
            "global_status": global_status.value,
            "accounting": accounting.to_canonical_dict(),
            "multivariate": (
                {
                    "mmd_sq": multivariate_res.statistic_value,
                    "permutation_p_value": multivariate_res.permutation_p_value,
                    "num_permutations": multivariate_res.num_permutations,
                    "bandwidth_gamma": multivariate_res.bandwidth,
                    "status": multivariate_res.status.value,
                }
                if multivariate_res is not None
                else None
            ),
        }
        evidence_bytes = canonicalize(evidence_data)
        evidence_hash = hashlib.sha256(evidence_bytes).hexdigest()

        evidence = {
            "evidence_layer": "detection",
            "evidence_type": "representation_drift_evidence",
            "title": "Representation Distribution Shift Evidence",
            "description": (
                f"Multivariate two-sample kernel discrepancy evidence for comparison boundary "
                f"{boundary_result.comparison_boundary_hash[:16]} in {representation_contract.representation_id} space."
            ),
            "data_json": evidence_data,
            "confidence": confidence,
            "evidence_hash": evidence_hash,
        }
        evidence_records.append(evidence)

        return findings, evidence_records
