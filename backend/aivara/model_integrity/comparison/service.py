"""Reference Model Comparison & Drift Attribution Orchestrator Service (Phase 7.5).

Orchestrates multi-tier cryptographic and structural model comparison between
reference and candidate models, producing deterministic drift attributions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from aivara.model_integrity.comparison.attribution import (
    classify_drift,
    determine_comparison_status,
    synthesize_reason_codes,
)
from aivara.model_integrity.comparison.contract import (
    compare_contract_hashes,
    diff_contract_metadata,
)
from aivara.model_integrity.comparison.identity import (
    compare_artifact_hashes,
    compare_master_fingerprints,
)
from aivara.model_integrity.comparison.schemas import (
    ArtifactComparisonStatus,
    ComparisonStatus,
    ContractComparisonStatus,
    DriftClassification,
    ModelComparisonResult,
    StructuralComparisonStatus,
    WeightComparisonStatus,
)
from aivara.model_integrity.comparison.structural import (
    compare_structural_hashes,
    diff_structural_metadata,
)
from aivara.model_integrity.comparison.weights import (
    attribute_tensor_changes,
    compare_weight_roots,
)
from aivara.model_integrity.contract_verification.schemas import ContractVerificationResult
from aivara.model_integrity.contract_verification.service import ModelContractVerificationService
from aivara.model_integrity.fingerprinting.schemas import (
    HierarchicalFingerprintResult,
    TensorLeafDescriptor,
)
from aivara.model_integrity.fingerprinting.service import ModelFingerprintingService
from aivara.model_integrity.fingerprinting.tensors import extract_tensor_leaves
from aivara.model_integrity.limits import DEFAULT_LIMITS, ModelIngestionLimits
from aivara.model_integrity.schemas import NormalizedModelMetadata
from aivara.model_integrity.service import ModelIngestionService


class ModelComparisonService:
    """Orchestrator for reference vs candidate model integrity comparison and drift attribution."""

    def __init__(self, limits: Optional[ModelIngestionLimits] = None) -> None:
        self.limits = limits or DEFAULT_LIMITS
        self.ingestion_service = ModelIngestionService(limits=self.limits)
        self.fingerprinting_service = ModelFingerprintingService(limits=self.limits)
        self.contract_service = ModelContractVerificationService(limits=self.limits)

    def compare_models(
        self,
        reference_fingerprint: Union[HierarchicalFingerprintResult, Dict[str, Any]],
        candidate_fingerprint: Union[HierarchicalFingerprintResult, Dict[str, Any]],
        reference_metadata: Optional[NormalizedModelMetadata] = None,
        candidate_metadata: Optional[NormalizedModelMetadata] = None,
        reference_leaves: Optional[List[TensorLeafDescriptor]] = None,
        candidate_leaves: Optional[List[TensorLeafDescriptor]] = None,
        reference_contract: Optional[ContractVerificationResult] = None,
        candidate_contract: Optional[ContractVerificationResult] = None,
        reference_trust: str = "VERIFIED",
        candidate_trust: str = "VERIFIED",
    ) -> ModelComparisonResult:
        """Perform deterministic comparison across all 4 cryptographic and structural identities.

        Args:
            reference_fingerprint: Fingerprints of reference model.
            candidate_fingerprint: Fingerprints of candidate model.
            reference_metadata: Optional normalized metadata of reference model.
            candidate_metadata: Optional normalized metadata of candidate model.
            reference_leaves: Optional tensor leaf descriptors of reference model.
            candidate_leaves: Optional tensor leaf descriptors of candidate model.
            reference_contract: Optional contract verification result of reference model.
            candidate_contract: Optional contract verification result of candidate model.
            reference_trust: Verification state of reference (e.g. VERIFIED, UNVERIFIABLE, INVALID).
            candidate_trust: Verification state of candidate.

        Returns:
            ModelComparisonResult containing multi-tier status and granular attribution.
        """
        # Extract digests safely
        ref_fp = (
            reference_fingerprint.model_dump()
            if isinstance(reference_fingerprint, HierarchicalFingerprintResult)
            else reference_fingerprint
        )
        cand_fp = (
            candidate_fingerprint.model_dump()
            if isinstance(candidate_fingerprint, HierarchicalFingerprintResult)
            else candidate_fingerprint
        )

        ref_art = ref_fp.get("artifact_hash")
        cand_art = cand_fp.get("artifact_hash")
        ref_struct = ref_fp.get("structural_hash")
        cand_struct = cand_fp.get("structural_hash")
        ref_weight = ref_fp.get("weight_merkle_root")
        cand_weight = cand_fp.get("weight_merkle_root")
        ref_contract_hash = ref_fp.get("contract_hash")
        cand_contract_hash = cand_fp.get("contract_hash")
        ref_master = ref_fp.get("master_fingerprint")
        cand_master = cand_fp.get("master_fingerprint")

        # 1. Artifact Identity Comparison
        artifact_status, is_exact_artifact = compare_artifact_hashes(ref_art, cand_art)

        # 2. Master Model Fingerprint Comparison
        is_exact_master = compare_master_fingerprints(ref_master, cand_master)

        # 3. Structural Identity Comparison & Diffing
        structural_status = compare_structural_hashes(ref_struct, cand_struct)
        structural_diffs = diff_structural_metadata(reference_metadata, candidate_metadata)

        # 4. Weight Merkle Comparison & Tensor Attribution
        weight_status = compare_weight_roots(ref_weight, cand_weight)
        tensor_changes, tensor_summary = attribute_tensor_changes(reference_leaves, candidate_leaves)

        # 5. Contract Identity Comparison & Diffing
        contract_status = compare_contract_hashes(ref_contract_hash, cand_contract_hash)
        contract_diffs = diff_contract_metadata(reference_contract, candidate_contract)

        # 6. Multi-Tier Drift Classification
        drift_class = classify_drift(
            structural_status=structural_status,
            weight_status=weight_status,
            contract_status=contract_status,
        )

        # 7. Comparison Feasibility & Validity Status
        comp_status = determine_comparison_status(
            reference_trust=reference_trust,
            candidate_trust=candidate_trust,
            artifact_status=artifact_status,
            structural_status=structural_status,
            weight_status=weight_status,
            contract_status=contract_status,
        )

        # 8. Deterministic Reason Codes
        reason_codes = synthesize_reason_codes(
            comparison_status=comp_status,
            drift_classification=drift_class,
            is_exact_artifact_match=is_exact_artifact,
            is_exact_master_match=is_exact_master,
            structural_status=structural_status,
            weight_status=weight_status,
            contract_status=contract_status,
        )

        ref_prints = {
            "artifact_hash": ref_art,
            "structural_hash": ref_struct,
            "weight_merkle_root": ref_weight,
            "contract_hash": ref_contract_hash,
            "master_fingerprint": ref_master,
        }
        cand_prints = {
            "artifact_hash": cand_art,
            "structural_hash": cand_struct,
            "weight_merkle_root": cand_weight,
            "contract_hash": cand_contract_hash,
            "master_fingerprint": cand_master,
        }

        return ModelComparisonResult(
            schema_version="1.0",
            comparison_status=comp_status,
            reference_trust=reference_trust,
            candidate_trust=candidate_trust,
            drift_classification=drift_class,
            is_exact_artifact_match=is_exact_artifact,
            is_exact_master_match=is_exact_master,
            artifact_status=artifact_status,
            structural_status=structural_status,
            weight_status=weight_status,
            contract_status=contract_status,
            reference_fingerprints=ref_prints,
            candidate_fingerprints=cand_prints,
            structural_differences=structural_diffs,
            contract_differences=contract_diffs,
            tensor_changes=tensor_changes,
            tensor_summary=tensor_summary,
            reason_codes=reason_codes,
            warnings=[],
        )

    def compare_artifacts(
        self,
        reference_path: Union[str, Path],
        candidate_path: Union[str, Path],
    ) -> ModelComparisonResult:
        """Inspect and compare two model artifacts on disk from end to end.

        Args:
            reference_path: Path to reference model artifact on disk.
            candidate_path: Path to candidate model artifact on disk.

        Returns:
            ModelComparisonResult.
        """
        ref_p = Path(reference_path)
        cand_p = Path(candidate_path)

        # Ingest both artifacts safely
        ref_insp = self.ingestion_service.inspect_artifact(ref_p)
        cand_insp = self.ingestion_service.inspect_artifact(cand_p)

        ref_trust = "VERIFIED" if ref_insp.normalized_metadata is not None else "INVALID"
        cand_trust = "VERIFIED" if cand_insp.normalized_metadata is not None else "INVALID"

        ref_meta = ref_insp.normalized_metadata
        cand_meta = cand_insp.normalized_metadata

        # Fingerprint both models
        ref_fp = (
            self.fingerprinting_service.fingerprint_model(ref_p, metadata=ref_meta)
            if ref_meta is not None
            else HierarchicalFingerprintResult(
                schema_version="1.0",
                status="unavailable",
                artifact_hash="0" * 64,
                structural_hash="0" * 64,
                contract_hash="0" * 64,
                weight_merkle_root=None,
                master_fingerprint="0" * 64,
                weight_status="unavailable",
            )
        )
        cand_fp = (
            self.fingerprinting_service.fingerprint_model(cand_p, metadata=cand_meta)
            if cand_meta is not None
            else HierarchicalFingerprintResult(
                schema_version="1.0",
                status="unavailable",
                artifact_hash="0" * 64,
                structural_hash="0" * 64,
                contract_hash="0" * 64,
                weight_merkle_root=None,
                master_fingerprint="0" * 64,
                weight_status="unavailable",
            )
        )

        # Extract leaves if possible
        ref_leaves = None
        cand_leaves = None
        if ref_meta is not None:
            try:
                ref_leaves = extract_tensor_leaves(ref_p, ref_meta)
            except Exception:
                ref_leaves = None
        if cand_meta is not None:
            try:
                cand_leaves = extract_tensor_leaves(cand_p, cand_meta)
            except Exception:
                cand_leaves = None

        # Verify contracts
        ref_contract = self.contract_service.verify_contract(ref_meta) if ref_meta is not None else None
        cand_contract = self.contract_service.verify_contract(cand_meta) if cand_meta is not None else None

        return self.compare_models(
            reference_fingerprint=ref_fp,
            candidate_fingerprint=cand_fp,
            reference_metadata=ref_meta,
            candidate_metadata=cand_meta,
            reference_leaves=ref_leaves,
            candidate_leaves=cand_leaves,
            reference_contract=ref_contract,
            candidate_contract=cand_contract,
            reference_trust=ref_trust,
            candidate_trust=cand_trust,
        )
