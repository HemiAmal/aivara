"""Model Fingerprinting Service Orchestrator (Phase 7.3).

Coordinates hierarchical multi-tier fingerprinting:
  1. Artifact Hash (H_artifact)
  2. Structural Hash (H_structural)
  3. Weight Merkle Root (H_weight_merkle)
  4. Contract Hash (H_contract)
  5. Master Model Fingerprint (H_model)
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Union

from aivara.model_integrity.fingerprinting.artifact import compute_artifact_hash
from aivara.model_integrity.fingerprinting.contract import (
    build_contract_representation,
    compute_contract_hash,
)
from aivara.model_integrity.fingerprinting.exceptions import (
    FingerprintingError,
    WeightContentUnavailableError,
)
from aivara.model_integrity.fingerprinting.master import compute_master_fingerprint
from aivara.model_integrity.fingerprinting.merkle import (
    EMPTY_WEIGHT_ROOT_HEX,
    WeightMerkleTree,
)
from aivara.model_integrity.fingerprinting.schemas import (
    HierarchicalFingerprintResult,
    WeightMerkleResult,
)
from aivara.model_integrity.fingerprinting.structural import (
    build_structural_representation,
    compute_structural_hash,
)
from aivara.model_integrity.fingerprinting.tensors import extract_tensor_leaves
from aivara.model_integrity.limits import DEFAULT_LIMITS, ModelIngestionLimits
from aivara.model_integrity.schemas import (
    InspectionStatus,
    NormalizedModelMetadata,
    ReasonCode,
)
from aivara.model_integrity.service import ModelIngestionService


class ModelFingerprintingService:
    """Orchestrator for hierarchical model identity derivation."""

    def __init__(self, limits: Optional[ModelIngestionLimits] = None) -> None:
        self.limits = limits or DEFAULT_LIMITS
        self.ingestion_service = ModelIngestionService(limits=self.limits)

    def fingerprint_model(
        self,
        artifact_path: Union[str, Path],
        metadata: Optional[NormalizedModelMetadata] = None,
    ) -> HierarchicalFingerprintResult:
        """Compute the full hierarchical cryptographic fingerprint for a model artifact.

        Args:
            artifact_path: Validated path or string to model artifact.
            metadata: Optional pre-parsed NormalizedModelMetadata from Phase 7.2.

        Returns:
            HierarchicalFingerprintResult containing all 5 distinct identity components.
        """
        path = Path(artifact_path)
        warnings = []
        reason_codes = []

        # 1. Ingest/inspect if metadata not supplied
        if metadata is None:
            insp_res = self.ingestion_service.inspect_artifact(path)
            if insp_res.normalized_metadata is None:
                raise FingerprintingError(
                    f"Model inspection failed: {insp_res.warnings}",
                    details={"reasons": [r.value for r in insp_res.reason_codes]},
                )
            metadata = insp_res.normalized_metadata
            artifact_hash = insp_res.artifact_hash_sha256 or compute_artifact_hash(path)
            warnings.extend(insp_res.warnings)
            reason_codes.extend(insp_res.reason_codes)
        else:
            artifact_hash = metadata.artifact_hash_sha256
            warnings.extend(metadata.warnings)
            reason_codes.extend(metadata.reason_codes)

        # 2. Structural Identity (H_structural)
        structural_rep = build_structural_representation(metadata)
        structural_hash = compute_structural_hash(structural_rep)

        # 3. Contract Identity (H_contract)
        contract_rep = build_contract_representation(metadata)
        contract_hash = compute_contract_hash(contract_rep)

        # 4. Weight Merkle Tree & Root (H_weight_merkle)
        weight_root: Optional[str] = None
        weight_status = "unavailable"

        try:
            leaves = extract_tensor_leaves(path, metadata)
            tree = WeightMerkleTree(leaves)
            weight_root = tree.root_hex
            weight_status = "empty" if tree.total_leaves == 0 else "verified"
        except WeightContentUnavailableError as e:
            weight_status = "unavailable"
            warnings.append(
                f"Weight Merkle tree calculation unavailable for format '{metadata.format.value}': {e}"
            )
        except Exception as e:
            weight_status = "unavailable"
            warnings.append(f"Could not compute weight Merkle tree: {e}")

        # 5. Master Model Fingerprint (H_model)
        master_fp = compute_master_fingerprint(
            artifact_hash=artifact_hash,
            structural_hash=structural_hash,
            contract_hash=contract_hash,
        )

        overall_status = "verified"
        if weight_status == "unavailable":
            overall_status = "partial"

        return HierarchicalFingerprintResult(
            schema_version="1.0",
            status=overall_status,
            artifact_hash=artifact_hash,
            structural_hash=structural_hash,
            contract_hash=contract_hash,
            weight_merkle_root=weight_root,
            master_fingerprint=master_fp,
            weight_status=weight_status,
            tensor_count=metadata.tensor_count,
            parameter_count=metadata.parameter_count,
            reason_codes=reason_codes,
            warnings=warnings,
        )

    def compute_weight_merkle_tree(
        self,
        artifact_path: Union[str, Path],
        metadata: Optional[NormalizedModelMetadata] = None,
    ) -> WeightMerkleResult:
        """Compute only the weight Merkle tree and leaf descriptors."""
        path = Path(artifact_path)
        if metadata is None:
            insp_res = self.ingestion_service.inspect_artifact(path)
            if insp_res.normalized_metadata is None:
                raise FingerprintingError(
                    f"Model inspection failed: {insp_res.warnings}",
                    details={"reasons": [r.value for r in insp_res.reason_codes]},
                )
            metadata = insp_res.normalized_metadata

        leaves = extract_tensor_leaves(path, metadata)
        tree = WeightMerkleTree(leaves)
        return tree.to_result()
