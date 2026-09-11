"""Reference Model Comparison & Drift Attribution Module (Phase 7.5).

Provides deterministic comparison between reference and candidate models across
artifact identity, structural architecture, weight Merkle roots, and I/O contracts.
"""

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
    ContractDifferenceRecord,
    DriftClassification,
    ModelComparisonResult,
    StructuralComparisonStatus,
    StructuralDifferenceRecord,
    TensorChangeRecord,
    TensorChangeType,
    WeightComparisonStatus,
)
from aivara.model_integrity.comparison.service import ModelComparisonService
from aivara.model_integrity.comparison.structural import (
    compare_structural_hashes,
    diff_structural_metadata,
)
from aivara.model_integrity.comparison.weights import (
    attribute_tensor_changes,
    compare_weight_roots,
)

__all__ = [
    # Core Service
    "ModelComparisonService",
    # Functions
    "compare_artifact_hashes",
    "compare_master_fingerprints",
    "compare_structural_hashes",
    "diff_structural_metadata",
    "compare_weight_roots",
    "attribute_tensor_changes",
    "compare_contract_hashes",
    "diff_contract_metadata",
    "classify_drift",
    "determine_comparison_status",
    "synthesize_reason_codes",
    # Schemas & Enums
    "ComparisonStatus",
    "ArtifactComparisonStatus",
    "StructuralComparisonStatus",
    "WeightComparisonStatus",
    "ContractComparisonStatus",
    "DriftClassification",
    "TensorChangeType",
    "TensorChangeRecord",
    "StructuralDifferenceRecord",
    "ContractDifferenceRecord",
    "ModelComparisonResult",
]
