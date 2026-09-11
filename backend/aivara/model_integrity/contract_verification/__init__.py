"""Contract Verification Module for Model Integrity Engine (Phase 7.4).

Provides static validation, shape checking, dtype canonicalization, preprocessing
consistency, graph interface integrity, and canonical contract hashing for AI/CV models.
"""

from aivara.model_integrity.contract_verification.input_contract import (
    inspect_input_contract,
)
from aivara.model_integrity.contract_verification.normalization import (
    DTYPE_CANONICAL_MAP,
    build_canonical_contract_representation,
    normalize_dtype,
    normalize_shape_entry,
)
from aivara.model_integrity.contract_verification.output_contract import (
    inspect_output_contract,
)
from aivara.model_integrity.contract_verification.preprocessing import (
    extract_preprocessing_from_metadata,
    validate_preprocessing_consistency,
)
from aivara.model_integrity.contract_verification.schemas import (
    ContractCompleteness,
    ContractFinding,
    ContractFindingCode,
    ContractStatus,
    FindingSeverity,
    PreprocessingDeclaration,
    PreprocessingSource,
    ValidatedInputContract,
    ValidatedOutputContract,
    ContractVerificationResult,
)
from aivara.model_integrity.contract_verification.service import (
    ModelContractVerificationService,
)
from aivara.model_integrity.contract_verification.validation import (
    validate_contract_integrity,
)

__all__ = [
    # Core Service
    "ModelContractVerificationService",
    # Functions
    "inspect_input_contract",
    "inspect_output_contract",
    "extract_preprocessing_from_metadata",
    "validate_preprocessing_consistency",
    "validate_contract_integrity",
    "normalize_dtype",
    "normalize_shape_entry",
    "build_canonical_contract_representation",
    # Schemas & Enums
    "ContractStatus",
    "ContractCompleteness",
    "PreprocessingSource",
    "FindingSeverity",
    "ContractFindingCode",
    "ContractFinding",
    "ValidatedInputContract",
    "ValidatedOutputContract",
    "PreprocessingDeclaration",
    "ContractVerificationResult",
    "DTYPE_CANONICAL_MAP",
]
