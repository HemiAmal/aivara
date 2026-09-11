"""Model Input/Output Contract and Preprocessing Verification Service (Phase 7.4).

Orchestrates deterministic static verification of model interfaces, shape declarations,
dtype specifications, preprocessing consistency, and canonical contract hashing.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Union

from aivara.model_integrity.contract_verification.input_contract import inspect_input_contract
from aivara.model_integrity.contract_verification.normalization import (
    build_canonical_contract_representation,
)
from aivara.model_integrity.contract_verification.output_contract import inspect_output_contract
from aivara.model_integrity.contract_verification.preprocessing import (
    extract_preprocessing_from_metadata,
    validate_preprocessing_consistency,
)
from aivara.model_integrity.contract_verification.schemas import (
    ContractCompleteness,
    ContractFinding,
    ContractStatus,
    ContractVerificationResult,
    PreprocessingDeclaration,
    ValidatedInputContract,
    ValidatedOutputContract,
)
from aivara.model_integrity.contract_verification.validation import validate_contract_integrity
from aivara.model_integrity.fingerprinting.contract import compute_contract_hash
from aivara.model_integrity.limits import DEFAULT_LIMITS, ModelIngestionLimits
from aivara.model_integrity.schemas import NormalizedModelMetadata
from aivara.model_integrity.service import ModelIngestionService


class ModelContractVerificationService:
    """Orchestrator for deterministic static model contract and preprocessing verification."""

    def __init__(self, limits: Optional[ModelIngestionLimits] = None) -> None:
        self.limits = limits or DEFAULT_LIMITS
        self.ingestion_service = ModelIngestionService(limits=self.limits)

    def verify_contract(
        self,
        metadata: NormalizedModelMetadata,
        explicit_preprocessing: Optional[PreprocessingDeclaration] = None,
    ) -> ContractVerificationResult:
        """Statically verify the contract interface and preprocessing of normalized metadata.

        Args:
            metadata: NormalizedModelMetadata extracted during Phase 7.2.
            explicit_preprocessing: Optional external preprocessing declaration.

        Returns:
            ContractVerificationResult containing validated contracts, status, findings, and hash.
        """
        all_findings: List[ContractFinding] = []
        warnings: List[str] = list(metadata.warnings)

        # 1. Validate Input Contracts
        validated_inputs: List[ValidatedInputContract] = []
        for idx, raw_in in enumerate(metadata.inputs):
            v_in, in_findings = inspect_input_contract(raw_in, index=idx, limits=self.limits)
            validated_inputs.append(v_in)
            all_findings.extend(in_findings)

        # 2. Validate Output Contracts
        validated_outputs: List[ValidatedOutputContract] = []
        for idx, raw_out in enumerate(metadata.outputs):
            v_out, out_findings = inspect_output_contract(raw_out, index=idx, limits=self.limits)
            validated_outputs.append(v_out)
            all_findings.extend(out_findings)

        # 3. Preprocessing Resolution & Consistency
        preprocessing = explicit_preprocessing
        if preprocessing is None:
            preprocessing = extract_preprocessing_from_metadata(metadata)

        if preprocessing is not None:
            prep_findings = validate_preprocessing_consistency(preprocessing, validated_inputs)
            all_findings.extend(prep_findings)

        # 4. Graph Integrity & Completeness Cross-Checks
        integrity_findings, completeness, status = validate_contract_integrity(
            metadata=metadata,
            inputs=validated_inputs,
            outputs=validated_outputs,
            preprocessing=preprocessing,
            limits=self.limits,
        )
        all_findings.extend(integrity_findings)

        # If individual inputs/outputs had invalid dimensions, ensure status is INVALID
        if any(f.code.value in ("INVALID_DIMENSION", "RANK_MISMATCH") for f in all_findings):
            status = ContractStatus.INVALID
            completeness = ContractCompleteness.INVALID

        # 5. Canonical Contract Representation & Contract Hash
        contract_rep = build_canonical_contract_representation(
            inputs=validated_inputs,
            outputs=validated_outputs,
        )
        contract_hash = compute_contract_hash(contract_rep)

        return ContractVerificationResult(
            schema_version="1.0",
            status=status,
            completeness=completeness,
            inputs=validated_inputs,
            outputs=validated_outputs,
            preprocessing=preprocessing,
            findings=all_findings,
            contract_representation=contract_rep,
            contract_hash=contract_hash,
            warnings=warnings,
        )

    def verify_artifact_contract(
        self,
        artifact_path: Union[str, Path],
        explicit_preprocessing: Optional[PreprocessingDeclaration] = None,
    ) -> ContractVerificationResult:
        """Inspect model artifact from file path and verify its contract interface.

        Args:
            artifact_path: File path to untrusted model artifact.
            explicit_preprocessing: Optional external preprocessing declaration.

        Returns:
            ContractVerificationResult.
        """
        path = Path(artifact_path)
        insp_res = self.ingestion_service.inspect_artifact(path)
        if insp_res.normalized_metadata is None:
            # Inspection failed at container or security level
            contract_rep = build_canonical_contract_representation([], [])
            return ContractVerificationResult(
                schema_version="1.0",
                status=ContractStatus.INVALID,
                completeness=ContractCompleteness.INVALID,
                inputs=[],
                outputs=[],
                preprocessing=explicit_preprocessing,
                findings=[],
                contract_representation=contract_rep,
                contract_hash=compute_contract_hash(contract_rep),
                warnings=insp_res.warnings,
            )

        return self.verify_contract(
            metadata=insp_res.normalized_metadata,
            explicit_preprocessing=explicit_preprocessing,
        )
