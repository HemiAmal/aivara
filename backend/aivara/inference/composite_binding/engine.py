"""Core deterministic engine and verification for Phase 10.7 Cryptographic Input-to-Output Binding."""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any, Dict, List, Optional, Union

from aivara.crypto.canonical import canonicalize
from aivara.inference.binding.models import InputModelBinding
from aivara.inference.composite_binding.models import (
    InferenceBinding,
    InferenceBindingVerificationResult,
)
from aivara.inference.enums import (
    InferenceFindingCode,
    InferenceIntegrityStatus,
)
from aivara.inference.exceptions import (
    InferenceBindingComponentMismatchError,
    InferenceBindingError,
    InferenceBindingHashMismatchError,
    InferenceBindingMissingComponentError,
    InferenceBindingProjectMismatchError,
    InferenceBindingUnavailableError,
    InferenceBindingUnverifiableError,
    InvalidHashFormatError,
)
from aivara.inference.execution.models import InferenceExecution
from aivara.inference.input.models import InputFinding, InputIdentity
from aivara.inference.output.models import OutputIntegrityAssessment
from aivara.inference.preprocessing.models import (
    PreprocessingContract,
    TransformedInputIdentity,
)

HEX64_LOWERCASE_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def validate_sha256_hex_format(name: str, value: Any) -> None:
    """Validate that a field is a strict 64-character lowercase hexadecimal SHA-256 digest."""
    if not isinstance(value, str) or not HEX64_LOWERCASE_PATTERN.match(value):
        raise InvalidHashFormatError(
            f"Field '{name}' must be a 64-character lowercase hex SHA-256 digest, got '{value}'.",
            details={"field": name, "value": str(value)},
        )


def build_canonical_inference_binding_descriptor(
    *,
    project_id: str,
    input_id: str,
    input_canonical_hash: str,
    input_raw_hash: Optional[str] = None,
    model_id: str,
    model_master_fingerprint: str,
    model_artifact_hash: str,
    model_structural_hash: str,
    model_contract_hash: str,
    input_model_binding_hash: str,
    preprocessing_contract_hash: str,
    transformed_input_hash: str,
    execution_identity_hash: str,
    raw_output_hash: str,
    validated_output_identity: str,
    output_contract_hash: Optional[str] = None,
    binding_version: str = "1.0",
    schema_version: str = "1.0",
) -> Dict[str, Any]:
    """Construct the deterministic dictionary descriptor for RFC 8785 JCS canonicalization.

    Commits all 18 atomic transaction parameters into a canonical sorted dictionary.
    """
    return {
        "binding_version": str(binding_version),
        "execution_identity_hash": str(execution_identity_hash),
        "input_canonical_hash": str(input_canonical_hash),
        "input_id": str(input_id),
        "input_model_binding_hash": str(input_model_binding_hash),
        "input_raw_hash": str(input_raw_hash) if input_raw_hash else "",
        "model_artifact_hash": str(model_artifact_hash),
        "model_contract_hash": str(model_contract_hash),
        "model_id": str(model_id),
        "model_master_fingerprint": str(model_master_fingerprint),
        "model_structural_hash": str(model_structural_hash),
        "output_contract_hash": str(output_contract_hash) if output_contract_hash else "",
        "preprocessing_contract_hash": str(preprocessing_contract_hash),
        "project_id": str(project_id),
        "raw_output_hash": str(raw_output_hash),
        "schema_version": str(schema_version),
        "transformed_input_hash": str(transformed_input_hash),
        "validated_output_identity": str(validated_output_identity),
    }


def compute_inference_binding_hash(descriptor: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over the canonical RFC 8785 JCS inference binding descriptor."""
    canonical_bytes = canonicalize(descriptor)
    return hashlib.sha256(canonical_bytes).hexdigest()


def create_inference_binding(
    *,
    project_id: str,
    input_identity: Optional[InputIdentity] = None,
    input_model_binding: Optional[InputModelBinding] = None,
    preprocessing_contract: Optional[PreprocessingContract] = None,
    transformed_input: Optional[TransformedInputIdentity] = None,
    execution: Optional[InferenceExecution] = None,
    output_assessment: Optional[OutputIntegrityAssessment] = None,
    # Direct hash parameters (used when passing explicit envelopes or tested components)
    input_id: Optional[str] = None,
    input_canonical_hash: Optional[str] = None,
    input_raw_hash: Optional[str] = None,
    model_id: Optional[str] = None,
    model_master_fingerprint: Optional[str] = None,
    model_artifact_hash: Optional[str] = None,
    model_structural_hash: Optional[str] = None,
    model_contract_hash: Optional[str] = None,
    input_model_binding_hash: Optional[str] = None,
    preprocessing_contract_hash: Optional[str] = None,
    transformed_input_hash: Optional[str] = None,
    execution_identity_hash: Optional[str] = None,
    raw_output_hash: Optional[str] = None,
    validated_output_identity: Optional[str] = None,
    output_contract_hash: Optional[str] = None,
    binding_version: str = "1.0",
    schema_version: str = "1.0",
    raise_on_error: bool = True,
) -> InferenceBinding:
    """Create an immutable, cryptographically verifiable InferenceBinding across the entire transaction."""
    findings: List[InputFinding] = []
    details: Dict[str, Any] = {}

    # 1. Project ID Validation
    if not isinstance(project_id, str) or not project_id.strip():
        err = "project_id must be a non-empty string."
        if raise_on_error:
            raise InferenceBindingProjectMismatchError(err, details={"project_id": str(project_id)})
        findings.append(InputFinding(code=InferenceFindingCode.INFERENCE_BINDING_PROJECT_MISMATCH.value, message=err))

    # 2. Extract and Validate Input Identity (Phase 10.2)
    resolved_input_id = input_id
    resolved_input_canonical_hash = input_canonical_hash
    resolved_input_raw_hash = input_raw_hash

    if input_identity is not None:
        resolved_input_id = input_identity.input_id
        resolved_input_canonical_hash = input_identity.canonical_hash
        resolved_input_raw_hash = input_identity.raw_file_hash
        if input_identity.validation_status != InferenceIntegrityStatus.VERIFIED:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.INFERENCE_BINDING_COMPONENT_MISMATCH.value,
                    message=f"Input identity has non-verified status: '{input_identity.validation_status}'.",
                )
            )

    # 3. Extract and Validate Input-Model Binding (Phase 10.3)
    resolved_model_id = model_id
    resolved_model_master_fingerprint = model_master_fingerprint
    resolved_model_artifact_hash = model_artifact_hash
    resolved_model_structural_hash = model_structural_hash
    resolved_model_contract_hash = model_contract_hash
    resolved_input_model_binding_hash = input_model_binding_hash

    if input_model_binding is not None:
        if input_model_binding.project_id != project_id:
            err = f"Project isolation mismatch: InputModelBinding project '{input_model_binding.project_id}' != '{project_id}'."
            if raise_on_error:
                raise InferenceBindingProjectMismatchError(err)
            findings.append(InputFinding(code=InferenceFindingCode.INFERENCE_BINDING_PROJECT_MISMATCH.value, message=err))

        resolved_model_id = input_model_binding.model_id
        resolved_model_master_fingerprint = input_model_binding.model_master_fingerprint
        resolved_model_artifact_hash = input_model_binding.model_artifact_hash
        resolved_model_structural_hash = input_model_binding.model_structural_hash
        resolved_model_contract_hash = input_model_binding.model_contract_hash
        resolved_input_model_binding_hash = input_model_binding.binding_hash

        # Cross-stage consistency check with InputIdentity
        if resolved_input_id and input_model_binding.input_id != resolved_input_id:
            err = f"Input ID divergence: InputModelBinding input_id '{input_model_binding.input_id}' != '{resolved_input_id}'."
            if raise_on_error:
                raise InferenceBindingComponentMismatchError(err)
            findings.append(InputFinding(code=InferenceFindingCode.INFERENCE_BINDING_COMPONENT_MISMATCH.value, message=err))

    # 4. Extract and Validate Preprocessing (Phase 10.4)
    resolved_preprocessing_contract_hash = preprocessing_contract_hash
    if preprocessing_contract is not None:
        resolved_preprocessing_contract_hash = preprocessing_contract.contract_hash

    resolved_transformed_input_hash = transformed_input_hash
    if transformed_input is not None:
        resolved_transformed_input_hash = (
            getattr(transformed_input, "transformed_canonical_hash", None)
            or getattr(transformed_input, "transformed_input_hash", None)
        )
        if resolved_input_id and transformed_input.input_id != resolved_input_id:
            err = f"Input ID divergence: Transformed input input_id '{transformed_input.input_id}' != '{resolved_input_id}'."
            if raise_on_error:
                raise InferenceBindingComponentMismatchError(err)
            findings.append(InputFinding(code=InferenceFindingCode.INFERENCE_BINDING_COMPONENT_MISMATCH.value, message=err))

    # 5. Extract and Validate Execution (Phase 10.5)
    resolved_execution_identity_hash = execution_identity_hash
    resolved_raw_output_hash = raw_output_hash

    if execution is not None:
        if execution.project_id != project_id:
            err = f"Project isolation mismatch: InferenceExecution project '{execution.project_id}' != '{project_id}'."
            if raise_on_error:
                raise InferenceBindingProjectMismatchError(err)
            findings.append(InputFinding(code=InferenceFindingCode.INFERENCE_BINDING_PROJECT_MISMATCH.value, message=err))

        resolved_execution_identity_hash = execution.execution_identity_hash
        resolved_raw_output_hash = execution.raw_output_hash or (execution.raw_output.raw_output_hash if execution.raw_output else None)

        if resolved_input_id and execution.input_id != resolved_input_id:
            err = f"Input ID divergence: InferenceExecution input_id '{execution.input_id}' != '{resolved_input_id}'."
            if raise_on_error:
                raise InferenceBindingComponentMismatchError(err)
            findings.append(InputFinding(code=InferenceFindingCode.INFERENCE_BINDING_COMPONENT_MISMATCH.value, message=err))

        if resolved_input_model_binding_hash and execution.binding_hash != resolved_input_model_binding_hash:
            err = f"Binding hash divergence: InferenceExecution binding_hash '{execution.binding_hash}' != '{resolved_input_model_binding_hash}'."
            if raise_on_error:
                raise InferenceBindingComponentMismatchError(err)
            findings.append(InputFinding(code=InferenceFindingCode.INFERENCE_BINDING_COMPONENT_MISMATCH.value, message=err))

    # 6. Extract and Validate Output Assessment (Phase 10.6)
    resolved_validated_output_identity = validated_output_identity
    resolved_output_contract_hash = output_contract_hash

    if output_assessment is not None:
        resolved_validated_output_identity = output_assessment.validated_output_identity
        if output_assessment.output_contract_hash:
            resolved_output_contract_hash = output_assessment.output_contract_hash

        # Cross-stage raw output hash verification
        if resolved_raw_output_hash and output_assessment.raw_output_hash != resolved_raw_output_hash:
            err = f"Raw output hash divergence: OutputIntegrityAssessment raw_output_hash '{output_assessment.raw_output_hash}' != '{resolved_raw_output_hash}'."
            if raise_on_error:
                raise InferenceBindingComponentMismatchError(err)
            findings.append(InputFinding(code=InferenceFindingCode.INFERENCE_BINDING_RAW_OUTPUT_MISMATCH.value, message=err))

    # 7. Check for Missing Mandatory Components
    missing_fields: List[str] = []
    if not resolved_input_id:
        missing_fields.append("input_id")
    if not resolved_input_canonical_hash:
        missing_fields.append("input_canonical_hash")
    if not resolved_model_id:
        missing_fields.append("model_id")
    if not resolved_model_master_fingerprint:
        missing_fields.append("model_master_fingerprint")
    if not resolved_model_artifact_hash:
        missing_fields.append("model_artifact_hash")
    if not resolved_model_structural_hash:
        missing_fields.append("model_structural_hash")
    if not resolved_model_contract_hash:
        missing_fields.append("model_contract_hash")
    if not resolved_input_model_binding_hash:
        missing_fields.append("input_model_binding_hash")
    if not resolved_preprocessing_contract_hash:
        missing_fields.append("preprocessing_contract_hash")
    if not resolved_transformed_input_hash:
        missing_fields.append("transformed_input_hash")
    if not resolved_execution_identity_hash:
        missing_fields.append("execution_identity_hash")
    if not resolved_raw_output_hash:
        missing_fields.append("raw_output_hash")
    if not resolved_validated_output_identity:
        missing_fields.append("validated_output_identity")

    if missing_fields:
        err = f"Missing mandatory transaction components for end-to-end binding: {', '.join(missing_fields)}."
        if raise_on_error:
            raise InferenceBindingMissingComponentError(err, details={"missing_fields": missing_fields})
        findings.append(InputFinding(code=InferenceFindingCode.INFERENCE_BINDING_INPUT_MISSING.value, message=err))

    # 8. SHA-256 Hex Format Validation
    if raise_on_error or not missing_fields:
        validate_sha256_hex_format("input_id", resolved_input_id)
        validate_sha256_hex_format("input_canonical_hash", resolved_input_canonical_hash)
        if resolved_input_raw_hash:
            validate_sha256_hex_format("input_raw_hash", resolved_input_raw_hash)
        validate_sha256_hex_format("model_master_fingerprint", resolved_model_master_fingerprint)
        validate_sha256_hex_format("model_artifact_hash", resolved_model_artifact_hash)
        validate_sha256_hex_format("model_structural_hash", resolved_model_structural_hash)
        validate_sha256_hex_format("model_contract_hash", resolved_model_contract_hash)
        validate_sha256_hex_format("input_model_binding_hash", resolved_input_model_binding_hash)
        validate_sha256_hex_format("preprocessing_contract_hash", resolved_preprocessing_contract_hash)
        validate_sha256_hex_format("transformed_input_hash", resolved_transformed_input_hash)
        validate_sha256_hex_format("execution_identity_hash", resolved_execution_identity_hash)
        validate_sha256_hex_format("raw_output_hash", resolved_raw_output_hash)
        validate_sha256_hex_format("validated_output_identity", resolved_validated_output_identity)
        if resolved_output_contract_hash:
            validate_sha256_hex_format("output_contract_hash", resolved_output_contract_hash)

    # 9. Construct Canonical Descriptor & Compute Inference Binding Hash
    descriptor = build_canonical_inference_binding_descriptor(
        project_id=project_id,
        input_id=resolved_input_id,
        input_canonical_hash=resolved_input_canonical_hash,
        input_raw_hash=resolved_input_raw_hash,
        model_id=resolved_model_id,
        model_master_fingerprint=resolved_model_master_fingerprint,
        model_artifact_hash=resolved_model_artifact_hash,
        model_structural_hash=resolved_model_structural_hash,
        model_contract_hash=resolved_model_contract_hash,
        input_model_binding_hash=resolved_input_model_binding_hash,
        preprocessing_contract_hash=resolved_preprocessing_contract_hash,
        transformed_input_hash=resolved_transformed_input_hash,
        execution_identity_hash=resolved_execution_identity_hash,
        raw_output_hash=resolved_raw_output_hash,
        validated_output_identity=resolved_validated_output_identity,
        output_contract_hash=resolved_output_contract_hash,
        binding_version=binding_version,
        schema_version=schema_version,
    )
    binding_hash = compute_inference_binding_hash(descriptor)

    # 10. Status Determination
    status = InferenceIntegrityStatus.VERIFIED
    if any(
        f.code in (
            InferenceFindingCode.INFERENCE_BINDING_PROJECT_MISMATCH.value,
            InferenceFindingCode.INFERENCE_BINDING_COMPONENT_MISMATCH.value,
            InferenceFindingCode.INFERENCE_BINDING_RAW_OUTPUT_MISMATCH.value,
        )
        for f in findings
    ):
        status = InferenceIntegrityStatus.MISMATCHED
    elif missing_fields:
        status = InferenceIntegrityStatus.MISSING
    elif output_assessment and output_assessment.integrity_status != InferenceIntegrityStatus.VERIFIED:
        status = output_assessment.integrity_status

    details["binding_version"] = binding_version
    details["schema_version"] = schema_version
    details["project_id"] = project_id

    return InferenceBinding(
        schema_version=schema_version,
        binding_version=binding_version,
        project_id=project_id,
        input_id=resolved_input_id,
        input_canonical_hash=resolved_input_canonical_hash,
        input_raw_hash=resolved_input_raw_hash,
        model_id=resolved_model_id,
        model_master_fingerprint=resolved_model_master_fingerprint,
        model_artifact_hash=resolved_model_artifact_hash,
        model_structural_hash=resolved_model_structural_hash,
        model_contract_hash=resolved_model_contract_hash,
        input_model_binding_hash=resolved_input_model_binding_hash,
        preprocessing_contract_hash=resolved_preprocessing_contract_hash,
        transformed_input_hash=resolved_transformed_input_hash,
        execution_identity_hash=resolved_execution_identity_hash,
        raw_output_hash=resolved_raw_output_hash,
        validated_output_identity=resolved_validated_output_identity,
        output_contract_hash=resolved_output_contract_hash,
        binding_status=status,
        inference_binding_hash=binding_hash,
        findings=findings,
        details=details,
    )


def verify_inference_binding(
    binding: InferenceBinding,
    *,
    input_identity: Optional[InputIdentity] = None,
    input_model_binding: Optional[InputModelBinding] = None,
    preprocessing_contract: Optional[PreprocessingContract] = None,
    transformed_input: Optional[TransformedInputIdentity] = None,
    execution: Optional[InferenceExecution] = None,
    output_assessment: Optional[OutputIntegrityAssessment] = None,
) -> InferenceBindingVerificationResult:
    """Pure cryptographic verification of an InferenceBinding transaction."""
    findings: List[InputFinding] = []
    details: Dict[str, Any] = {}

    # 1. Validate hash format on binding itself
    try:
        validate_sha256_hex_format("inference_binding_hash", binding.inference_binding_hash)
        validate_sha256_hex_format("input_id", binding.input_id)
        validate_sha256_hex_format("input_canonical_hash", binding.input_canonical_hash)
        if binding.input_raw_hash:
            validate_sha256_hex_format("input_raw_hash", binding.input_raw_hash)
        validate_sha256_hex_format("model_master_fingerprint", binding.model_master_fingerprint)
        validate_sha256_hex_format("model_artifact_hash", binding.model_artifact_hash)
        validate_sha256_hex_format("model_structural_hash", binding.model_structural_hash)
        validate_sha256_hex_format("model_contract_hash", binding.model_contract_hash)
        validate_sha256_hex_format("input_model_binding_hash", binding.input_model_binding_hash)
        validate_sha256_hex_format("preprocessing_contract_hash", binding.preprocessing_contract_hash)
        validate_sha256_hex_format("transformed_input_hash", binding.transformed_input_hash)
        validate_sha256_hex_format("execution_identity_hash", binding.execution_identity_hash)
        validate_sha256_hex_format("raw_output_hash", binding.raw_output_hash)
        validate_sha256_hex_format("validated_output_identity", binding.validated_output_identity)
        if binding.output_contract_hash:
            validate_sha256_hex_format("output_contract_hash", binding.output_contract_hash)
    except InvalidHashFormatError as e:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.INFERENCE_BINDING_HASH_MISMATCH.value,
                message=f"Hash format validation error: {str(e)}",
            )
        )
        return InferenceBindingVerificationResult(
            is_valid=False,
            status=InferenceIntegrityStatus.INVALID,
            computed_binding_hash="",
            expected_binding_hash=binding.inference_binding_hash,
            findings=findings,
            details=details,
        )

    # 2. Recompute Canonical Descriptor & Hash
    descriptor = build_canonical_inference_binding_descriptor(
        project_id=binding.project_id,
        input_id=binding.input_id,
        input_canonical_hash=binding.input_canonical_hash,
        input_raw_hash=binding.input_raw_hash,
        model_id=binding.model_id,
        model_master_fingerprint=binding.model_master_fingerprint,
        model_artifact_hash=binding.model_artifact_hash,
        model_structural_hash=binding.model_structural_hash,
        model_contract_hash=binding.model_contract_hash,
        input_model_binding_hash=binding.input_model_binding_hash,
        preprocessing_contract_hash=binding.preprocessing_contract_hash,
        transformed_input_hash=binding.transformed_input_hash,
        execution_identity_hash=binding.execution_identity_hash,
        raw_output_hash=binding.raw_output_hash,
        validated_output_identity=binding.validated_output_identity,
        output_contract_hash=binding.output_contract_hash,
        binding_version=binding.binding_version,
        schema_version=binding.schema_version,
    )
    computed_hash = compute_inference_binding_hash(descriptor)

    # Constant-time comparison
    hash_matches = hmac.compare_digest(computed_hash, binding.inference_binding_hash)
    if not hash_matches:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.INFERENCE_BINDING_HASH_MISMATCH.value,
                message=f"Computed binding hash '{computed_hash}' does not match expected '{binding.inference_binding_hash}'.",
                details={"computed": computed_hash, "expected": binding.inference_binding_hash},
            )
        )

    # 3. Component Consistency Checks
    if input_identity and input_identity.input_id != binding.input_id:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.INFERENCE_BINDING_COMPONENT_MISMATCH.value,
                message=f"InputIdentity input_id '{input_identity.input_id}' does not match binding '{binding.input_id}'.",
            )
        )

    if input_model_binding:
        if input_model_binding.project_id != binding.project_id:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.INFERENCE_BINDING_PROJECT_MISMATCH.value,
                    message=f"InputModelBinding project '{input_model_binding.project_id}' != '{binding.project_id}'.",
                )
            )
        if input_model_binding.binding_hash != binding.input_model_binding_hash:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.INFERENCE_BINDING_COMPONENT_MISMATCH.value,
                    message=f"InputModelBinding hash '{input_model_binding.binding_hash}' != '{binding.input_model_binding_hash}'.",
                )
            )

    if preprocessing_contract and preprocessing_contract.contract_hash != binding.preprocessing_contract_hash:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.INFERENCE_BINDING_COMPONENT_MISMATCH.value,
                message=f"Preprocessing contract hash '{preprocessing_contract.contract_hash}' != '{binding.preprocessing_contract_hash}'.",
            )
        )

    if transformed_input:
        exp_th = (
            getattr(transformed_input, "transformed_canonical_hash", None)
            or getattr(transformed_input, "transformed_input_hash", None)
        )
        if exp_th and exp_th != binding.transformed_input_hash:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.INFERENCE_BINDING_COMPONENT_MISMATCH.value,
                    message=f"Transformed input hash '{exp_th}' != '{binding.transformed_input_hash}'.",
                )
            )

    if execution:
        if execution.project_id != binding.project_id:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.INFERENCE_BINDING_PROJECT_MISMATCH.value,
                    message=f"InferenceExecution project '{execution.project_id}' != '{binding.project_id}'.",
                )
            )
        if execution.execution_identity_hash != binding.execution_identity_hash:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.INFERENCE_BINDING_COMPONENT_MISMATCH.value,
                    message=f"InferenceExecution hash '{execution.execution_identity_hash}' != '{binding.execution_identity_hash}'.",
                )
            )
        raw_exec_h = execution.raw_output_hash or (execution.raw_output.raw_output_hash if execution.raw_output else None)
        if raw_exec_h and raw_exec_h != binding.raw_output_hash:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.INFERENCE_BINDING_RAW_OUTPUT_MISMATCH.value,
                    message=f"InferenceExecution raw_output_hash '{raw_exec_h}' != '{binding.raw_output_hash}'.",
                )
            )

    if output_assessment:
        if output_assessment.validated_output_identity != binding.validated_output_identity:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.INFERENCE_BINDING_VALIDATED_OUTPUT_MISMATCH.value,
                    message=f"Output assessment identity '{output_assessment.validated_output_identity}' != '{binding.validated_output_identity}'.",
                )
            )
        if output_assessment.raw_output_hash != binding.raw_output_hash:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.INFERENCE_BINDING_RAW_OUTPUT_MISMATCH.value,
                    message=f"Output assessment raw_output_hash '{output_assessment.raw_output_hash}' != '{binding.raw_output_hash}'.",
                )
            )

    is_valid = hash_matches and len(findings) == 0
    status = InferenceIntegrityStatus.VERIFIED if is_valid else (
        InferenceIntegrityStatus.MISMATCHED if any(
            f.code in (
                InferenceFindingCode.INFERENCE_BINDING_PROJECT_MISMATCH.value,
                InferenceFindingCode.INFERENCE_BINDING_COMPONENT_MISMATCH.value,
                InferenceFindingCode.INFERENCE_BINDING_RAW_OUTPUT_MISMATCH.value,
                InferenceFindingCode.INFERENCE_BINDING_VALIDATED_OUTPUT_MISMATCH.value,
                InferenceFindingCode.INFERENCE_BINDING_HASH_MISMATCH.value,
            )
            for f in findings
        ) else InferenceIntegrityStatus.INVALID
    )

    return InferenceBindingVerificationResult(
        is_valid=is_valid,
        status=status,
        computed_binding_hash=computed_hash,
        expected_binding_hash=binding.inference_binding_hash,
        findings=findings,
        details=details,
    )
