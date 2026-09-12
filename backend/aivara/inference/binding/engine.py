"""Input / Model Binding Engine for AIVARA Phase 10 Inference Integrity."""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from aivara.crypto.canonical import canonicalize
from aivara.inference.enums import (
    InferenceFindingCode,
    InferenceIntegrityStatus,
    InputKind,
)
from aivara.inference.exceptions import (
    BindingError,
    BindingInconsistencyError,
    InvalidHashFormatError,
    ModelIntegrityBindingError,
    ProjectMismatchError,
    InferenceInputError,
)
from aivara.inference.binding.models import (
    BindingVerificationResult,
    InputModelBinding,
    ModelIdentityEnvelope,
)
from aivara.inference.input.models import InputFinding, InputIdentity
from aivara.model_integrity.fingerprinting.schemas import HierarchicalFingerprintResult

_SHA256_HEX_REGEX = re.compile(r"^[0-9a-f]{64}$")
_BINDING_SCHEMA_VERSION = "1.0"
_BINDING_VERSION = "1.0"


def validate_sha256_hex_format(name: str, value: str) -> None:
    """Verify that a string is a 64-character lowercase hexadecimal digest."""
    if not isinstance(value, str) or not _SHA256_HEX_REGEX.match(value):
        raise InvalidHashFormatError(
            f"Field '{name}' must be a 64-character lowercase hex SHA-256 digest, got '{value}'.",
            details={"field": name, "value": str(value)},
        )


def build_canonical_binding_descriptor(
    *,
    binding_version: str = _BINDING_VERSION,
    input_canonical_hash: str,
    input_id: str,
    input_kind: Union[str, InputKind],
    model_artifact_hash: str,
    model_contract_hash: str,
    model_id: str,
    model_master_fingerprint: str,
    model_structural_hash: str,
    project_id: str,
    schema_version: str = _BINDING_SCHEMA_VERSION,
) -> Dict[str, Any]:
    """Construct the deterministic dictionary descriptor for RFC 8785 JCS canonicalization."""
    kind_str = input_kind.value if isinstance(input_kind, InputKind) else str(input_kind)
    return {
        "binding_version": binding_version,
        "input_canonical_hash": input_canonical_hash,
        "input_id": input_id,
        "input_kind": kind_str,
        "model_artifact_hash": model_artifact_hash,
        "model_contract_hash": model_contract_hash,
        "model_id": model_id,
        "model_master_fingerprint": model_master_fingerprint,
        "model_structural_hash": model_structural_hash,
        "project_id": project_id,
        "schema_version": schema_version,
    }


def compute_binding_hash(descriptor: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 digest of RFC 8785 JCS canonicalized descriptor."""
    canonical_bytes = canonicalize(descriptor)
    return hashlib.sha256(canonical_bytes).hexdigest()


def verify_master_fingerprint_consistency(
    artifact_hash: str,
    structural_hash: str,
    contract_hash: str,
    master_fingerprint: str,
) -> bool:
    """Verify Phase 7 ADR-040 Master Fingerprint internal cryptographic consistency."""
    binding_payload = {
        "artifact_hash": artifact_hash,
        "contract_hash": contract_hash,
        "schema_version": "1.0",
        "structural_hash": structural_hash,
    }
    computed_master = hashlib.sha256(canonicalize(binding_payload)).hexdigest()
    return hmac.compare_digest(computed_master, master_fingerprint)


def _extract_model_identity_components(
    model_identity: Union[ModelIdentityEnvelope, HierarchicalFingerprintResult, Dict[str, Any]],
    model_id: Optional[str] = None,
    project_id: Optional[str] = None,
) -> Tuple[str, str, str, str, str, str, str]:
    """Extract and validate normalized components from various model identity representations.

    Returns:
        Tuple of (model_id, model_project_id, master_fingerprint, artifact_hash, structural_hash, contract_hash, status).
    """
    if isinstance(model_identity, ModelIdentityEnvelope):
        return (
            model_identity.model_id,
            model_identity.project_id,
            model_identity.master_fingerprint,
            model_identity.artifact_hash,
            model_identity.structural_hash,
            model_identity.contract_hash,
            model_identity.status,
        )
    elif isinstance(model_identity, HierarchicalFingerprintResult):
        if not model_id:
            raise ModelIntegrityBindingError("Explicit model_id required when binding from HierarchicalFingerprintResult.")
        return (
            model_id,
            project_id or "",
            model_identity.master_fingerprint,
            model_identity.artifact_hash,
            model_identity.structural_hash,
            model_identity.contract_hash,
            model_identity.status,
        )
    elif isinstance(model_identity, dict):
        m_id = model_identity.get("model_id") or model_id or ""
        p_id = model_identity.get("project_id") or project_id or ""
        mf = model_identity.get("master_fingerprint") or ""
        ah = model_identity.get("artifact_hash") or model_identity.get("artifact_hash_sha256") or ""
        sh = model_identity.get("structural_hash") or ""
        ch = model_identity.get("contract_hash") or ""
        st = model_identity.get("status") or "verified"
        return (m_id, p_id, mf, ah, sh, ch, st)
    else:
        raise ModelIntegrityBindingError(
            f"Unsupported model identity type '{type(model_identity).__name__}'.",
            details={"type": type(model_identity).__name__},
        )


def create_input_model_binding(
    input_identity: InputIdentity,
    model_identity: Union[ModelIdentityEnvelope, HierarchicalFingerprintResult, Dict[str, Any]],
    project_id: str,
    model_id: Optional[str] = None,
    raise_on_error: bool = True,
) -> InputModelBinding:
    """Create an immutable, cryptographically verifiable InputModelBinding.

    Args:
        input_identity: Validated InputIdentity envelope from Phase 10.2.
        model_identity: Authoritative model identity envelope from Phase 7.
        project_id: Owning project identifier.
        model_id: Optional explicit model ID if not present in model_identity.
        raise_on_error: If True, raises domain exceptions on failure.

    Returns:
        Immutable InputModelBinding instance.
    """
    findings: List[InputFinding] = []

    # 1. Validate project_id
    if not isinstance(project_id, str) or not project_id.strip():
        err_msg = "project_id must be a non-empty string."
        if raise_on_error:
            raise ProjectMismatchError(err_msg, details={"project_id": str(project_id)})
        findings.append(InputFinding(code=InferenceFindingCode.BINDING_PROJECT_MISMATCH.value, message=err_msg))

    # 2. Extract and validate model components
    (
        m_id,
        m_project_id,
        master_fp,
        artifact_h,
        struct_h,
        contract_h,
        m_status,
    ) = _extract_model_identity_components(model_identity, model_id=model_id, project_id=project_id)

    if not m_id:
        err_msg = "model_id is missing from model identity."
        if raise_on_error:
            raise ModelIntegrityBindingError(err_msg)
        findings.append(InputFinding(code=InferenceFindingCode.BINDING_MODEL_NOT_VERIFIED.value, message=err_msg))

    # 3. Verify Project Isolation
    if m_project_id and m_project_id != project_id:
        err_msg = f"Project isolation violation: Model belongs to project '{m_project_id}' but binding requested for '{project_id}'."
        if raise_on_error:
            raise ProjectMismatchError(err_msg, details={"model_project": m_project_id, "binding_project": project_id})
        findings.append(InputFinding(code=InferenceFindingCode.BINDING_PROJECT_MISMATCH.value, message=err_msg))

    # 4. Verify Input Validation Status
    if not isinstance(input_identity, InputIdentity):
        err_msg = f"Expected InputIdentity instance, got '{type(input_identity).__name__}'."
        if raise_on_error:
            raise InferenceInputError(err_msg)
        findings.append(InputFinding(code=InferenceFindingCode.BINDING_INPUT_NOT_VERIFIED.value, message=err_msg))

    if input_identity.validation_status != InferenceIntegrityStatus.VERIFIED:
        err_msg = f"Cannot bind input with status '{input_identity.validation_status.value}'. Input must be VERIFIED."
        if raise_on_error:
            raise InferenceInputError(err_msg, details={"status": input_identity.validation_status.value})
        findings.append(InputFinding(code=InferenceFindingCode.BINDING_INPUT_NOT_VERIFIED.value, message=err_msg))

    # 5. Verify Model Status
    if str(m_status).lower() not in ("verified", "success"):
        err_msg = f"Cannot bind model with status '{m_status}'. Model must be verified."
        if raise_on_error:
            raise ModelIntegrityBindingError(err_msg, details={"status": str(m_status)})
        findings.append(InputFinding(code=InferenceFindingCode.BINDING_MODEL_NOT_VERIFIED.value, message=err_msg))

    # 6. Verify SHA-256 Formats
    try:
        validate_sha256_hex_format("input_id", input_identity.input_id)
        validate_sha256_hex_format("input_canonical_hash", input_identity.canonical_hash)
        if input_identity.raw_file_hash:
            validate_sha256_hex_format("input_raw_hash", input_identity.raw_file_hash)
        validate_sha256_hex_format("model_master_fingerprint", master_fp)
        validate_sha256_hex_format("model_artifact_hash", artifact_h)
        validate_sha256_hex_format("model_structural_hash", struct_h)
        validate_sha256_hex_format("model_contract_hash", contract_h)
    except InvalidHashFormatError as err:
        if raise_on_error:
            raise
        findings.append(InputFinding(code=InferenceFindingCode.BINDING_MALFORMED_HASH.value, message=str(err)))

    # 7. Check Internal Fingerprint Consistency
    if not verify_master_fingerprint_consistency(artifact_h, struct_h, contract_h, master_fp):
        err_msg = "Model master fingerprint does not match canonical binding of (artifact_hash, structural_hash, contract_hash)."
        if raise_on_error:
            raise BindingInconsistencyError(err_msg, details={"master_fingerprint": master_fp})
        findings.append(InputFinding(code=InferenceFindingCode.BINDING_INCONSISTENT_IDENTITY.value, message=err_msg))

    # 8. Construct Canonical Descriptor & Binding Hash
    descriptor = build_canonical_binding_descriptor(
        binding_version=_BINDING_VERSION,
        input_canonical_hash=input_identity.canonical_hash,
        input_id=input_identity.input_id,
        input_kind=input_identity.input_kind,
        model_artifact_hash=artifact_h,
        model_contract_hash=contract_h,
        model_id=m_id,
        model_master_fingerprint=master_fp,
        model_structural_hash=struct_h,
        project_id=project_id,
        schema_version=_BINDING_SCHEMA_VERSION,
    )

    binding_hash = compute_binding_hash(descriptor)

    binding_status = InferenceIntegrityStatus.VERIFIED if not findings else InferenceIntegrityStatus.INVALID

    return InputModelBinding(
        schema_version=_BINDING_SCHEMA_VERSION,
        binding_version=_BINDING_VERSION,
        project_id=project_id,
        input_id=input_identity.input_id,
        input_kind=input_identity.input_kind,
        input_canonical_hash=input_identity.canonical_hash,
        input_raw_hash=input_identity.raw_file_hash,
        model_id=m_id,
        model_master_fingerprint=master_fp,
        model_artifact_hash=artifact_h,
        model_structural_hash=struct_h,
        model_contract_hash=contract_h,
        binding_status=binding_status,
        binding_hash=binding_hash,
        findings=findings,
        details={
            "input_shape": list(input_identity.shape) if input_identity.shape else None,
            "input_dtype": input_identity.dtype,
            "input_layout": input_identity.layout.value,
            "model_version": getattr(model_identity, "version", None) if not isinstance(model_identity, dict) else model_identity.get("version"),
        },
    )


def verify_input_model_binding(
    binding: InputModelBinding,
    raise_on_error: bool = False,
) -> BindingVerificationResult:
    """Pure, side-effect free cryptographic verification of an InputModelBinding.

    Args:
        binding: The InputModelBinding instance to verify.
        raise_on_error: If True, raises BindingError on failure.

    Returns:
        BindingVerificationResult detailing cryptographic match status.
    """
    findings: List[InputFinding] = []

    if not isinstance(binding, InputModelBinding):
        err_msg = f"Expected InputModelBinding instance, got '{type(binding).__name__}'."
        if raise_on_error:
            raise BindingError(err_msg)
        return BindingVerificationResult(
            is_valid=False,
            status=InferenceIntegrityStatus.INVALID,
            computed_hash="",
            expected_hash="",
            findings=[InputFinding(code="BINDING_TYPE_ERROR", message=err_msg)],
        )

    # 1. Validate schema version
    if binding.schema_version != _BINDING_SCHEMA_VERSION:
        findings.append(InputFinding(
            code=InferenceFindingCode.BINDING_UNSUPPORTED_SCHEMA.value,
            message=f"Unsupported binding schema version '{binding.schema_version}'.",
        ))

    # 2. Validate hash formats
    for field_name in (
        "input_id", "input_canonical_hash", "model_master_fingerprint",
        "model_artifact_hash", "model_structural_hash", "model_contract_hash", "binding_hash"
    ):
        val = getattr(binding, field_name)
        if not _SHA256_HEX_REGEX.match(val):
            findings.append(InputFinding(
                code=InferenceFindingCode.BINDING_MALFORMED_HASH.value,
                message=f"Field '{field_name}' does not match 64-char lowercase hex SHA-256 format: '{val}'.",
            ))

    # 3. Master fingerprint consistency check
    if not verify_master_fingerprint_consistency(
        binding.model_artifact_hash,
        binding.model_structural_hash,
        binding.model_contract_hash,
        binding.model_master_fingerprint,
    ):
        findings.append(InputFinding(
            code=InferenceFindingCode.BINDING_INCONSISTENT_IDENTITY.value,
            message="Model master fingerprint does not match canonical binding of model components.",
        ))

    # 4. Reconstruct canonical descriptor and recompute hash
    descriptor = build_canonical_binding_descriptor(
        binding_version=binding.binding_version,
        input_canonical_hash=binding.input_canonical_hash,
        input_id=binding.input_id,
        input_kind=binding.input_kind,
        model_artifact_hash=binding.model_artifact_hash,
        model_contract_hash=binding.model_contract_hash,
        model_id=binding.model_id,
        model_master_fingerprint=binding.model_master_fingerprint,
        model_structural_hash=binding.model_structural_hash,
        project_id=binding.project_id,
        schema_version=binding.schema_version,
    )

    computed_hash = compute_binding_hash(descriptor)
    hashes_match = hmac.compare_digest(computed_hash, binding.binding_hash)

    if not hashes_match:
        findings.append(InputFinding(
            code=InferenceFindingCode.BINDING_HASH_MISMATCH.value,
            message=f"Recomputed binding hash '{computed_hash}' does not match recorded hash '{binding.binding_hash}'.",
        ))

    is_valid = hashes_match and not findings
    status = InferenceIntegrityStatus.VERIFIED if is_valid else InferenceIntegrityStatus.INVALID

    if not is_valid and raise_on_error:
        raise BindingError(
            f"Binding verification failed: {findings[0].message if findings else 'Hash mismatch'}",
            details={"computed_hash": computed_hash, "expected_hash": binding.binding_hash},
        )

    return BindingVerificationResult(
        is_valid=is_valid,
        status=status,
        computed_hash=computed_hash,
        expected_hash=binding.binding_hash,
        findings=findings,
        details={
            "project_id": binding.project_id,
            "model_id": binding.model_id,
            "input_id": binding.input_id,
        },
    )
