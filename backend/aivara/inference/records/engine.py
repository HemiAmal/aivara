"""Pure functional cryptographic engine for Phase 10.8 Inference Record Integrity."""

import hashlib
import hmac
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from aivara.crypto.canonical import canonicalize
from aivara.inference.composite_binding import verify_inference_binding
from aivara.inference.composite_binding.models import InferenceBinding
from aivara.inference.enums import InferenceFindingCode, InferenceIntegrityStatus
from aivara.inference.exceptions import (
    InferenceRecordBindingInvalidError,
    InferenceRecordHashMismatchError,
    InferenceRecordInvalidError,
    InferenceRecordProjectMismatchError,
    InferenceRecordTamperedError,
    InferenceRecordVersionUnsupportedError,
    InvalidHashFormatError,
)
from aivara.inference.input.models import InputFinding
from aivara.inference.records.enums import InferenceRecordStatus, InferenceRecordType
from aivara.inference.records.models import (
    InferenceRecord,
    InferenceRecordCreate,
    InferenceRecordVerificationResult,
)

HEX64_LOWERCASE_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SUPPORTED_SCHEMA_VERSIONS = {"1.0"}
SUPPORTED_RECORD_VERSIONS = {"1.0"}


def validate_record_hash_format(name: str, value: Any) -> None:
    """Validate that a cryptographic identity field is a strict 64-character lowercase hex digest."""
    if not isinstance(value, str) or not HEX64_LOWERCASE_PATTERN.match(value):
        raise InvalidHashFormatError(
            f"Field '{name}' must be a 64-character lowercase hexadecimal SHA-256 digest, got '{value}'.",
            details={"field": name, "value": str(value)},
        )


def build_canonical_record_descriptor(
    *,
    record_id: str,
    project_id: str,
    inference_binding_hash: str,
    binding_version: str = "1.0",
    record_type: str = "STANDARD",
    record_status: str = "VERIFIED",
    record_version: str = "1.0",
    schema_version: str = "1.0",
) -> Dict[str, Any]:
    """Construct the deterministic dictionary descriptor for RFC 8785 JCS canonicalization.

    Commits exactly the 8 atomic record parameters into a canonical sorted dictionary.
    """
    type_str = record_type.value if hasattr(record_type, "value") else str(record_type)
    status_str = record_status.value if hasattr(record_status, "value") else str(record_status)

    return {
        "binding_version": str(binding_version),
        "inference_binding_hash": str(inference_binding_hash),
        "project_id": str(project_id),
        "record_id": str(record_id),
        "record_status": status_str,
        "record_type": type_str,
        "record_version": str(record_version),
        "schema_version": str(schema_version),
    }


def compute_record_integrity_hash(descriptor: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over the canonical RFC 8785 JCS record descriptor."""
    canonical_bytes = canonicalize(descriptor)
    return hashlib.sha256(canonical_bytes).hexdigest()


def create_inference_record(
    *,
    project_id: str,
    binding: InferenceBinding,
    record_id: Optional[str] = None,
    record_type: InferenceRecordType = InferenceRecordType.STANDARD,
    record_version: str = "1.0",
    schema_version: str = "1.0",
    created_at: Optional[str] = None,
    raise_on_error: bool = True,
) -> InferenceRecord:
    """Transform a verified Phase 10.7 InferenceBinding into an immutable InferenceRecord."""
    findings: List[InputFinding] = []
    details: Dict[str, Any] = {}

    # 1. Validate Project ID
    if not isinstance(project_id, str) or not project_id.strip():
        err = "project_id must be a non-empty string."
        if raise_on_error:
            raise InferenceRecordProjectMismatchError(err, details={"project_id": str(project_id)})
        findings.append(InputFinding(code=InferenceFindingCode.INFERENCE_RECORD_PROJECT_MISMATCH.value, message=err))

    # 2. Validate Versions
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        err = f"Unsupported schema_version: '{schema_version}'. Supported: {sorted(SUPPORTED_SCHEMA_VERSIONS)}."
        if raise_on_error:
            raise InferenceRecordVersionUnsupportedError(err, details={"schema_version": schema_version})
        findings.append(InputFinding(code=InferenceFindingCode.INFERENCE_RECORD_VERSION_UNSUPPORTED.value, message=err))

    if record_version not in SUPPORTED_RECORD_VERSIONS:
        err = f"Unsupported record_version: '{record_version}'. Supported: {sorted(SUPPORTED_RECORD_VERSIONS)}."
        if raise_on_error:
            raise InferenceRecordVersionUnsupportedError(err, details={"record_version": record_version})
        findings.append(InputFinding(code=InferenceFindingCode.INFERENCE_RECORD_VERSION_UNSUPPORTED.value, message=err))

    # 3. Validate Phase 10.7 Binding
    if binding is None:
        err = "Inference record creation requires a valid Phase 10.7 InferenceBinding."
        if raise_on_error:
            raise InferenceRecordBindingInvalidError(err)
        findings.append(InputFinding(code=InferenceFindingCode.INFERENCE_RECORD_BINDING_INVALID.value, message=err))
    else:
        if binding.project_id != project_id:
            err = f"Project isolation mismatch: Binding project '{binding.project_id}' != '{project_id}'."
            if raise_on_error:
                raise InferenceRecordProjectMismatchError(err)
            findings.append(InputFinding(code=InferenceFindingCode.INFERENCE_RECORD_PROJECT_MISMATCH.value, message=err))

        # Perform pure verification of the binding
        binding_verif = verify_inference_binding(binding)
        if not binding_verif.is_valid or binding_verif.status != InferenceIntegrityStatus.VERIFIED:
            err = f"Phase 10.7 binding failed verification with status '{binding_verif.status}'."
            if raise_on_error:
                raise InferenceRecordBindingInvalidError(err, details={"findings": [f.model_dump() for f in binding_verif.findings]})
            findings.append(InputFinding(code=InferenceFindingCode.INFERENCE_RECORD_BINDING_INVALID.value, message=err))

        try:
            validate_record_hash_format("inference_binding_hash", binding.inference_binding_hash)
        except InvalidHashFormatError as e:
            if raise_on_error:
                raise
            findings.append(InputFinding(code=InferenceFindingCode.INFERENCE_RECORD_HASH_MISMATCH.value, message=str(e)))

    # 4. Resolve Record ID
    resolved_record_id = record_id or uuid.uuid4().hex
    if not isinstance(resolved_record_id, str) or not resolved_record_id.strip():
        err = "record_id must be a non-empty string."
        if raise_on_error:
            raise InferenceRecordInvalidError(err)
        findings.append(InputFinding(code=InferenceFindingCode.INFERENCE_RECORD_INVALID.value, message=err))

    # 5. Resolve Creation Timestamp (Persistence Metadata)
    resolved_created_at = created_at or datetime.now(timezone.utc).isoformat()

    # 6. Determine Record Status
    record_status = InferenceRecordStatus.VERIFIED if not findings else InferenceRecordStatus.INVALID

    # 7. Construct Canonical Descriptor & Compute record_integrity_hash
    binding_hash_str = binding.inference_binding_hash if binding else ""
    binding_ver_str = binding.binding_version if binding else "1.0"

    descriptor = build_canonical_record_descriptor(
        record_id=resolved_record_id,
        project_id=project_id,
        inference_binding_hash=binding_hash_str,
        binding_version=binding_ver_str,
        record_type=record_type.value if hasattr(record_type, "value") else str(record_type),
        record_status=record_status.value if hasattr(record_status, "value") else str(record_status),
        record_version=record_version,
        schema_version=schema_version,
    )

    record_integrity_hash = compute_record_integrity_hash(descriptor)

    details["canonical_descriptor"] = descriptor
    details["canonical_algorithm"] = "RFC 8785 JCS"
    details["hash_algorithm"] = "SHA-256"

    return InferenceRecord(
        schema_version=schema_version,
        record_version=record_version,
        record_id=resolved_record_id,
        project_id=project_id,
        record_type=record_type,
        binding_version=binding_ver_str,
        inference_binding_hash=binding_hash_str,
        record_integrity_hash=record_integrity_hash,
        record_status=record_status,
        created_at=resolved_created_at,
        binding=binding,
        findings=findings,
        details=details,
    )


def verify_inference_record(
    record: InferenceRecord,
    binding: Optional[InferenceBinding] = None,
    expected_project_id: Optional[str] = None,
) -> InferenceRecordVerificationResult:
    """Pure offline verification of an InferenceRecord's integrity and underlying binding."""
    findings: List[InputFinding] = []
    details: Dict[str, Any] = {}

    # 1. Project Isolation Check
    if expected_project_id and record.project_id != expected_project_id:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.INFERENCE_RECORD_PROJECT_MISMATCH.value,
                message=f"Project isolation violation: record project '{record.project_id}' != expected '{expected_project_id}'.",
            )
        )

    # 2. Hash Format Validation
    try:
        validate_record_hash_format("record_integrity_hash", record.record_integrity_hash)
        validate_record_hash_format("inference_binding_hash", record.inference_binding_hash)
    except InvalidHashFormatError as e:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.INFERENCE_RECORD_HASH_MISMATCH.value,
                message=f"Hash format validation error: {str(e)}",
            )
        )
        return InferenceRecordVerificationResult(
            is_valid=False,
            status=InferenceRecordStatus.INVALID,
            record_id=record.record_id,
            project_id=record.project_id,
            stored_integrity_hash=record.record_integrity_hash,
            computed_integrity_hash="",
            inference_binding_hash=record.inference_binding_hash,
            binding_verification_status=InferenceIntegrityStatus.INVALID,
            findings=findings,
            details=details,
        )

    # 3. Version Support Check
    if record.schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.INFERENCE_RECORD_VERSION_UNSUPPORTED.value,
                message=f"Unsupported schema_version: '{record.schema_version}'.",
            )
        )

    if record.record_version not in SUPPORTED_RECORD_VERSIONS:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.INFERENCE_RECORD_VERSION_UNSUPPORTED.value,
                message=f"Unsupported record_version: '{record.record_version}'.",
            )
        )

    # 4. Reconstruct Canonical Descriptor and Recompute Integrity Hash
    descriptor = build_canonical_record_descriptor(
        record_id=record.record_id,
        project_id=record.project_id,
        inference_binding_hash=record.inference_binding_hash,
        binding_version=record.binding_version,
        record_type=record.record_type.value if hasattr(record.record_type, "value") else str(record.record_type),
        record_status=record.record_status.value if hasattr(record.record_status, "value") else str(record.record_status),
        record_version=record.record_version,
        schema_version=record.schema_version,
    )
    computed_hash = compute_record_integrity_hash(descriptor)

    # Constant-time comparison
    hash_matches = hmac.compare_digest(computed_hash, record.record_integrity_hash)
    if not hash_matches:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.INFERENCE_RECORD_TAMPERED.value,
                message=f"Record integrity hash mismatch. Computed '{computed_hash}' != stored '{record.record_integrity_hash}'.",
                details={"computed": computed_hash, "stored": record.record_integrity_hash},
            )
        )

    # 5. Verify Underlying Phase 10.7 Binding
    target_binding = binding or record.binding
    binding_status = InferenceIntegrityStatus.VERIFIED

    if target_binding is not None:
        if target_binding.project_id != record.project_id:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.INFERENCE_RECORD_PROJECT_MISMATCH.value,
                    message=f"Binding project '{target_binding.project_id}' != record project '{record.project_id}'.",
                )
            )
        if target_binding.inference_binding_hash != record.inference_binding_hash:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.INFERENCE_RECORD_BINDING_INVALID.value,
                    message=f"Binding hash '{target_binding.inference_binding_hash}' != record binding hash '{record.inference_binding_hash}'.",
                )
            )

        binding_verif = verify_inference_binding(target_binding)
        binding_status = binding_verif.status
        if not binding_verif.is_valid:
            findings.extend(binding_verif.findings)

    # 6. Overall Status Determination
    if any(f.code in {
        InferenceFindingCode.INFERENCE_RECORD_TAMPERED.value,
        InferenceFindingCode.INFERENCE_RECORD_HASH_MISMATCH.value,
    } for f in findings):
        status = InferenceRecordStatus.TAMPERED
    elif findings:
        status = InferenceRecordStatus.INVALID
    else:
        status = InferenceRecordStatus.VERIFIED

    is_valid = (status == InferenceRecordStatus.VERIFIED) and (binding_status == InferenceIntegrityStatus.VERIFIED)

    details["canonical_descriptor"] = descriptor
    details["hash_matches"] = hash_matches

    return InferenceRecordVerificationResult(
        is_valid=is_valid,
        status=status,
        record_id=record.record_id,
        project_id=record.project_id,
        stored_integrity_hash=record.record_integrity_hash,
        computed_integrity_hash=computed_hash,
        inference_binding_hash=record.inference_binding_hash,
        binding_verification_status=binding_status,
        findings=findings,
        details=details,
    )
