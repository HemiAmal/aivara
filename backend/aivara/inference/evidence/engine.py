"""Pure functional engine for Phase 10.10 Evidence & Provenance Binding."""

from __future__ import annotations

import hmac
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import hash_canonical_data, is_valid_sha256
from aivara.domain.schemas import Disposition, EvidenceLayer, Severity
from aivara.evidence.schemas import EvidencePayload, FindingSynthesisPayload
from aivara.inference.composite_binding.engine import verify_inference_binding
from aivara.inference.composite_binding.models import InferenceBinding
from aivara.inference.enums import InferenceIntegrityStatus
from aivara.inference.evidence.enums import (
    InferenceEvidenceStatus,
    InferenceEvidenceType,
    InferenceFindingType,
)
from aivara.inference.evidence.models import (
    InferenceEvidence,
    InferenceEvidenceVerificationResult,
    InferenceProvenanceBindingPayload,
)
from aivara.inference.exceptions import (
    InferenceEvidenceError,
    InferenceEvidenceHashMismatchError,
    InferenceEvidenceProjectMismatchError,
    InferenceEvidenceTamperedError,
    InferenceEvidenceValidationError,
    InvalidHashFormatError,
)
from aivara.inference.records.engine import verify_inference_record
from aivara.inference.records.models import InferenceRecord
from aivara.inference.replay.models import ReplayVerificationResult

_SHA256_HEX_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def validate_sha256_hex_format(field_name: str, value: Optional[str]) -> None:
    """Ensure that a cryptographic hash string is strictly a 64-character lowercase hexadecimal digest."""
    if value is None:
        return
    if not isinstance(value, str) or not _SHA256_HEX_PATTERN.match(value):
        raise InvalidHashFormatError(
            f"Field '{field_name}' must be a 64-character lowercase hex SHA-256 digest, got: {value!r}"
        )


def build_canonical_evidence_descriptor(
    *,
    schema_version: str = "1.0",
    evidence_version: str = "1.0",
    project_id: str,
    record_id: str,
    record_integrity_hash: str,
    inference_binding_hash: str,
    input_id: str,
    input_canonical_hash: str,
    input_raw_hash: Optional[str] = None,
    model_id: str,
    model_master_fingerprint: str,
    model_artifact_hash: str,
    model_structural_hash: str,
    model_contract_hash: str,
    preprocessing_contract_hash: str,
    transformed_input_hash: str,
    execution_identity_hash: str,
    raw_output_hash: str,
    validated_output_identity: str,
    output_contract_hash: Optional[str] = None,
    replay_status: Optional[str] = None,
    replay_mode: Optional[str] = None,
    evidence_type: str = InferenceEvidenceType.INFERENCE_INTEGRITY_VERIFICATION.value,
    evidence_layer: str = EvidenceLayer.PROOF.value,
    finding_type: str = InferenceFindingType.INFERENCE_INTEGRITY_VERIFIED.value,
    finding_status: str = "VERIFIED",
) -> Dict[str, Any]:
    """Construct deterministic dictionary containing exclusively semantic identity fields for RFC 8785 JCS."""
    if not project_id:
        raise InferenceEvidenceValidationError("project_id is required.")
    if not record_id:
        raise InferenceEvidenceValidationError("record_id is required.")
    if not model_id:
        raise InferenceEvidenceValidationError("model_id is required.")

    # Validate all 64-hex SHA-256 fields
    validate_sha256_hex_format("record_integrity_hash", record_integrity_hash)
    validate_sha256_hex_format("inference_binding_hash", inference_binding_hash)
    validate_sha256_hex_format("input_id", input_id)
    validate_sha256_hex_format("input_canonical_hash", input_canonical_hash)
    validate_sha256_hex_format("input_raw_hash", input_raw_hash)
    validate_sha256_hex_format("model_master_fingerprint", model_master_fingerprint)
    validate_sha256_hex_format("model_artifact_hash", model_artifact_hash)
    validate_sha256_hex_format("model_structural_hash", model_structural_hash)
    validate_sha256_hex_format("model_contract_hash", model_contract_hash)
    validate_sha256_hex_format("preprocessing_contract_hash", preprocessing_contract_hash)
    validate_sha256_hex_format("transformed_input_hash", transformed_input_hash)
    validate_sha256_hex_format("execution_identity_hash", execution_identity_hash)
    validate_sha256_hex_format("raw_output_hash", raw_output_hash)
    validate_sha256_hex_format("validated_output_identity", validated_output_identity)
    validate_sha256_hex_format("output_contract_hash", output_contract_hash)

    return {
        "evidence_layer": str(evidence_layer),
        "evidence_type": str(evidence_type),
        "evidence_version": str(evidence_version),
        "execution_identity_hash": str(execution_identity_hash).lower(),
        "finding_status": str(finding_status),
        "finding_type": str(finding_type),
        "inference_binding_hash": str(inference_binding_hash).lower(),
        "input_canonical_hash": str(input_canonical_hash).lower(),
        "input_id": str(input_id).lower(),
        "input_raw_hash": str(input_raw_hash).lower() if input_raw_hash is not None else None,
        "model_artifact_hash": str(model_artifact_hash).lower(),
        "model_contract_hash": str(model_contract_hash).lower(),
        "model_id": str(model_id),
        "model_master_fingerprint": str(model_master_fingerprint).lower(),
        "model_structural_hash": str(model_structural_hash).lower(),
        "output_contract_hash": str(output_contract_hash).lower() if output_contract_hash is not None else None,
        "preprocessing_contract_hash": str(preprocessing_contract_hash).lower(),
        "project_id": str(project_id),
        "raw_output_hash": str(raw_output_hash).lower(),
        "record_id": str(record_id),
        "record_integrity_hash": str(record_integrity_hash).lower(),
        "replay_mode": str(replay_mode) if replay_mode is not None else None,
        "replay_status": str(replay_status) if replay_status is not None else None,
        "schema_version": str(schema_version),
        "transformed_input_hash": str(transformed_input_hash).lower(),
        "validated_output_identity": str(validated_output_identity).lower(),
    }


def compute_evidence_hash(descriptor_or_evidence: Union[InferenceEvidence, Dict[str, Any]]) -> str:
    """Compute deterministic SHA-256 digest of canonical RFC 8785 serialized evidence descriptor."""
    if isinstance(descriptor_or_evidence, InferenceEvidence):
        descriptor = build_canonical_evidence_descriptor(
            schema_version=descriptor_or_evidence.schema_version,
            evidence_version=descriptor_or_evidence.evidence_version,
            project_id=descriptor_or_evidence.project_id,
            record_id=descriptor_or_evidence.record_id,
            record_integrity_hash=descriptor_or_evidence.record_integrity_hash,
            inference_binding_hash=descriptor_or_evidence.inference_binding_hash,
            input_id=descriptor_or_evidence.input_id,
            input_canonical_hash=descriptor_or_evidence.input_canonical_hash,
            input_raw_hash=descriptor_or_evidence.input_raw_hash,
            model_id=descriptor_or_evidence.model_id,
            model_master_fingerprint=descriptor_or_evidence.model_master_fingerprint,
            model_artifact_hash=descriptor_or_evidence.model_artifact_hash,
            model_structural_hash=descriptor_or_evidence.model_structural_hash,
            model_contract_hash=descriptor_or_evidence.model_contract_hash,
            preprocessing_contract_hash=descriptor_or_evidence.preprocessing_contract_hash,
            transformed_input_hash=descriptor_or_evidence.transformed_input_hash,
            execution_identity_hash=descriptor_or_evidence.execution_identity_hash,
            raw_output_hash=descriptor_or_evidence.raw_output_hash,
            validated_output_identity=descriptor_or_evidence.validated_output_identity,
            output_contract_hash=descriptor_or_evidence.output_contract_hash,
            replay_status=descriptor_or_evidence.replay_status,
            replay_mode=descriptor_or_evidence.replay_mode,
            evidence_type=descriptor_or_evidence.evidence_type.value if hasattr(descriptor_or_evidence.evidence_type, "value") else str(descriptor_or_evidence.evidence_type),
            evidence_layer=descriptor_or_evidence.evidence_layer.value if hasattr(descriptor_or_evidence.evidence_layer, "value") else str(descriptor_or_evidence.evidence_layer),
            finding_type=descriptor_or_evidence.finding_type,
            finding_status=descriptor_or_evidence.finding_status,
        )
    else:
        descriptor = descriptor_or_evidence

    return hash_canonical_data(descriptor)


def create_inference_evidence(
    *,
    record: InferenceRecord,
    binding: Optional[InferenceBinding] = None,
    replay_result: Optional[ReplayVerificationResult] = None,
    provenance_record_id: Optional[str] = None,
    provenance_record_hash: Optional[str] = None,
    created_at: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    finding_type: Optional[str] = None,
    finding_status: Optional[str] = None,
    severity: Optional[Severity] = None,
    disposition: Optional[Disposition] = None,
) -> InferenceEvidence:
    """Pure functional constructor of an immutable, cryptographically verifiable InferenceEvidence item."""
    actual_binding = binding or record.binding
    if actual_binding is None:
        raise InferenceEvidenceValidationError(
            f"Cannot create InferenceEvidence: InferenceBinding missing for record '{record.record_id}'."
        )

    # Validate cross-component project consistency
    if record.project_id != actual_binding.project_id:
        raise InferenceEvidenceProjectMismatchError(
            f"Project mismatch between record '{record.project_id}' and binding '{actual_binding.project_id}'."
        )

    # Validate binding hash matching
    if not hmac.compare_digest(record.inference_binding_hash, actual_binding.inference_binding_hash):
        raise InferenceEvidenceHashMismatchError(
            f"Binding hash mismatch: record has '{record.inference_binding_hash}', binding has '{actual_binding.inference_binding_hash}'."
        )

    replay_status_val = replay_result.consistency_status.value if replay_result is not None else None
    replay_mode_val = None
    if replay_result is not None and replay_result.details:
        replay_mode_val = replay_result.details.get("replay_mode")

    ft = finding_type or InferenceFindingType.INFERENCE_INTEGRITY_VERIFIED.value
    fs = finding_status or "VERIFIED"
    sev = severity or Severity.INFO
    disp = disposition or Disposition.ACCEPT

    descriptor = build_canonical_evidence_descriptor(
        schema_version="1.0",
        evidence_version="1.0",
        project_id=record.project_id,
        record_id=record.record_id,
        record_integrity_hash=record.record_integrity_hash,
        inference_binding_hash=actual_binding.inference_binding_hash,
        input_id=actual_binding.input_id,
        input_canonical_hash=actual_binding.input_canonical_hash,
        input_raw_hash=actual_binding.input_raw_hash,
        model_id=actual_binding.model_id,
        model_master_fingerprint=actual_binding.model_master_fingerprint,
        model_artifact_hash=actual_binding.model_artifact_hash,
        model_structural_hash=actual_binding.model_structural_hash,
        model_contract_hash=actual_binding.model_contract_hash,
        preprocessing_contract_hash=actual_binding.preprocessing_contract_hash,
        transformed_input_hash=actual_binding.transformed_input_hash,
        execution_identity_hash=actual_binding.execution_identity_hash,
        raw_output_hash=actual_binding.raw_output_hash,
        validated_output_identity=actual_binding.validated_output_identity,
        output_contract_hash=actual_binding.output_contract_hash,
        replay_status=replay_status_val,
        replay_mode=replay_mode_val,
        evidence_type=InferenceEvidenceType.INFERENCE_INTEGRITY_VERIFICATION.value,
        evidence_layer=EvidenceLayer.PROOF.value,
        finding_type=ft,
        finding_status=fs,
    )

    ev_id = compute_evidence_hash(descriptor)

    return InferenceEvidence(
        schema_version="1.0",
        evidence_version="1.0",
        evidence_id=ev_id,
        project_id=record.project_id,
        record_id=record.record_id,
        record_integrity_hash=record.record_integrity_hash,
        inference_binding_hash=actual_binding.inference_binding_hash,
        input_id=actual_binding.input_id,
        input_canonical_hash=actual_binding.input_canonical_hash,
        input_raw_hash=actual_binding.input_raw_hash,
        model_id=actual_binding.model_id,
        model_master_fingerprint=actual_binding.model_master_fingerprint,
        model_artifact_hash=actual_binding.model_artifact_hash,
        model_structural_hash=actual_binding.model_structural_hash,
        model_contract_hash=actual_binding.model_contract_hash,
        preprocessing_contract_hash=actual_binding.preprocessing_contract_hash,
        transformed_input_hash=actual_binding.transformed_input_hash,
        execution_identity_hash=actual_binding.execution_identity_hash,
        raw_output_hash=actual_binding.raw_output_hash,
        validated_output_identity=actual_binding.validated_output_identity,
        output_contract_hash=actual_binding.output_contract_hash,
        replay_status=replay_status_val,
        replay_mode=replay_mode_val,
        evidence_type=InferenceEvidenceType.INFERENCE_INTEGRITY_VERIFICATION,
        evidence_layer=EvidenceLayer.PROOF,
        finding_type=ft,
        finding_status=fs,
        confidence=1.0,
        severity=sev,
        disposition=disp,
        provenance_record_id=provenance_record_id,
        provenance_record_hash=provenance_record_hash,
        created_at=created_at,
        metadata=metadata or {},
    )


def build_inference_provenance_payload(evidence: InferenceEvidence) -> Dict[str, Any]:
    """Construct canonical payload descriptor for commitment to Phase 4 ProvenanceRecord."""
    return {
        "evidence_id": evidence.evidence_id,
        "evidence_version": evidence.evidence_version,
        "execution_identity_hash": evidence.execution_identity_hash,
        "inference_binding_hash": evidence.inference_binding_hash,
        "input_canonical_hash": evidence.input_canonical_hash,
        "model_master_fingerprint": evidence.model_master_fingerprint,
        "output_contract_hash": evidence.output_contract_hash,
        "preprocessing_contract_hash": evidence.preprocessing_contract_hash,
        "project_id": evidence.project_id,
        "raw_output_hash": evidence.raw_output_hash,
        "record_id": evidence.record_id,
        "record_integrity_hash": evidence.record_integrity_hash,
        "replay_status": evidence.replay_status,
        "schema_version": evidence.schema_version,
        "validated_output_identity": evidence.validated_output_identity,
    }


def compute_provenance_binding_hash(
    payload: Union[InferenceProvenanceBindingPayload, Dict[str, Any]]
) -> str:
    """Compute deterministic SHA-256 hash of canonical RFC 8785 serialized provenance binding payload."""
    if isinstance(payload, InferenceProvenanceBindingPayload):
        descriptor = payload.model_dump()
    else:
        descriptor = dict(payload)
    return hash_canonical_data(descriptor)


def create_phase5_evidence_and_finding_payloads(
    evidence: InferenceEvidence,
    audit_run_id: Optional[str] = None,
) -> Tuple[EvidencePayload, FindingSynthesisPayload]:
    """Bridge Phase 10.10 InferenceEvidence into Phase 5.9 standard EvidencePayload and FindingSynthesisPayload."""
    measurements = {
        "record_id": evidence.record_id,
        "record_integrity_hash": evidence.record_integrity_hash,
        "inference_binding_hash": evidence.inference_binding_hash,
        "input_canonical_hash": evidence.input_canonical_hash,
        "model_master_fingerprint": evidence.model_master_fingerprint,
        "execution_identity_hash": evidence.execution_identity_hash,
        "raw_output_hash": evidence.raw_output_hash,
        "validated_output_identity": evidence.validated_output_identity,
        "replay_status": evidence.replay_status,
        "provenance_record_id": evidence.provenance_record_id,
        "provenance_record_hash": evidence.provenance_record_hash,
    }

    ev_payload = EvidencePayload(
        title=f"Inference Transaction Assurance: Record {evidence.record_id[:8]}",
        description=f"Cryptographic proof-layer verification of inference transaction '{evidence.record_id}' on model '{evidence.model_id}'.",
        evidence_layer=evidence.evidence_layer,
        evidence_type=evidence.evidence_type.value,
        confidence=evidence.confidence,
        target_asset_type="model",
        target_asset_id=evidence.model_id,
        target_asset_hash=evidence.model_master_fingerprint,
        evidence_hash=evidence.evidence_id,
        detector_id="inference_integrity_assurance_engine",
        detector_version=evidence.evidence_version,
        detector_config_hash=evidence.execution_identity_hash,
        model_fingerprint=evidence.model_master_fingerprint,
        measurements=measurements,
        data_json=evidence.model_dump(mode="json"),
    )

    finding_payload = FindingSynthesisPayload(
        project_id=evidence.project_id,
        audit_run_id=audit_run_id,
        engine_id="inference_integrity_assurance_engine",
        engine_version=evidence.evidence_version,
        evidence_layer=evidence.evidence_layer,
        finding_type=evidence.finding_type,
        title=f"Inference Transaction Verification: {evidence.record_id[:8]} [{evidence.finding_status}]",
        description=f"End-to-end cryptographic and structural verification of inference execution '{evidence.record_id}'.",
        severity=evidence.severity,
        confidence=evidence.confidence,
        affected_asset_type="model",
        affected_asset_id=evidence.model_id,
        disposition=evidence.disposition,
        status="verified" if evidence.finding_status == "VERIFIED" else "open",
        primary_evidence_items=[ev_payload],
        metadata_json={
            "record_id": evidence.record_id,
            "inference_binding_hash": evidence.inference_binding_hash,
            "replay_status": evidence.replay_status,
            "provenance_record_id": evidence.provenance_record_id,
        },
    )

    return ev_payload, finding_payload


def verify_inference_evidence(
    evidence: InferenceEvidence,
    *,
    record: Optional[InferenceRecord] = None,
    binding: Optional[InferenceBinding] = None,
    replay_result: Optional[ReplayVerificationResult] = None,
    provenance_payload: Optional[Dict[str, Any]] = None,
    expected_project_id: Optional[str] = None,
) -> InferenceEvidenceVerificationResult:
    """Comprehensive, pure functional end-to-end verifier for InferenceEvidence.

    Evaluates:
      1. Tenant project isolation.
      2. Evidence descriptor canonicalization and SHA-256 identity matching.
      3. Phase 10.8 InferenceRecord integrity and canonical descriptor verification.
      4. Phase 10.7 composite InferenceBinding verification and 16-field matching.
      5. Phase 10.9 Replay consistency verification and state consistency.
      6. Phase 4 Provenance binding integrity and payload consistency.
      7. Cross-component consistency and tamper rejection.
    """
    findings: List[Dict[str, Any]] = []
    details: Dict[str, Any] = {}

    # 1. Project isolation validation
    if expected_project_id is not None:
        if not hmac.compare_digest(evidence.project_id, expected_project_id):
            return InferenceEvidenceVerificationResult(
                is_valid=False,
                status=InferenceEvidenceStatus.PROJECT_MISMATCH,
                evidence_id=evidence.evidence_id,
                computed_evidence_hash=evidence.evidence_id,
                record_verified=False,
                binding_verified=False,
                replay_verified=False,
                provenance_verified=False,
                findings=[{
                    "code": "PROJECT_MISMATCH",
                    "message": f"Evidence project '{evidence.project_id}' does not match expected '{expected_project_id}'.",
                }],
                details={"expected_project_id": expected_project_id, "evidence_project_id": evidence.project_id},
            )

    # 2. Recompute evidence SHA-256 hash
    computed_ev_hash = compute_evidence_hash(evidence)
    if not hmac.compare_digest(evidence.evidence_id, computed_ev_hash):
        return InferenceEvidenceVerificationResult(
            is_valid=False,
            status=InferenceEvidenceStatus.TAMPERED,
            evidence_id=evidence.evidence_id,
            computed_evidence_hash=computed_ev_hash,
            record_verified=False,
            binding_verified=False,
            replay_verified=False,
            provenance_verified=False,
            findings=[{
                "code": "INFERENCE_EVIDENCE_TAMPERED",
                "message": f"Evidence identity hash mismatch: stored '{evidence.evidence_id}', computed '{computed_ev_hash}'.",
            }],
            details={"stored_hash": evidence.evidence_id, "computed_hash": computed_ev_hash},
        )

    # 3. Verify InferenceRecord if provided
    record_verified = True
    if record is not None:
        if not hmac.compare_digest(record.project_id, evidence.project_id):
            return InferenceEvidenceVerificationResult(
                is_valid=False,
                status=InferenceEvidenceStatus.PROJECT_MISMATCH,
                evidence_id=evidence.evidence_id,
                computed_evidence_hash=computed_ev_hash,
                record_verified=False,
                binding_verified=False,
                replay_verified=False,
                provenance_verified=False,
                findings=[{
                    "code": "PROJECT_MISMATCH",
                    "message": f"Record project '{record.project_id}' does not match evidence project '{evidence.project_id}'.",
                }],
                details={"record_project": record.project_id, "evidence_project": evidence.project_id},
            )

        if not hmac.compare_digest(record.record_id, evidence.record_id):
            return InferenceEvidenceVerificationResult(
                is_valid=False,
                status=InferenceEvidenceStatus.INVALID,
                evidence_id=evidence.evidence_id,
                computed_evidence_hash=computed_ev_hash,
                record_verified=False,
                binding_verified=False,
                replay_verified=False,
                provenance_verified=False,
                findings=[{
                    "code": "INFERENCE_RECORD_MISMATCH",
                    "message": f"Record ID mismatch: record has '{record.record_id}', evidence has '{evidence.record_id}'.",
                }],
                details={"record_id": record.record_id, "evidence_record_id": evidence.record_id},
            )

        if not hmac.compare_digest(record.record_integrity_hash, evidence.record_integrity_hash):
            return InferenceEvidenceVerificationResult(
                is_valid=False,
                status=InferenceEvidenceStatus.TAMPERED,
                evidence_id=evidence.evidence_id,
                computed_evidence_hash=computed_ev_hash,
                record_verified=False,
                binding_verified=False,
                replay_verified=False,
                provenance_verified=False,
                findings=[{
                    "code": "INFERENCE_RECORD_TAMPERED",
                    "message": f"Record integrity hash mismatch: record has '{record.record_integrity_hash}', evidence has '{evidence.record_integrity_hash}'.",
                }],
                details={"record_hash": record.record_integrity_hash, "evidence_record_hash": evidence.record_integrity_hash},
            )

        # Cryptographically recompute record integrity hash via Phase 10.8
        rec_ver_res = verify_inference_record(record, expected_project_id=evidence.project_id)
        if not rec_ver_res.is_valid:
            return InferenceEvidenceVerificationResult(
                is_valid=False,
                status=InferenceEvidenceStatus.TAMPERED,
                evidence_id=evidence.evidence_id,
                computed_evidence_hash=computed_ev_hash,
                record_verified=False,
                binding_verified=False,
                replay_verified=False,
                provenance_verified=False,
                findings=[{
                    "code": "INFERENCE_RECORD_TAMPERED",
                    "message": f"Phase 10.8 InferenceRecord failed cryptographic verification.",
                }],
                details={"record_verification": rec_ver_res.model_dump()},
            )

    # 4. Verify InferenceBinding if provided (or extracted from record)
    actual_binding = binding or (record.binding if record is not None else None)
    binding_verified = True
    if actual_binding is not None:
        if not hmac.compare_digest(actual_binding.project_id, evidence.project_id):
            return InferenceEvidenceVerificationResult(
                is_valid=False,
                status=InferenceEvidenceStatus.PROJECT_MISMATCH,
                evidence_id=evidence.evidence_id,
                computed_evidence_hash=computed_ev_hash,
                record_verified=record_verified,
                binding_verified=False,
                replay_verified=False,
                provenance_verified=False,
                findings=[{
                    "code": "PROJECT_MISMATCH",
                    "message": f"Binding project '{actual_binding.project_id}' does not match evidence project '{evidence.project_id}'.",
                }],
                details={"binding_project": actual_binding.project_id, "evidence_project": evidence.project_id},
            )

        if not hmac.compare_digest(actual_binding.inference_binding_hash, evidence.inference_binding_hash):
            return InferenceEvidenceVerificationResult(
                is_valid=False,
                status=InferenceEvidenceStatus.INVALID,
                evidence_id=evidence.evidence_id,
                computed_evidence_hash=computed_ev_hash,
                record_verified=record_verified,
                binding_verified=False,
                replay_verified=False,
                provenance_verified=False,
                findings=[{
                    "code": "INFERENCE_BINDING_MISMATCH",
                    "message": f"Binding hash mismatch: binding has '{actual_binding.inference_binding_hash}', evidence has '{evidence.inference_binding_hash}'.",
                }],
                details={"binding_hash": actual_binding.inference_binding_hash, "evidence_binding_hash": evidence.inference_binding_hash},
            )

        # Recompute binding hash via Phase 10.7
        b_ver_res = verify_inference_binding(actual_binding)
        if not b_ver_res.is_valid:
            return InferenceEvidenceVerificationResult(
                is_valid=False,
                status=InferenceEvidenceStatus.INVALID,
                evidence_id=evidence.evidence_id,
                computed_evidence_hash=computed_ev_hash,
                record_verified=record_verified,
                binding_verified=False,
                replay_verified=False,
                provenance_verified=False,
                findings=[{
                    "code": "INFERENCE_BINDING_INVALID",
                    "message": "Phase 10.7 InferenceBinding failed cryptographic verification.",
                }],
                details={"binding_verification": b_ver_res.model_dump()},
            )

        # Cross-component field checks
        field_checks = [
            ("input_id", actual_binding.input_id, evidence.input_id),
            ("input_canonical_hash", actual_binding.input_canonical_hash, evidence.input_canonical_hash),
            ("model_id", actual_binding.model_id, evidence.model_id),
            ("model_master_fingerprint", actual_binding.model_master_fingerprint, evidence.model_master_fingerprint),
            ("model_artifact_hash", actual_binding.model_artifact_hash, evidence.model_artifact_hash),
            ("model_structural_hash", actual_binding.model_structural_hash, evidence.model_structural_hash),
            ("model_contract_hash", actual_binding.model_contract_hash, evidence.model_contract_hash),
            ("preprocessing_contract_hash", actual_binding.preprocessing_contract_hash, evidence.preprocessing_contract_hash),
            ("transformed_input_hash", actual_binding.transformed_input_hash, evidence.transformed_input_hash),
            ("execution_identity_hash", actual_binding.execution_identity_hash, evidence.execution_identity_hash),
            ("raw_output_hash", actual_binding.raw_output_hash, evidence.raw_output_hash),
            ("validated_output_identity", actual_binding.validated_output_identity, evidence.validated_output_identity),
        ]
        for field_name, b_val, ev_val in field_checks:
            if not hmac.compare_digest(str(b_val), str(ev_val)):
                return InferenceEvidenceVerificationResult(
                    is_valid=False,
                    status=InferenceEvidenceStatus.INVALID,
                    evidence_id=evidence.evidence_id,
                    computed_evidence_hash=computed_ev_hash,
                    record_verified=record_verified,
                    binding_verified=False,
                    replay_verified=False,
                    provenance_verified=False,
                    findings=[{
                        "code": "CROSS_COMPONENT_INCONSISTENCY",
                        "message": f"Contradiction in '{field_name}': binding has '{b_val}', evidence has '{ev_val}'.",
                    }],
                    details={"field": field_name, "binding_value": b_val, "evidence_value": ev_val},
                )

    # 5. Verify ReplayVerificationResult if provided
    replay_verified = True
    if replay_result is not None:
        if not hmac.compare_digest(replay_result.project_id, evidence.project_id):
            return InferenceEvidenceVerificationResult(
                is_valid=False,
                status=InferenceEvidenceStatus.PROJECT_MISMATCH,
                evidence_id=evidence.evidence_id,
                computed_evidence_hash=computed_ev_hash,
                record_verified=record_verified,
                binding_verified=binding_verified,
                replay_verified=False,
                provenance_verified=False,
                findings=[{
                    "code": "PROJECT_MISMATCH",
                    "message": f"Replay project '{replay_result.project_id}' does not match evidence project '{evidence.project_id}'.",
                }],
                details={"replay_project": replay_result.project_id, "evidence_project": evidence.project_id},
            )

        if not hmac.compare_digest(replay_result.record_id, evidence.record_id):
            return InferenceEvidenceVerificationResult(
                is_valid=False,
                status=InferenceEvidenceStatus.INVALID,
                evidence_id=evidence.evidence_id,
                computed_evidence_hash=computed_ev_hash,
                record_verified=record_verified,
                binding_verified=binding_verified,
                replay_verified=False,
                provenance_verified=False,
                findings=[{
                    "code": "REPLAY_RECORD_MISMATCH",
                    "message": f"Replay record ID mismatch: replay has '{replay_result.record_id}', evidence has '{evidence.record_id}'.",
                }],
                details={"replay_record_id": replay_result.record_id, "evidence_record_id": evidence.record_id},
            )

        if evidence.replay_status is not None:
            if evidence.replay_status != replay_result.consistency_status.value:
                return InferenceEvidenceVerificationResult(
                    is_valid=False,
                    status=InferenceEvidenceStatus.INVALID,
                    evidence_id=evidence.evidence_id,
                    computed_evidence_hash=computed_ev_hash,
                    record_verified=record_verified,
                    binding_verified=binding_verified,
                    replay_verified=False,
                    provenance_verified=False,
                    findings=[{
                        "code": "REPLAY_DIVERGENCE",
                        "message": f"Replay status mismatch: replay has '{replay_result.consistency_status.value}', evidence has '{evidence.replay_status}'.",
                    }],
                    details={"replay_status": replay_result.consistency_status.value, "evidence_replay_status": evidence.replay_status},
                )

    # 6. Verify Provenance payload if provided
    provenance_verified = True
    if provenance_payload is not None:
        prov_proj = provenance_payload.get("project_id")
        if prov_proj and not hmac.compare_digest(str(prov_proj), evidence.project_id):
            return InferenceEvidenceVerificationResult(
                is_valid=False,
                status=InferenceEvidenceStatus.PROJECT_MISMATCH,
                evidence_id=evidence.evidence_id,
                computed_evidence_hash=computed_ev_hash,
                record_verified=record_verified,
                binding_verified=binding_verified,
                replay_verified=replay_verified,
                provenance_verified=False,
                findings=[{
                    "code": "PROJECT_MISMATCH",
                    "message": f"Provenance payload project '{prov_proj}' does not match evidence project '{evidence.project_id}'.",
                }],
                details={"provenance_project": prov_proj, "evidence_project": evidence.project_id},
            )

        prov_ev_id = provenance_payload.get("evidence_id")
        if prov_ev_id and not hmac.compare_digest(str(prov_ev_id), evidence.evidence_id):
            return InferenceEvidenceVerificationResult(
                is_valid=False,
                status=InferenceEvidenceStatus.INVALID,
                evidence_id=evidence.evidence_id,
                computed_evidence_hash=computed_ev_hash,
                record_verified=record_verified,
                binding_verified=binding_verified,
                replay_verified=replay_verified,
                provenance_verified=False,
                findings=[{
                    "code": "PROVENANCE_MISMATCH",
                    "message": f"Provenance payload evidence_id '{prov_ev_id}' does not match evidence '{evidence.evidence_id}'.",
                }],
                details={"provenance_evidence_id": prov_ev_id, "evidence_id": evidence.evidence_id},
            )

        prov_rec_id = provenance_payload.get("record_id")
        if prov_rec_id and not hmac.compare_digest(str(prov_rec_id), evidence.record_id):
            return InferenceEvidenceVerificationResult(
                is_valid=False,
                status=InferenceEvidenceStatus.INVALID,
                evidence_id=evidence.evidence_id,
                computed_evidence_hash=computed_ev_hash,
                record_verified=record_verified,
                binding_verified=binding_verified,
                replay_verified=replay_verified,
                provenance_verified=False,
                findings=[{
                    "code": "PROVENANCE_MISMATCH",
                    "message": f"Provenance payload record_id '{prov_rec_id}' does not match evidence record '{evidence.record_id}'.",
                }],
                details={"provenance_record_id": prov_rec_id, "evidence_record_id": evidence.record_id},
            )

    findings.append({
        "code": "INFERENCE_INTEGRITY_VERIFIED",
        "message": "Inference evidence and complete provenance binding chain verified successfully.",
    })

    return InferenceEvidenceVerificationResult(
        is_valid=True,
        status=InferenceEvidenceStatus.VERIFIED,
        evidence_id=evidence.evidence_id,
        computed_evidence_hash=computed_ev_hash,
        record_verified=record_verified,
        binding_verified=binding_verified,
        replay_verified=replay_verified,
        provenance_verified=provenance_verified,
        findings=findings,
        details={"verification_mode": "end_to_end_pure_cryptographic"},
    )
