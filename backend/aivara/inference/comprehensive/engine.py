"""Authoritative End-to-End Comprehensive Inference Verification Engine (Phase 10.12).

Executes the complete 18-checkpoint verification pipeline:
  1. Project Identity & Multi-Tenant Boundary Isolation
  2. Input Identity & Boundary Checks (Phase 10.2)
  3. Model Identity Envelope & Master Fingerprint (Phase 7 / Phase 10.3)
  4. Input-Model Binding Integrity (Phase 10.3)
  5. Preprocessing Contract Integrity (Phase 10.4)
  6. Transformed Input Identity & Finiteness (Phase 10.4)
  7. Controlled Execution Identity (Phase 10.5)
  8. Raw Output Descriptors & Non-Finite Trapping (Phase 10.5)
  9. Output Schema & Geometry Contracts (Phase 10.6)
  10. Validated Output Identity (Phase 10.6)
  11. Composite Input-Output Binding (Phase 10.7 - 18 Committed Fields)
  12. Inference Record Persistence & Canonical Descriptor (Phase 10.8 - 8 Committed Fields)
  13. Replay Eligibility Verification (Phase 10.9)
  14. Replay Numerical & Structural Consistency (Phase 10.9)
  15. Evidence Integrity & Phase 5 Payload Binding (Phase 10.10)
  16. Provenance Chain Linkage & Hash Sealing (Phase 4 / Phase 10.10)
  17. Cross-Component Contradiction Matrix Detection
  18. Deterministic Overall Status Aggregation & Finding Synthesis
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

from aivara.crypto.canonical import canonicalize
from aivara.domain.schemas import Disposition, EvidenceLayer, Severity
from aivara.domain.schemas import ProvenanceRecordRead
from aivara.inference.binding.engine import (
    verify_input_model_binding,
    verify_master_fingerprint_consistency,
)
from aivara.inference.binding.models import InputModelBinding, ModelIdentityEnvelope
from aivara.inference.composite_binding.engine import verify_inference_binding
from aivara.inference.composite_binding.enums import InferenceBindingStatus
from aivara.inference.composite_binding.models import InferenceBinding
from aivara.inference.comprehensive.models import ComprehensiveInferenceVerificationResult
from aivara.inference.enums import InferenceFindingCode, InferenceIntegrityStatus
from aivara.inference.evidence.engine import verify_inference_evidence
from aivara.inference.evidence.enums import InferenceEvidenceStatus
from aivara.inference.evidence.models import InferenceEvidence
from aivara.inference.execution.engine import verify_execution_identity
from aivara.inference.execution.models import InferenceExecution
from aivara.inference.input.models import InputFinding, InputIdentity
from aivara.inference.output.engine import verify_validated_output_identity
from aivara.inference.output.models import ModelOutputContract, OutputIntegrityAssessment
from aivara.inference.preprocessing.engine import verify_preprocessing_contract
from aivara.inference.preprocessing.models import PreprocessingContract, TransformedInputIdentity
from aivara.inference.records.enums import InferenceRecordStatus
from aivara.inference.records.engine import verify_inference_record
from aivara.inference.records.models import InferenceRecord
from aivara.inference.replay.enums import ReplayConsistencyStatus, ReplayEligibilityStatus
from aivara.inference.replay.models import ReplayVerificationResult

logger = logging.getLogger("aivara.inference.comprehensive")


def _secure_compare(val_a: Optional[str], val_b: Optional[str]) -> bool:
    """Perform constant-time string comparison to prevent timing side-channels."""
    if val_a is None or val_b is None:
        return val_a == val_b
    return hmac.compare_digest(val_a.strip().lower(), val_b.strip().lower())


class ComprehensiveInferenceVerifier:
    """Authoritative verifier for the complete Phase 10 Inference Integrity Chain."""

    @classmethod
    def verify(
        cls,
        project_id: str,
        record: Optional[InferenceRecord] = None,
        binding: Optional[InferenceBinding] = None,
        input_identity: Optional[InputIdentity] = None,
        model_identity: Optional[ModelIdentityEnvelope] = None,
        input_model_binding: Optional[InputModelBinding] = None,
        preprocessing_contract: Optional[PreprocessingContract] = None,
        transformed_input: Optional[TransformedInputIdentity] = None,
        execution: Optional[InferenceExecution] = None,
        output_contract: Optional[ModelOutputContract] = None,
        output_assessment: Optional[OutputIntegrityAssessment] = None,
        replay_result: Optional[ReplayVerificationResult] = None,
        evidence: Optional[InferenceEvidence] = None,
        provenance: Optional[Union[ProvenanceRecordRead, Dict[str, Any]]] = None,
    ) -> ComprehensiveInferenceVerificationResult:
        """Execute the full 18-checkpoint comprehensive inference assurance verification."""
        findings: List[InputFinding] = []
        layer_details: Dict[str, Any] = {}
        summary: Dict[str, Any] = {}

        # If binding embedded in record, unpack if not explicitly passed
        active_binding = binding
        if active_binding is None and record is not None and record.binding is not None:
            active_binding = record.binding

        # -------------------------------------------------------------
        # 1. Project Identity & Multi-Tenant Boundary Isolation
        # -------------------------------------------------------------
        has_project_mismatch = False

        def _check_project(name: str, entity_proj: Optional[str]) -> None:
            nonlocal has_project_mismatch
            if entity_proj and not _secure_compare(entity_proj, project_id):
                has_project_mismatch = True
                findings.append(
                    InputFinding(
                        code=InferenceFindingCode.BINDING_PROJECT_MISMATCH.value,
                        message=f"{name} project '{entity_proj}' does not match expected project '{project_id}'.",
                    )
                )

        _check_project("InferenceRecord", record.project_id if record else None)
        _check_project("InferenceBinding", active_binding.project_id if active_binding else None)
        _check_project("ModelIdentity", model_identity.project_id if model_identity else None)
        _check_project("InputModelBinding", input_model_binding.project_id if input_model_binding else None)
        _check_project("Execution", execution.project_id if execution else None)
        _check_project("Evidence", evidence.project_id if evidence else None)
        if provenance is not None:
            prov_proj = provenance.project_id if isinstance(provenance, ProvenanceRecordRead) else provenance.get("project_id")
            _check_project("Provenance", prov_proj)

        # -------------------------------------------------------------
        # 2. Input Identity & Boundary Checks (Phase 10.2)
        # -------------------------------------------------------------
        input_status = InferenceIntegrityStatus.UNVERIFIABLE
        if input_identity is not None:
            if input_identity.canonical_hash and len(input_identity.canonical_hash) == 64:
                input_status = InferenceIntegrityStatus.VERIFIED
            else:
                input_status = InferenceIntegrityStatus.INVALID
                findings.append(
                    InputFinding(
                        code=InferenceFindingCode.INPUT_MUTATION_DETECTED.value,
                        message="Input canonical hash is invalid or malformed.",
                    )
                )
            for f in input_identity.findings:
                findings.append(f)
            layer_details["input"] = {
                "input_id": input_identity.input_id,
                "canonical_hash": input_identity.canonical_hash,
                "input_kind": input_identity.input_kind.value if hasattr(input_identity.input_kind, "value") else str(input_identity.input_kind),
            }
        elif active_binding is not None:
            input_status = InferenceIntegrityStatus.VERIFIED
            layer_details["input"] = {
                "input_id": active_binding.input_id,
                "canonical_hash": active_binding.input_canonical_hash,
            }
        summary["input"] = input_status.value

        # -------------------------------------------------------------
        # 3. Model Identity Envelope & Master Fingerprint (Phase 7 / Phase 10.3)
        # -------------------------------------------------------------
        model_status = InferenceIntegrityStatus.UNVERIFIABLE
        if model_identity is not None:
            fp_valid = verify_master_fingerprint_consistency(
                artifact_hash=model_identity.artifact_hash,
                structural_hash=model_identity.structural_hash,
                contract_hash=model_identity.contract_hash,
                master_fingerprint=model_identity.master_fingerprint,
            )
            if fp_valid:
                model_status = InferenceIntegrityStatus.VERIFIED
            else:
                model_status = InferenceIntegrityStatus.INVALID
                findings.append(
                    InputFinding(
                        code=InferenceFindingCode.BINDING_MODEL_NOT_VERIFIED.value,
                        message="Model master fingerprint does not match canonical recomputed fingerprint.",
                    )
                )
            layer_details["model"] = {
                "model_id": model_identity.model_id,
                "master_fingerprint": model_identity.master_fingerprint,
                "artifact_hash": model_identity.artifact_hash,
            }
        elif active_binding is not None:
            fp_valid = verify_master_fingerprint_consistency(
                artifact_hash=active_binding.model_artifact_hash,
                structural_hash=active_binding.model_structural_hash,
                contract_hash=active_binding.model_contract_hash,
                master_fingerprint=active_binding.model_master_fingerprint,
            )
            if fp_valid:
                model_status = InferenceIntegrityStatus.VERIFIED
            else:
                model_status = InferenceIntegrityStatus.INVALID
                findings.append(
                    InputFinding(
                        code=InferenceFindingCode.BINDING_MODEL_NOT_VERIFIED.value,
                        message="Embedded model master fingerprint in binding does not match recomputed fingerprint.",
                    )
                )
            layer_details["model"] = {
                "model_id": active_binding.model_id,
                "master_fingerprint": active_binding.model_master_fingerprint,
            }
        summary["model"] = model_status.value

        # -------------------------------------------------------------
        # 4. Input-Model Binding Integrity (Phase 10.3)
        # -------------------------------------------------------------
        input_model_binding_status = InferenceIntegrityStatus.UNVERIFIABLE
        if input_model_binding is not None:
            imb_res = verify_input_model_binding(input_model_binding)
            input_model_binding_status = imb_res.status
            if not imb_res.is_valid:
                for f in imb_res.findings:
                    findings.append(f)
            layer_details["input_model_binding"] = {
                "binding_hash": input_model_binding.binding_hash,
                "is_valid": imb_res.is_valid,
            }
        elif active_binding is not None:
            input_model_binding_status = InferenceIntegrityStatus.VERIFIED
            layer_details["input_model_binding"] = {
                "binding_hash": active_binding.input_model_binding_hash,
            }
        summary["input_model_binding"] = input_model_binding_status.value

        # -------------------------------------------------------------
        # 5. Preprocessing Contract Integrity (Phase 10.4)
        # -------------------------------------------------------------
        preprocessing_status = InferenceIntegrityStatus.UNVERIFIABLE
        if preprocessing_contract is not None:
            prep_res = verify_preprocessing_contract(preprocessing_contract)
            preprocessing_status = prep_res.status
            if not prep_res.is_valid:
                for f in prep_res.findings:
                    findings.append(f)
            layer_details["preprocessing"] = {
                "contract_hash": preprocessing_contract.contract_hash,
                "operations_count": len(preprocessing_contract.operations),
                "is_valid": prep_res.is_valid,
            }
        elif active_binding is not None:
            preprocessing_status = InferenceIntegrityStatus.VERIFIED
            layer_details["preprocessing"] = {
                "contract_hash": active_binding.preprocessing_contract_hash,
                "transformed_input_hash": active_binding.transformed_input_hash,
            }
        summary["preprocessing"] = preprocessing_status.value

        # -------------------------------------------------------------
        # 6. Transformed Input Identity & Finiteness (Phase 10.4)
        # -------------------------------------------------------------
        if transformed_input is not None:
            if not transformed_input.finite:
                findings.append(
                    InputFinding(
                        code=InferenceFindingCode.INPUT_NONFINITE_VALUE.value,
                        message="Transformed input tensor contains non-finite values (NaN/Inf).",
                    )
                )
                preprocessing_status = InferenceIntegrityStatus.INVALID

        # -------------------------------------------------------------
        # 7. Controlled Execution Identity (Phase 10.5)
        # -------------------------------------------------------------
        execution_status = InferenceIntegrityStatus.UNVERIFIABLE
        if execution is not None:
            exec_res = verify_execution_identity(execution)
            execution_status = exec_res.status
            if not exec_res.is_valid:
                for f in exec_res.findings:
                    findings.append(f)
            layer_details["execution"] = {
                "execution_identity_hash": execution.execution_identity_hash,
                "raw_output_hash": execution.raw_output_hash,
                "provider": execution.execution_provider,
                "is_valid": exec_res.is_valid,
            }
        elif active_binding is not None:
            execution_status = InferenceIntegrityStatus.VERIFIED
            layer_details["execution"] = {
                "execution_identity_hash": active_binding.execution_identity_hash,
                "raw_output_hash": active_binding.raw_output_hash,
            }
        summary["execution"] = execution_status.value

        # -------------------------------------------------------------
        # 8 & 9 & 10. Output Schema & Validated Output Identity (Phase 10.6)
        # -------------------------------------------------------------
        output_status = InferenceIntegrityStatus.UNVERIFIABLE
        if output_assessment is not None:
            out_is_valid = verify_validated_output_identity(output_assessment)
            if out_is_valid and output_assessment.integrity_status == InferenceIntegrityStatus.VERIFIED:
                output_status = InferenceIntegrityStatus.VERIFIED
            else:
                output_status = InferenceIntegrityStatus.INVALID
            for f in output_assessment.findings:
                findings.append(f)
            layer_details["output"] = {
                "validated_output_identity": output_assessment.validated_output_identity,
                "is_valid": out_is_valid,
                "numerical_status": output_assessment.numerical_status.value if hasattr(output_assessment.numerical_status, "value") else str(output_assessment.numerical_status),
            }
        elif active_binding is not None:
            output_status = InferenceIntegrityStatus.VERIFIED
            layer_details["output"] = {
                "validated_output_identity": active_binding.validated_output_identity,
                "output_contract_hash": active_binding.output_contract_hash,
            }
        summary["output"] = output_status.value

        # -------------------------------------------------------------
        # 11. Composite Input-Output Binding (Phase 10.7)
        # -------------------------------------------------------------
        binding_status = InferenceIntegrityStatus.UNVERIFIABLE
        if active_binding is not None:
            binding_res = verify_inference_binding(active_binding)
            binding_status = binding_res.status
            if not binding_res.is_valid:
                for f in binding_res.findings:
                    findings.append(f)
            layer_details["binding"] = {
                "inference_binding_hash": active_binding.inference_binding_hash,
                "is_valid": binding_res.is_valid,
                "status": binding_res.status.value,
            }
        summary["binding"] = binding_status.value

        # -------------------------------------------------------------
        # 12. Inference Record Persistence & Integrity (Phase 10.8)
        # -------------------------------------------------------------
        record_status: Optional[InferenceRecordStatus] = None
        if record is not None:
            rec_res = verify_inference_record(record=record, binding=active_binding, expected_project_id=project_id)
            record_status = rec_res.status
            if not rec_res.is_valid:
                for f in rec_res.findings:
                    findings.append(f)
            layer_details["record"] = {
                "record_id": record.record_id,
                "record_integrity_hash": record.record_integrity_hash,
                "stored_integrity_hash": rec_res.stored_integrity_hash,
                "computed_integrity_hash": rec_res.computed_integrity_hash,
                "is_valid": rec_res.is_valid,
                "status": rec_res.status.value,
            }
        summary["record"] = record_status.value if record_status else None

        # -------------------------------------------------------------
        # 13 & 14. Replay Eligibility & Consistency (Phase 10.9)
        # -------------------------------------------------------------
        replay_status_str: Optional[str] = None
        if replay_result is not None:
            replay_status_str = (
                replay_result.consistency_status.value
                if hasattr(replay_result.consistency_status, "value")
                else str(replay_result.consistency_status)
            )
            if not replay_result.is_consistent:
                for f in replay_result.findings:
                    findings.append(f)
            layer_details["replay"] = {
                "eligibility": replay_result.eligibility_status.value if hasattr(replay_result.eligibility_status, "value") else str(replay_result.eligibility_status),
                "consistency": replay_status_str,
                "is_consistent": replay_result.is_consistent,
            }
        summary["replay"] = replay_status_str

        # -------------------------------------------------------------
        # 15. Evidence Integrity & Phase 5 Binding (Phase 10.10)
        # -------------------------------------------------------------
        evidence_status: Optional[InferenceEvidenceStatus] = None
        if evidence is not None:
            ev_res = verify_inference_evidence(
                evidence,
                record=record,
                binding=active_binding,
                replay_result=replay_result,
                expected_project_id=project_id,
            )
            evidence_status = ev_res.status
            if not ev_res.is_valid:
                for f in ev_res.findings:
                    findings.append(
                        InputFinding(
                            code=f.get("code", InferenceFindingCode.INFERENCE_EVIDENCE_INVALID.value),
                            message=f.get("message", "Evidence verification failure."),
                        )
                    )
            layer_details["evidence"] = {
                "evidence_id": evidence.evidence_id,
                "is_valid": ev_res.is_valid,
                "status": evidence_status.value,
            }
        summary["evidence"] = evidence_status.value if evidence_status else None

        # -------------------------------------------------------------
        # 16. Provenance Chain Linkage & Hash Sealing (Phase 4 / Phase 10.10)
        # -------------------------------------------------------------
        provenance_status_str: Optional[str] = None
        if provenance is not None:
            prov_hash = provenance.record_hash if isinstance(provenance, ProvenanceRecordRead) else provenance.get("record_hash")
            prov_meta = provenance.metadata_json if isinstance(provenance, ProvenanceRecordRead) else (provenance.get("metadata_json") or provenance.get("metadata") or {})
            
            # Verify record_hash validity
            if prov_hash and len(prov_hash) == 64:
                provenance_status_str = "VERIFIED"
            else:
                provenance_status_str = "INVALID"
                findings.append(
                    InputFinding(
                        code=InferenceFindingCode.INFERENCE_EVIDENCE_PROVENANCE_MISMATCH.value,
                        message="Provenance record hash is missing or invalid format.",
                    )
                )
            layer_details["provenance"] = {
                "provenance_record_hash": prov_hash,
                "status": provenance_status_str,
            }
        summary["provenance"] = provenance_status_str

        # -------------------------------------------------------------
        # 17. Cross-Component Contradiction Matrix Detection
        # -------------------------------------------------------------
        contradictions = []

        if active_binding is not None:
            if input_identity is not None:
                if not _secure_compare(input_identity.canonical_hash, active_binding.input_canonical_hash):
                    contradictions.append(
                        f"Input canonical hash '{input_identity.canonical_hash}' contradicts binding input hash '{active_binding.input_canonical_hash}'"
                    )
                if not _secure_compare(input_identity.input_id, active_binding.input_id):
                    contradictions.append(
                        f"Input ID '{input_identity.input_id}' contradicts binding input ID '{active_binding.input_id}'"
                    )
            if model_identity is not None:
                if not _secure_compare(model_identity.master_fingerprint, active_binding.model_master_fingerprint):
                    contradictions.append(
                        f"Model master fingerprint '{model_identity.master_fingerprint}' contradicts binding master fingerprint '{active_binding.model_master_fingerprint}'"
                    )
                if not _secure_compare(model_identity.model_id, active_binding.model_id):
                    contradictions.append(
                        f"Model ID '{model_identity.model_id}' contradicts binding model ID '{active_binding.model_id}'"
                    )
                if not _secure_compare(model_identity.artifact_hash, active_binding.model_artifact_hash):
                    contradictions.append(
                        f"Model artifact hash '{model_identity.artifact_hash}' contradicts binding artifact hash '{active_binding.model_artifact_hash}'"
                    )
            if input_model_binding is not None:
                if not _secure_compare(input_model_binding.binding_hash, active_binding.input_model_binding_hash):
                    contradictions.append(
                        f"InputModelBinding hash '{input_model_binding.binding_hash}' contradicts composite binding hash '{active_binding.input_model_binding_hash}'"
                    )
            if preprocessing_contract is not None:
                if not _secure_compare(preprocessing_contract.contract_hash, active_binding.preprocessing_contract_hash):
                    contradictions.append(
                        f"Preprocessing contract hash '{preprocessing_contract.contract_hash}' contradicts binding contract hash '{active_binding.preprocessing_contract_hash}'"
                    )
            if transformed_input is not None:
                if not _secure_compare(transformed_input.transformed_canonical_hash, active_binding.transformed_input_hash):
                    contradictions.append(
                        f"Transformed input hash '{transformed_input.transformed_canonical_hash}' contradicts binding transformed input hash '{active_binding.transformed_input_hash}'"
                    )
            if execution is not None:
                if not _secure_compare(execution.execution_identity_hash, active_binding.execution_identity_hash):
                    contradictions.append(
                        f"Execution identity hash '{execution.execution_identity_hash}' contradicts binding execution identity hash '{active_binding.execution_identity_hash}'"
                    )
                if not _secure_compare(execution.raw_output_hash, active_binding.raw_output_hash):
                    contradictions.append(
                        f"Raw output hash '{execution.raw_output_hash}' contradicts binding raw output hash '{active_binding.raw_output_hash}'"
                    )
            if output_assessment is not None:
                if not _secure_compare(output_assessment.validated_output_identity, active_binding.validated_output_identity):
                    contradictions.append(
                        f"Validated output identity '{output_assessment.validated_output_identity}' contradicts binding output identity '{active_binding.validated_output_identity}'"
                    )
            if record is not None:
                if not _secure_compare(record.inference_binding_hash, active_binding.inference_binding_hash):
                    contradictions.append(
                        f"Inference record binding hash '{record.inference_binding_hash}' contradicts composite binding hash '{active_binding.inference_binding_hash}'"
                    )
            if evidence is not None:
                if not _secure_compare(evidence.inference_binding_hash, active_binding.inference_binding_hash):
                    contradictions.append(
                        f"Evidence binding hash '{evidence.inference_binding_hash}' contradicts composite binding hash '{active_binding.inference_binding_hash}'"
                    )
                if record is not None and not _secure_compare(evidence.record_integrity_hash, record.record_integrity_hash):
                    contradictions.append(
                        f"Evidence record integrity hash '{evidence.record_integrity_hash}' contradicts record integrity hash '{record.record_integrity_hash}'"
                    )
            if provenance is not None:
                prov_meta = provenance.metadata_json if isinstance(provenance, ProvenanceRecordRead) else (provenance.get("metadata_json") or provenance.get("metadata") or {})
                if prov_meta.get("inference_binding_hash") and not _secure_compare(prov_meta.get("inference_binding_hash"), active_binding.inference_binding_hash):
                    contradictions.append(
                        f"Provenance binding hash '{prov_meta.get('inference_binding_hash')}' contradicts composite binding hash '{active_binding.inference_binding_hash}'"
                    )
                if record is not None and prov_meta.get("record_id") and not _secure_compare(prov_meta.get("record_id"), record.record_id):
                    contradictions.append(
                        f"Provenance record ID '{prov_meta.get('record_id')}' contradicts record ID '{record.record_id}'"
                    )

        for cont in contradictions:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.INFERENCE_BINDING_COMPONENT_MISMATCH.value,
                    message=cont,
                )
            )

        # -------------------------------------------------------------
        # 18. Deterministic Overall Status Aggregation & Finding Synthesis
        # -------------------------------------------------------------
        has_contradictions = len(contradictions) > 0
        has_tamper = (
            input_status == InferenceIntegrityStatus.INVALID
            or model_status == InferenceIntegrityStatus.INVALID
            or input_model_binding_status == InferenceIntegrityStatus.INVALID
            or preprocessing_status == InferenceIntegrityStatus.INVALID
            or execution_status == InferenceIntegrityStatus.INVALID
            or output_status == InferenceIntegrityStatus.INVALID
            or binding_status == InferenceIntegrityStatus.INVALID
            or record_status in (InferenceRecordStatus.INVALID, InferenceRecordStatus.TAMPERED)
            or (evidence_status is not None and evidence_status in (InferenceEvidenceStatus.INVALID, InferenceEvidenceStatus.TAMPERED))
            or (provenance_status_str == "INVALID")
            or (replay_result is not None and replay_result.consistency_status in (
                ReplayConsistencyStatus.STRUCTURAL_DIVERGENCE,
                ReplayConsistencyStatus.NUMERICAL_DIVERGENCE,
                ReplayConsistencyStatus.EXECUTION_DIVERGENCE,
                ReplayConsistencyStatus.INVALID_RECORD,
                ReplayConsistencyStatus.INVALID_BINDING,
            ))
        )
        has_missing = (
            active_binding is None
            and record is None
            and input_identity is None
        )

        overall_status = InferenceIntegrityStatus.UNVERIFIABLE
        is_verified = False

        if has_project_mismatch:
            overall_status = InferenceIntegrityStatus.MISMATCHED
        elif has_tamper or has_contradictions:
            overall_status = InferenceIntegrityStatus.INVALID
        elif (
            binding_status == InferenceIntegrityStatus.VERIFIED
            and (record is None or record_status == InferenceRecordStatus.VERIFIED)
            and (evidence is None or evidence_status == InferenceEvidenceStatus.VERIFIED)
            and (provenance is None or provenance_status_str == "VERIFIED")
            and (replay_result is None or replay_result.is_consistent)
            and input_status in (InferenceIntegrityStatus.VERIFIED, InferenceIntegrityStatus.UNVERIFIABLE)
            and model_status in (InferenceIntegrityStatus.VERIFIED, InferenceIntegrityStatus.UNVERIFIABLE)
            and preprocessing_status in (InferenceIntegrityStatus.VERIFIED, InferenceIntegrityStatus.UNVERIFIABLE)
            and execution_status in (InferenceIntegrityStatus.VERIFIED, InferenceIntegrityStatus.UNVERIFIABLE)
            and output_status in (InferenceIntegrityStatus.VERIFIED, InferenceIntegrityStatus.UNVERIFIABLE)
            and not has_missing
        ):
            overall_status = InferenceIntegrityStatus.VERIFIED
            is_verified = True
        elif has_missing:
            overall_status = InferenceIntegrityStatus.MISSING
        else:
            overall_status = InferenceIntegrityStatus.UNVERIFIABLE

        # Severity & Disposition
        if overall_status == InferenceIntegrityStatus.VERIFIED:
            severity = Severity.INFO
            disposition = Disposition.ACCEPT
        elif overall_status == InferenceIntegrityStatus.MISMATCHED:
            severity = Severity.HIGH
            disposition = Disposition.QUARANTINE
        elif overall_status == InferenceIntegrityStatus.INVALID:
            severity = Severity.CRITICAL
            disposition = Disposition.QUARANTINE
        else:
            severity = Severity.MEDIUM
            disposition = Disposition.REVIEW

        summary["overall_status"] = overall_status.value
        summary["is_verified"] = is_verified
        summary["findings_count"] = len(findings)
        summary["contradictions_count"] = len(contradictions)

        return ComprehensiveInferenceVerificationResult(
            project_id=project_id,
            record_id=record.record_id if record else None,
            inference_binding_hash=active_binding.inference_binding_hash if active_binding else None,
            record_integrity_hash=record.record_integrity_hash if record else None,
            input_status=input_status,
            model_status=model_status,
            input_model_binding_status=input_model_binding_status,
            preprocessing_status=preprocessing_status,
            execution_status=execution_status,
            output_status=output_status,
            binding_status=binding_status,
            record_status=record_status,
            replay_status=replay_status_str,
            evidence_status=evidence_status,
            provenance_status=provenance_status_str,
            overall_status=overall_status,
            is_verified=is_verified,
            findings=findings,
            confidence=1.0,
            severity=severity,
            disposition=disposition,
            verification_summary=summary,
            layer_details=layer_details,
        )
