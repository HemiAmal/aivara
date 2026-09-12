"""Behavioral Evidence and Provenance Verification Engine (Phase 8.7).

Provides:
  - Deep cryptographic and semantic verification of behavioral evidence and provenance records.
  - Verification of JCS SHA-256 evidence identity, anomaly digest, model fingerprint, and baseline linkage.
  - Multi-dimensional verification vector (signatures, chain linkage, sequence, nonce, project isolation).
  - Explicit distinction between cryptographic tampering (INVALID) and operational issues (MISSING, UNAVAILABLE, UNKNOWN_SIGNER).
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple, Union
from sqlalchemy.orm import Session

from aivara.crypto.canonical import format_canonical_datetime
from aivara.crypto.keys import KeyManager
from aivara.crypto.verification import FailureCode, verify_record
from aivara.database.models import EvidenceModel, FindingModel, ProvenanceRecordModel
from aivara.domain.schemas import ProvenanceRecordRead
from aivara.evidence.schemas import ProvenanceStatus
from aivara.services.audit_service import AuditService
from aivara.behavioral.provenance.enums import (
    BehavioralEvidenceType,
    EvidenceLifecycleState,
)
from aivara.behavioral.provenance.exceptions import (
    BehavioralProvenanceError,
    CrossProjectBindingError,
    EvidenceTamperedError,
)
from aivara.behavioral.provenance.identity import (
    compute_behavioral_evidence_hash,
    is_valid_hash,
)
from aivara.behavioral.provenance.schemas import (
    BehavioralEvidence,
    BehavioralEvidenceContent,
    BehavioralVerificationResult,
    BehavioralVerificationVector,
)

logger = logging.getLogger("aivara.behavioral.provenance.verifier")


class BehavioralProvenanceVerifier:
    """Verifier for assessing behavioral evidence integrity and provenance validity."""

    def __init__(
        self,
        db: Session,
        key_manager: Optional[KeyManager] = None,
        audit_service: Optional[AuditService] = None,
    ) -> None:
        self.db = db
        self.key_manager = key_manager
        self.audit_service = audit_service or AuditService(db)

    def verify_evidence_integrity(
        self,
        evidence: BehavioralEvidence,
    ) -> Tuple[bool, List[str]]:
        """Verify that the evidence content deterministically reproduces its declared evidence_id."""
        failures: List[str] = []
        try:
            recomputed_hash = compute_behavioral_evidence_hash(evidence.content)
            if recomputed_hash != evidence.evidence_id:
                failures.append(
                    f"Evidence identity mismatch: stored '{evidence.evidence_id}', recomputed '{recomputed_hash}'."
                )
                return False, failures
            return True, []
        except Exception as e:
            failures.append(f"Evidence hash computation failed: {str(e)}")
            return False, failures

    def verify_behavioral_provenance(
        self,
        *,
        evidence: BehavioralEvidence,
        provenance_record: Optional[Union[ProvenanceRecordModel, ProvenanceRecordRead, Dict[str, Any]]] = None,
        provenance_record_id: Optional[str] = None,
        expected_project_id: Optional[str] = None,
        actor: str = "system:behavioral_verifier",
    ) -> BehavioralVerificationResult:
        """Perform comprehensive cryptographic and semantic verification of a behavioral evidence item."""
        content = evidence.content
        project_id = content.project_id
        model_id = content.model_id
        failures: List[str] = []
        limitations: List[str] = []

        # 1. Project Isolation Check
        project_isolation_valid = True
        if expected_project_id and expected_project_id != project_id:
            project_isolation_valid = False
            failures.append(
                f"Project mismatch: evidence belongs to project '{project_id}', but verification requested for '{expected_project_id}'."
            )

        # 2. Evidence Content Identity Check (Tamper Detection on Evidence)
        ev_id_valid, ev_failures = self.verify_evidence_integrity(evidence)
        failures.extend(ev_failures)

        # 3. Anomaly & Baseline & Model Identity semantic checks
        analysis_id_valid = bool(content.anomaly_analysis_id and (content.anomaly_analysis_id == "NONE" or is_valid_hash(content.anomaly_analysis_id)))
        observation_id_valid = bool(content.observation_id)
        baseline_id_valid = bool(content.baseline_id)
        model_id_valid = bool(content.model_id and content.model_fingerprint)

        if not observation_id_valid:
            failures.append("Observation identity is missing or invalid.")
        if not baseline_id_valid:
            failures.append("Baseline identity is missing or invalid.")
        if not model_id_valid:
            failures.append("Model identity or fingerprint is missing.")

        # 4. Resolve Provenance Record
        record_model: Optional[ProvenanceRecordModel] = None
        if isinstance(provenance_record, ProvenanceRecordModel):
            record_model = provenance_record
        elif isinstance(provenance_record, ProvenanceRecordRead):
            record_model = self.db.query(ProvenanceRecordModel).filter_by(id=provenance_record.id).first()
        elif isinstance(provenance_record, dict) and "id" in provenance_record:
            record_model = self.db.query(ProvenanceRecordModel).filter_by(id=provenance_record["id"]).first()
        elif provenance_record_id:
            record_model = self.db.query(ProvenanceRecordModel).filter_by(id=provenance_record_id).first()
        elif evidence.provenance_record_id:
            record_model = self.db.query(ProvenanceRecordModel).filter_by(id=evidence.provenance_record_id).first()

        # Provenance Vector Flags
        prov_hash_valid = False
        sig_valid = False
        chain_valid = False
        seq_valid = False
        nonce_valid = False
        signer_status = "NONE"
        overall_status = ProvenanceStatus.UNAVAILABLE

        if record_model is None:
            if evidence.provenance_record_id or provenance_record_id:
                overall_status = ProvenanceStatus.MISSING
                failures.append(f"Provenance record '{provenance_record_id or evidence.provenance_record_id}' not found in database.")
            else:
                overall_status = ProvenanceStatus.UNAVAILABLE
                limitations.append("No provenance record was bound to this evidence item.")
        else:
            # Check record project matches evidence project
            if record_model.project_id != project_id:
                project_isolation_valid = False
                failures.append(
                    f"Cross-project provenance record mismatch: record is project '{record_model.project_id}', evidence is '{project_id}'."
                )

            rec_timestamp = (record_model.metadata_json or {}).get("canonical_timestamp")
            if not rec_timestamp:
                rec_timestamp = format_canonical_datetime(record_model.created_at) if record_model.created_at else format_canonical_datetime(datetime.now(timezone.utc))

            record_dict = {
                "id": record_model.id,
                "project_id": record_model.project_id,
                "record_type": record_model.record_type,
                "actor": record_model.actor,
                "action": record_model.action,
                "target_type": record_model.target_type,
                "target_id": record_model.target_id,
                "input_hash": record_model.input_hash,
                "output_hash": record_model.output_hash,
                "metadata_json": record_model.metadata_json,
                "sequence_number": record_model.sequence_number,
                "previous_record_hash": record_model.previous_record_hash,
                "record_hash": record_model.record_hash,
                "nonce": record_model.nonce,
                "signer_key_id": record_model.signer_key_id or ("0" * 64),
                "signature": record_model.signature,
                "timestamp": rec_timestamp,
            }

            try:
                verification_summary = verify_record(
                    record_dict,
                    key_manager=self.key_manager,
                    allow_unsigned=True,
                    expected_project_id=project_id,
                    expected_sequence=record_model.sequence_number,
                    expected_previous_record_hash=record_model.previous_record_hash,
                )
            except Exception as exc:
                failures.append(f"Verification engine execution error: {exc}")
                verification_summary = None

            if verification_summary is not None:
                prov_hash_valid = verification_summary.record_valid
                sig_valid = bool(verification_summary.signature_valid)
                chain_valid = (verification_summary.chain_valid is not False)
                seq_valid = not any(f.code in (FailureCode.INVALID_SEQUENCE, FailureCode.SEQUENCE_GAP, FailureCode.DUPLICATE_SEQUENCE, FailureCode.SEQUENCE_VIOLATION) for f in verification_summary.failures)
                nonce_valid = not any(f.code in (FailureCode.INVALID_NONCE, FailureCode.DUPLICATE_NONCE, FailureCode.REPLAY_DETECTED) for f in verification_summary.failures)

                if verification_summary.key_status:
                    signer_status = verification_summary.key_status.value
                elif verification_summary.key_is_active:
                    signer_status = "ACTIVE"
                elif any(f.code == FailureCode.UNKNOWN_SIGNER_KEY for f in verification_summary.failures):
                    signer_status = "UNKNOWN_SIGNER"
                elif record_model.signature:
                    signer_status = "ACTIVE" if sig_valid else "UNKNOWN_SIGNER"
                else:
                    signer_status = "NONE"

                for f in verification_summary.failures:
                    failures.append(f"Provenance failure [{f.code.value}]: {f.message}")

                failure_codes = set(verification_summary.failure_codes)
                tamper_codes = {
                    FailureCode.RECORD_HASH_MISMATCH,
                    FailureCode.INVALID_SIGNATURE,
                    FailureCode.MALFORMED_SIGNATURE,
                    FailureCode.BROKEN_CHAIN,
                    FailureCode.REPLAY_DETECTED,
                    FailureCode.DUPLICATE_NONCE,
                    FailureCode.DUPLICATE_RECORD,
                    FailureCode.DUPLICATE_SEQUENCE,
                    FailureCode.SEQUENCE_GAP,
                    FailureCode.SEQUENCE_VIOLATION,
                }

                if not project_isolation_valid or FailureCode.PROJECT_MISMATCH in failure_codes:
                    overall_status = ProvenanceStatus.MISMATCHED
                elif not ev_id_valid or bool(tamper_codes & failure_codes):
                    overall_status = ProvenanceStatus.INVALID
                elif FailureCode.UNKNOWN_SIGNER_KEY in failure_codes or not record_model.signature or not verification_summary.signature_present or not sig_valid:
                    overall_status = ProvenanceStatus.UNVERIFIABLE
                elif verification_summary.overall_valid and sig_valid:
                    overall_status = ProvenanceStatus.VERIFIED
                else:
                    overall_status = ProvenanceStatus.INVALID
            else:
                overall_status = ProvenanceStatus.UNVERIFIABLE

        # 5. Build Verification Vector
        vector = BehavioralVerificationVector(
            evidence_identity_valid=ev_id_valid,
            analysis_identity_valid=analysis_id_valid,
            observation_identity_valid=observation_id_valid,
            baseline_identity_valid=baseline_id_valid,
            model_identity_valid=model_id_valid,
            provenance_hash_valid=prov_hash_valid,
            signature_valid=sig_valid,
            chain_valid=chain_valid,
            sequence_valid=seq_valid,
            nonce_valid=nonce_valid,
            project_isolation_valid=project_isolation_valid,
            signer_status=signer_status,
            failures=failures,
            limitations=limitations,
        )

        message = (
            f"Behavioral evidence verification complete: status={overall_status.value}. "
            f"Failures: {len(failures)}, Limitations: {len(limitations)}."
        )

        # 6. Audit Trail Event
        event_type = "BEHAVIORAL_PROVENANCE_VERIFIED" if overall_status == ProvenanceStatus.VERIFIED else "BEHAVIORAL_PROVENANCE_MISMATCH"
        self.audit_service.record_event(
            project_id=project_id,
            event_type=event_type,
            actor=actor,
            action="VERIFY_PROVENANCE",
            target_type="model",
            target_id=model_id,
            outcome="SUCCESS" if overall_status == ProvenanceStatus.VERIFIED else "FAILURE",
            description=message,
            metadata_json={
                "evidence_id": evidence.evidence_id,
                "overall_status": overall_status.value,
                "failure_count": len(failures),
                "provenance_record_id": record_model.id if record_model else None,
            },
        )

        return BehavioralVerificationResult(
            evidence_id=evidence.evidence_id,
            project_id=project_id,
            model_id=model_id,
            overall_status=overall_status,
            verification_vector=vector,
            message=message,
        )
