"""Provenance Binding Adapter and Verification Engine for Evidence (Phase 5.9).

Provides:
  - Cryptographic binding of analytical findings to Phase 4 Provenance Records.
  - Ed25519 signing and hash chain commitment using Phase 4 KeyManager and ProvenanceService.
  - Verification of findings against the cryptographic provenance ledger.
  - Strict separation: VALID_SIGNATURE != ANALYTICAL_ACCURACY.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Sequence, Union
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from aivara.crypto.canonical import format_canonical_datetime
from aivara.crypto.chain import ChainRecord, generate_nonce
from aivara.crypto.hashing import hash_canonical_data, hash_provenance_payload
from aivara.crypto.keys import Ed25519KeyHandle, KeyManager
from aivara.crypto.signing import sign_hash
from aivara.crypto.verification import FailureCode, verify_record
from aivara.database.models import EvidenceModel, FindingModel, ProvenanceRecordModel
from aivara.domain.schemas import ProvenanceRecordCreate, ProvenanceRecordRead
from aivara.evidence.exceptions import (
    CrossProjectContaminationError,
    EvidenceValidationError,
    MissingProvenanceError,
    ProvenanceBindingError,
)
from aivara.evidence.schemas import (
    EvidenceProvenanceVerificationResult,
    ProvenanceStatus,
)
from aivara.evidence.validators import validate_project_isolation
from aivara.services.audit_service import AuditService
from aivara.services.provenance_service import ProvenanceService

logger = logging.getLogger("aivara.evidence.provenance")


class ProvenanceBindingAdapter:
    """Client adapter connecting Phase 5 evidence findings to the Phase 4 cryptographic ledger."""

    def __init__(
        self,
        db: Session,
        key_manager: Optional[KeyManager] = None,
        audit_service: Optional[AuditService] = None,
        provenance_service: Optional[ProvenanceService] = None,
    ) -> None:
        """Initialize with an active database session and optional crypto services.

        Args:
            db: Active SQLAlchemy database session.
            key_manager: Optional KeyManager for Ed25519 signing and verification.
            audit_service: Optional AuditService instance.
            provenance_service: Optional ProvenanceService instance.
        """
        self.db = db
        self.key_manager = key_manager
        self.audit_service = audit_service or AuditService(db)
        self.provenance_service = provenance_service or ProvenanceService(
            db=db,
            key_manager=key_manager,
            audit_service=self.audit_service,
        )

    def seal_scan_findings(
        self,
        *,
        project_id: str,
        dataset_version_id: str,
        dataset_fingerprint: str,
        execution_identity_hash: str,
        audit_run_id: str,
        findings: Sequence[FindingModel],
        signer_key_id: Optional[str] = None,
        signer_passphrase: Optional[str] = None,
        key_handle: Optional[Ed25519KeyHandle] = None,
        actor: str = "system:die_orchestrator",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ProvenanceRecordRead:
        """Atomically commit and sign an analytical findings batch into the Phase 4 provenance chain.

        Args:
            project_id: Project identifier.
            dataset_version_id: Target dataset version identifier.
            dataset_fingerprint: SHA-256 manifest hash of the dataset.
            execution_identity_hash: Deterministic execution identity hash.
            audit_run_id: Scan audit run identifier.
            findings: List of FindingModel rows to seal.
            signer_key_id: Optional key ID to sign the record.
            signer_passphrase: Optional passphrase to decrypt private key.
            key_handle: Optional loaded Ed25519KeyHandle for signing.
            actor: Calling system or user actor.
            metadata: Additional metadata dictionary.

        Returns:
            The committed and signed ProvenanceRecordRead instance.
        """
        if not project_id:
            raise ProvenanceBindingError("project_id is required to seal findings.")
        if not dataset_version_id:
            raise ProvenanceBindingError("dataset_version_id is required to seal findings.")

        # 1. Validate all findings belong to the target project
        finding_ids = []
        all_evidence_hashes: List[str] = []
        for f in findings:
            validate_project_isolation(project_id, f.project_id, entity_name=f"Finding '{f.id}'")
            finding_ids.append(f.id)
            meta = f.metadata_json or {}
            primary_hashes = meta.get("primary_evidence_hashes", [])
            all_evidence_hashes.extend(primary_hashes)

        # 2. Compute composite digest over evidence hashes (Merkle/Digest representation)
        evidence_digest = hash_canonical_data({"evidence_hashes": sorted(all_evidence_hashes)})

        # 3. Query the latest sequence number in the project provenance chain
        latest_record = (
            self.db.query(ProvenanceRecordModel)
            .filter(ProvenanceRecordModel.project_id == project_id)
            .order_by(ProvenanceRecordModel.sequence_number.desc())
            .first()
        )

        next_seq = (latest_record.sequence_number + 1) if (latest_record and latest_record.sequence_number is not None) else 0
        prev_hash = latest_record.record_hash if latest_record else "0" * 64
        nonce = generate_nonce()

        timestamp_iso = format_canonical_datetime(datetime.now(timezone.utc))

        # 4. Prepare metadata payload
        record_metadata = dict(metadata) if metadata else {}
        record_metadata.update({
            "audit_run_id": str(audit_run_id),
            "canonical_timestamp": timestamp_iso,
            "execution_identity_hash": str(execution_identity_hash),
            "finding_count": len(findings),
            "finding_ids": finding_ids,
            "evidence_count": len(all_evidence_hashes),
            "dataset_fingerprint": str(dataset_fingerprint),
        })

        # 5. Sign the record if KeyManager and signer_key_id or key_handle are available
        signature: Optional[str] = None
        used_signer_key: Optional[str] = None

        if key_handle:
            used_signer_key = str(key_handle.key_id)
        elif signer_key_id:
            used_signer_key = str(signer_key_id.key_id) if hasattr(signer_key_id, "key_id") else str(signer_key_id)

        # 6. Compute final record hash
        rec_hash = hash_provenance_payload(
            record_type="DATASET_SCAN_FINDINGS_COMMITTED",
            project_id=project_id,
            actor=actor,
            action="SEAL_FINDINGS",
            sequence_number=next_seq,
            nonce=nonce,
            timestamp=timestamp_iso,
            signer_key_id=used_signer_key or ("0" * 64),
            target_type="dataset_version",
            target_id=dataset_version_id,
            input_hash=dataset_fingerprint,
            output_hash=evidence_digest,
            previous_record_hash=prev_hash,
            metadata_json=record_metadata,
        )

        if key_handle:
            try:
                sig_res = sign_hash(rec_hash, key_handle=key_handle)
                signature = sig_res.signature
            except Exception as exc:
                logger.warning("Failed to sign provenance record with key handle: %s", exc)
        elif self.key_manager and signer_key_id:
            try:
                loaded_handle = self.key_manager.load_key(signer_key_id, passphrase=signer_passphrase, load_private=True)
                sig_res = sign_hash(rec_hash, key_handle=loaded_handle)
                signature = sig_res.signature
            except Exception as exc:
                logger.warning("Failed to sign provenance record with key '%s': %s", signer_key_id, exc)

        record_create = ProvenanceRecordCreate(
            project_id=project_id,
            record_type="DATASET_SCAN_FINDINGS_COMMITTED",
            actor=actor,
            action="SEAL_FINDINGS",
            target_type="dataset_version",
            target_id=dataset_version_id,
            input_hash=dataset_fingerprint,
            output_hash=evidence_digest,
            metadata_json=record_metadata,
            sequence_number=next_seq,
            previous_record_hash=prev_hash,
            record_hash=rec_hash,
            nonce=nonce,
            signer_key_id=used_signer_key,
            signature=signature,
        )

        # 7. Persist via ProvenanceService with authoritative replay protection
        persisted = self.provenance_service.record_provenance_event(record_create)

        # 8. Update all synthesized Finding rows to store the provenance_record_id
        for f in findings:
            f_meta = dict(f.metadata_json) if f.metadata_json else {}
            f_meta["provenance_record_id"] = persisted.id
            f_meta["dataset_fingerprint"] = dataset_fingerprint
            f_meta["execution_identity_hash"] = execution_identity_hash
            f.metadata_json = dict(f_meta)
            flag_modified(f, "metadata_json")

        self.db.flush()
        return persisted

    def verify_finding_provenance(
        self,
        finding_id: str,
        project_id: str,
    ) -> EvidenceProvenanceVerificationResult:
        """Verify the cryptographic provenance record bound to a finding.

        Args:
            finding_id: Finding identifier.
            project_id: Expected project identifier.

        Returns:
            EvidenceProvenanceVerificationResult summarizing verification status and integrity.
        """
        finding = self.db.query(FindingModel).filter(FindingModel.id == finding_id).first()
        if not finding:
            raise EvidenceValidationError(f"Finding with ID '{finding_id}' not found.")

        validate_project_isolation(project_id, finding.project_id, entity_name=f"Finding '{finding_id}'")

        meta = finding.metadata_json or {}
        prov_record_id = meta.get("provenance_record_id")

        if not prov_record_id:
            # 1. UNAVAILABLE: Provenance tracking has not been initialized for this finding
            return EvidenceProvenanceVerificationResult(
                finding_id=finding_id,
                provenance_record_id=None,
                provenance_status=ProvenanceStatus.UNAVAILABLE,
                cryptographic_validity=False,
                evidence_count=0,
                verified_evidence_hashes=[],
                unverified_evidence_hashes=[],
                warnings=["Provenance tracking has not been initialized for this finding."],
                errors=[],
            )

        prov_record = (
            self.db.query(ProvenanceRecordModel)
            .filter(
                ProvenanceRecordModel.id == prov_record_id,
                ProvenanceRecordModel.project_id == project_id,
            )
            .first()
        )

        if not prov_record:
            # 2. MISSING: Finding references a provenance record ID that does not exist in the ledger
            return EvidenceProvenanceVerificationResult(
                finding_id=finding_id,
                provenance_record_id=prov_record_id,
                provenance_status=ProvenanceStatus.MISSING,
                cryptographic_validity=False,
                evidence_count=0,
                verified_evidence_hashes=[],
                unverified_evidence_hashes=[],
                warnings=[],
                errors=[f"Referenced provenance record '{prov_record_id}' not found in project '{project_id}'."],
            )

        primary_hashes = meta.get("primary_evidence_hashes")
        if not primary_hashes:
            ev_items = self.db.query(EvidenceModel).filter(EvidenceModel.finding_id == finding_id).all()
            primary_hashes = [e.evidence_hash for e in ev_items if e.evidence_hash]

        # 3. Contextual Mismatch: Finding's dataset fingerprint vs record input_hash
        finding_ds_fp = meta.get("dataset_fingerprint")
        if finding_ds_fp and prov_record.input_hash and str(finding_ds_fp).lower() != str(prov_record.input_hash).lower():
            return EvidenceProvenanceVerificationResult(
                finding_id=finding_id,
                provenance_record_id=prov_record_id,
                provenance_status=ProvenanceStatus.MISMATCHED,
                cryptographic_validity=False,
                evidence_count=len(primary_hashes),
                verified_evidence_hashes=[],
                unverified_evidence_hashes=primary_hashes,
                warnings=[],
                errors=[f"Provenance input_hash '{prov_record.input_hash}' does not match finding dataset fingerprint '{finding_ds_fp}'."],
            )

        rec_timestamp = (prov_record.metadata_json or {}).get("canonical_timestamp")
        if not rec_timestamp:
            rec_timestamp = format_canonical_datetime(prov_record.created_at)

        # Execute Phase 4 cryptographic verification on the record
        record_dict = {
            "id": prov_record.id,
            "project_id": prov_record.project_id,
            "record_type": prov_record.record_type,
            "actor": prov_record.actor,
            "action": prov_record.action,
            "target_type": prov_record.target_type,
            "target_id": prov_record.target_id,
            "input_hash": prov_record.input_hash,
            "output_hash": prov_record.output_hash,
            "metadata_json": prov_record.metadata_json,
            "sequence_number": prov_record.sequence_number,
            "previous_record_hash": prov_record.previous_record_hash,
            "record_hash": prov_record.record_hash,
            "nonce": prov_record.nonce,
            "signer_key_id": prov_record.signer_key_id or ("0" * 64),
            "signature": prov_record.signature,
            "timestamp": rec_timestamp,
        }

        try:
            verif_res = verify_record(
                record_dict,
                key_manager=self.key_manager,
                allow_unsigned=True,
                expected_project_id=project_id,
                expected_sequence=prov_record.sequence_number,
                expected_previous_record_hash=prov_record.previous_record_hash,
            )
        except Exception as exc:
            # 4. UNVERIFIABLE: Structural or runtime failure preventing cryptographic evaluation
            return EvidenceProvenanceVerificationResult(
                finding_id=finding_id,
                provenance_record_id=prov_record_id,
                provenance_status=ProvenanceStatus.UNVERIFIABLE,
                cryptographic_validity=False,
                evidence_count=len(primary_hashes),
                verified_evidence_hashes=[],
                unverified_evidence_hashes=primary_hashes,
                warnings=[],
                errors=[f"Verification execution failed on record '{prov_record_id}': {exc}"],
            )

        warnings: List[str] = [w for w in verif_res.warnings]
        errors: List[str] = [f.message for f in verif_res.failures]

        # Determine precise verification status according to frozen taxonomy:
        if not verif_res.is_valid:
            has_schema_fail = any(f.code in (FailureCode.MALFORMED_INPUT, FailureCode.INVALID_SCHEMA) for f in verif_res.failures)
            has_project_mismatch = any(f.code == FailureCode.PROJECT_MISMATCH for f in verif_res.failures)

            if has_schema_fail:
                status = ProvenanceStatus.UNVERIFIABLE
                crypto_valid = False
            elif has_project_mismatch:
                status = ProvenanceStatus.MISMATCHED
                crypto_valid = False
            else:
                # Actual cryptographic integrity violation / signature failure / broken chain
                status = ProvenanceStatus.INVALID
                crypto_valid = False
        elif not prov_record.signature:
            # Unsigned record (tracking incomplete / signing key unavailable at creation)
            status = ProvenanceStatus.UNAVAILABLE
            crypto_valid = True
            warnings.append("Provenance record is cryptographically untampered but unsigned.")
        else:
            # Fully verified cryptographic provenance
            status = ProvenanceStatus.VERIFIED
            crypto_valid = True

        return EvidenceProvenanceVerificationResult(
            finding_id=finding_id,
            provenance_record_id=prov_record_id,
            provenance_status=status,
            cryptographic_validity=crypto_valid,
            evidence_count=len(primary_hashes),
            verified_evidence_hashes=primary_hashes if crypto_valid else [],
            unverified_evidence_hashes=[] if crypto_valid else primary_hashes,
            warnings=warnings,
            errors=errors,
        )
