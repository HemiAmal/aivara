"""Universal Proof & Provenance Integration Engine (Phase 12.8).

Reuses Phase 4 cryptographic verification infrastructure to authenticate evidence,
validate hash-chains and Ed25519 signatures, enforce ancestry/scope bindings,
and generate immutable UniversalProofAssessment instances.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Union

from pydantic import BaseModel

from aivara.crypto.chain import ChainRecord, ProvenanceChain
from aivara.crypto.keys import KeyManager
from aivara.crypto.verification import (
    FailureCode,
    UnifiedChainVerificationResult,
    UnifiedVerificationResult,
    verify_provenance_chain as crypto_verify_provenance_chain,
    verify_record as crypto_verify_record,
)
from aivara.domain.schemas import EvidenceLayer
from aivara.universal.enums import SubsystemDomain
from aivara.universal.graph.schemas import GraphNode
from aivara.universal.policy.enums import UniversalDecision
from aivara.universal.proof.enums import (
    ProofCheckType,
    ProofVerificationStatus,
)
from aivara.universal.proof.exceptions import (
    AncestryMismatchError,
    ProofResourceLimitExceededError,
    ProofVerificationError,
    ProvenanceIntegrityError,
    ProvenanceReplayError,
    ProvenanceTamperError,
    ScopeMismatchError,
)
from aivara.universal.proof.schemas import (
    MAX_EVIDENCE_PROOFS,
    MAX_PROVENANCE_RECORDS,
    ProofVerificationCheck,
    ProofVerificationResult,
    UniversalProofAssessment,
)
from aivara.universal.schemas import AncestryPath, UniversalEvidenceEnvelope


class UniversalProofIntegrationEngine:
    """Authoritative Phase 12.8 Proof and Provenance Integration Engine.
    
    Guarantees:
    - 100% offline, air-gapped execution reusing Phase 4 cryptographic verification.
    - Zero modification to Phase 12.6 risk computation or Phase 12.7 policy thresholds.
    - Strict non-compensability: proof failure cannot be masked by detection confidence.
    - Strict detection/proof segregation: detection confidence is preserved, proof confidence = 1.0 upon verification only.
    - O(P + E) linear verification complexity bounded by resource limits.
    """

    def __init__(
        self,
        key_manager: Optional[KeyManager] = None,
        allow_unsigned_detection: bool = True,
    ) -> None:
        self.key_manager = key_manager
        self.allow_unsigned_detection = allow_unsigned_detection

    def verify_evidence_provenance(
        self,
        envelope_or_node: Union[UniversalEvidenceEnvelope, GraphNode],
        provenance_records: Optional[List[Union[ChainRecord, Dict[str, Any]]]] = None,
        public_key: Optional[Any] = None,
    ) -> ProofVerificationResult:
        """Verify the cryptographic provenance binding of a single evidence item or graph node.
        
        Evaluates:
        1. Provenance record canonical hash integrity (RFC 8785 JCS + SHA-256).
        2. Ed25519 digital signature validity.
        3. Replay protection (nonce uniqueness and sequence numbers).
        4. Evidence-to-provenance payload binding (evidence ID and hash).
        5. Scope consistency (project_id and asset_id).
        6. Ancestry binding (5-tuple ancestry path).
        """
        if isinstance(envelope_or_node, UniversalEvidenceEnvelope):
            ev_id = envelope_or_node.evidence_id
            ev_hash = envelope_or_node.normalized_payload_hash
            ev_layer = envelope_or_node.evidence_layer
            ev_conf = envelope_or_node.confidence
            project_id = envelope_or_node.project_id
            asset_id = envelope_or_node.primary_asset_id
            finding_id = envelope_or_node.finding_id
            domain = envelope_or_node.domain
            ancestry = envelope_or_node.ancestry_path
        elif isinstance(envelope_or_node, GraphNode):
            ev_id = envelope_or_node.canonical_identity or envelope_or_node.node_id
            ev_hash = envelope_or_node.canonical_hash
            ev_layer = envelope_or_node.evidence_layer or EvidenceLayer.DETECTION
            ev_conf = envelope_or_node.confidence
            project_id = envelope_or_node.project_id
            asset_id = envelope_or_node.metadata.get("primary_asset_id", "unknown")
            finding_id = envelope_or_node.metadata.get("finding_id")
            domain = envelope_or_node.domain
            ancestry = envelope_or_node.ancestry_path
        else:
            raise ProofVerificationError(
                f"Expected UniversalEvidenceEnvelope or GraphNode, got {type(envelope_or_node).__name__}"
            )

        checks: List[ProofVerificationCheck] = []

        # Case 1: No provenance records provided
        if not provenance_records:
            if ev_layer == EvidenceLayer.PROOF:
                checks.append(
                    ProofVerificationCheck(
                        check_type=ProofCheckType.EVIDENCE_BINDING,
                        passed=False,
                        message="Proof layer evidence requires valid cryptographic provenance records, none provided",
                    )
                )
                return ProofVerificationResult(
                    evidence_id=ev_id,
                    evidence_hash=ev_hash,
                    evidence_layer=ev_layer,
                    proof_status=ProofVerificationStatus.MISSING,
                    project_id=project_id,
                    asset_id=asset_id,
                    finding_id=finding_id,
                    domain=domain,
                    ancestry_path=ancestry,
                    checks=checks,
                    failure_reason="Missing cryptographic provenance records for proof evidence",
                    proof_confidence=None,
                    detection_confidence=ev_conf,
                )
            else:
                # Detection evidence without provenance is acceptable with status MISSING
                checks.append(
                    ProofVerificationCheck(
                        check_type=ProofCheckType.EVIDENCE_BINDING,
                        passed=True,
                        message="Detection layer evidence has no attached cryptographic provenance records (MISSING)",
                    )
                )
                return ProofVerificationResult(
                    evidence_id=ev_id,
                    evidence_hash=ev_hash,
                    evidence_layer=ev_layer,
                    proof_status=ProofVerificationStatus.MISSING,
                    project_id=project_id,
                    asset_id=asset_id,
                    finding_id=finding_id,
                    domain=domain,
                    ancestry_path=ancestry,
                    checks=checks,
                    failure_reason=None,
                    proof_confidence=None,
                    detection_confidence=ev_conf,
                )

        if len(provenance_records) > MAX_PROVENANCE_RECORDS:
            raise ProofResourceLimitExceededError(
                f"Provenance record count ({len(provenance_records)}) exceeds limit of {MAX_PROVENANCE_RECORDS}"
            )

        # Case 2: Provenance records are provided -> verify each record
        final_status = ProofVerificationStatus.VERIFIED
        failure_reasons: List[str] = []
        last_provenance_id: Optional[str] = None
        last_record_hash: Optional[str] = None

        for rec in provenance_records:
            if isinstance(rec, BaseModel):
                rec_dict = rec.model_dump()
            elif hasattr(rec, "to_dict"):
                rec_dict = rec.to_dict()
            elif isinstance(rec, dict):
                rec_dict = rec
            else:
                rec_dict = dict(rec)

            last_provenance_id = rec_dict.get("record_id") or rec_dict.get("nonce") or rec_dict.get("record_hash")
            last_record_hash = rec_dict.get("record_hash")

            # Check 1: Scope consistency (project_id)
            rec_proj = rec_dict.get("project_id")
            if rec_proj != project_id:
                checks.append(
                    ProofVerificationCheck(
                        check_type=ProofCheckType.SCOPE_CONSISTENCY,
                        passed=False,
                        message=f"Project ID mismatch: evidence project '{project_id}' != provenance project '{rec_proj}'",
                    )
                )
                final_status = ProofVerificationStatus.INVALID
                failure_reasons.append("Scope mismatch: project_id does not match")
                continue
            else:
                checks.append(
                    ProofVerificationCheck(
                        check_type=ProofCheckType.SCOPE_CONSISTENCY,
                        passed=True,
                        message="Project ID scope consistent",
                    )
                )

            # Check 2: Cryptographic single record verification via Phase 4 unified engine
            is_proof_layer = (ev_layer == EvidenceLayer.PROOF)
            allow_unsigned = (not is_proof_layer) and self.allow_unsigned_detection
            ver_res: UnifiedVerificationResult = crypto_verify_record(
                record=rec,
                key_manager=self.key_manager,
                public_key=public_key,
                allow_unsigned=allow_unsigned,
                expected_project_id=project_id,
            )

            # Check Layer B: Record Hash Integrity
            if not ver_res.record_valid:
                checks.append(
                    ProofVerificationCheck(
                        check_type=ProofCheckType.RECORD_HASH,
                        passed=False,
                        message="Canonical record hash mismatch (TAMPERED)",
                    )
                )
                final_status = ProofVerificationStatus.TAMPERED
                failure_reasons.append("Canonical record hash mismatch")
            else:
                checks.append(
                    ProofVerificationCheck(
                        check_type=ProofCheckType.RECORD_HASH,
                        passed=True,
                        message="Canonical record hash intact",
                    )
                )

            # Check Layer D: Signature
            if is_proof_layer or ver_res.signature_present:
                if not ver_res.signature_valid:
                    checks.append(
                        ProofVerificationCheck(
                            check_type=ProofCheckType.SIGNATURE_VALIDITY,
                            passed=False,
                            message="Digital signature invalid or unverified",
                        )
                    )
                    if final_status != ProofVerificationStatus.TAMPERED:
                        final_status = ProofVerificationStatus.INVALID
                    failure_reasons.append("Invalid or unverified digital signature")
                else:
                    checks.append(
                        ProofVerificationCheck(
                            check_type=ProofCheckType.SIGNATURE_VALIDITY,
                            passed=True,
                            message="Digital signature cryptographically valid",
                        )
                    )

            # Check for Replay failures in ver_res
            if FailureCode.REPLAY_DETECTED in ver_res.failure_codes or FailureCode.DUPLICATE_NONCE in ver_res.failure_codes:
                checks.append(
                    ProofVerificationCheck(
                        check_type=ProofCheckType.NONCE_UNIQUENESS,
                        passed=False,
                        message="Provenance replay or nonce collision detected",
                    )
                )
                final_status = ProofVerificationStatus.REPLAY_DETECTED
                failure_reasons.append("Provenance replay detected")
            else:
                checks.append(
                    ProofVerificationCheck(
                        check_type=ProofCheckType.NONCE_UNIQUENESS,
                        passed=True,
                        message="Nonce and sequence monotonic",
                    )
                )

            # Check 3: Evidence payload binding
            payload = rec_dict.get("metadata_json") or rec_dict.get("payload") or {}
            target_id = rec_dict.get("target_id") or rec_dict.get("entity_id")
            payload_ev_id = payload.get("evidence_id") if isinstance(payload, dict) else None
            effective_rec_ev_id = payload_ev_id or target_id

            payload_ev_hash = (
                payload.get("evidence_hash")
                or payload.get("normalized_payload_hash")
                or payload.get("source_payload_hash")
            ) if isinstance(payload, dict) else None

            # Validate binding: either target_id/entity_id matches ev_id, or payload explicitly references ev_id or ev_hash
            binding_matches = True
            if effective_rec_ev_id and effective_rec_ev_id != ev_id:
                binding_matches = False

            if payload_ev_hash and payload_ev_hash != ev_hash:
                binding_matches = False

            if not binding_matches:
                checks.append(
                    ProofVerificationCheck(
                        check_type=ProofCheckType.EVIDENCE_BINDING,
                        passed=False,
                        message=f"Evidence binding mismatch: rec entity '{effective_rec_ev_id}' != ev_id '{ev_id}' or hash mismatch",
                    )
                )
                if final_status not in (ProofVerificationStatus.TAMPERED, ProofVerificationStatus.REPLAY_DETECTED):
                    final_status = ProofVerificationStatus.INVALID
                failure_reasons.append("Evidence identity/hash binding mismatch")
            else:
                checks.append(
                    ProofVerificationCheck(
                        check_type=ProofCheckType.EVIDENCE_BINDING,
                        passed=True,
                        message="Evidence binding matches provenance payload",
                    )
                )

            # Check 4: Ancestry path binding
            if ancestry and not ancestry.is_empty():
                anc_payload = payload.get("ancestry_path") or payload if isinstance(payload, dict) else {}
                anc_mismatch = False
                for field in ["sample_id", "dataset_version_id", "model_fingerprint", "window_id", "source_id"]:
                    ev_val = getattr(ancestry, field, None)
                    rec_val = anc_payload.get(field) if isinstance(anc_payload, dict) else getattr(anc_payload, field, None)
                    if not rec_val and isinstance(rec_dict, dict):
                        rec_val = rec_dict.get(field)
                    if ev_val and rec_val and ev_val != rec_val:
                        anc_mismatch = True
                        break

                if anc_mismatch:
                    checks.append(
                        ProofVerificationCheck(
                            check_type=ProofCheckType.ANCESTRY_BINDING,
                            passed=False,
                            message="Ancestry path field mismatch between evidence and provenance",
                        )
                    )
                    if final_status not in (ProofVerificationStatus.TAMPERED, ProofVerificationStatus.REPLAY_DETECTED):
                        final_status = ProofVerificationStatus.INVALID
                    failure_reasons.append("Ancestry path identity mismatch")
                else:
                    checks.append(
                        ProofVerificationCheck(
                            check_type=ProofCheckType.ANCESTRY_BINDING,
                            passed=True,
                            message="Ancestry path matches provenance record",
                        )
                    )

        reason_str = "; ".join(failure_reasons) if failure_reasons else None
        proof_conf = 1.0 if final_status == ProofVerificationStatus.VERIFIED else None

        return ProofVerificationResult(
            evidence_id=ev_id,
            evidence_hash=ev_hash,
            evidence_layer=ev_layer,
            proof_status=final_status,
            provenance_id=last_provenance_id,
            provenance_record_hash=last_record_hash,
            finding_id=finding_id,
            domain=domain,
            project_id=project_id,
            asset_id=asset_id,
            ancestry_path=ancestry,
            checks=checks,
            failure_reason=reason_str,
            proof_confidence=proof_conf,
            detection_confidence=ev_conf,
        )

    def verify_provenance_chain(
        self,
        chain_or_records: Union[ProvenanceChain, Sequence[Union[ChainRecord, Dict[str, Any]]]],
        expected_project_id: Optional[str] = None,
    ) -> UnifiedChainVerificationResult:
        """Verify a complete ProvenanceChain instance using the Phase 4 verification engine."""
        records = chain_or_records.records if isinstance(chain_or_records, ProvenanceChain) else chain_or_records
        return crypto_verify_provenance_chain(
            records=records,
            key_manager=self.key_manager,
            expected_project_id=expected_project_id,
        )

    def integrate_proof_assessment(
        self,
        project_id: str,
        asset_id: str,
        evidence_items: Sequence[Union[UniversalEvidenceEnvelope, GraphNode]],
        provenance_records_map: Optional[Dict[str, List[Union[ChainRecord, Dict[str, Any]]]]] = None,
        public_key: Optional[Any] = None,
    ) -> UniversalProofAssessment:
        """Aggregate cryptographic proof verification across all evidence items for a given asset.
        
        Determines overall proof status and triggers proof override (UniversalDecision.REJECT)
        if any fatal proof violation (INVALID, TAMPERED, REPLAY_DETECTED) occurs on proof-layer evidence.
        """
        if len(evidence_items) > MAX_EVIDENCE_PROOFS:
            raise ProofResourceLimitExceededError(
                f"Evidence count ({len(evidence_items)}) exceeds maximum limit of {MAX_EVIDENCE_PROOFS}"
            )

        records_map = provenance_records_map or {}
        results: List[ProofVerificationResult] = []

        verified_cnt = 0
        invalid_cnt = 0
        missing_cnt = 0
        unavailable_cnt = 0
        tampered_cnt = 0
        replay_cnt = 0
        has_fatal_proof_failure = False

        for ev in evidence_items:
            ev_id = ev.evidence_id if isinstance(ev, UniversalEvidenceEnvelope) else (ev.canonical_identity or ev.node_id)
            ev_records = records_map.get(ev_id)

            res = self.verify_evidence_provenance(
                envelope_or_node=ev,
                provenance_records=ev_records,
                public_key=public_key,
            )
            results.append(res)

            st = res.proof_status
            if st == ProofVerificationStatus.VERIFIED:
                verified_cnt += 1
            elif st == ProofVerificationStatus.INVALID:
                invalid_cnt += 1
                if res.evidence_layer == EvidenceLayer.PROOF:
                    has_fatal_proof_failure = True
            elif st == ProofVerificationStatus.MISSING:
                missing_cnt += 1
                if res.evidence_layer == EvidenceLayer.PROOF:
                    has_fatal_proof_failure = True
            elif st == ProofVerificationStatus.UNAVAILABLE:
                unavailable_cnt += 1
            elif st == ProofVerificationStatus.TAMPERED:
                tampered_cnt += 1
                if res.evidence_layer == EvidenceLayer.PROOF:
                    has_fatal_proof_failure = True
            elif st == ProofVerificationStatus.REPLAY_DETECTED:
                replay_cnt += 1
                if res.evidence_layer == EvidenceLayer.PROOF:
                    has_fatal_proof_failure = True

        # Synthesize overall status
        if tampered_cnt > 0:
            overall_status = ProofVerificationStatus.TAMPERED
        elif replay_cnt > 0:
            overall_status = ProofVerificationStatus.REPLAY_DETECTED
        elif invalid_cnt > 0:
            overall_status = ProofVerificationStatus.INVALID
        elif missing_cnt > 0:
            overall_status = ProofVerificationStatus.MISSING
        elif unavailable_cnt > 0:
            overall_status = ProofVerificationStatus.UNAVAILABLE
        else:
            overall_status = ProofVerificationStatus.VERIFIED

        override_required = has_fatal_proof_failure
        override_decision = UniversalDecision.REJECT if override_required else None

        return UniversalProofAssessment(
            project_id=project_id,
            asset_id=asset_id,
            overall_proof_status=overall_status,
            total_evidence_evaluated=len(evidence_items),
            verified_count=verified_cnt,
            invalid_count=invalid_cnt,
            missing_count=missing_cnt,
            unavailable_count=unavailable_cnt,
            tampered_count=tampered_cnt,
            replay_count=replay_cnt,
            proof_override_required=override_required,
            override_decision=override_decision,
            evidence_results=results,
        )
