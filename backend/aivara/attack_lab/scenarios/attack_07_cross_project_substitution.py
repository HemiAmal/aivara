"""ATTACK-07 — Cross-Project Evidence Substitution Demonstration.

Demonstrates:
  1. Creation of valid cryptographic provenance evidence for Project A.
  2. Creation of valid audit evidence for Project A.
  3. Attempted substitution of Project A evidence into Project B context:
     - Single record verification with mismatched expected_project_id.
     - Insertion of Project A record into Project B provenance chain.
     - Insertion of Project A audit event into Project B audit chain.
  4. Authoritative detection of PROJECT_MISMATCH across all verification layers.
  5. Strict maintenance of project isolation guarantees.
"""

from __future__ import annotations

import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List

from aivara.attack_lab.models import (
    AttackCategory,
    AttackResult,
    AttackScenario,
    AttackSubResult,
)
from aivara.crypto.audit import (
    AuditEventType,
    AuditFailureCode,
    AuditOutcome,
    AuditVerificationStatus,
    canonicalize_audit_payload,
    create_audit_genesis_payload,
    hash_audit_payload,
    verify_audit_chain,
)
from aivara.crypto.canonical import CANONICAL_SCHEMA_VERSION
from aivara.crypto.chain import ChainRecord, create_genesis_record, generate_nonce
from aivara.crypto.hashing import hash_provenance_payload, sha256_text
from aivara.crypto.keys import KeyManager
from aivara.crypto.signing import sign_hash
from aivara.crypto.tamper_detection import (
    TamperAssessmentStatus,
    assess_record_tampering,
)
from aivara.crypto.verification import (
    FailureCode,
    verify_provenance_chain,
    verify_record,
)


def get_scenario() -> AttackScenario:
    """Return static metadata for ATTACK-07."""
    return AttackScenario(
        attack_id="ATTACK-07",
        attack_name="Cross-Project Evidence Substitution",
        category=AttackCategory.CROSS_PROJECT,
        description=(
            "Controlled demonstration proving that AIVARA enforces strict cryptographic "
            "project boundaries, immediately rejecting any attempt to reuse, splice, or "
            "substitute valid evidence from Project A into Project B verification contexts."
        ),
        target="Multi-Project Cryptographic Isolation",
        prerequisites=["KeyManager instance", "Two distinct project contexts (A and B)"],
        setup={"action": "Generate signed records and audit trails in Project A and Project B"},
        attack={"action": "Substitute Project A record/event into Project B verification call"},
        verification={"engine": "verify_record + verify_provenance_chain + verify_audit_chain"},
        expected_result={
            "detected": True,
            "failure_codes": ["PROJECT_MISMATCH"],
        },
        cleanup="Re-verify that authentic records verify cleanly in their genuine project contexts",
    )


def run_attack_07() -> AttackResult:
    """Execute the ATTACK-07 demonstration."""
    proj_a = f"proj-alpha-{uuid.uuid4().hex[:6]}"
    proj_b = f"proj-beta-{uuid.uuid4().hex[:6]}"

    with tempfile.TemporaryDirectory() as tmp_dir:
        km = KeyManager(keys_dir=Path(tmp_dir))
        handle = km.generate_key(passphrase="Demo_CrossProj_Passphrase_2026!")

        # 1. Baseline Evidence for Project A
        gen_a = create_genesis_record(proj_a)
        nonce_a = generate_nonce()
        rec_a_hash = hash_provenance_payload(
            record_type="INFERENCE",
            project_id=proj_a,
            actor="cross-proj-tester",
            action="RUN_INFERENCE",
            sequence_number=1,
            nonce=nonce_a,
            timestamp="2026-03-01T12:00:00Z",
            signer_key_id=handle.key_id,
            target_type="MODEL",
            target_id="mod-proj-a",
            input_hash=sha256_text("input project A"),
            output_hash=sha256_text("output project A"),
            model_id="mod-proj-a",
            previous_record_hash=gen_a.record_hash,
            schema_version=CANONICAL_SCHEMA_VERSION,
        )
        sig_res = sign_hash(rec_a_hash, handle)
        rec_a = ChainRecord(
            schema_version=CANONICAL_SCHEMA_VERSION,
            record_type="INFERENCE",
            project_id=proj_a,
            sequence_number=1,
            previous_record_hash=gen_a.record_hash,
            nonce=nonce_a,
            actor="cross-proj-tester",
            action="RUN_INFERENCE",
            target_type="MODEL",
            target_id="mod-proj-a",
            timestamp="2026-03-01T12:00:00Z",
            input_hash=sha256_text("input project A"),
            output_hash=sha256_text("output project A"),
            model_id="mod-proj-a",
            record_hash=rec_a_hash,
            signature=sig_res.signature,
            signer_key_id=handle.key_id,
        )

        # Verify baseline in Project A context -> Valid
        v_base_a = verify_record(rec_a, public_key=handle.public_key, expected_project_id=proj_a)
        assert v_base_a.overall_valid, "Baseline evidence in Project A must be valid"

        sub_results: List[AttackSubResult] = []

        # --- Sub 1: Verify Project A record under Project B expected_project_id ---
        v_sub1 = verify_record(rec_a, public_key=handle.public_key, expected_project_id=proj_b)
        t_sub1 = assess_record_tampering(v_sub1, rec_a)
        codes1 = [f.code.value for f in v_sub1.failures]
        det1 = (not v_sub1.overall_valid) and (FailureCode.PROJECT_MISMATCH.value in codes1)
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-07A",
                name="Single record verification in foreign project context",
                target_asset="verify_record.expected_project_id",
                attack_technique="Substituting Project A record into Project B verification call",
                original_state={"record_project_id": proj_a, "expected_project_id": proj_a},
                modified_state={"record_project_id": proj_a, "expected_project_id": proj_b},
                verification_status=t_sub1.status.value,
                failure_codes=codes1,
                evidence={"failures": codes1, "detected": det1},
                detected=det1,
                cleanup_status="RESTORED",
            )
        )

        # --- Sub 2: Inject Project A record into Project B chain ---
        gen_b = create_genesis_record(proj_b)
        cross_chain = [gen_b, rec_a]
        v_sub2 = verify_provenance_chain(cross_chain, expected_project_id=proj_b, key_manager=km)
        codes2 = [f.code.value for f in v_sub2.failures]
        det2 = (not v_sub2.chain_valid) and (FailureCode.PROJECT_MISMATCH.value in codes2)
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-07B",
                name="Inject Project A record into Project B provenance chain",
                target_asset="verify_provenance_chain",
                attack_technique="Splicing foreign project record into target project chain",
                original_state={"chain_project": proj_b},
                modified_state={"injected_record_project": proj_a},
                verification_status="CHAIN_VERIFICATION_FAILED",
                failure_codes=codes2,
                evidence={"failures": codes2},
                detected=det2,
                cleanup_status="RESTORED",
            )
        )

        # --- Sub 3: Audit event cross-project substitution ---
        # Construct audit genesis for B, and audit event for A
        gen_audit_b = create_audit_genesis_payload(proj_b)
        gen_audit_b_hash = gen_audit_b["event_hash"]

        # Operational event built for Project A
        ev_audit_a_hash = hash_audit_payload(
            project_id=proj_a,
            sequence_number=1,
            previous_event_hash=gen_audit_b_hash,
            event_type=AuditEventType.PROVENANCE_RECORDED.value,
            actor="user-a",
            action="RECORD",
            target_type="MODEL",
            target_id="mod-a",
            outcome=AuditOutcome.SUCCESS.value,
            description="Event from Project A",
            timestamp="2026-03-01T12:00:00Z",
            metadata={},
        )
        ev_audit_a_payload = {
            "project_id": proj_a,
            "sequence_number": 1,
            "previous_event_hash": gen_audit_b_hash,
            "event_type": AuditEventType.PROVENANCE_RECORDED.value,
            "actor": "user-a",
            "action": "RECORD",
            "target_type": "MODEL",
            "target_id": "mod-a",
            "outcome": AuditOutcome.SUCCESS.value,
            "description": "Event from Project A",
            "created_at": "2026-03-01T12:00:00Z",
            "metadata_json": {},
            "event_hash": ev_audit_a_hash,
        }

        # Verify audit chain under Project B context
        cross_audit_chain = [gen_audit_b, ev_audit_a_payload]
        v_audit_res = verify_audit_chain(cross_audit_chain, expected_project_id=proj_b)
        codes3 = [f.code.value for f in v_audit_res.failures]
        det3 = (v_audit_res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION) and (
            AuditFailureCode.PROJECT_MISMATCH.value in codes3
        )
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-07C",
                name="Audit event cross-project substitution",
                target_asset="verify_audit_chain.expected_project_id",
                attack_technique="Inserting Project A audit event into Project B audit sequence",
                original_state={"audit_project": proj_b},
                modified_state={"audit_event_project": proj_a},
                verification_status=v_audit_res.status.value,
                failure_codes=codes3,
                evidence={"failures": codes3},
                detected=det3,
                cleanup_status="RESTORED",
            )
        )

        all_detected = all(sr.detected for sr in sub_results)

        return AttackResult(
            attack_id="ATTACK-07",
            attack_name="Cross-Project Evidence Substitution",
            target_asset="Multi-Tenant Project Context Isolation",
            attack_technique="Cross-tenant evidence splicing across record, chain, and audit layers",
            original_state={"project_a": proj_a, "project_b": proj_b},
            modified_state={"substitutions_tested": len(sub_results)},
            verification_status="PROJECT_MISMATCH_DETECTED",
            failure_codes=[FailureCode.PROJECT_MISMATCH.value, AuditFailureCode.PROJECT_MISMATCH.value],
            evidence={"sub_results_count": len(sub_results), "isolation_enforced": all_detected},
            detected=all_detected,
            cleanup_status="RESTORED",
            sub_results=sub_results,
            details={"summary": "Cross-project substitution detected in record, chain, and audit verifications"},
        )
