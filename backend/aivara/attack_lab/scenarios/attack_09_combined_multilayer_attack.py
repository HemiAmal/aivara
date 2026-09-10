"""ATTACK-09 — Combined Multi-Layer Attack Demonstration.

Demonstrates:
  1. Construction of an end-to-end valid baseline:
     - Valid canonical provenance record
     - Valid cryptographic digital signature
     - Valid hash-linked provenance chain
     - Valid hash-linked audit chain
  2. Injection of simultaneous, multi-layer attacks across independent layers:
     - Layer B: Payload modification (tampered input_hash)
     - Layer C: Chain continuity manipulation (tampered previous_record_hash)
     - Layer D: Signature byte corruption (tampered signature)
     - Audit Layer: Audit event payload modification
  3. Execution of full verification pipelines.
  4. Mathematical proof of NON-MASKING:
     Multiple independent failures are strictly preserved and reported together,
     preventing early error suppression or masking of critical security findings.
  5. Complete baseline restoration and re-verification.
"""

from __future__ import annotations

import copy
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
from aivara.crypto.signing import decode_signature, encode_signature, sign_hash
from aivara.crypto.verification import (
    FailureCode,
    verify_provenance_chain,
    verify_record,
)


def get_scenario() -> AttackScenario:
    """Return static metadata for ATTACK-09."""
    return AttackScenario(
        attack_id="ATTACK-09",
        attack_name="Combined Multi-Layer Attack",
        category=AttackCategory.MULTI_LAYER,
        description=(
            "Controlled demonstration proving that when multiple cryptographic layers "
            "are attacked simultaneously across record payload, chain linkage, digital signature, "
            "and audit logs, AIVARA preserves all individual failure codes without masking or "
            "short-circuiting diagnostic visibility."
        ),
        target="Full Cryptographic Defense-in-Depth Stack",
        prerequisites=["KeyManager instance", "Valid provenance and audit chains"],
        setup={"action": "Construct valid multi-record provenance and audit chains"},
        attack={"action": "Inject simultaneous mutations across all 4 cryptographic protection layers"},
        verification={"engine": "verify_provenance_chain + verify_audit_chain"},
        expected_result={
            "non_masking_verified": True,
            "detected_failures": [
                "RECORD_HASH_MISMATCH",
                "BROKEN_CHAIN",
                "INVALID_SIGNATURE",
                "EVENT_HASH_MISMATCH",
            ],
        },
        cleanup="Restore genuine baseline and confirm all layers return to valid state",
    )


def run_attack_09() -> AttackResult:
    """Execute the ATTACK-09 demonstration."""
    project_id = f"proj-multi-{uuid.uuid4().hex[:6]}"

    with tempfile.TemporaryDirectory() as tmp_dir:
        km = KeyManager(keys_dir=Path(tmp_dir))
        handle = km.generate_key(passphrase="Demo_Multi_Passphrase_2026!")

        # 1. Construct valid provenance chain (Genesis -> R1 -> R2)
        gen = create_genesis_record(project_id)

        nonce1 = generate_nonce()
        ts1 = "2026-03-01T12:00:00Z"
        r1_hash = hash_provenance_payload(
            record_type="INFERENCE",
            project_id=project_id,
            actor="multi-tester",
            action="STEP_1",
            sequence_number=1,
            nonce=nonce1,
            timestamp=ts1,
            signer_key_id=handle.key_id,
            target_type="MODEL",
            target_id="mod-01",
            input_hash=sha256_text("input 1"),
            output_hash=sha256_text("output 1"),
            model_id="mod-01",
            previous_record_hash=gen.record_hash,
            schema_version=CANONICAL_SCHEMA_VERSION,
        )
        r1_sig_res = sign_hash(r1_hash, handle)
        r1 = ChainRecord(
            schema_version=CANONICAL_SCHEMA_VERSION,
            record_type="INFERENCE",
            project_id=project_id,
            sequence_number=1,
            previous_record_hash=gen.record_hash,
            nonce=nonce1,
            actor="multi-tester",
            action="STEP_1",
            target_type="MODEL",
            target_id="mod-01",
            timestamp=ts1,
            input_hash=sha256_text("input 1"),
            output_hash=sha256_text("output 1"),
            model_id="mod-01",
            record_hash=r1_hash,
            signature=r1_sig_res.signature,
            signer_key_id=handle.key_id,
        )

        nonce2 = generate_nonce()
        ts2 = "2026-03-01T12:01:00Z"
        r2_hash = hash_provenance_payload(
            record_type="INFERENCE",
            project_id=project_id,
            actor="multi-tester",
            action="STEP_2",
            sequence_number=2,
            nonce=nonce2,
            timestamp=ts2,
            signer_key_id=handle.key_id,
            target_type="MODEL",
            target_id="mod-01",
            input_hash=sha256_text("input 2"),
            output_hash=sha256_text("output 2"),
            model_id="mod-01",
            previous_record_hash=r1_hash,
            schema_version=CANONICAL_SCHEMA_VERSION,
        )
        r2_sig_res = sign_hash(r2_hash, handle)
        r2 = ChainRecord(
            schema_version=CANONICAL_SCHEMA_VERSION,
            record_type="INFERENCE",
            project_id=project_id,
            sequence_number=2,
            previous_record_hash=r1_hash,
            nonce=nonce2,
            actor="multi-tester",
            action="STEP_2",
            target_type="MODEL",
            target_id="mod-01",
            timestamp=ts2,
            input_hash=sha256_text("input 2"),
            output_hash=sha256_text("output 2"),
            model_id="mod-01",
            record_hash=r2_hash,
            signature=r2_sig_res.signature,
            signer_key_id=handle.key_id,
        )

        baseline_chain = [gen, r1, r2]

        # Baseline provenance verification -> Valid
        v_prov_base = verify_provenance_chain(baseline_chain, expected_project_id=project_id, key_manager=km)
        assert v_prov_base.chain_valid, "Baseline provenance chain must be valid"

        # 2. Construct valid audit chain (AuditGenesis -> A1)
        gen_audit = create_audit_genesis_payload(project_id)
        gen_audit_hash = gen_audit["event_hash"]

        a1_hash = hash_audit_payload(
            project_id=project_id,
            sequence_number=1,
            previous_event_hash=gen_audit_hash,
            event_type=AuditEventType.PROVENANCE_RECORDED.value,
            actor="multi-tester",
            action="RECORD_EVIDENCE",
            target_type="RECORD",
            target_id=r1_hash,
            outcome=AuditOutcome.SUCCESS.value,
            description="Baseline audit event",
            timestamp="2026-03-01T12:00:00Z",
            metadata={"seq": 1},
        )
        a1_payload = {
            "project_id": project_id,
            "sequence_number": 1,
            "previous_event_hash": gen_audit_hash,
            "event_type": AuditEventType.PROVENANCE_RECORDED.value,
            "actor": "multi-tester",
            "action": "RECORD_EVIDENCE",
            "target_type": "RECORD",
            "target_id": r1_hash,
            "outcome": AuditOutcome.SUCCESS.value,
            "description": "Baseline audit event",
            "created_at": "2026-03-01T12:00:00Z",
            "metadata_json": {"seq": 1},
            "event_hash": a1_hash,
        }

        baseline_audit = [gen_audit, a1_payload]
        v_audit_base = verify_audit_chain(baseline_audit, expected_project_id=project_id)
        assert v_audit_base.status == AuditVerificationStatus.VALID, "Baseline audit chain must be valid"

        # 3. Apply SIMULTANEOUS MULTI-LAYER ATTACKS on R2
        # Layer B attack: mutate input_hash
        # Layer C attack: corrupt previous_record_hash
        # Layer D attack: corrupt signature bytes
        sig_raw = decode_signature(r2.signature)
        tampered_sig = encode_signature(bytes([sig_raw[0] ^ 0xFF]) + sig_raw[1:])

        r2_multi_tampered = ChainRecord(
            **{
                **r2.model_dump(),
                "input_hash": sha256_text("MULTI_ATTACK_TAMPERED_INPUT"),
                "previous_record_hash": sha256_text("MULTI_ATTACK_BROKEN_LINK"),
                "signature": tampered_sig,
            }
        )

        tampered_prov_chain = [gen, r1, r2_multi_tampered]

        # Audit attack: mutate description in a1_payload
        tampered_audit_chain = copy.deepcopy(baseline_audit)
        tampered_audit_chain[1]["description"] = "TAMPERED_AUDIT_DESCRIPTION"

        # 4. Verify simultaneous detection without masking
        v_multi_prov = verify_provenance_chain(tampered_prov_chain, expected_project_id=project_id, key_manager=km)
        prov_failures = [f.code.value for f in v_multi_prov.failures]

        v_multi_audit = verify_audit_chain(tampered_audit_chain, expected_project_id=project_id)
        audit_failures = [f.code.value for f in v_multi_audit.failures]

        # Check that individual layers were NOT masked
        det_b = FailureCode.RECORD_HASH_MISMATCH.value in prov_failures
        det_c = FailureCode.BROKEN_CHAIN.value in prov_failures
        det_d = FailureCode.INVALID_SIGNATURE.value in prov_failures
        det_audit = AuditFailureCode.EVENT_HASH_MISMATCH.value in audit_failures

        non_masking_verified = det_b and det_c and det_d and det_audit

        sub_results = [
            AttackSubResult(
                sub_id="MULTI-LAYER-B",
                name="Layer B: Record Hash Integrity Anomaly",
                target_asset="ChainRecord.input_hash",
                attack_technique="Payload corruption under preserved stored hash",
                original_state={"input_hash": r2.input_hash},
                modified_state={"input_hash": r2_multi_tampered.input_hash},
                verification_status="MISMATCH_RECORDED",
                failure_codes=[FailureCode.RECORD_HASH_MISMATCH.value],
                evidence={"detected": det_b},
                detected=det_b,
                cleanup_status="RESTORED",
            ),
            AttackSubResult(
                sub_id="MULTI-LAYER-C",
                name="Layer C: Chain Linkage Continuity Anomaly",
                target_asset="ChainRecord.previous_record_hash",
                attack_technique="Link pointer corruption severing parent hash chain",
                original_state={"previous_record_hash": r2.previous_record_hash},
                modified_state={"previous_record_hash": r2_multi_tampered.previous_record_hash},
                verification_status="BROKEN_CHAIN_RECORDED",
                failure_codes=[FailureCode.BROKEN_CHAIN.value],
                evidence={"detected": det_c},
                detected=det_c,
                cleanup_status="RESTORED",
            ),
            AttackSubResult(
                sub_id="MULTI-LAYER-D",
                name="Layer D: Digital Signature Cryptographic Failure",
                target_asset="ChainRecord.signature",
                attack_technique="Signature byte corruption combined with payload corruption",
                original_state={"signature_valid": True},
                modified_state={"signature_valid": False},
                verification_status="INVALID_SIGNATURE_RECORDED",
                failure_codes=[FailureCode.INVALID_SIGNATURE.value],
                evidence={"detected": det_d},
                detected=det_d,
                cleanup_status="RESTORED",
            ),
            AttackSubResult(
                sub_id="MULTI-AUDIT",
                name="Audit Layer: Event Hash Integrity Anomaly",
                target_asset="audit_events.description",
                attack_technique="Simultaneous out-of-band audit log alteration",
                original_state={"audit_status": "VALID"},
                modified_state={"audit_status": v_multi_audit.status.value},
                verification_status=v_multi_audit.status.value,
                failure_codes=audit_failures,
                evidence={"detected": det_audit},
                detected=det_audit,
                cleanup_status="RESTORED",
            ),
        ]

        # 5. Verify clean restoration of baseline
        restore_prov_v = verify_provenance_chain(baseline_chain, expected_project_id=project_id, key_manager=km)
        restore_audit_v = verify_audit_chain(baseline_audit, expected_project_id=project_id)
        cleanly_restored = restore_prov_v.chain_valid and (restore_audit_v.status == AuditVerificationStatus.VALID)

        all_detected = non_masking_verified and cleanly_restored

        return AttackResult(
            attack_id="ATTACK-09",
            attack_name="Combined Multi-Layer Attack",
            target_asset="Comprehensive Provenance & Audit Verification Pipeline",
            attack_technique="Simultaneous multi-vector tampering across Layers B, C, D, and Audit",
            original_state={"all_layers_valid": True},
            modified_state={"simultaneous_attacks_active": len(sub_results)},
            verification_status="MULTI_LAYER_VIOLATIONS_DETECTED",
            failure_codes=prov_failures + audit_failures,
            evidence={
                "layer_b_detected": det_b,
                "layer_c_detected": det_c,
                "layer_d_detected": det_d,
                "audit_layer_detected": det_audit,
                "total_independent_failures": len(prov_failures) + len(audit_failures),
                "cleanly_restored": cleanly_restored,
            },
            detected=all_detected,
            cleanup_status="RESTORED" if cleanly_restored else "CORRUPTED",
            sub_results=sub_results,
            details={
                "summary": (
                    "Verified non-masking property: Layer B (RECORD_HASH_MISMATCH), "
                    "Layer C (BROKEN_CHAIN), Layer D (INVALID_SIGNATURE), and Audit "
                    "(EVENT_HASH_MISMATCH) were all independently detected simultaneously."
                )
            },
        )
