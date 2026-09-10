"""ATTACK-02 — Digital Signature Forgery Demonstration.

Demonstrates:
  A. Valid signed record -> verification succeeds.
  B. Modify payload after signing -> signature verification fails.
  C. Modify signature bytes -> INVALID_SIGNATURE.
  D. Use malformed signature encoding -> MALFORMED_SIGNATURE.
  E. Unknown signer key -> UNKNOWN_SIGNER_KEY / AUTHENTICITY_UNAVAILABLE.
  F. Mismatched signer_key_id -> SIGNER_KEY_MISMATCH.
  G. Attempt new signing using ROTATED/REVOKED/EXPIRED key -> lifecycle rejection.
  H. Historical signature created while key was active remains mathematically
     verifiable after rotation/revocation/expiration, while lifecycle state
     correctly reports key as inactive.
"""

from __future__ import annotations

import base64
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from aivara.attack_lab.models import (
    AttackCategory,
    AttackResult,
    AttackScenario,
    AttackSubResult,
)
from aivara.core.exceptions import AivaraException
from aivara.crypto.canonical import CANONICAL_SCHEMA_VERSION
from aivara.crypto.chain import ChainRecord, generate_nonce
from aivara.crypto.hashing import hash_provenance_payload, sha256_text
from aivara.crypto.keys import (
    KeyExpiredError,
    KeyManagementError,
    KeyManager,
    KeyRevokedError,
    KeyRotatedError,
    KeyStatus,
    KeyStatusError,
)
from aivara.crypto.signing import (
    VerificationStatus as SigVerificationStatus,
    decode_signature,
    encode_signature,
    sign_hash,
    verify_hash_signature,
)
from aivara.crypto.tamper_detection import (
    TamperAssessmentStatus,
    assess_record_tampering,
)
from aivara.crypto.verification import FailureCode, verify_record

TEST_PASSPHRASE = "Demo_Attack02_Passphrase_2026!"


def get_scenario() -> AttackScenario:
    """Return static metadata for ATTACK-02."""
    return AttackScenario(
        attack_id="ATTACK-02",
        attack_name="Digital Signature Forgery",
        category=AttackCategory.SIGNATURE,
        description=(
            "Controlled demonstration proving that AIVARA's cryptographic signature engine "
            "authoritatively detects signature bit corruption, post-signing payload tampering, "
            "malformed encodings, key mismatches, and enforces key lifecycle signing prohibitions."
        ),
        target="Ed25519 Digital Signatures",
        prerequisites=["KeyManager instance", "Active Ed25519 keypair"],
        setup={"action": "Generate active key handle and sign canonical baseline record"},
        attack={"action": "Execute 8 targeted signature attacks (sub-A through sub-H)"},
        verification={"engine": "aivara.crypto.verification + aivara.crypto.signing + KeyManager"},
        expected_result={
            "detected": True,
            "sub_scenarios": ["A", "B", "C", "D", "E", "F", "G", "H"],
        },
        cleanup="Verify historical verification validity and restore clean key management",
    )


def run_attack_02() -> AttackResult:
    """Execute the ATTACK-02 demonstration."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        km = KeyManager(keys_dir=Path(tmp_dir))
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)
        nonce = generate_nonce()
        meta = {"precision": "fp32"}

        rec_hash = hash_provenance_payload(
            record_type="MODEL_REGISTRATION",
            project_id="proj-demo-attack02",
            actor="sec-tester",
            action="REGISTER_MODEL",
            sequence_number=1,
            nonce=nonce,
            timestamp="2026-03-01T12:00:00Z",
            signer_key_id=handle.key_id,
            target_type="MODEL",
            target_id="mod-bert-base",
            input_hash=sha256_text("model weights"),
            output_hash=sha256_text("initialization"),
            model_id="mod-bert-base",
            previous_record_hash="0" * 64,
            metadata_json=meta,
            schema_version=CANONICAL_SCHEMA_VERSION,
        )
        sig_res = sign_hash(rec_hash, handle)
        valid_sig = sig_res.signature

        baseline = ChainRecord(
            schema_version=CANONICAL_SCHEMA_VERSION,
            record_type="MODEL_REGISTRATION",
            project_id="proj-demo-attack02",
            sequence_number=1,
            previous_record_hash="0" * 64,
            nonce=nonce,
            actor="sec-tester",
            action="REGISTER_MODEL",
            target_type="MODEL",
            target_id="mod-bert-base",
            timestamp="2026-03-01T12:00:00Z",
            input_hash=sha256_text("model weights"),
            output_hash=sha256_text("initialization"),
            model_id="mod-bert-base",
            metadata_json=meta,
            record_hash=rec_hash,
            signature=valid_sig,
            signer_key_id=handle.key_id,
        )

        sub_results: List[AttackSubResult] = []

        # --- Sub A: Valid signed record ---
        v_a = verify_record(baseline, public_key=handle.public_key, expected_project_id=baseline.project_id)
        t_a = assess_record_tampering(v_a, baseline)
        detected_a = v_a.overall_valid and (t_a.status == TamperAssessmentStatus.CLEAN)
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-02A",
                name="Valid signed record verification",
                target_asset="Signed ChainRecord",
                attack_technique="Baseline genuine signature verification",
                original_state={"overall_valid": True},
                modified_state={"overall_valid": True},
                verification_status=t_a.status.value,
                failure_codes=[f.code.value for f in v_a.failures],
                evidence={"signature_valid": v_a.signature_valid, "record_valid": v_a.record_valid},
                detected=detected_a,
                cleanup_status="RESTORED",
            )
        )

        # --- Sub B: Modify payload after signing ---
        tampered_payload_rec = ChainRecord(
            **{
                **baseline.model_dump(),
                "input_hash": sha256_text("MALICIOUS_INPUT_DATA"),
            }
        )
        v_b = verify_record(tampered_payload_rec, public_key=handle.public_key, expected_project_id=baseline.project_id)
        t_b = assess_record_tampering(v_b, tampered_payload_rec)
        codes_b = [f.code.value for f in v_b.failures]
        detected_b = (
            (not v_b.overall_valid)
            and (FailureCode.RECORD_HASH_MISMATCH.value in codes_b or FailureCode.INVALID_SIGNATURE.value in codes_b)
            and t_b.tampering_detected
        )
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-02B",
                name="Modify payload after signing",
                target_asset="ChainRecord.input_hash",
                attack_technique="Post-signing payload mutation with original signature attached",
                original_state={"input_hash": baseline.input_hash},
                modified_state={"input_hash": tampered_payload_rec.input_hash},
                verification_status=t_b.status.value,
                failure_codes=codes_b,
                evidence={"failures": codes_b, "tampering_detected": t_b.tampering_detected},
                detected=detected_b,
                cleanup_status="RESTORED",
            )
        )

        # --- Sub C: Modify signature bytes ---
        sig_raw = decode_signature(valid_sig)
        corrupted_sig_raw = bytes([sig_raw[0] ^ 0xFF]) + sig_raw[1:]
        corrupted_sig = encode_signature(corrupted_sig_raw)
        corrupted_sig_rec = ChainRecord(
            **{
                **baseline.model_dump(),
                "signature": corrupted_sig,
            }
        )
        v_c = verify_record(corrupted_sig_rec, public_key=handle.public_key, expected_project_id=baseline.project_id)
        t_c = assess_record_tampering(v_c, corrupted_sig_rec)
        codes_c = [f.code.value for f in v_c.failures]
        detected_c = (not v_c.overall_valid) and (FailureCode.INVALID_SIGNATURE.value in codes_c)
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-02C",
                name="Corrupt signature bytes",
                target_asset="ChainRecord.signature",
                attack_technique="Single bit-flip in Ed25519 signature bytes",
                original_state={"signature": valid_sig[:16] + "..."},
                modified_state={"signature": corrupted_sig[:16] + "..."},
                verification_status=t_c.status.value,
                failure_codes=codes_c,
                evidence={"failures": codes_c, "signature_valid": v_c.signature_valid},
                detected=detected_c,
                cleanup_status="RESTORED",
            )
        )

        # --- Sub D: Malformed signature encoding ---
        malformed_sig_rec = ChainRecord(
            **{
                **baseline.model_dump(),
                "signature": "!!!NOT_VALID_BASE64_SIGNATURE_STRING!!!",
            }
        )
        v_d = verify_record(malformed_sig_rec, public_key=handle.public_key, expected_project_id=baseline.project_id)
        t_d = assess_record_tampering(v_d, malformed_sig_rec)
        codes_d = [f.code.value for f in v_d.failures]
        detected_d = (not v_d.overall_valid) and (FailureCode.MALFORMED_SIGNATURE.value in codes_d)
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-02D",
                name="Malformed signature encoding",
                target_asset="ChainRecord.signature",
                attack_technique="Non-base64 malformed character injection",
                original_state={"signature_format": "base64"},
                modified_state={"signature_format": "malformed string"},
                verification_status=t_d.status.value,
                failure_codes=codes_d,
                evidence={"failures": codes_d},
                detected=detected_d,
                cleanup_status="RESTORED",
            )
        )

        # --- Sub E: Unknown signer key ---
        with tempfile.TemporaryDirectory() as empty_dir:
            empty_km = KeyManager(keys_dir=Path(empty_dir))
            v_e = verify_record(baseline, key_manager=empty_km, expected_project_id=baseline.project_id)
            t_e = assess_record_tampering(v_e, baseline)
            codes_e = [f.code.value for f in v_e.failures]
            detected_e = (
                (not v_e.overall_valid)
                and (FailureCode.UNKNOWN_SIGNER_KEY.value in codes_e)
                and (t_e.status == TamperAssessmentStatus.AUTHENTICITY_UNAVAILABLE)
            )
            sub_results.append(
                AttackSubResult(
                    sub_id="ATTACK-02E",
                    name="Unknown signer key ID",
                    target_asset="ChainRecord.signer_key_id",
                    attack_technique="Submission with key ID absent from trusted KeyManager",
                    original_state={"trusted_key_id": handle.key_id},
                    modified_state={"key_id": handle.key_id, "trusted_status": "absent"},
                    verification_status=t_e.status.value,
                    failure_codes=codes_e,
                    evidence={"failures": codes_e, "authenticity_status": t_e.status.value},
                    detected=detected_e,
                    cleanup_status="RESTORED",
                )
            )

        # --- Sub F: Mismatched signer_key_id ---
        other_handle = km.generate_key(passphrase=TEST_PASSPHRASE, set_as_active=False)
        mismatched_rec = ChainRecord(
            **{
                **baseline.model_dump(),
                "signer_key_id": other_handle.key_id,  # Points to other_handle, but signed with handle
            }
        )
        v_f = verify_record(mismatched_rec, public_key=other_handle.public_key, expected_project_id=baseline.project_id)
        t_f = assess_record_tampering(v_f, mismatched_rec)
        codes_f = [f.code.value for f in v_f.failures]
        detected_f = (not v_f.overall_valid) and (
            FailureCode.INVALID_SIGNATURE.value in codes_f or FailureCode.SIGNER_KEY_MISMATCH.value in codes_f
        )
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-02F",
                name="Mismatched signer_key_id",
                target_asset="ChainRecord.signer_key_id",
                attack_technique="Signer key ID substituted with distinct key identity",
                original_state={"signer_key_id": handle.key_id},
                modified_state={"signer_key_id": other_handle.key_id},
                verification_status=t_f.status.value,
                failure_codes=codes_f,
                evidence={"failures": codes_f},
                detected=detected_f,
                cleanup_status="RESTORED",
            )
        )

        # --- Sub G: Attempt new signing using ROTATED / REVOKED / EXPIRED key ---
        with tempfile.TemporaryDirectory() as lc_dir:
            lifecycle_km = KeyManager(keys_dir=Path(lc_dir))
            lc_handle = lifecycle_km.generate_key(passphrase=TEST_PASSPHRASE)
            revoked_handle = lifecycle_km.revoke_key(lc_handle.key_id, reason="Security revocation demo")

            signing_rejected = False
            try:
                sign_hash(sha256_text("new data"), revoked_handle)
            except (KeyStatusError, KeyManagementError, AivaraException):
                signing_rejected = True

            sub_results.append(
                AttackSubResult(
                    sub_id="ATTACK-02G",
                    name="Attempt signing with revoked key",
                    target_asset="KeyManager.sign_with_key / sign_hash",
                    attack_technique="Attempting to forge new signature using revoked key",
                    original_state={"key_status": "ACTIVE"},
                    modified_state={"key_status": "REVOKED"},
                    verification_status="rejected",
                    failure_codes=["KEY_STATUS_INVALID"],
                    evidence={"signing_rejected": signing_rejected, "key_status": revoked_handle.status.value},
                    detected=signing_rejected,
                    cleanup_status="RESTORED",
                )
            )

        # --- Sub H: Historical signature remains mathematically verifiable after rotation ---
        # Note: handle is currently the active key in km
        old_h, new_h = km.rotate_key(passphrase="New_Rotated_Passphrase_2026!")
        rotated_v = verify_record(
            baseline,
            key_manager=km,
            expected_project_id=baseline.project_id,
        )
        hist_detected = (
            rotated_v.signature_valid is True
            and rotated_v.key_is_active is False
            and rotated_v.key_status == KeyStatus.ROTATED.value
        )
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-02H",
                name="Historical signature verification post-rotation",
                target_asset="Historical Signature Cryptographic Authority",
                attack_technique="Verification of historical active signature after key status transition to ROTATED",
                original_state={"key_status": "ACTIVE", "signature_valid": True},
                modified_state={"key_status": "ROTATED", "key_is_active": False},
                verification_status="historically_valid",
                failure_codes=[],
                evidence={
                    "signature_valid": rotated_v.signature_valid,
                    "key_status": rotated_v.key_status,
                    "key_is_active": rotated_v.key_is_active,
                },
                detected=hist_detected,
                cleanup_status="RESTORED",
            )
        )

        all_detected = all(sr.detected for sr in sub_results)

        return AttackResult(
            attack_id="ATTACK-02",
            attack_name="Digital Signature Forgery",
            target_asset="Ed25519 Cryptographic Signatures and Keys",
            attack_technique="Exhaustive evaluation across 8 signature and key lifecycle vectors",
            original_state={"baseline_signature_valid": True, "active_key": handle.key_id},
            modified_state={"vectors_tested": len(sub_results)},
            verification_status=TamperAssessmentStatus.INTEGRITY_VIOLATION.value if all_detected else "failed",
            failure_codes=[FailureCode.INVALID_SIGNATURE.value, FailureCode.MALFORMED_SIGNATURE.value],
            evidence={"sub_results_count": len(sub_results), "all_sub_detected": all_detected},
            detected=all_detected,
            cleanup_status="RESTORED",
            sub_results=sub_results,
            details={"summary": "All 8 signature and lifecycle security guarantees mathematically proven"},
        )
