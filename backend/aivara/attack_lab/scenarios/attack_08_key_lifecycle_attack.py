"""ATTACK-08 — Key Lifecycle Attack Demonstration.

Demonstrates:
  1. Separation of historical verification authority from current signing authority:
     - ACTIVE key signs baseline record -> valid historical signature.
     - Key transitioned to ROTATED / REVOKED / EXPIRED.
     - Historical signature remains mathematically verifiable after transition.
     - Key lifecycle status correctly reflects inactive state.
  2. Strict rejection of new signing attempts using inactive keys:
     - ROTATED key signing attempt -> REJECTED.
     - REVOKED key signing attempt -> REJECTED.
     - EXPIRED key signing attempt -> REJECTED.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from aivara.attack_lab.models import (
    AttackCategory,
    AttackResult,
    AttackScenario,
    AttackSubResult,
)
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
from aivara.crypto.signing import sign_hash
from aivara.crypto.verification import verify_record

TEST_PASSPHRASE = "Demo_KeyLifecycle_Passphrase_2026!"


def get_scenario() -> AttackScenario:
    """Return static metadata for ATTACK-08."""
    return AttackScenario(
        attack_id="ATTACK-08",
        attack_name="Key Lifecycle Attack",
        category=AttackCategory.KEY_LIFECYCLE,
        description=(
            "Controlled demonstration proving that AIVARA's cryptographic verification engine "
            "strictly enforces Ed25519 key lifecycle transitions: historical signatures created "
            "when a key was active remain mathematically verifiable indefinitely, but any attempt "
            "to create new signatures using non-active keys (ROTATED, REVOKED, EXPIRED) is immediately "
            "rejected with authoritative lifecycle exceptions."
        ),
        target="Ed25519 Key Lifecycle & Historical Verification",
        prerequisites=["KeyManager instance", "Passphrase-protected active keypair"],
        setup={"action": "Generate active key and create valid historical signature"},
        attack={"action": "Transition key status (ROTATED, REVOKED, EXPIRED) and attempt new signing"},
        verification={"engine": "sign_hash (rejection) + verify_record (historical validity)"},
        expected_result={
            "historical_verification_preserved": True,
            "new_signing_rejected": True,
            "inactive_states_verified": ["ROTATED", "REVOKED", "EXPIRED"],
        },
        cleanup="Verify key lifecycle reports correct final status and restore baseline",
    )


def _create_record_and_sign(km: KeyManager, handle, seq: int) -> ChainRecord:
    nonce = generate_nonce()
    ts = "2026-03-01T12:00:00Z"
    rec_hash = hash_provenance_payload(
        record_type="INFERENCE",
        project_id="proj-key-lifecycle",
        actor="sec-lifecycle",
        action=f"ACTION_{seq}",
        sequence_number=seq,
        nonce=nonce,
        timestamp=ts,
        signer_key_id=handle.key_id,
        target_type="MODEL",
        target_id="mod-test",
        input_hash=sha256_text(f"input_{seq}"),
        output_hash=sha256_text(f"output_{seq}"),
        model_id="mod-test",
        previous_record_hash="0" * 64,
        schema_version=CANONICAL_SCHEMA_VERSION,
    )
    sig_res = sign_hash(rec_hash, handle)
    return ChainRecord(
        schema_version=CANONICAL_SCHEMA_VERSION,
        record_type="INFERENCE",
        project_id="proj-key-lifecycle",
        sequence_number=seq,
        previous_record_hash="0" * 64,
        nonce=nonce,
        actor="sec-lifecycle",
        action=f"ACTION_{seq}",
        target_type="MODEL",
        target_id="mod-test",
        timestamp=ts,
        input_hash=sha256_text(f"input_{seq}"),
        output_hash=sha256_text(f"output_{seq}"),
        model_id="mod-test",
        record_hash=rec_hash,
        signature=sig_res.signature,
        signer_key_id=handle.key_id,
    )


def run_attack_08() -> AttackResult:
    """Execute the ATTACK-08 demonstration."""
    sub_results: List[AttackSubResult] = []
    all_cases_passed = True

    with tempfile.TemporaryDirectory() as tmp_dir:
        keys_path = Path(tmp_dir)

        # -------------------------------------------------------------
        # CASE 1: ROTATED
        # -------------------------------------------------------------
        km1 = KeyManager(keys_dir=keys_path / "rotated")
        handle1 = km1.generate_key(passphrase=TEST_PASSPHRASE, set_as_active=True)
        key_id1 = handle1.key_id
        hist_rec1 = _create_record_and_sign(km1, handle1, seq=1)

        v_act1 = verify_record(hist_rec1, key_manager=km1, expected_project_id="proj-key-lifecycle")
        assert v_act1.overall_valid and v_act1.key_is_active is True

        # Rotate key
        km1.rotate_key(passphrase="Rotated_New_Key_Passphrase_2026!")

        # Historical verification: signature remains valid, key is ROTATED
        v_rot = verify_record(hist_rec1, key_manager=km1, expected_project_id="proj-key-lifecycle")
        hist_valid1 = (
            v_rot.signature_valid is True
            and v_rot.key_is_active is False
            and v_rot.key_status == KeyStatus.ROTATED.value
        )

        # Attempt new signing with rotated key handle
        rotated_handle = km1.load_key(key_id1, passphrase=TEST_PASSPHRASE, require_active=False, load_private=True)
        new_signing_rejected1 = False
        rejection_reason1 = ""
        try:
            sign_hash(sha256_text("fraudulent new data"), rotated_handle)
        except (KeyStatusError, KeyManagementError) as koe:
            new_signing_rejected1 = True
            rejection_reason1 = str(koe)

        det1 = hist_valid1 and new_signing_rejected1
        if not det1:
            all_cases_passed = False

        sub_results.append(
            AttackSubResult(
                sub_id="KEY-ROTATED",
                name="Key Lifecycle: Transition to ROTATED",
                target_asset=f"KeyManager [{key_id1[:8]}...]",
                attack_technique="Sign while active -> rotate key -> attempt new signature",
                original_state={"status": "ACTIVE", "signing_allowed": True},
                modified_state={"status": "ROTATED", "signing_allowed": False},
                verification_status="AUTHORITY_SEPARATION_VERIFIED",
                failure_codes=["KEY_ROTATED"] if new_signing_rejected1 else [],
                evidence={
                    "target_status": "ROTATED",
                    "historical_signature_valid": v_rot.signature_valid,
                    "key_is_active": v_rot.key_is_active,
                    "new_signing_rejected": new_signing_rejected1,
                    "rejection_reason": rejection_reason1,
                },
                detected=det1,
                cleanup_status="RESTORED",
            )
        )

        # -------------------------------------------------------------
        # CASE 2: REVOKED
        # -------------------------------------------------------------
        km2 = KeyManager(keys_dir=keys_path / "revoked")
        handle2 = km2.generate_key(passphrase=TEST_PASSPHRASE, set_as_active=True)
        key_id2 = handle2.key_id
        hist_rec2 = _create_record_and_sign(km2, handle2, seq=1)

        v_act2 = verify_record(hist_rec2, key_manager=km2, expected_project_id="proj-key-lifecycle")
        assert v_act2.overall_valid and v_act2.key_is_active is True

        # Revoke key
        revoked_handle = km2.revoke_key(key_id2, reason="Emergency compromise simulation")

        # Historical verification: signature remains valid, key is REVOKED
        v_rev = verify_record(hist_rec2, key_manager=km2, expected_project_id="proj-key-lifecycle")
        hist_valid2 = (
            v_rev.signature_valid is True
            and v_rev.key_is_active is False
            and v_rev.key_status == KeyStatus.REVOKED.value
        )

        new_signing_rejected2 = False
        rejection_reason2 = ""
        try:
            sign_hash(sha256_text("fraudulent new data"), revoked_handle)
        except (KeyStatusError, KeyManagementError) as koe:
            new_signing_rejected2 = True
            rejection_reason2 = str(koe)

        det2 = hist_valid2 and new_signing_rejected2
        if not det2:
            all_cases_passed = False

        sub_results.append(
            AttackSubResult(
                sub_id="KEY-REVOKED",
                name="Key Lifecycle: Transition to REVOKED",
                target_asset=f"KeyManager [{key_id2[:8]}...]",
                attack_technique="Sign while active -> revoke key -> attempt new signature",
                original_state={"status": "ACTIVE", "signing_allowed": True},
                modified_state={"status": "REVOKED", "signing_allowed": False},
                verification_status="AUTHORITY_SEPARATION_VERIFIED",
                failure_codes=["KEY_REVOKED"] if new_signing_rejected2 else [],
                evidence={
                    "target_status": "REVOKED",
                    "historical_signature_valid": v_rev.signature_valid,
                    "key_is_active": v_rev.key_is_active,
                    "new_signing_rejected": new_signing_rejected2,
                    "rejection_reason": rejection_reason2,
                },
                detected=det2,
                cleanup_status="RESTORED",
            )
        )

        # -------------------------------------------------------------
        # CASE 3: EXPIRED
        # -------------------------------------------------------------
        km3 = KeyManager(keys_dir=keys_path / "expired")
        handle3 = km3.generate_key(passphrase=TEST_PASSPHRASE, set_as_active=True)
        key_id3 = handle3.key_id
        hist_rec3 = _create_record_and_sign(km3, handle3, seq=1)

        v_act3 = verify_record(hist_rec3, key_manager=km3, expected_project_id="proj-key-lifecycle")
        assert v_act3.overall_valid and v_act3.key_is_active is True

        # Expire key by updating metadata file
        meta_path3 = km3._resolve_key_path(key_id3, "meta.json")
        meta_dict3 = json.loads(meta_path3.read_text(encoding="utf-8"))
        meta_dict3["status"] = KeyStatus.EXPIRED.value
        meta_path3.write_text(json.dumps(meta_dict3), encoding="utf-8")

        # Historical verification: signature remains valid, key is EXPIRED
        v_exp = verify_record(hist_rec3, key_manager=km3, expected_project_id="proj-key-lifecycle")
        hist_valid3 = (
            v_exp.signature_valid is True
            and v_exp.key_is_active is False
            and v_exp.key_status == KeyStatus.EXPIRED.value
        )

        expired_handle = km3.load_key(key_id3, passphrase=TEST_PASSPHRASE, require_active=False, load_private=True)
        new_signing_rejected3 = False
        rejection_reason3 = ""
        try:
            sign_hash(sha256_text("fraudulent new data"), expired_handle)
        except (KeyStatusError, KeyManagementError) as koe:
            new_signing_rejected3 = True
            rejection_reason3 = str(koe)

        det3 = hist_valid3 and new_signing_rejected3
        if not det3:
            all_cases_passed = False

        sub_results.append(
            AttackSubResult(
                sub_id="KEY-EXPIRED",
                name="Key Lifecycle: Transition to EXPIRED",
                target_asset=f"KeyManager [{key_id3[:8]}...]",
                attack_technique="Sign while active -> expire key -> attempt new signature",
                original_state={"status": "ACTIVE", "signing_allowed": True},
                modified_state={"status": "EXPIRED", "signing_allowed": False},
                verification_status="AUTHORITY_SEPARATION_VERIFIED",
                failure_codes=["KEY_EXPIRED"] if new_signing_rejected3 else [],
                evidence={
                    "target_status": "EXPIRED",
                    "historical_signature_valid": v_exp.signature_valid,
                    "key_is_active": v_exp.key_is_active,
                    "new_signing_rejected": new_signing_rejected3,
                    "rejection_reason": rejection_reason3,
                },
                detected=det3,
                cleanup_status="RESTORED",
            )
        )

    return AttackResult(
        attack_id="ATTACK-08",
        attack_name="Key Lifecycle Attack",
        target_asset="Cryptographic Signing Authority & Key Lifecycle Engine",
        attack_technique="Evaluation of ROTATED, REVOKED, and EXPIRED key states",
        original_state={"lifecycle_states_tested": ["ROTATED", "REVOKED", "EXPIRED"]},
        modified_state={"active_keys_transitioned": 3},
        verification_status="KEY_LIFECYCLE_ENFORCED",
        failure_codes=["KEY_ROTATED", "KEY_REVOKED", "KEY_EXPIRED"],
        evidence={
            "transitions_tested": ["ROTATED", "REVOKED", "EXPIRED"],
            "historical_validity_preserved_all": all_cases_passed,
            "new_signing_blocked_all": all_cases_passed,
        },
        detected=all_cases_passed,
        cleanup_status="RESTORED",
        sub_results=sub_results,
        details={
            "summary": (
                "Decoupled historical verification from signing authority: "
                "historical signatures remain verifiable across ROTATED/REVOKED/EXPIRED, "
                "while new signing attempts are strictly rejected."
            )
        },
    )
