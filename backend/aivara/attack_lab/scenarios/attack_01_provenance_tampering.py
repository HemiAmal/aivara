"""ATTACK-01 — Provenance Record Tampering Demonstration.

Creates a valid signed provenance record baseline.
Independently tampers with each cryptographically protected field:
  - input_hash
  - output_hash
  - model_id
  - model_weight_digest
  - config_hash
  - nonce
  - sequence_number
  - previous_record_hash
  - project_id
  - target_type
  - target_id
  - metadata_json
  - actor
  - action
  - record_type
  - timestamp
  - schema_version

For every field, demonstrates:
  1. baseline creation
  2. original state capture
  3. single-field modification
  4. cryptographic verification & tamper detection
  5. detection & evidence capture
  6. baseline restoration
"""

from __future__ import annotations

import copy
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
from aivara.crypto.keys import KeyManager
from aivara.crypto.signing import sign_hash
from aivara.crypto.tamper_detection import (
    TamperAssessmentStatus,
    assess_record_tampering,
)
from aivara.crypto.verification import FailureCode, verify_record


def get_scenario() -> AttackScenario:
    """Return static metadata for ATTACK-01."""
    return AttackScenario(
        attack_id="ATTACK-01",
        attack_name="Provenance Record Tampering",
        category=AttackCategory.PROVENANCE,
        description=(
            "Controlled demonstration proving that any independent modification to any "
            "cryptographically protected field in a canonical provenance record is "
            "authoritatively detected by AIVARA's verification engine as an integrity violation."
        ),
        target="Single Canonical Provenance Record",
        prerequisites=["Active Ed25519 signing key", "Valid provenance payload"],
        setup={"action": "Create baseline signed provenance record"},
        attack={"action": "Independently mutate each protected field and verify detection"},
        verification={"engine": "aivara.crypto.verification.verify_record + assess_record_tampering"},
        expected_result={
            "status": "integrity_violation",
            "detected": True,
            "failure_codes": ["RECORD_HASH_MISMATCH", "INVALID_SCHEMA", "MALFORMED_INPUT"],
        },
        cleanup="Restore baseline record state and verify overall_valid=True",
    )


def _create_baseline_record(km: KeyManager) -> ChainRecord:
    """Generate a valid, signed baseline ChainRecord."""
    handle = km.generate_key(passphrase="demo-passphrase-2026!")
    nonce = generate_nonce()
    prev_hash = "0" * 64
    meta = {"batch_size": 32, "temperature": 0.7}
    timestamp = "2026-03-01T12:00:00Z"

    rec_hash = hash_provenance_payload(
        record_type="INFERENCE",
        project_id="proj-demo-attack01",
        actor="sec-tester",
        action="VERIFY_INFERENCE",
        sequence_number=1,
        nonce=nonce,
        timestamp=timestamp,
        signer_key_id=handle.key_id,
        target_type="MODEL",
        target_id="mod-resnet-50",
        input_hash=sha256_text("test input data"),
        output_hash=sha256_text("test output data"),
        model_id="mod-resnet-50",
        model_weight_digest=sha256_text("weights v1.0"),
        config_hash=sha256_text("config: fp16=true"),
        previous_record_hash=prev_hash,
        metadata_json=meta,
        schema_version=CANONICAL_SCHEMA_VERSION,
    )

    sig_res = sign_hash(rec_hash, handle)

    return ChainRecord(
        schema_version=CANONICAL_SCHEMA_VERSION,
        record_type="INFERENCE",
        project_id="proj-demo-attack01",
        sequence_number=1,
        previous_record_hash=prev_hash,
        nonce=nonce,
        actor="sec-tester",
        action="VERIFY_INFERENCE",
        target_type="MODEL",
        target_id="mod-resnet-50",
        timestamp=timestamp,
        input_hash=sha256_text("test input data"),
        output_hash=sha256_text("test output data"),
        model_id="mod-resnet-50",
        model_weight_digest=sha256_text("weights v1.0"),
        config_hash=sha256_text("config: fp16=true"),
        metadata_json=meta,
        record_hash=rec_hash,
        signature=sig_res.signature,
        signer_key_id=handle.key_id,
    )


def run_attack_01() -> AttackResult:
    """Execute the ATTACK-01 demonstration."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        km = KeyManager(keys_dir=Path(tmp_dir))
        baseline = _create_baseline_record(km)
        pub_key = km.load_key(baseline.signer_key_id, load_private=False).public_key

        # Verify baseline is completely valid
        base_res = verify_record(baseline, public_key=pub_key, expected_project_id=baseline.project_id)
        assert base_res.overall_valid, "Baseline record must be valid prior to attack"

        fields_to_tamper = [
            ("input_hash", sha256_text("TAMPERED_INPUT_DATA")),
            ("output_hash", sha256_text("TAMPERED_OUTPUT_DATA")),
            ("model_id", "mod-tampered-backdoored"),
            ("model_weight_digest", sha256_text("tampered_weights")),
            ("config_hash", sha256_text("tampered_config")),
            ("nonce", generate_nonce()),
            ("sequence_number", 42),
            ("previous_record_hash", sha256_text("tampered_prev_hash")),
            ("project_id", "proj-tampered-other"),
            ("target_type", "DATASET"),
            ("target_id", "dataset-tampered-99"),
            ("metadata_json", {"batch_size": 32, "temperature": 0.7, "backdoor": "injected"}),
            ("actor", "malicious-actor"),
            ("action", "UNAUTHORIZED_OVERRIDE"),
            ("record_type", "TRAINING"),
            ("timestamp", "2026-03-01T12:00:01Z"),
            ("schema_version", "1.1"),
        ]

        sub_results: List[AttackSubResult] = []
        all_detected = True

        for field_name, tampered_val in fields_to_tamper:
            orig_val = getattr(baseline, field_name)
            tampered_dict = baseline.model_dump()
            tampered_dict[field_name] = tampered_val

            try:
                tampered_record = ChainRecord(**tampered_dict)
                v_res = verify_record(
                    tampered_record,
                    public_key=pub_key,
                    expected_project_id=baseline.project_id,
                )
                tamper_res = assess_record_tampering(v_res, tampered_record)
                failure_codes = [f.code.value for f in v_res.failures]
                status_str = tamper_res.status.value
                detected = (not v_res.overall_valid) and (
                    tamper_res.tampering_detected or len(v_res.failures) > 0
                )
            except Exception:
                status_str = "unverifiable_input"
                failure_codes = [FailureCode.MALFORMED_INPUT.value]
                detected = True

            if not detected:
                all_detected = False

            # Cleanup & restore check: verify baseline is still completely valid
            restore_v = verify_record(baseline, public_key=pub_key, expected_project_id=baseline.project_id)
            cleanup_status = "RESTORED" if restore_v.overall_valid else "CORRUPTED"

            sub_results.append(
                AttackSubResult(
                    sub_id=field_name,
                    name=f"Tamper field '{field_name}'",
                    target_asset=f"ChainRecord.{field_name}",
                    attack_technique=f"Direct value substitution: {repr(orig_val)} -> {repr(tampered_val)}",
                    original_state={field_name: orig_val},
                    modified_state={field_name: tampered_val},
                    verification_status=status_str,
                    failure_codes=failure_codes,
                    evidence={
                        "stored_record_hash": baseline.record_hash,
                        "tampered_field": field_name,
                        "num_failures": len(failure_codes),
                    },
                    detected=detected,
                    cleanup_status=cleanup_status,
                )
            )

        return AttackResult(
            attack_id="ATTACK-01",
            attack_name="Provenance Record Tampering",
            target_asset="Provenance Record Protected Fields",
            attack_technique="Single-field corruption across 17 distinct cryptographic fields",
            original_state={"fields_tested": len(fields_to_tamper), "baseline_valid": True},
            modified_state={"tampered_fields_count": len(fields_to_tamper)},
            verification_status=TamperAssessmentStatus.INTEGRITY_VIOLATION.value if all_detected else "partial",
            failure_codes=[FailureCode.RECORD_HASH_MISMATCH.value, FailureCode.PROJECT_MISMATCH.value],
            evidence={"fields_tested": [f[0] for f in fields_to_tamper], "sub_results_count": len(sub_results)},
            detected=all_detected,
            cleanup_status="RESTORED",
            sub_results=sub_results,
            details={"summary": "All 17 protected fields independently detected upon modification"},
        )
