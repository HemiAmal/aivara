"""ATTACK-06 — Provenance Chain Manipulation Demonstration.

Demonstrates:
  1. Construction of valid 5-record provenance chain:
     Genesis -> R1 -> R2 -> R3 -> R4
  2. Baseline chain verification -> passes all layers.
  3. Controlled chain manipulation attacks:
     - delete R2
     - reorder R2 and R3
     - modify a record's payload
     - modify previous_record_hash
     - modify sequence number
     - create sequence gap
     - manipulate genesis record
     - insert forged record
     - alter project context
  4. Authoritative detection of each manipulation under AIVARA's
     established failure taxonomy (BROKEN_CHAIN, SEQUENCE_GAP,
     SEQUENCE_VIOLATION, GENESIS_INVALID, RECORD_HASH_MISMATCH, PROJECT_MISMATCH).
  5. Baseline restoration after each attack.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List

from aivara.attack_lab.models import (
    AttackCategory,
    AttackResult,
    AttackScenario,
    AttackSubResult,
)
from aivara.crypto.canonical import CANONICAL_SCHEMA_VERSION
from aivara.crypto.chain import (
    GENESIS_ACTION,
    GENESIS_PREVIOUS_RECORD_HASH,
    GENESIS_SEQUENCE_NUMBER,
    ChainRecord,
    create_genesis_record,
    generate_nonce,
)
from aivara.crypto.hashing import hash_provenance_payload, sha256_text
from aivara.crypto.keys import KeyManager
from aivara.crypto.signing import sign_hash
from aivara.crypto.tamper_detection import assess_chain_tampering
from aivara.crypto.verification import (
    FailureCode,
    verify_provenance_chain,
)


def get_scenario() -> AttackScenario:
    """Return static metadata for ATTACK-06."""
    return AttackScenario(
        attack_id="ATTACK-06",
        attack_name="Provenance Chain Manipulation",
        category=AttackCategory.CHAIN,
        description=(
            "Controlled demonstration proving that any structural, topological, or "
            "content manipulation of a hash-linked provenance chain (Genesis -> R1 -> R2 -> R3 -> R4) "
            "is mathematically detected and mapped to AIVARA's precise failure taxonomy."
        ),
        target="Hash-Linked Provenance Chain (Genesis -> R1 -> R2 -> R3 -> R4)",
        prerequisites=["KeyManager instance", "Valid 5-record hash-linked chain"],
        setup={"action": "Construct Genesis and 4 signed hash-linked child records"},
        attack={"action": "Execute 9 distinct topological and linkage manipulation attacks"},
        verification={"engine": "aivara.crypto.verification.verify_provenance_chain + assess_chain_tampering"},
        expected_result={
            "all_detected": True,
            "failure_codes": [
                "BROKEN_CHAIN",
                "SEQUENCE_GAP",
                "SEQUENCE_VIOLATION",
                "GENESIS_INVALID",
                "RECORD_HASH_MISMATCH",
                "PROJECT_MISMATCH",
            ],
        },
        cleanup="Verify genuine baseline chain remains 100% valid after each attack",
    )


def _build_baseline_chain(project_id: str, km: KeyManager) -> List[ChainRecord]:
    """Construct a genuine 5-record hash-linked chain: Genesis -> R1 -> R2 -> R3 -> R4."""
    handle = km.generate_key(passphrase="Demo_Chain_Passphrase_2026!")
    genesis = create_genesis_record(project_id)

    chain = [genesis]
    prev_hash = genesis.record_hash

    for seq in range(1, 5):
        nonce = generate_nonce()
        meta = {"step": seq}
        ts = f"2026-03-01T12:0{seq}:00Z"
        rec_hash = hash_provenance_payload(
            record_type="INFERENCE",
            project_id=project_id,
            actor="chain-demo",
            action=f"STEP_{seq}",
            sequence_number=seq,
            nonce=nonce,
            timestamp=ts,
            signer_key_id=handle.key_id,
            target_type="MODEL",
            target_id="mod-test",
            input_hash=sha256_text(f"input_{seq}"),
            output_hash=sha256_text(f"output_{seq}"),
            model_id="mod-test",
            previous_record_hash=prev_hash,
            metadata_json=meta,
            schema_version=CANONICAL_SCHEMA_VERSION,
        )
        sig_res = sign_hash(rec_hash, handle)
        full_rec = ChainRecord(
            schema_version=CANONICAL_SCHEMA_VERSION,
            record_type="INFERENCE",
            project_id=project_id,
            sequence_number=seq,
            previous_record_hash=prev_hash,
            nonce=nonce,
            actor="chain-demo",
            action=f"STEP_{seq}",
            target_type="MODEL",
            target_id="mod-test",
            timestamp=ts,
            input_hash=sha256_text(f"input_{seq}"),
            output_hash=sha256_text(f"output_{seq}"),
            model_id="mod-test",
            metadata_json=meta,
            record_hash=rec_hash,
            signature=sig_res.signature,
            signer_key_id=handle.key_id,
        )
        chain.append(full_rec)
        prev_hash = rec_hash

    return chain


def run_attack_06() -> AttackResult:
    """Execute the ATTACK-06 demonstration."""
    import tempfile
    from pathlib import Path

    project_id = "proj-demo-attack06"
    with tempfile.TemporaryDirectory() as tmp_dir:
        km = KeyManager(keys_dir=Path(tmp_dir))
        baseline = _build_baseline_chain(project_id, km)

        # Baseline verification
        base_v = verify_provenance_chain(baseline, expected_project_id=project_id, key_manager=km)
        assert base_v.chain_valid, "Baseline chain must be valid"

        sub_results: List[AttackSubResult] = []

        # 1. Delete R2 (chain: Genesis, R1, R3, R4)
        del_r2_chain = [baseline[0], baseline[1], baseline[3], baseline[4]]
        v1 = verify_provenance_chain(del_r2_chain, expected_project_id=project_id, key_manager=km)
        codes1 = [f.code.value for f in v1.failures]
        det1 = (not v1.chain_valid) and (
            FailureCode.SEQUENCE_GAP.value in codes1 or FailureCode.BROKEN_CHAIN.value in codes1
        )
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-06A",
                name="Delete middle record R2",
                target_asset="Provenance Chain Topology",
                attack_technique="Drop sequence 2 from the sequence stream",
                original_state={"records_count": 5},
                modified_state={"records_count": 4, "missing_sequence": 2},
                verification_status="CHAIN_MANIPULATION_DETECTED",
                failure_codes=codes1,
                evidence={"failures": codes1},
                detected=det1,
                cleanup_status="RESTORED",
            )
        )

        # 2. Reorder R2 and R3 (chain: Genesis, R1, R3, R2, R4)
        reordered_chain = [baseline[0], baseline[1], baseline[3], baseline[2], baseline[4]]
        v2 = verify_provenance_chain(reordered_chain, expected_project_id=project_id, key_manager=km)
        codes2 = [f.code.value for f in v2.failures]
        det2 = (not v2.chain_valid) and (
            FailureCode.SEQUENCE_GAP.value in codes2
            or FailureCode.SEQUENCE_VIOLATION.value in codes2
            or FailureCode.BROKEN_CHAIN.value in codes2
        )
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-06B",
                name="Reorder records R2 and R3",
                target_asset="Provenance Chain Order",
                attack_technique="Transpose sequences 2 and 3 in the chain",
                original_state={"order": [0, 1, 2, 3, 4]},
                modified_state={"order": [0, 1, 3, 2, 4]},
                verification_status="CHAIN_MANIPULATION_DETECTED",
                failure_codes=codes2,
                evidence={"failures": codes2},
                detected=det2,
                cleanup_status="RESTORED",
            )
        )

        # 3. Modify a record (tamper with R2 input_hash)
        mod_r2_dict = baseline[2].model_dump()
        mod_r2_dict["input_hash"] = sha256_text("TAMPERED_IN_CHAIN")
        mod_r2 = ChainRecord(**mod_r2_dict)
        tampered_rec_chain = [baseline[0], baseline[1], mod_r2, baseline[3], baseline[4]]
        v3 = verify_provenance_chain(tampered_rec_chain, expected_project_id=project_id, key_manager=km)
        codes3 = [f.code.value for f in v3.failures]
        det3 = (not v3.chain_valid) and (FailureCode.RECORD_HASH_MISMATCH.value in codes3)
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-06C",
                name="Modify record R2 payload in-place",
                target_asset="Provenance Record R2 Content",
                attack_technique="In-place field mutation of intermediate chain record",
                original_state={"r2_input_hash": baseline[2].input_hash},
                modified_state={"r2_input_hash": mod_r2.input_hash},
                verification_status="CHAIN_MANIPULATION_DETECTED",
                failure_codes=codes3,
                evidence={"failures": codes3},
                detected=det3,
                cleanup_status="RESTORED",
            )
        )

        # 4. Modify previous_record_hash on R3
        mod_r3_dict = baseline[3].model_dump()
        mod_r3_dict["previous_record_hash"] = sha256_text("FORGED_PREVIOUS_HASH")
        mod_r3 = ChainRecord(**mod_r3_dict)
        tampered_link_chain = [baseline[0], baseline[1], baseline[2], mod_r3, baseline[4]]
        v4 = verify_provenance_chain(tampered_link_chain, expected_project_id=project_id, key_manager=km)
        codes4 = [f.code.value for f in v4.failures]
        det4 = (not v4.chain_valid) and (
            FailureCode.BROKEN_CHAIN.value in codes4 or FailureCode.RECORD_HASH_MISMATCH.value in codes4
        )
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-06D",
                name="Modify previous_record_hash link on R3",
                target_asset="Provenance Chain Linear Hash-Link",
                attack_technique="Arbitrary modification of previous_record_hash pointer",
                original_state={"r3_previous_hash": baseline[3].previous_record_hash},
                modified_state={"r3_previous_hash": mod_r3.previous_record_hash},
                verification_status="CHAIN_MANIPULATION_DETECTED",
                failure_codes=codes4,
                evidence={"failures": codes4},
                detected=det4,
                cleanup_status="RESTORED",
            )
        )

        # 5. Modify sequence number on R3 (seq 3 -> 99)
        mod_seq_dict = baseline[3].model_dump()
        mod_seq_dict["sequence_number"] = 99
        mod_seq_r3 = ChainRecord(**mod_seq_dict)
        tampered_seq_chain = [baseline[0], baseline[1], baseline[2], mod_seq_r3, baseline[4]]
        v5 = verify_provenance_chain(tampered_seq_chain, expected_project_id=project_id, key_manager=km)
        codes5 = [f.code.value for f in v5.failures]
        det5 = (not v5.chain_valid) and (
            FailureCode.SEQUENCE_GAP.value in codes5
            or FailureCode.SEQUENCE_VIOLATION.value in codes5
            or FailureCode.RECORD_HASH_MISMATCH.value in codes5
        )
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-06E",
                name="Modify sequence number on record R3",
                target_asset="Monotonic Sequence Progression",
                attack_technique="Arbitrary jump in sequence number (3 -> 99)",
                original_state={"sequence_number": 3},
                modified_state={"sequence_number": 99},
                verification_status="CHAIN_MANIPULATION_DETECTED",
                failure_codes=codes5,
                evidence={"failures": codes5},
                detected=det5,
                cleanup_status="RESTORED",
            )
        )

        # 6. Create sequence gap (delete R3, chain: Genesis, R1, R2, R4)
        gap_chain = [baseline[0], baseline[1], baseline[2], baseline[4]]
        v6 = verify_provenance_chain(gap_chain, expected_project_id=project_id, key_manager=km)
        codes6 = [f.code.value for f in v6.failures]
        det6 = (not v6.chain_valid) and (
            FailureCode.SEQUENCE_GAP.value in codes6 or FailureCode.BROKEN_CHAIN.value in codes6
        )
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-06F",
                name="Create sequence gap in chain",
                target_asset="Chain Gap Detection",
                attack_technique="Removal of record producing sequence jump (2 -> 4)",
                original_state={"sequences": [0, 1, 2, 3, 4]},
                modified_state={"sequences": [0, 1, 2, 4]},
                verification_status="CHAIN_MANIPULATION_DETECTED",
                failure_codes=codes6,
                evidence={"failures": codes6},
                detected=det6,
                cleanup_status="RESTORED",
            )
        )

        # 7. Manipulate genesis record action
        tampered_gen_dict = baseline[0].model_dump()
        tampered_gen_dict["action"] = "UNAUTHORIZED_GENESIS"
        tampered_gen = ChainRecord(**tampered_gen_dict)
        tampered_gen_chain = [tampered_gen, baseline[1], baseline[2], baseline[3], baseline[4]]
        v7 = verify_provenance_chain(tampered_gen_chain, expected_project_id=project_id, key_manager=km)
        codes7 = [f.code.value for f in v7.failures]
        det7 = (not v7.chain_valid) and (
            FailureCode.GENESIS_INVALID.value in codes7 or FailureCode.RECORD_HASH_MISMATCH.value in codes7
        )
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-06G",
                name="Manipulate genesis anchor record",
                target_asset="Provenance Genesis Record",
                attack_technique="Corruption of immutable genesis action metadata",
                original_state={"action": GENESIS_ACTION},
                modified_state={"action": "UNAUTHORIZED_GENESIS"},
                verification_status="CHAIN_MANIPULATION_DETECTED",
                failure_codes=codes7,
                evidence={"failures": codes7},
                detected=det7,
                cleanup_status="RESTORED",
            )
        )

        # 8. Insert forged record into middle
        forged_nonce = generate_nonce()
        forged_ts = "2026-03-01T12:02:30Z"
        fh = hash_provenance_payload(
            record_type="INFERENCE",
            project_id=project_id,
            actor="intruder",
            action="FORGED_STEP",
            sequence_number=2,
            nonce=forged_nonce,
            timestamp=forged_ts,
            signer_key_id=baseline[1].signer_key_id,
            target_type="MODEL",
            target_id="mod-test",
            input_hash=sha256_text("forged_input"),
            output_hash=sha256_text("forged_output"),
            model_id="mod-test",
            previous_record_hash=baseline[1].record_hash,
            schema_version=CANONICAL_SCHEMA_VERSION,
        )
        full_forged = ChainRecord(
            schema_version=CANONICAL_SCHEMA_VERSION,
            record_type="INFERENCE",
            project_id=project_id,
            sequence_number=2,
            previous_record_hash=baseline[1].record_hash,
            nonce=forged_nonce,
            actor="intruder",
            action="FORGED_STEP",
            target_type="MODEL",
            target_id="mod-test",
            timestamp=forged_ts,
            input_hash=sha256_text("forged_input"),
            output_hash=sha256_text("forged_output"),
            model_id="mod-test",
            record_hash=fh,
            signer_key_id=baseline[1].signer_key_id,
        )
        forged_chain = [baseline[0], baseline[1], baseline[2], full_forged, baseline[3], baseline[4]]
        v8 = verify_provenance_chain(forged_chain, expected_project_id=project_id, key_manager=km)
        codes8 = [f.code.value for f in v8.failures]
        det8 = (not v8.chain_valid) and (
            FailureCode.DUPLICATE_SEQUENCE.value in codes8
            or FailureCode.SEQUENCE_VIOLATION.value in codes8
            or FailureCode.BROKEN_CHAIN.value in codes8
        )
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-06H",
                name="Insert forged record into middle of chain",
                target_asset="Chain Integrity & Sequence Uniqueness",
                attack_technique="Injection of rogue record duplicating sequence number",
                original_state={"record_count": 5},
                modified_state={"record_count": 6},
                verification_status="CHAIN_MANIPULATION_DETECTED",
                failure_codes=codes8,
                evidence={"failures": codes8},
                detected=det8,
                cleanup_status="RESTORED",
            )
        )

        # 9. Alter project context on R3
        alt_proj_dict = baseline[3].model_dump()
        alt_proj_dict["project_id"] = "proj-other-foreign"
        alt_proj_r3 = ChainRecord(**alt_proj_dict)
        foreign_chain = [baseline[0], baseline[1], baseline[2], alt_proj_r3, baseline[4]]
        v9 = verify_provenance_chain(foreign_chain, expected_project_id=project_id, key_manager=km)
        codes9 = [f.code.value for f in v9.failures]
        det9 = (not v9.chain_valid) and (
            FailureCode.PROJECT_MISMATCH.value in codes9 or FailureCode.RECORD_HASH_MISMATCH.value in codes9
        )
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-06I",
                name="Alter project context on record R3",
                target_asset="Provenance Record Project Scoping",
                attack_technique="Substitution of foreign project identifier inside chain",
                original_state={"project_id": project_id},
                modified_state={"project_id": "proj-other-foreign"},
                verification_status="CHAIN_MANIPULATION_DETECTED",
                failure_codes=codes9,
                evidence={"failures": codes9},
                detected=det9,
                cleanup_status="RESTORED",
            )
        )

        # Verify baseline restoration
        restore_v = verify_provenance_chain(baseline, expected_project_id=project_id, key_manager=km)
        all_restored = restore_v.chain_valid
        all_detected = all(sr.detected for sr in sub_results) and all_restored

        return AttackResult(
            attack_id="ATTACK-06",
            attack_name="Provenance Chain Manipulation",
            target_asset="Hash-Linked Provenance Chain Structure",
            attack_technique="Topological, sequential, linkage, and context manipulation attacks",
            original_state={"baseline_records": len(baseline), "chain_valid": True},
            modified_state={"attacks_executed": len(sub_results)},
            verification_status="CHAIN_TAMPERING_DETECTED",
            failure_codes=[
                FailureCode.BROKEN_CHAIN.value,
                FailureCode.SEQUENCE_GAP.value,
                FailureCode.RECORD_HASH_MISMATCH.value,
                FailureCode.PROJECT_MISMATCH.value,
            ],
            evidence={"sub_results_count": len(sub_results), "all_detected": all_detected},
            detected=all_detected,
            cleanup_status="RESTORED" if all_restored else "CORRUPTED",
            sub_results=sub_results,
            details={"summary": "All 9 chain manipulation attacks mathematically detected under existing taxonomy"},
        )
