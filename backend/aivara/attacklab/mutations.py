"""Deterministic copy-only mutation engine for the AIVARA Attack Simulation Lab (Phase 13)."""

from __future__ import annotations

import copy
import hashlib
from typing import Any, Dict

from aivara.attacklab.enums import MutationType
from aivara.attacklab.exceptions import MutationError
from aivara.attacklab.schemas import FixturePayload, MutationDefinition
from aivara.universal.hashing import compute_payload_hash


def canonical_hash(data: Dict[str, Any]) -> str:
    return compute_payload_hash(data)


class MutationEngine:
    """Applies controlled, deterministic mutations to deep copies of fixtures."""

    @staticmethod
    def apply_mutation(fixture: FixturePayload, mutation: MutationDefinition) -> FixturePayload:
        """Apply a mutation to a deep copy of the fixture data."""
        mutated_data = copy.deepcopy(fixture.data)
        op = mutation.operator

        try:
            if op == MutationType.LABEL_SWAP:
                MutationEngine._mutate_label_swap(mutated_data, mutation.parameters)
            elif op == MutationType.VALUE_SUBSTITUTION:
                MutationEngine._mutate_value_substitution(mutated_data, mutation.target_path, mutation.parameters)
            elif op == MutationType.NOISE_INJECTION:
                MutationEngine._mutate_noise_injection(mutated_data, mutation.target_path, mutation.parameters)
            elif op == MutationType.RECORD_DUPLICATION:
                MutationEngine._mutate_record_duplication(mutated_data, mutation.parameters)
            elif op == MutationType.RECORD_DELETION:
                MutationEngine._mutate_record_deletion(mutated_data, mutation.parameters)
            elif op == MutationType.SIGNATURE_CORRUPTION:
                MutationEngine._mutate_signature_corruption(mutated_data, mutation.parameters)
            elif op == MutationType.METRIC_SCALING:
                MutationEngine._mutate_metric_scaling(mutated_data, mutation.parameters)
            elif op == MutationType.SCHEMA_TAMPERING:
                MutationEngine._mutate_schema_tampering(mutated_data, mutation.parameters)
            elif op == MutationType.TENANT_OVERRIDE:
                MutationEngine._mutate_tenant_override(mutated_data, mutation.parameters)
            elif op == MutationType.BIT_FLIP:
                MutationEngine._mutate_bit_flip(mutated_data, mutation.target_path, mutation.parameters)
            else:
                raise MutationError(f"Unsupported mutation operator: {op}")
        except Exception as e:
            if isinstance(e, MutationError):
                raise
            raise MutationError(f"Failed to apply mutation {mutation.mutation_id}: {e}") from e

        new_hash = canonical_hash(mutated_data)
        return FixturePayload(
            fixture_id=f"{fixture.fixture_id}_mut_{mutation.mutation_id}",
            fixture_type=fixture.fixture_type,
            project_id=mutated_data.get("project_id", fixture.project_id),
            data=mutated_data,
            content_hash=new_hash,
        )

    @staticmethod
    def _mutate_label_swap(data: Dict[str, Any], params: Dict[str, Any]) -> None:
        target_idx = params.get("target_index", 0)
        samples = data.get("samples", [])
        if 0 <= target_idx < len(samples):
            current_label = samples[target_idx]["label"]
            samples[target_idx]["label"] = 1 - current_label if isinstance(current_label, int) else "corrupted_label"
            samples[target_idx]["is_flipped"] = True

    @staticmethod
    def _mutate_value_substitution(data: Dict[str, Any], target_path: str, params: Dict[str, Any]) -> None:
        new_val = params.get("new_value")
        parts = target_path.split(".")
        cur = data
        for p in parts[:-1]:
            cur = cur[p]
        cur[parts[-1]] = new_val

    @staticmethod
    def _mutate_noise_injection(data: Dict[str, Any], target_path: str, params: Dict[str, Any]) -> None:
        delta = params.get("delta", 5.0)
        if "traces" in data:
            for trace in data["traces"][:params.get("count", 3)]:
                trace["observed_output"] = [round(x + delta, 3) for x in trace["observed_output"]]
                trace["stability_score"] = 0.10

    @staticmethod
    def _mutate_record_duplication(data: Dict[str, Any], params: Dict[str, Any]) -> None:
        samples = data.get("samples", [])
        if samples:
            dup_count = params.get("dup_count", 3)
            first_sample = copy.deepcopy(samples[0])
            for i in range(dup_count):
                dup = copy.deepcopy(first_sample)
                dup["sample_id"] = f"dup_{i}_{first_sample['sample_id']}"
                dup["is_duplicate"] = True
                samples.append(dup)

    @staticmethod
    def _mutate_record_deletion(data: Dict[str, Any], params: Dict[str, Any]) -> None:
        commits = data.get("commits", [])
        if commits:
            data["commits"] = [c for c in commits if c.get("contributor_id") != params.get("target_contributor")]

    @staticmethod
    def _mutate_signature_corruption(data: Dict[str, Any], params: Dict[str, Any]) -> None:
        if "signature" in data:
            data["signature"] = "deadbeef" * 8
            data["is_valid"] = False
        if "proof" in data and isinstance(data["proof"], dict):
            data["proof"]["signature"] = "deadbeef" * 8
            data["proof"]["is_valid"] = False

    @staticmethod
    def _mutate_metric_scaling(data: Dict[str, Any], params: Dict[str, Any]) -> None:
        shift_amount = params.get("shift_amount", 3.5)
        if "target_distribution" in data:
            means = data["target_distribution"]["means"]
            data["target_distribution"]["means"] = [round(m + shift_amount, 4) for m in means]
            data["kl_divergence"] = params.get("kl_divergence", 2.45)
            data["ks_p_value"] = params.get("ks_p_value", 0.001)

    @staticmethod
    def _mutate_schema_tampering(data: Dict[str, Any], params: Dict[str, Any]) -> None:
        if "contract" in data:
            data["contract"]["input_shape"] = params.get("new_shape", [1, 999])
        if "output_payload" in data:
            data["output_payload"] = {"unexpected_field": "corrupted"}

    @staticmethod
    def _mutate_tenant_override(data: Dict[str, Any], params: Dict[str, Any]) -> None:
        data["project_id"] = params.get("unauthorized_project_id", "project_attacker_999")

    @staticmethod
    def _mutate_bit_flip(data: Dict[str, Any], target_path: str, params: Dict[str, Any]) -> None:
        if "has_backdoor" in data:
            data["has_backdoor"] = True
            data["backdoor_detected"] = True
        if "weights_hash" in data:
            data["weights_hash"] = "00000000" + data["weights_hash"][8:]
