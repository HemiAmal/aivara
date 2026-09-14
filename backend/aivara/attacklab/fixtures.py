"""Deterministic synthetic fixture generator for the AIVARA Attack Simulation Lab (Phase 13)."""

from __future__ import annotations

import hashlib
import json
import random
from typing import Any, Dict, List

from aivara.attacklab.exceptions import FixtureGenerationError
from aivara.attacklab.schemas import FixturePayload
from aivara.universal.hashing import compute_payload_hash


def canonical_hash(data: Dict[str, Any]) -> str:
    return compute_payload_hash(data)


class SyntheticFixtureGenerator:
    """Generates deterministic, synthetic test fixtures for all 7 assurance domains."""

    @staticmethod
    def create_fixture(
        fixture_type: str,
        project_id: str,
        seed: int = 42,
        params: Dict[str, Any] | None = None,
    ) -> FixturePayload:
        """Create a deterministic synthetic fixture by type."""
        params = params or {}
        rng = random.Random(seed)

        if fixture_type == "dataset_integrity":
            data = SyntheticFixtureGenerator._gen_dataset(rng, project_id, params)
        elif fixture_type == "contributor_risk":
            data = SyntheticFixtureGenerator._gen_contributor(rng, project_id, params)
        elif fixture_type == "model_integrity":
            data = SyntheticFixtureGenerator._gen_model(rng, project_id, params)
        elif fixture_type == "behavioral_integrity":
            data = SyntheticFixtureGenerator._gen_behavioral(rng, project_id, params)
        elif fixture_type == "backdoor_trigger":
            data = SyntheticFixtureGenerator._gen_backdoor(rng, project_id, params)
        elif fixture_type == "inference_integrity":
            data = SyntheticFixtureGenerator._gen_inference(rng, project_id, params)
        elif fixture_type == "distribution_shift":
            data = SyntheticFixtureGenerator._gen_distribution(rng, project_id, params)
        elif fixture_type == "proof_provenance":
            data = SyntheticFixtureGenerator._gen_proof(rng, project_id, params)
        elif fixture_type == "security_boundary":
            data = SyntheticFixtureGenerator._gen_security(rng, project_id, params)
        elif fixture_type == "multi_domain":
            data = SyntheticFixtureGenerator._gen_multi_domain(rng, project_id, params)
        else:
            raise FixtureGenerationError(f"Unknown fixture type: {fixture_type}")

        fixture_id = f"fix_{fixture_type}_{seed}"
        content_hash = canonical_hash(data)
        return FixturePayload(
            fixture_id=fixture_id,
            fixture_type=fixture_type,
            project_id=project_id,
            data=data,
            content_hash=content_hash,
        )

    @staticmethod
    def _gen_dataset(rng: random.Random, project_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        num_samples = params.get("num_samples", 20)
        samples = []
        for i in range(num_samples):
            feat = [round(rng.uniform(-2.0, 2.0), 4) for _ in range(4)]
            label = 1 if sum(feat) > 0 else 0
            samples.append({
                "sample_id": f"s_{i:04d}",
                "features": feat,
                "label": label,
                "metadata": {"source": "synthetic_alpha"},
            })
        return {
            "dataset_id": "ds_synth_001",
            "version": "1.0",
            "project_id": project_id,
            "samples": samples,
            "schema": {"features": ["f1", "f2", "f3", "f4"], "target": "label"},
        }

    @staticmethod
    def _gen_contributor(rng: random.Random, project_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        num_commits = params.get("num_commits", 30)
        commits = []
        contributors = [f"contrib_{j:02d}" for j in range(5)]
        for i in range(num_commits):
            c_id = contributors[i % len(contributors)]
            commits.append({
                "commit_hash": hashlib.sha256(f"commit_{i}_{c_id}".encode()).hexdigest()[:16],
                "contributor_id": c_id,
                "lines_added": rng.randint(5, 50),
                "lines_deleted": rng.randint(0, 20),
                "files_changed": ["model/core.py", "data/loader.py"],
            })
        return {
            "repository_id": "repo_synth_001",
            "project_id": project_id,
            "commits": commits,
            "contributors": contributors,
        }

    @staticmethod
    def _gen_model(rng: random.Random, project_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        weights_seed = rng.randint(1000, 9999)
        weights_hash = hashlib.sha256(f"weights_{weights_seed}".encode()).hexdigest()
        return {
            "model_id": "model_synth_001",
            "project_id": project_id,
            "architecture": "ResNet-Synthetic",
            "contract": {
                "input_shape": [1, 4],
                "output_shape": [1, 2],
                "dtype": "float32",
            },
            "weights_hash": weights_hash,
            "parameters_count": 10240,
            "framework": "torch",
        }

    @staticmethod
    def _gen_behavioral(rng: random.Random, project_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        num_tests = params.get("num_tests", 15)
        traces = []
        for i in range(num_tests):
            inp = [round(rng.uniform(-1.0, 1.0), 3) for _ in range(3)]
            out = [round(x * 1.5, 3) for x in inp]
            traces.append({
                "test_id": f"t_{i:03d}",
                "input": inp,
                "expected_output": out,
                "observed_output": out,  # Clean baseline matches expected
                "stability_score": 1.0,
            })
        return {
            "suite_id": "suite_synth_001",
            "project_id": project_id,
            "traces": traces,
        }

    @staticmethod
    def _gen_backdoor(rng: random.Random, project_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "trigger_test_id": "trig_synth_001",
            "project_id": project_id,
            "clean_sample": {"input": [0.1, 0.2, 0.3], "label": 0, "prediction": 0},
            "trigger_spec": {"type": "corner_pixel", "pattern": [1.0, 1.0], "target_class": 1},
            "has_backdoor": False,  # Clean baseline
        }

    @staticmethod
    def _gen_inference(rng: random.Random, project_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        inp = [0.5, -0.2, 1.1, 0.0]
        model_id = "model_synth_001"
        return {
            "inference_id": "inf_synth_001",
            "project_id": project_id,
            "model_id": model_id,
            "input_payload": {"vector": inp},
            "preprocessing_hash": hashlib.sha256(b"standard_scaler_v1").hexdigest(),
            "output_payload": {"logits": [0.12, 0.88], "predicted_class": 1},
            "binding_token": hashlib.sha256(f"{project_id}_{model_id}_inf_synth_001".encode()).hexdigest(),
        }

    @staticmethod
    def _gen_distribution(rng: random.Random, project_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        ref_mean = [0.0, 0.0, 0.0]
        # Clean target population matches reference closely
        target_mean = [round(rng.gauss(0.0, 0.02), 4) for _ in range(3)]
        return {
            "shift_id": "shift_synth_001",
            "project_id": project_id,
            "reference_distribution": {"means": ref_mean, "variance": [1.0, 1.0, 1.0], "sample_count": 1000},
            "target_distribution": {"means": target_mean, "variance": [1.0, 1.0, 1.0], "sample_count": 1000},
            "kl_divergence": 0.01,
            "ks_p_value": 0.95,
        }

    @staticmethod
    def _gen_proof(rng: random.Random, project_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        genesis_hash = hashlib.sha256(f"genesis_{project_id}".encode()).hexdigest()
        record_hash = hashlib.sha256(f"{genesis_hash}_record_001".encode()).hexdigest()
        return {
            "proof_id": "proof_synth_001",
            "project_id": project_id,
            "genesis_hash": genesis_hash,
            "previous_hash": genesis_hash,
            "record_hash": record_hash,
            "signature": hashlib.sha256(f"ed25519_sig_{record_hash}".encode()).hexdigest(),
            "is_valid": True,
            "confidence": 1.0,
        }

    @staticmethod
    def _gen_security(rng: random.Random, project_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "security_test_id": "sec_synth_001",
            "project_id": project_id,
            "target_path": "valid/path/artifact.json",
            "payload_size_bytes": 1024,
            "is_authorized": True,
        }

    @staticmethod
    def _gen_multi_domain(rng: random.Random, project_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "multi_domain_id": "multi_synth_001",
            "project_id": project_id,
            "dataset": SyntheticFixtureGenerator._gen_dataset(rng, project_id, params),
            "model": SyntheticFixtureGenerator._gen_model(rng, project_id, params),
            "proof": SyntheticFixtureGenerator._gen_proof(rng, project_id, params),
        }
