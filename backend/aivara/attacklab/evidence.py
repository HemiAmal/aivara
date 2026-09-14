"""Evidence generation bridge for the AIVARA Attack Simulation Lab (Phase 13)."""

from __future__ import annotations

import hashlib
from typing import List, Tuple

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.attacklab.schemas import FixturePayload
from aivara.universal.enums import SubsystemDomain
from aivara.universal.hashing import compute_payload_hash
from aivara.universal.schemas import AncestryPath, UniversalEvidenceEnvelope


def canonical_hash(data: Dict[str, Any]) -> str:
    return compute_payload_hash(data)


class SimulationEvidenceBridge:
    """Bridges synthetic fixture observations into Phase 12 Universal Evidence Envelopes."""

    @staticmethod
    def extract_evidence_and_findings(fixture: FixturePayload) -> Tuple[List[UniversalEvidenceEnvelope], List[str]]:
        """Extract evidence envelopes and finding types from a fixture payload.
        
        Returns:
            Tuple of (envelopes, finding_types)
        """
        f_type = fixture.fixture_type
        data = fixture.data
        project_id = fixture.project_id
        envelopes: List[UniversalEvidenceEnvelope] = []
        finding_types: List[str] = []

        if f_type == "dataset_integrity":
            samples = data.get("samples", [])
            # Check for flipped labels or duplicate samples
            flipped_samples = [s for s in samples if s.get("is_flipped")]
            duplicate_samples = [s for s in samples if s.get("is_duplicate")]
            sample_ids = [s["sample_id"] for s in samples]
            has_duplicates = (len(sample_ids) != len(set(sample_ids))) or (len(duplicate_samples) > 0)

            if flipped_samples or has_duplicates:
                finding_id = f"find_ds_anomaly_{fixture.fixture_id[:8]}"
                if flipped_samples:
                    finding_types.append("DATASET_LABEL_ANOMALY")
                if has_duplicates:
                    finding_types.append("DATASET_DUPLICATE_SAMPLES")

                payload_hash = canonical_hash(data)
                env = UniversalEvidenceEnvelope(
                    evidence_id=f"ev_ds_{fixture.fixture_id[:8]}",
                    project_id=project_id,
                    domain=SubsystemDomain.DATASET_INTEGRITY,
                    evidence_type="dataset_label_flip_evidence",
                    evidence_layer=EvidenceLayer.DETECTION,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    primary_asset_type="dataset",
                    primary_asset_id=data.get("dataset_id", "ds_001"),
                    finding_id=finding_id,
                    source_payload_hash=payload_hash,
                    normalized_payload_hash=payload_hash,
                    ancestry_path=AncestryPath(dataset_version_id="1.0", sample_id=flipped_samples[0]["sample_id"] if flipped_samples else "s_0000"),
                    data_json={"flipped_count": len(flipped_samples), "has_duplicates": has_duplicates},
                )
                envelopes.append(env)

        elif f_type == "contributor_risk":
            commits = data.get("commits", [])
            contributors = data.get("contributors", [])
            # Check if any contributor has 0 commits or extreme distribution
            c_counts = {}
            for c in commits:
                c_id = c.get("contributor_id")
                c_counts[c_id] = c_counts.get(c_id, 0) + 1

            if len(c_counts) < len(contributors):
                finding_types.append("CONTRIBUTOR_SOURCE_FRAGMENTATION")
                payload_hash = canonical_hash(data)
                env = UniversalEvidenceEnvelope(
                    evidence_id=f"ev_contrib_{fixture.fixture_id[:8]}",
                    project_id=project_id,
                    domain=SubsystemDomain.CONTRIBUTOR_RISK,
                    evidence_type="source_fragmentation_evidence",
                    evidence_layer=EvidenceLayer.DETECTION,
                    severity=Severity.MEDIUM,
                    confidence=0.75,
                    primary_asset_type="repository",
                    primary_asset_id=data.get("repository_id", "repo_001"),
                    finding_id=f"find_contrib_{fixture.fixture_id[:8]}",
                    source_payload_hash=payload_hash,
                    normalized_payload_hash=payload_hash,
                    ancestry_path=AncestryPath(source_id="contrib_deleted"),
                    data_json={"active_contributors": len(c_counts), "expected": len(contributors)},
                )
                envelopes.append(env)

        elif f_type == "model_integrity":
            weights_hash = data.get("weights_hash", "")
            contract_shape = data.get("contract", {}).get("input_shape", [1, 4])
            is_mutated = weights_hash.startswith("00000000") or contract_shape != [1, 4]

            if is_mutated:
                if weights_hash.startswith("00000000"):
                    finding_types.append("MODEL_FINGERPRINT_MISMATCH")
                if contract_shape != [1, 4]:
                    finding_types.append("MODEL_CONTRACT_VIOLATION")

                payload_hash = canonical_hash(data)
                env = UniversalEvidenceEnvelope(
                    evidence_id=f"ev_model_{fixture.fixture_id[:8]}",
                    project_id=project_id,
                    domain=SubsystemDomain.MODEL_INTEGRITY,
                    evidence_type="model_weights_mismatch",
                    evidence_layer=EvidenceLayer.DETECTION,
                    severity=Severity.HIGH,
                    confidence=0.90,
                    primary_asset_type="model",
                    primary_asset_id=data.get("model_id", "model_001"),
                    finding_id=f"find_model_{fixture.fixture_id[:8]}",
                    source_payload_hash=payload_hash,
                    normalized_payload_hash=payload_hash,
                    ancestry_path=AncestryPath(model_fingerprint=weights_hash[:16]),
                    data_json={"weights_hash": weights_hash, "contract_shape": contract_shape},
                )
                envelopes.append(env)

        elif f_type == "behavioral_integrity":
            traces = data.get("traces", [])
            unstable_traces = [t for t in traces if t.get("stability_score", 1.0) < 0.5]

            if unstable_traces:
                finding_types.append("BEHAVIORAL_OUTPUT_INSTABILITY")
                payload_hash = canonical_hash(data)
                env = UniversalEvidenceEnvelope(
                    evidence_id=f"ev_behav_{fixture.fixture_id[:8]}",
                    project_id=project_id,
                    domain=SubsystemDomain.BEHAVIORAL_ANALYSIS,
                    evidence_type="behavioral_instability_evidence",
                    evidence_layer=EvidenceLayer.DETECTION,
                    severity=Severity.MEDIUM,
                    confidence=0.80,
                    primary_asset_type="model",
                    primary_asset_id="model_synth_001",
                    finding_id=f"find_behav_{fixture.fixture_id[:8]}",
                    source_payload_hash=payload_hash,
                    normalized_payload_hash=payload_hash,
                    ancestry_path=AncestryPath(sample_id="trace_instability"),
                    data_json={"unstable_count": len(unstable_traces)},
                )
                envelopes.append(env)

        elif f_type == "backdoor_trigger":
            if data.get("has_backdoor"):
                finding_types.append("BACKDOOR_TRIGGER_DETECTED")
                payload_hash = canonical_hash(data)
                env = UniversalEvidenceEnvelope(
                    evidence_id=f"ev_backdoor_{fixture.fixture_id[:8]}",
                    project_id=project_id,
                    domain=SubsystemDomain.BACKDOOR_TRIGGER,
                    evidence_type="backdoor_activation_evidence",
                    evidence_layer=EvidenceLayer.DETECTION,
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    primary_asset_type="model",
                    primary_asset_id="model_synth_001",
                    finding_id=f"find_backdoor_{fixture.fixture_id[:8]}",
                    source_payload_hash=payload_hash,
                    normalized_payload_hash=payload_hash,
                    ancestry_path=AncestryPath(model_fingerprint="trig_fingerprint"),
                    data_json={"trigger_spec": data.get("trigger_spec")},
                )
                envelopes.append(env)

        elif f_type == "inference_integrity":
            output_payload = data.get("output_payload", {})
            if "unexpected_field" in output_payload:
                finding_types.append("INFERENCE_SCHEMA_VIOLATION")
                payload_hash = canonical_hash(data)
                env = UniversalEvidenceEnvelope(
                    evidence_id=f"ev_inf_{fixture.fixture_id[:8]}",
                    project_id=project_id,
                    domain=SubsystemDomain.INFERENCE_INTEGRITY,
                    evidence_type="inference_schema_anomaly",
                    evidence_layer=EvidenceLayer.DETECTION,
                    severity=Severity.HIGH,
                    confidence=0.90,
                    primary_asset_type="inference_record",
                    primary_asset_id=data.get("inference_id", "inf_001"),
                    finding_id=f"find_inf_{fixture.fixture_id[:8]}",
                    source_payload_hash=payload_hash,
                    normalized_payload_hash=payload_hash,
                    ancestry_path=AncestryPath(window_id="inf_window_01"),
                    data_json={"output_payload": output_payload},
                )
                envelopes.append(env)

        elif f_type == "distribution_shift":
            kl = data.get("kl_divergence", 0.0)
            if kl > 1.0:
                finding_types.append("NUMERICAL_DISTRIBUTION_SHIFT")
                payload_hash = canonical_hash(data)
                env = UniversalEvidenceEnvelope(
                    evidence_id=f"ev_shift_{fixture.fixture_id[:8]}",
                    project_id=project_id,
                    domain=SubsystemDomain.DISTRIBUTION_SHIFT,
                    evidence_type="distribution_divergence_evidence",
                    evidence_layer=EvidenceLayer.DETECTION,
                    severity=Severity.MEDIUM,
                    confidence=0.85,
                    primary_asset_type="dataset",
                    primary_asset_id="ds_shift_001",
                    finding_id=f"find_shift_{fixture.fixture_id[:8]}",
                    source_payload_hash=payload_hash,
                    normalized_payload_hash=payload_hash,
                    ancestry_path=AncestryPath(window_id="shift_window_01"),
                    data_json={"kl_divergence": kl},
                )
                envelopes.append(env)

        elif f_type == "proof_provenance":
            is_valid = data.get("is_valid", True)
            payload_hash = canonical_hash(data)
            if not is_valid:
                finding_types.append("PROOF_SIGNATURE_INVALID")
                # Proof violation envelope
                env = UniversalEvidenceEnvelope(
                    evidence_id=f"ev_proof_{fixture.fixture_id[:8]}",
                    project_id=project_id,
                    domain=SubsystemDomain.MODEL_INTEGRITY,
                    evidence_type="proof_signature_mismatch",
                    evidence_layer=EvidenceLayer.PROOF,
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    primary_asset_type="model",
                    primary_asset_id="model_synth_001",
                    finding_id=f"find_proof_fail_{fixture.fixture_id[:8]}",
                    source_payload_hash=payload_hash,
                    normalized_payload_hash=payload_hash,
                    ancestry_path=AncestryPath(model_fingerprint="proof_tampered"),
                    data_json={"signature": data.get("signature"), "is_valid": False},
                )
                envelopes.append(env)

        elif f_type == "multi_domain":
            # Multi-domain combines dataset + model + proof
            ds_sub = FixturePayload(
                fixture_id=f"{fixture.fixture_id}_ds",
                fixture_type="dataset_integrity",
                project_id=project_id,
                data=data.get("dataset", {}),
                content_hash=canonical_hash(data.get("dataset", {})),
            )
            md_sub = FixturePayload(
                fixture_id=f"{fixture.fixture_id}_model",
                fixture_type="model_integrity",
                project_id=project_id,
                data=data.get("model", {}),
                content_hash=canonical_hash(data.get("model", {})),
            )
            pr_sub = FixturePayload(
                fixture_id=f"{fixture.fixture_id}_proof",
                fixture_type="proof_provenance",
                project_id=project_id,
                data=data.get("proof", {}),
                content_hash=canonical_hash(data.get("proof", {})),
            )
            e1, f1 = SimulationEvidenceBridge.extract_evidence_and_findings(ds_sub)
            e2, f2 = SimulationEvidenceBridge.extract_evidence_and_findings(md_sub)
            e3, f3 = SimulationEvidenceBridge.extract_evidence_and_findings(pr_sub)
            envelopes.extend(e1 + e2 + e3)
            finding_types.extend(f1 + f2 + f3)

        return envelopes, finding_types
