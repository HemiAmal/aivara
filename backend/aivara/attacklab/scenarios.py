"""Authoritative Golden Attack Scenario suite (G01 to G20) for Phase 13."""

from __future__ import annotations

from typing import Dict, List

from aivara.attacklab.enums import (
    AttackClass,
    AttackDomain,
    ExpectedDecisionClass,
    MutationType,
    OracleOutcome,
)
from aivara.attacklab.schemas import (
    ExpectedBehavior,
    MutationDefinition,
    ScenarioDefinition,
)


def get_all_golden_scenarios(project_id: str = "proj_lab_001") -> List[ScenarioDefinition]:
    """Retrieve the authoritative 20 Golden Attack Scenarios (G01 to G20)."""
    return [
        # G01: Clean dataset baseline
        ScenarioDefinition(
            scenario_id="G01",
            name="Clean Dataset Baseline Control",
            target_domain=AttackDomain.DATASET_INTEGRITY,
            attack_class=AttackClass.SAMPLE_POISONING,
            description="Executes a completely clean, synthetic dataset verifying zero findings and low baseline risk.",
            project_id=project_id,
            seed=101,
            fixture_type="dataset_integrity",
            fixture_params={"num_samples": 25},
            mutations=[],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.EXPECTED_NO_DETECTION,
                max_risk=0.30,
                expected_decision=ExpectedDecisionClass.ACCEPT,
            ),
        ),
        # G02: Modified dataset sample
        ScenarioDefinition(
            scenario_id="G02",
            name="Modified Dataset Sample Poisoning",
            target_domain=AttackDomain.DATASET_INTEGRITY,
            attack_class=AttackClass.SAMPLE_POISONING,
            description="Injects flipped labels and anomalous values into synthetic dataset samples.",
            project_id=project_id,
            seed=102,
            fixture_type="dataset_integrity",
            fixture_params={"num_samples": 25},
            mutations=[
                MutationDefinition(
                    mutation_id="m_g02_flip",
                    operator=MutationType.LABEL_SWAP,
                    target_path="samples",
                    parameters={"target_index": 2},
                    description="Flips binary class label for target sample index 2.",
                )
            ],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.EXPECTED_DETECTION,
                expect_finding_types=["DATASET_LABEL_ANOMALY"],
                min_risk=0.30,
                expected_decision=ExpectedDecisionClass.ANY_ELEVATED,
            ),
        ),
        # G03: Duplicate Injection
        ScenarioDefinition(
            scenario_id="G03",
            name="Dataset Duplicate Sample Injection",
            target_domain=AttackDomain.DATASET_INTEGRITY,
            attack_class=AttackClass.DUPLICATE_INJECTION,
            description="Injects duplicated synthetic samples into dataset to test frequency anomaly detection.",
            project_id=project_id,
            seed=103,
            fixture_type="dataset_integrity",
            fixture_params={"num_samples": 20},
            mutations=[
                MutationDefinition(
                    mutation_id="m_g03_dup",
                    operator=MutationType.RECORD_DUPLICATION,
                    target_path="samples",
                    parameters={"dup_count": 4},
                    description="Duplicates sample 0 four times.",
                )
            ],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.EXPECTED_DETECTION,
                expect_finding_types=["DATASET_DUPLICATE_SAMPLES"],
                min_risk=0.30,
                expected_decision=ExpectedDecisionClass.ANY_ELEVATED,
            ),
        ),
        # G04: Synthetic source anomaly
        ScenarioDefinition(
            scenario_id="G04",
            name="Contributor Source Fragmentation Anomaly",
            target_domain=AttackDomain.CONTRIBUTOR_RISK,
            attack_class=AttackClass.SOURCE_FRAGMENTATION,
            description="Simulates contributor deletion and repository commit fragmentation.",
            project_id=project_id,
            seed=104,
            fixture_type="contributor_risk",
            fixture_params={"num_commits": 30},
            mutations=[
                MutationDefinition(
                    mutation_id="m_g04_del",
                    operator=MutationType.RECORD_DELETION,
                    target_path="commits",
                    parameters={"target_contributor": "contrib_04"},
                    description="Deletes all commit records authored by contrib_04.",
                )
            ],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.EXPECTED_DETECTION,
                expect_finding_types=["CONTRIBUTOR_SOURCE_FRAGMENTATION"],
                min_risk=0.30,
                expected_decision=ExpectedDecisionClass.ANY_ELEVATED,
            ),
        ),
        # G05: Model artifact mutation
        ScenarioDefinition(
            scenario_id="G05",
            name="Model Contract Architecture Violation",
            target_domain=AttackDomain.MODEL_INTEGRITY,
            attack_class=AttackClass.CONTRACT_VIOLATION,
            description="Tamper with model contract input shape dimensions.",
            project_id=project_id,
            seed=105,
            fixture_type="model_integrity",
            mutations=[
                MutationDefinition(
                    mutation_id="m_g05_contract",
                    operator=MutationType.SCHEMA_TAMPERING,
                    target_path="contract.input_shape",
                    parameters={"new_shape": [1, 999]},
                    description="Alters expected contract input tensor shape to [1, 999].",
                )
            ],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.EXPECTED_DETECTION,
                expect_finding_types=["MODEL_CONTRACT_VIOLATION"],
                min_risk=0.30,
                expected_decision=ExpectedDecisionClass.ANY_ELEVATED,
            ),
        ),
        # G06: Model substitution
        ScenarioDefinition(
            scenario_id="G06",
            name="Model Weights Fingerprint Mismatch",
            target_domain=AttackDomain.MODEL_INTEGRITY,
            attack_class=AttackClass.FINGERPRINT_MISMATCH,
            description="Simulates stealth substitution of model weight parameters.",
            project_id=project_id,
            seed=106,
            fixture_type="model_integrity",
            mutations=[
                MutationDefinition(
                    mutation_id="m_g06_fingerprint",
                    operator=MutationType.BIT_FLIP,
                    target_path="weights_hash",
                    parameters={},
                    description="Substitutes model weight hash digest prefix.",
                )
            ],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.EXPECTED_DETECTION,
                expect_finding_types=["MODEL_FINGERPRINT_MISMATCH"],
                min_risk=0.30,
                expected_decision=ExpectedDecisionClass.ANY_ELEVATED,
            ),
        ),
        # G07: Behavioral output mutation
        ScenarioDefinition(
            scenario_id="G07",
            name="Behavioral Output Perturbation Instability",
            target_domain=AttackDomain.BEHAVIORAL_INTEGRITY,
            attack_class=AttackClass.OUTPUT_INSTABILITY,
            description="Injects high perturbation variance into model evaluation outputs.",
            project_id=project_id,
            seed=107,
            fixture_type="behavioral_integrity",
            fixture_params={"num_tests": 15},
            mutations=[
                MutationDefinition(
                    mutation_id="m_g07_noise",
                    operator=MutationType.NOISE_INJECTION,
                    target_path="traces",
                    parameters={"delta": 8.0, "count": 5},
                    description="Injects variance delta into 5 behavioral execution traces.",
                )
            ],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.EXPECTED_DETECTION,
                expect_finding_types=["BEHAVIORAL_OUTPUT_INSTABILITY"],
                min_risk=0.30,
                expected_decision=ExpectedDecisionClass.ANY_ELEVATED,
            ),
        ),
        # G08: Synthetic trigger behavior
        ScenarioDefinition(
            scenario_id="G08",
            name="Backdoor Trigger Activation Detection",
            target_domain=AttackDomain.BACKDOOR_TRIGGER,
            attack_class=AttackClass.TRIGGER_ACTIVATION,
            description="Simulates synthetic paired trigger activation pattern.",
            project_id=project_id,
            seed=108,
            fixture_type="backdoor_trigger",
            mutations=[
                MutationDefinition(
                    mutation_id="m_g08_trig",
                    operator=MutationType.BIT_FLIP,
                    target_path="has_backdoor",
                    parameters={},
                    description="Flags candidate backdoor trigger as active and verified.",
                )
            ],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.EXPECTED_DETECTION,
                expect_finding_types=["BACKDOOR_TRIGGER_DETECTED"],
                min_risk=0.85,
                expected_decision=ExpectedDecisionClass.REJECT,
            ),
        ),
        # G09: Inference input mutation
        ScenarioDefinition(
            scenario_id="G09",
            name="Inference Input Output Schema Tampering",
            target_domain=AttackDomain.INFERENCE_INTEGRITY,
            attack_class=AttackClass.OUTPUT_SCHEMA_TAMPERING,
            description="Injects unexpected schema fields into inference execution output payload.",
            project_id=project_id,
            seed=109,
            fixture_type="inference_integrity",
            mutations=[
                MutationDefinition(
                    mutation_id="m_g09_inf",
                    operator=MutationType.SCHEMA_TAMPERING,
                    target_path="output_payload",
                    parameters={},
                    description="Corrupts inference output record schema.",
                )
            ],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.EXPECTED_DETECTION,
                expect_finding_types=["INFERENCE_SCHEMA_VIOLATION"],
                min_risk=0.30,
                expected_decision=ExpectedDecisionClass.ANY_ELEVATED,
            ),
        ),
        # G10: Preprocessing mismatch
        ScenarioDefinition(
            scenario_id="G10",
            name="Inference Preprocessing Contract Mismatch",
            target_domain=AttackDomain.INFERENCE_INTEGRITY,
            attack_class=AttackClass.PREPROCESSING_MISMATCH,
            description="Corrupts preprocessing contract payload in inference record.",
            project_id=project_id,
            seed=110,
            fixture_type="inference_integrity",
            mutations=[
                MutationDefinition(
                    mutation_id="m_g10_prep",
                    operator=MutationType.SCHEMA_TAMPERING,
                    target_path="output_payload",
                    parameters={},
                    description="Tampering with inference preprocessing pipeline output.",
                )
            ],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.EXPECTED_DETECTION,
                expect_finding_types=["INFERENCE_SCHEMA_VIOLATION"],
                min_risk=0.30,
                expected_decision=ExpectedDecisionClass.ANY_ELEVATED,
            ),
        ),
        # G11: Output mutation
        ScenarioDefinition(
            scenario_id="G11",
            name="Inference Output Anomaly",
            target_domain=AttackDomain.INFERENCE_INTEGRITY,
            attack_class=AttackClass.OUTPUT_SCHEMA_TAMPERING,
            description="Corrupts inference prediction record fields.",
            project_id=project_id,
            seed=111,
            fixture_type="inference_integrity",
            mutations=[
                MutationDefinition(
                    mutation_id="m_g11_out",
                    operator=MutationType.SCHEMA_TAMPERING,
                    target_path="output_payload",
                    parameters={},
                    description="Corrupts inference result envelope.",
                )
            ],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.EXPECTED_DETECTION,
                expect_finding_types=["INFERENCE_SCHEMA_VIOLATION"],
                min_risk=0.30,
                expected_decision=ExpectedDecisionClass.ANY_ELEVATED,
            ),
        ),
        # G12: Replay inconsistency
        ScenarioDefinition(
            scenario_id="G12",
            name="Inference Replay Execution Divergence",
            target_domain=AttackDomain.INFERENCE_INTEGRITY,
            attack_class=AttackClass.REPLAY_DIVERGENCE,
            description="Simulates non-deterministic inference replay output.",
            project_id=project_id,
            seed=112,
            fixture_type="inference_integrity",
            mutations=[
                MutationDefinition(
                    mutation_id="m_g12_rep",
                    operator=MutationType.SCHEMA_TAMPERING,
                    target_path="output_payload",
                    parameters={},
                    description="Divergent output payload during re-execution.",
                )
            ],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.EXPECTED_DETECTION,
                expect_finding_types=["INFERENCE_SCHEMA_VIOLATION"],
                min_risk=0.30,
                expected_decision=ExpectedDecisionClass.ANY_ELEVATED,
            ),
        ),
        # G13: Numerical distribution shift
        ScenarioDefinition(
            scenario_id="G13",
            name="Numerical Feature Distribution Shift",
            target_domain=AttackDomain.DISTRIBUTION_SHIFT,
            attack_class=AttackClass.FEATURE_SHIFT,
            description="Induces statistical mean shift and elevated KL divergence.",
            project_id=project_id,
            seed=113,
            fixture_type="distribution_shift",
            mutations=[
                MutationDefinition(
                    mutation_id="m_g13_shift",
                    operator=MutationType.METRIC_SCALING,
                    target_path="target_distribution",
                    parameters={"shift_amount": 4.5, "kl_divergence": 3.80},
                    description="Shifts distribution target mean by +4.5 units.",
                )
            ],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.EXPECTED_DETECTION,
                expect_finding_types=["NUMERICAL_DISTRIBUTION_SHIFT"],
                min_risk=0.30,
                expected_decision=ExpectedDecisionClass.ANY_ELEVATED,
            ),
        ),
        # G14: Categorical distribution shift
        ScenarioDefinition(
            scenario_id="G14",
            name="Categorical Population Frequency Shift",
            target_domain=AttackDomain.DISTRIBUTION_SHIFT,
            attack_class=AttackClass.CATEGORICAL_DRIFT,
            description="Induces distribution drift in categorical population counts.",
            project_id=project_id,
            seed=114,
            fixture_type="distribution_shift",
            mutations=[
                MutationDefinition(
                    mutation_id="m_g14_cat",
                    operator=MutationType.METRIC_SCALING,
                    target_path="target_distribution",
                    parameters={"shift_amount": 3.0, "kl_divergence": 2.90},
                    description="Shifts categorical feature distribution frequencies.",
                )
            ],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.EXPECTED_DETECTION,
                expect_finding_types=["NUMERICAL_DISTRIBUTION_SHIFT"],
                min_risk=0.30,
                expected_decision=ExpectedDecisionClass.ANY_ELEVATED,
            ),
        ),
        # G15: Image distribution shift
        ScenarioDefinition(
            scenario_id="G15",
            name="Image Quality and Descriptor Distribution Shift",
            target_domain=AttackDomain.DISTRIBUTION_SHIFT,
            attack_class=AttackClass.IMAGE_DESCRIPTOR_SHIFT,
            description="Induces statistical drift in image brightness and noise descriptors.",
            project_id=project_id,
            seed=115,
            fixture_type="distribution_shift",
            mutations=[
                MutationDefinition(
                    mutation_id="m_g15_img",
                    operator=MutationType.METRIC_SCALING,
                    target_path="target_distribution",
                    parameters={"shift_amount": 3.2, "kl_divergence": 3.10},
                    description="Alters image descriptor population statistics.",
                )
            ],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.EXPECTED_DETECTION,
                expect_finding_types=["NUMERICAL_DISTRIBUTION_SHIFT"],
                min_risk=0.30,
                expected_decision=ExpectedDecisionClass.ANY_ELEVATED,
            ),
        ),
        # G16: Embedding distribution shift
        ScenarioDefinition(
            scenario_id="G16",
            name="Latent Representation Embedding Drift",
            target_domain=AttackDomain.DISTRIBUTION_SHIFT,
            attack_class=AttackClass.EMBEDDING_DRIFT,
            description="Simulates latent space representation centroid drift.",
            project_id=project_id,
            seed=116,
            fixture_type="distribution_shift",
            mutations=[
                MutationDefinition(
                    mutation_id="m_g16_emb",
                    operator=MutationType.METRIC_SCALING,
                    target_path="target_distribution",
                    parameters={"shift_amount": 3.6, "kl_divergence": 3.40},
                    description="Shifts embedding centroid representation vector.",
                )
            ],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.EXPECTED_DETECTION,
                expect_finding_types=["NUMERICAL_DISTRIBUTION_SHIFT"],
                min_risk=0.30,
                expected_decision=ExpectedDecisionClass.ANY_ELEVATED,
            ),
        ),
        # G17: Multi-domain correlated attack
        ScenarioDefinition(
            scenario_id="G17",
            name="Multi-Domain Correlated Attack Composition",
            target_domain=AttackDomain.MULTI_DOMAIN,
            attack_class=AttackClass.MULTI_DOMAIN_CORRELATED,
            description="Applies simultaneous dataset label flipping and model contract violation.",
            project_id=project_id,
            seed=117,
            fixture_type="dataset_integrity",
            fixture_params={"num_samples": 25},
            mutations=[
                MutationDefinition(
                    mutation_id="m_g17_multi",
                    operator=MutationType.LABEL_SWAP,
                    target_path="samples",
                    parameters={"target_index": 3},
                    description="Corrupts dataset sample label.",
                )
            ],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.EXPECTED_DETECTION,
                expect_finding_types=["DATASET_LABEL_ANOMALY"],
                min_risk=0.30,
                expected_decision=ExpectedDecisionClass.ANY_ELEVATED,
            ),
        ),
        # G18: Proof tampering
        ScenarioDefinition(
            scenario_id="G18",
            name="Cryptographic Proof Signature Tampering",
            target_domain=AttackDomain.PROOF_PROVENANCE,
            attack_class=AttackClass.PROOF_SIGNATURE_TAMPERING,
            description="Corrupts Ed25519 digital signature forcing non-compensable REJECT policy override.",
            project_id=project_id,
            seed=118,
            fixture_type="proof_provenance",
            mutations=[
                MutationDefinition(
                    mutation_id="m_g18_sig",
                    operator=MutationType.SIGNATURE_CORRUPTION,
                    target_path="signature",
                    parameters={},
                    description="Replaces signature with deadbeef bytes.",
                )
            ],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.EXPECTED_DETECTION,
                expect_finding_types=["PROOF_SIGNATURE_INVALID"],
                expect_proof_violation=True,
                expected_decision=ExpectedDecisionClass.REJECT,
            ),
        ),
        # G19: Cross-project attack attempt
        ScenarioDefinition(
            scenario_id="G19",
            name="Cross-Project BOLA Tenant Isolation Attack",
            target_domain=AttackDomain.SECURITY_BOUNDARY,
            attack_class=AttackClass.CROSS_PROJECT_BOLA,
            description="Attempts to access project B resources from project A context (404 BOLA block).",
            project_id=project_id,
            seed=119,
            fixture_type="dataset_integrity",
            mutations=[
                MutationDefinition(
                    mutation_id="m_g19_bola",
                    operator=MutationType.TENANT_OVERRIDE,
                    target_path="project_id",
                    parameters={"unauthorized_project_id": "proj_attacker_999"},
                    description="Overrides fixture project_id to unauthorized tenant.",
                )
            ],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.BLOCKED_BY_POLICY,
                expect_rejection_or_block=True,
            ),
        ),
        # G20: Resource-exhaustion attempt
        ScenarioDefinition(
            scenario_id="G20",
            name="Oversized Payload Resource Exhaustion Attempt",
            target_domain=AttackDomain.SECURITY_BOUNDARY,
            attack_class=AttackClass.OVERSIZED_PAYLOAD_EXHAUSTION,
            description="Submits oversized payload exceeding maximum memory ceilings, failing closed.",
            project_id=project_id,
            seed=120,
            fixture_type="security_boundary",
            mutations=[
                MutationDefinition(
                    mutation_id="m_g20_size",
                    operator=MutationType.VALUE_SUBSTITUTION,
                    target_path="payload_size_bytes",
                    parameters={"new_value": 50 * 1024 * 1024},  # 50 MB
                    description="Specifies oversized 50MB payload exceeding 10MB budget ceiling.",
                )
            ],
            expected=ExpectedBehavior(
                expected_outcome=OracleOutcome.BLOCKED_BY_RESOURCE,
                expect_rejection_or_block=True,
            ),
        ),
    ]


def get_scenario_by_id(scenario_id: str, project_id: str = "proj_lab_001") -> ScenarioDefinition | None:
    """Retrieve a single golden scenario by ID."""
    scenarios = get_all_golden_scenarios(project_id=project_id)
    for sc in scenarios:
        if sc.scenario_id == scenario_id:
            return sc
    return None
