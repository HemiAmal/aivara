"""Pydantic V2 schemas for the AIVARA Attack Simulation Lab (Phase 13)."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from aivara.attacklab.enums import (
    AttackClass,
    AttackDomain,
    ExpectedDecisionClass,
    MutationType,
    OracleOutcome,
    SimulationStatus,
)
from aivara.universal.hashing import compute_payload_hash


def canonical_hash(data: Dict[str, Any]) -> str:
    return compute_payload_hash(data)


class MutationDefinition(BaseModel):
    """Specification of a deterministic mutation operator."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    mutation_id: str = Field(..., description="Unique identifier for the mutation.")
    operator: MutationType = Field(..., description="Type of mutation operator to apply.")
    target_path: str = Field(..., description="JSON path or field key targeted by the mutation.")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Operator-specific parameters.")
    description: str = Field(..., description="Human-readable description of the mutation.")


class ExpectedBehavior(BaseModel):
    """Expected oracle verification criteria for a simulation."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    expected_outcome: OracleOutcome = Field(..., description="Target classified oracle outcome.")
    expect_evidence_domains: List[str] = Field(default_factory=list, description="Expected domains producing evidence.")
    expect_finding_types: List[str] = Field(default_factory=list, description="Expected finding category assertions.")
    expect_proof_violation: bool = Field(default=False, description="Whether proof verification is expected to fail.")
    min_risk: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Minimum expected scalar risk.")
    max_risk: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Maximum expected scalar risk.")
    expected_decision: Optional[ExpectedDecisionClass] = Field(default=None, description="Expected policy decision.")
    expect_rejection_or_block: bool = Field(default=False, description="Whether pipeline is expected to block request.")


class ScenarioDefinition(BaseModel):
    """Immutable, deterministic declaration of an attack simulation scenario."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str = Field(..., description="Canonical scenario identifier (e.g. G01, G02).")
    version: str = Field(default="1.0", description="SemVer version of the scenario specification.")
    name: str = Field(..., description="Human-readable scenario title.")
    target_domain: AttackDomain = Field(..., description="Primary assurance domain targeted.")
    attack_class: AttackClass = Field(..., description="Discrete attack taxonomy class.")
    description: str = Field(..., description="Comprehensive technical explanation of scenario.")
    project_id: str = Field(..., description="Tenant project identifier for isolation.")
    seed: int = Field(default=42, description="Deterministic random seed.")
    fixture_type: str = Field(..., description="Type of synthetic fixture to construct.")
    fixture_params: Dict[str, Any] = Field(default_factory=dict, description="Parameters for fixture generator.")
    mutations: List[MutationDefinition] = Field(default_factory=list, description="Ordered list of mutations to apply.")
    expected: ExpectedBehavior = Field(..., description="Oracle verification expectations.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional descriptive metadata.")

    def compute_scenario_hash(self) -> str:
        """Compute deterministic RFC 8785 canonical hash of scenario definition."""
        return canonical_hash(self.model_dump())


class FixturePayload(BaseModel):
    """Container for synthetic test data with content addressing."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    fixture_id: str = Field(..., description="Unique fixture identifier.")
    fixture_type: str = Field(..., description="Domain fixture type.")
    project_id: str = Field(..., description="Project scoping.")
    data: Dict[str, Any] = Field(..., description="Synthetic data payload.")
    content_hash: str = Field(..., description="SHA-256 canonical hash of payload data.")


class PipelineExecutionTrace(BaseModel):
    """Execution trace of a single Phase 12 pipeline run (Clean or Attack)."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    executed_at: str = Field(..., description="Execution timestamp.")
    success: bool = Field(..., description="Whether pipeline completed without exception.")
    evidence_envelopes: List[Dict[str, Any]] = Field(default_factory=list, description="Generated UniversalEvidenceEnvelopes.")
    finding_types: List[str] = Field(default_factory=list, description="Discovered finding types.")
    risk_score: Optional[float] = Field(default=None, description="Calculated scalar risk score.")
    decision: Optional[str] = Field(default=None, description="Policy decision (ACCEPT, REVIEW, QUARANTINE, REJECT).")
    proof_valid: Optional[bool] = Field(default=None, description="Proof layer verification status.")
    error_message: Optional[str] = Field(default=None, description="Error message if execution failed.")


class SimulationOutcome(BaseModel):
    """Detailed differential outcome and oracle classification for a scenario."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str = Field(..., description="Evaluated scenario identifier.")
    oracle_outcome: OracleOutcome = Field(..., description="Classified outcome state.")
    is_pass: bool = Field(..., description="Whether outcome matches scenario oracle expectations.")
    clean_trace: PipelineExecutionTrace = Field(..., description="Trace of clean control run.")
    attack_trace: PipelineExecutionTrace = Field(..., description="Trace of mutated attack run.")
    risk_delta: Optional[float] = Field(default=0.0, description="Difference in risk (attack - clean).")
    new_findings: List[str] = Field(default_factory=list, description="Findings appearing only in attack run.")
    oracle_reasons: List[str] = Field(default_factory=list, description="Explanatory notes from oracle evaluation.")
    execution_time_ms: float = Field(default=0.0, description="Total execution duration in milliseconds.")


class SimulationReport(BaseModel):
    """Comprehensive, sealed simulation audit dossier."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    report_id: str = Field(..., description="Unique audit report identifier.")
    project_id: str = Field(..., description="Project tenancy scope.")
    created_at: str = Field(..., description="Report generation timestamp.")
    total_scenarios: int = Field(..., description="Total executed scenarios count.")
    passed_scenarios: int = Field(..., description="Scenarios meeting oracle expectations.")
    failed_scenarios: int = Field(..., description="Scenarios failing oracle expectations.")
    outcome_breakdown: Dict[str, int] = Field(default_factory=dict, description="Counts per OracleOutcome class.")
    detection_rate: float = Field(..., description="Ratio of expected detections successfully detected.")
    false_negative_rate: float = Field(..., description="Ratio of false negatives.")
    false_positive_rate: float = Field(..., description="Ratio of false positives.")
    outcomes: List[SimulationOutcome] = Field(default_factory=list, description="Per-scenario evaluation outcomes.")
    report_hash: str = Field(..., description="Deterministic SHA-256 hash of report contents.")
