"""Data models for AIVARA Attack & Tampering Demonstration Lab (Phase 4.15).

Defines structured models for attack scenarios, execution results,
tampering diagnostic evidence, and lifecycle tracking.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AttackCategory(str, Enum):
    """Categorization of controlled attack demonstrations."""

    PROVENANCE = "PROVENANCE"
    SIGNATURE = "SIGNATURE"
    REPLAY = "REPLAY"
    AUDIT = "AUDIT"
    DATABASE = "DATABASE"
    CHAIN = "CHAIN"
    CROSS_PROJECT = "CROSS_PROJECT"
    KEY_LIFECYCLE = "KEY_LIFECYCLE"
    MULTI_LAYER = "MULTI_LAYER"
    LIFECYCLE = "LIFECYCLE"


class AttackScenario(BaseModel):
    """Reusable specification for a controlled attack demonstration scenario."""

    model_config = ConfigDict(frozen=True)

    attack_id: str = Field(..., description="Unique scenario ID, e.g. ATTACK-01")
    attack_name: str = Field(..., description="Human-readable title of the attack")
    category: AttackCategory = Field(..., description="Classification category")
    description: str = Field(..., description="Detailed description of the attack purpose and vector")
    target: str = Field(..., description="Target asset or component under attack")
    prerequisites: List[str] = Field(default_factory=list, description="Requirements before running the attack")
    setup: Dict[str, Any] = Field(default_factory=dict, description="Metadata describing the setup phase")
    attack: Dict[str, Any] = Field(default_factory=dict, description="Metadata describing the attack execution")
    verification: Dict[str, Any] = Field(default_factory=dict, description="Verification engine invoked")
    expected_result: Dict[str, Any] = Field(default_factory=dict, description="Expected failure taxonomy and detection state")
    cleanup: str = Field(..., description="Restoration and cleanup procedure")


class AttackSubResult(BaseModel):
    """Result of an individual mutation or sub-demonstration within an attack scenario."""

    model_config = ConfigDict(frozen=True)

    sub_id: str = Field(..., description="Identifier for this sub-demonstration, e.g. input_hash or sub-B")
    name: str = Field(..., description="Description of the specific mutation")
    target_asset: str = Field(..., description="Specific field or asset tampered with")
    attack_technique: str = Field(..., description="Technique applied (e.g. byte corruption, field modification)")
    original_state: Dict[str, Any] = Field(default_factory=dict, description="Baseline state prior to attack")
    modified_state: Dict[str, Any] = Field(default_factory=dict, description="State after attack injection")
    verification_status: str = Field(..., description="Outcome status from verification engine")
    failure_codes: List[str] = Field(default_factory=list, description="Machine-readable failure codes detected")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Raw structured diagnostic evidence captured")
    detected: bool = Field(..., description="Whether AIVARA successfully detected the attack")
    cleanup_status: str = Field(..., description="Restoration status (e.g. RESTORED, CLEAN)")


class AttackResult(BaseModel):
    """Structured report produced by executing a controlled attack demonstration."""

    model_config = ConfigDict(frozen=True)

    attack_id: str = Field(..., description="Unique scenario identifier")
    attack_name: str = Field(..., description="Title of the attack demonstration")
    target_asset: str = Field(..., description="Primary asset or component targeted")
    attack_technique: str = Field(..., description="Attack methodology used")
    original_state: Dict[str, Any] = Field(default_factory=dict, description="Baseline state before attack")
    modified_state: Dict[str, Any] = Field(default_factory=dict, description="State during or after attack")
    verification_status: str = Field(..., description="Verification classification (e.g. integrity_violation, clean)")
    failure_codes: List[str] = Field(default_factory=list, description="All failure codes identified")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Collected cryptographic diagnostic evidence")
    detected: bool = Field(..., description="True if the attack was detected as intended")
    cleanup_status: str = Field(..., description="Outcome of post-attack restoration")
    sub_results: List[AttackSubResult] = Field(default_factory=list, description="Results of detailed sub-demonstrations")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional contextual details")


class AttackExecutionSummary(BaseModel):
    """Aggregated execution summary across multiple attack demonstrations."""

    model_config = ConfigDict(frozen=True)

    total_scenarios: int
    scenarios_executed: int
    scenarios_detected: int
    all_detected: bool
    results: List[AttackResult]
