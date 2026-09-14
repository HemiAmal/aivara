"""AIVARA Attack Simulation Lab (Phase 13).

Provides controlled, deterministic, offline, and safe defensive testing of the
Phase 12 Universal Assurance Core.
"""

from __future__ import annotations

from aivara.attacklab.comparator import DifferentialComparator
from aivara.attacklab.controls import CleanControlManager
from aivara.attacklab.enums import (
    AttackClass,
    AttackDomain,
    ExpectedDecisionClass,
    MutationType,
    OracleOutcome,
    SimulationStatus,
)
from aivara.attacklab.evidence import SimulationEvidenceBridge
from aivara.attacklab.exceptions import (
    AttackLabError,
    FixtureGenerationError,
    InvalidScenarioError,
    MutationError,
    OracleEvaluationError,
    ResourceBudgetExceededError,
    SecurityBoundaryViolationError,
)
from aivara.attacklab.fixtures import SyntheticFixtureGenerator
from aivara.attacklab.mutations import MutationEngine
from aivara.attacklab.oracle import SimulationOracle
from aivara.attacklab.reporting import SimulationReportGenerator
from aivara.attacklab.runner import AttackLabRunner
from aivara.attacklab.scenarios import get_all_golden_scenarios, get_scenario_by_id
from aivara.attacklab.schemas import (
    ExpectedBehavior,
    FixturePayload,
    MutationDefinition,
    PipelineExecutionTrace,
    ScenarioDefinition,
    SimulationOutcome,
    SimulationReport,
)

__all__ = [
    # Enums
    "AttackDomain",
    "AttackClass",
    "MutationType",
    "SimulationStatus",
    "OracleOutcome",
    "ExpectedDecisionClass",
    # Exceptions
    "AttackLabError",
    "InvalidScenarioError",
    "FixtureGenerationError",
    "MutationError",
    "OracleEvaluationError",
    "ResourceBudgetExceededError",
    "SecurityBoundaryViolationError",
    # Schemas
    "MutationDefinition",
    "ExpectedBehavior",
    "ScenarioDefinition",
    "FixturePayload",
    "PipelineExecutionTrace",
    "SimulationOutcome",
    "SimulationReport",
    # Core Components
    "SyntheticFixtureGenerator",
    "MutationEngine",
    "CleanControlManager",
    "DifferentialComparator",
    "SimulationEvidenceBridge",
    "SimulationOracle",
    "SimulationReportGenerator",
    "AttackLabRunner",
    "get_all_golden_scenarios",
    "get_scenario_by_id",
]
