"""AIVARA Attack & Tampering Demonstration Lab (Phase 4.15).

Converts cryptographic provenance and audit security guarantees established
in Phases 4.1–4.14 into controlled, deterministic, reproducible, reversible,
isolated, and safe attack demonstrations:
  - ATTACK-01: Provenance Record Tampering
  - ATTACK-02: Digital Signature Forgery
  - ATTACK-03: Replay Attack
  - ATTACK-04: Audit Event Tampering
  - ATTACK-05: Direct Database Tampering
  - ATTACK-06: Provenance Chain Manipulation
  - ATTACK-07: Cross-Project Evidence Substitution
  - ATTACK-08: Key Lifecycle Attack
  - ATTACK-09: Combined Multi-Layer Attack
  - ATTACK-10: Attack Lifecycle / Restoration
"""

from aivara.attack_lab.models import (
    AttackCategory,
    AttackExecutionSummary,
    AttackResult,
    AttackScenario,
    AttackSubResult,
)
from aivara.attack_lab.runner import AttackLabRunner
from aivara.attack_lab.scenarios import (
    get_scenario_by_id,
    list_all_scenarios,
    run_scenario_by_id,
)

__all__ = [
    "AttackCategory",
    "AttackScenario",
    "AttackSubResult",
    "AttackResult",
    "AttackExecutionSummary",
    "AttackLabRunner",
    "list_all_scenarios",
    "get_scenario_by_id",
    "run_scenario_by_id",
]
