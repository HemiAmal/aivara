"""Registry of all Phase 4.15 attack demonstration scenarios."""

from __future__ import annotations

from typing import Callable, Dict, List, Tuple

from aivara.attack_lab.models import AttackResult, AttackScenario
from aivara.attack_lab.scenarios.attack_01_provenance_tampering import (
    get_scenario as get_s01,
    run_attack_01,
)
from aivara.attack_lab.scenarios.attack_02_signature_forgery import (
    get_scenario as get_s02,
    run_attack_02,
)
from aivara.attack_lab.scenarios.attack_03_replay_attack import (
    get_scenario as get_s03,
    run_attack_03,
)
from aivara.attack_lab.scenarios.attack_04_audit_tampering import (
    get_scenario as get_s04,
    run_attack_04,
)
from aivara.attack_lab.scenarios.attack_05_direct_database_tampering import (
    get_scenario as get_s05,
    run_attack_05,
)
from aivara.attack_lab.scenarios.attack_06_provenance_chain_manipulation import (
    get_scenario as get_s06,
    run_attack_06,
)
from aivara.attack_lab.scenarios.attack_07_cross_project_substitution import (
    get_scenario as get_s07,
    run_attack_07,
)
from aivara.attack_lab.scenarios.attack_08_key_lifecycle_attack import (
    get_scenario as get_s08,
    run_attack_08,
)
from aivara.attack_lab.scenarios.attack_09_combined_multilayer_attack import (
    get_scenario as get_s09,
    run_attack_09,
)
from aivara.attack_lab.scenarios.attack_10_lifecycle_restoration import (
    get_scenario as get_s10,
    run_attack_10,
)

# Canonical mapping of scenario ID to (metadata_getter, runner_fn)
SCENARIO_REGISTRY: Dict[str, Tuple[Callable[[], AttackScenario], Callable[[], AttackResult]]] = {
    "ATTACK-01": (get_s01, run_attack_01),
    "ATTACK-02": (get_s02, run_attack_02),
    "ATTACK-03": (get_s03, run_attack_03),
    "ATTACK-04": (get_s04, run_attack_04),
    "ATTACK-05": (get_s05, run_attack_05),
    "ATTACK-06": (get_s06, run_attack_06),
    "ATTACK-07": (get_s07, run_attack_07),
    "ATTACK-08": (get_s08, run_attack_08),
    "ATTACK-09": (get_s09, run_attack_09),
    "ATTACK-10": (get_s10, run_attack_10),
}


def normalize_attack_id(raw_id: str) -> str:
    """Normalize input strings such as 'attack-01', 'ATTACK-001', '1', etc. to 'ATTACK-01'."""
    cleaned = raw_id.strip().upper()
    if cleaned.startswith("ATTACK-"):
        num_part = cleaned.split("-")[1]
        try:
            num = int(num_part)
            return f"ATTACK-{num:02d}"
        except ValueError:
            return cleaned
    try:
        num = int(cleaned)
        return f"ATTACK-{num:02d}"
    except ValueError:
        pass
    return cleaned


def list_all_scenarios() -> List[AttackScenario]:
    """Return static metadata for all registered attack scenarios."""
    return [getter() for getter, _ in SCENARIO_REGISTRY.values()]


def get_scenario_by_id(attack_id: str) -> AttackScenario:
    """Retrieve metadata for a specific scenario."""
    norm = normalize_attack_id(attack_id)
    if norm not in SCENARIO_REGISTRY:
        raise KeyError(f"Unknown attack scenario: {attack_id} (normalized: {norm})")
    return SCENARIO_REGISTRY[norm][0]()


def run_scenario_by_id(attack_id: str) -> AttackResult:
    """Execute a single scenario by its ID."""
    norm = normalize_attack_id(attack_id)
    if norm not in SCENARIO_REGISTRY:
        raise KeyError(f"Unknown attack scenario: {attack_id} (normalized: {norm})")
    return SCENARIO_REGISTRY[norm][1]()
