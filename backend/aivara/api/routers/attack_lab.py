"""Attack Demonstration Lab API Router (Phase 4.15).

Provides REST endpoints for querying scenario specifications and
triggering controlled, isolated attack demonstrations.
"""

from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, status

from aivara.api.envelope import ApiResponse
from aivara.attack_lab.models import (
    AttackExecutionSummary,
    AttackResult,
    AttackScenario,
)
from aivara.attack_lab.runner import AttackLabRunner

router = APIRouter(prefix="/attack_lab", tags=["attack_lab"])
_runner = AttackLabRunner()


@router.get("/status", response_model=ApiResponse[Dict[str, Any]])
async def get_attack_lab_status():
    """Return status and configuration of the Attack & Tampering Demonstration Lab."""
    scenarios = _runner.list_scenarios()
    return ApiResponse(
        data={
            "status": "ready",
            "demonstrations_enabled": True,
            "total_scenarios": len(scenarios),
            "engine": "AIVARA Cryptographic Attack Lab v4.15",
            "isolation_guarantee": "fully_offline_disposable_environments",
        }
    )


@router.get("/scenarios", response_model=ApiResponse[List[AttackScenario]])
async def list_attack_scenarios():
    """List all registered controlled attack scenarios."""
    scenarios = _runner.list_scenarios()
    return ApiResponse(data=scenarios)


@router.get("/scenarios/{attack_id}", response_model=ApiResponse[AttackScenario])
async def get_attack_scenario(attack_id: str):
    """Get metadata for a specific attack demonstration scenario."""
    try:
        scenario = _runner.get_scenario(attack_id)
        return ApiResponse(data=scenario)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack scenario '{attack_id}' not found.",
        )


@router.post("/run/{attack_id}", response_model=ApiResponse[AttackResult])
async def run_single_attack(attack_id: str):
    """Execute a single controlled attack demonstration in an isolated environment."""
    try:
        result = _runner.run_scenario(attack_id)
        return ApiResponse(data=result)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack scenario '{attack_id}' not found.",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Attack demonstration failed with unhandled error: {exc}",
        )


@router.post("/run_all", response_model=ApiResponse[AttackExecutionSummary])
async def run_all_attacks():
    """Execute all 10 attack demonstrations sequentially in isolation."""
    try:
        summary = _runner.run_all()
        return ApiResponse(data=summary)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Full attack demonstration run failed: {exc}",
        )
