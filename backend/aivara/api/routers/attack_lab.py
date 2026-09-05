"""Attack simulation lab router."""

from fastapi import APIRouter
from aivara.api.envelope import ApiResponse

router = APIRouter(prefix="/attack_lab", tags=["attack_lab"])


@router.get("/status", response_model=ApiResponse[dict])
async def get_attack_lab_status():
    """Attack lab status placeholder."""
    return ApiResponse(data={"status": "ready", "simulations_enabled": False})
