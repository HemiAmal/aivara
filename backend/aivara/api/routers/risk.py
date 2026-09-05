"""Risk assessments API router."""

from fastapi import APIRouter
from aivara.api.envelope import ApiResponse

router = APIRouter(prefix="/risk", tags=["risk"])


@router.get("/assessments", response_model=ApiResponse[list])
async def list_risk_assessments():
    """List risk assessments."""
    return ApiResponse(data=[])
