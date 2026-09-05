"""Findings API router."""

from fastapi import APIRouter
from aivara.api.envelope import ApiResponse

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=ApiResponse[list])
async def list_findings():
    """List audit findings."""
    return ApiResponse(data=[])
