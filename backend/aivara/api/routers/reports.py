"""Reports API router."""

from fastapi import APIRouter
from aivara.api.envelope import ApiResponse

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("", response_model=ApiResponse[list])
async def list_reports():
    """List generated assurance reports."""
    return ApiResponse(data=[])
