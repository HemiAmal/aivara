"""Evidence API router."""

from fastapi import APIRouter
from aivara.api.envelope import ApiResponse

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.get("", response_model=ApiResponse[list])
async def list_evidence():
    """List collected evidence records."""
    return ApiResponse(data=[])
