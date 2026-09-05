"""Provenance ledger API router."""

from fastapi import APIRouter
from aivara.api.envelope import ApiResponse

router = APIRouter(prefix="/provenance", tags=["provenance"])


@router.get("/chain", response_model=ApiResponse[list])
async def get_provenance_chain():
    """Retrieve hash-linked provenance records."""
    return ApiResponse(data=[])
