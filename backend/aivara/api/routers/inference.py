"""Inference API router."""

from fastapi import APIRouter
from aivara.api.envelope import ApiResponse

router = APIRouter(prefix="/inference", tags=["inference"])


@router.get("/records", response_model=ApiResponse[list])
async def list_inference_records():
    """List sealed inference records."""
    return ApiResponse(data=[])
