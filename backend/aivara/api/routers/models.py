"""AI Models API router."""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from aivara.api.envelope import ApiResponse
from aivara.database.connection import get_db
from aivara.domain.schemas import AIModelRead, AIModelCreate
from aivara.services.model_service import AIModelService

router = APIRouter(prefix="/models", tags=["models"])


@router.get("", response_model=ApiResponse[list[AIModelRead]])
async def list_models(project_id: str, db: Session = Depends(get_db)):
    """List models for a project."""
    service = AIModelService(db)
    return ApiResponse(data=service.list_models(project_id))


@router.post("", response_model=ApiResponse[AIModelRead], status_code=status.HTTP_201_CREATED)
async def create_model(payload: AIModelCreate, db: Session = Depends(get_db)):
    """Register a new AI model."""
    service = AIModelService(db)
    return ApiResponse(data=service.create_model(payload))


@router.get("/{model_id}", response_model=ApiResponse[AIModelRead])
async def get_model(model_id: str, db: Session = Depends(get_db)):
    """Get model by ID."""
    service = AIModelService(db)
    return ApiResponse(data=service.get_model(model_id))
