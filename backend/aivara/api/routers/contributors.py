"""Contributors API router."""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from aivara.api.envelope import ApiResponse
from aivara.database.connection import get_db
from aivara.domain.schemas import ContributorRead, ContributorCreate
from aivara.services.contributor_service import ContributorService

router = APIRouter(prefix="/contributors", tags=["contributors"])


@router.get("", response_model=ApiResponse[list[ContributorRead]])
async def list_contributors(project_id: str, db: Session = Depends(get_db)):
    """List contributors for a project."""
    service = ContributorService(db)
    return ApiResponse(data=service.list_contributors(project_id))


@router.post("", response_model=ApiResponse[ContributorRead], status_code=status.HTTP_201_CREATED)
async def create_contributor(payload: ContributorCreate, db: Session = Depends(get_db)):
    """Register a new contributor."""
    service = ContributorService(db)
    return ApiResponse(data=service.create_contributor(payload))


@router.get("/{contributor_id}", response_model=ApiResponse[ContributorRead])
async def get_contributor(contributor_id: str, db: Session = Depends(get_db)):
    """Get contributor by ID."""
    service = ContributorService(db)
    return ApiResponse(data=service.get_contributor(contributor_id))
