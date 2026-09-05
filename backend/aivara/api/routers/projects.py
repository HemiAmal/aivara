"""Projects API router."""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from aivara.api.envelope import ApiResponse
from aivara.database.connection import get_db
from aivara.domain.schemas import ProjectRead, ProjectCreate, ProjectUpdate
from aivara.services.project_service import ProjectService

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("", response_model=ApiResponse[list[ProjectRead]])
async def list_projects(db: Session = Depends(get_db)):
    """List all projects in workspace."""
    service = ProjectService(db)
    return ApiResponse(data=service.list_projects())


@router.post("", response_model=ApiResponse[ProjectRead], status_code=status.HTTP_201_CREATED)
async def create_project(payload: ProjectCreate, db: Session = Depends(get_db)):
    """Create a new assurance project."""
    service = ProjectService(db)
    return ApiResponse(data=service.create_project(payload))


@router.get("/{project_id}", response_model=ApiResponse[ProjectRead])
async def get_project(project_id: str, db: Session = Depends(get_db)):
    """Get project by ID."""
    service = ProjectService(db)
    return ApiResponse(data=service.get_project(project_id))


@router.patch("/{project_id}", response_model=ApiResponse[ProjectRead])
async def update_project(project_id: str, payload: ProjectUpdate, db: Session = Depends(get_db)):
    """Update project metadata."""
    service = ProjectService(db)
    return ApiResponse(data=service.update_project(project_id, payload))
