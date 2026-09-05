"""Datasets API router."""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from aivara.api.envelope import ApiResponse
from aivara.database.connection import get_db
from aivara.domain.schemas import DatasetRead, DatasetCreate, DatasetVersionRead, DatasetVersionCreate
from aivara.services.dataset_service import DatasetService

router = APIRouter(prefix="/datasets", tags=["datasets"])


@router.get("", response_model=ApiResponse[list[DatasetRead]])
async def list_datasets(project_id: str, db: Session = Depends(get_db)):
    """List datasets for a project."""
    service = DatasetService(db)
    return ApiResponse(data=service.list_datasets(project_id))


@router.post("", response_model=ApiResponse[DatasetRead], status_code=status.HTTP_201_CREATED)
async def create_dataset(payload: DatasetCreate, db: Session = Depends(get_db)):
    """Register a new dataset."""
    service = DatasetService(db)
    return ApiResponse(data=service.create_dataset(payload))


@router.get("/{dataset_id}", response_model=ApiResponse[DatasetRead])
async def get_dataset(dataset_id: str, db: Session = Depends(get_db)):
    """Get dataset by ID."""
    service = DatasetService(db)
    return ApiResponse(data=service.get_dataset(dataset_id))


@router.get("/{dataset_id}/versions", response_model=ApiResponse[list[DatasetVersionRead]])
async def list_dataset_versions(dataset_id: str, db: Session = Depends(get_db)):
    """List versions for a dataset."""
    service = DatasetService(db)
    return ApiResponse(data=service.list_versions(dataset_id))


@router.post("/{dataset_id}/versions", response_model=ApiResponse[DatasetVersionRead], status_code=status.HTTP_201_CREATED)
async def create_dataset_version(dataset_id: str, payload: DatasetVersionCreate, db: Session = Depends(get_db)):
    """Create a new version of a dataset."""
    service = DatasetService(db)
    # Ensure the dataset_id from path matches the payload
    payload.dataset_id = dataset_id
    return ApiResponse(data=service.create_version(payload))
