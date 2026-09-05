"""Dataset service for managing datasets and versions."""

from typing import List
from sqlalchemy.orm import Session

from aivara.database.models import DatasetModel, DatasetVersionModel, ProjectModel
from aivara.domain.schemas import (
    DatasetRead,
    DatasetCreate,
    DatasetVersionRead,
    DatasetVersionCreate,
)
from aivara.core.exceptions import NotFoundException


class DatasetService:
    """Service for managing datasets and dataset versions within a project."""

    def __init__(self, db: Session):
        self.db = db

    def _require_project(self, project_id: str) -> None:
        project = self.db.query(ProjectModel).filter(ProjectModel.id == project_id).first()
        if not project:
            raise NotFoundException(f"Project '{project_id}' not found.")

    def list_datasets(self, project_id: str) -> List[DatasetRead]:
        self._require_project(project_id)
        datasets = (
            self.db.query(DatasetModel)
            .filter(DatasetModel.project_id == project_id)
            .all()
        )
        return [DatasetRead.model_validate(d) for d in datasets]

    def get_dataset(self, dataset_id: str) -> DatasetRead:
        dataset = self.db.query(DatasetModel).filter(DatasetModel.id == dataset_id).first()
        if not dataset:
            raise NotFoundException(f"Dataset '{dataset_id}' not found.")
        return DatasetRead.model_validate(dataset)

    def create_dataset(self, data: DatasetCreate) -> DatasetRead:
        self._require_project(data.project_id)
        dataset = DatasetModel(
            project_id=data.project_id,
            name=data.name,
            format=data.format.value,
            source=data.source,
            description=data.description,
            metadata_json=data.metadata_json,
        )
        self.db.add(dataset)
        self.db.commit()
        self.db.refresh(dataset)
        return DatasetRead.model_validate(dataset)

    # ---- Dataset Versions ----

    def list_versions(self, dataset_id: str) -> List[DatasetVersionRead]:
        dataset = self.db.query(DatasetModel).filter(DatasetModel.id == dataset_id).first()
        if not dataset:
            raise NotFoundException(f"Dataset '{dataset_id}' not found.")
        versions = (
            self.db.query(DatasetVersionModel)
            .filter(DatasetVersionModel.dataset_id == dataset_id)
            .all()
        )
        return [DatasetVersionRead.model_validate(v) for v in versions]

    def create_version(self, data: DatasetVersionCreate) -> DatasetVersionRead:
        dataset = self.db.query(DatasetModel).filter(DatasetModel.id == data.dataset_id).first()
        if not dataset:
            raise NotFoundException(f"Dataset '{data.dataset_id}' not found.")
        version = DatasetVersionModel(
            dataset_id=data.dataset_id,
            version_label=data.version_label,
            dataset_hash=data.dataset_hash,
            sample_count=data.sample_count,
            metadata_json=data.metadata_json,
        )
        self.db.add(version)
        self.db.commit()
        self.db.refresh(version)
        return DatasetVersionRead.model_validate(version)
