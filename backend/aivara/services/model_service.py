"""AI Model service for managing model registration."""

from typing import List
from sqlalchemy.orm import Session

from aivara.database.models import AIModelModel, ProjectModel
from aivara.domain.schemas import AIModelRead, AIModelCreate
from aivara.core.exceptions import NotFoundException


class AIModelService:
    """Service for managing AI model registrations within a project."""

    def __init__(self, db: Session):
        self.db = db

    def _require_project(self, project_id: str) -> None:
        project = self.db.query(ProjectModel).filter(ProjectModel.id == project_id).first()
        if not project:
            raise NotFoundException(f"Project '{project_id}' not found.")

    def list_models(self, project_id: str) -> List[AIModelRead]:
        self._require_project(project_id)
        models = (
            self.db.query(AIModelModel)
            .filter(AIModelModel.project_id == project_id)
            .all()
        )
        return [AIModelRead.model_validate(m) for m in models]

    def get_model(self, model_id: str) -> AIModelRead:
        model = self.db.query(AIModelModel).filter(AIModelModel.id == model_id).first()
        if not model:
            raise NotFoundException(f"Model '{model_id}' not found.")
        return AIModelRead.model_validate(model)

    def create_model(self, data: AIModelCreate) -> AIModelRead:
        self._require_project(data.project_id)
        model = AIModelModel(
            project_id=data.project_id,
            name=data.name,
            format=data.format.value,
            architecture=data.architecture,
            version=data.version,
            file_path=data.file_path,
            file_hash_sha256=data.file_hash_sha256,
            file_size_bytes=data.file_size_bytes,
            access_level=data.access_level.value,
            metadata_json=data.metadata_json,
        )
        self.db.add(model)
        self.db.commit()
        self.db.refresh(model)
        return AIModelRead.model_validate(model)
