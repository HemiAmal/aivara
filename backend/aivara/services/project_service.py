"""Project service for managing workspace projects."""

from typing import List
from sqlalchemy.orm import Session

from aivara.database.models import ProjectModel
from aivara.domain.schemas import ProjectRead, ProjectCreate, ProjectUpdate
from aivara.core.exceptions import NotFoundException


class ProjectService:
    """Foundational service managing projects."""

    def __init__(self, db: Session):
        self.db = db

    def list_projects(self) -> List[ProjectRead]:
        projects = self.db.query(ProjectModel).all()
        return [ProjectRead.model_validate(p) for p in projects]

    def get_project(self, project_id: str) -> ProjectRead:
        project = self.db.query(ProjectModel).filter(ProjectModel.id == project_id).first()
        if not project:
            raise NotFoundException(f"Project '{project_id}' not found.")
        return ProjectRead.model_validate(project)

    def create_project(self, data: ProjectCreate) -> ProjectRead:
        project = ProjectModel(
            name=data.name,
            description=data.description,
            config_json=data.config,
        )
        self.db.add(project)
        self.db.commit()
        self.db.refresh(project)
        return ProjectRead.model_validate(project)

    def update_project(self, project_id: str, data: ProjectUpdate) -> ProjectRead:
        project = self.db.query(ProjectModel).filter(ProjectModel.id == project_id).first()
        if not project:
            raise NotFoundException(f"Project '{project_id}' not found.")
        if data.name is not None:
            project.name = data.name
        if data.description is not None:
            project.description = data.description
        if data.status is not None:
            project.status = data.status
        if data.config is not None:
            project.config_json = data.config
        self.db.commit()
        self.db.refresh(project)
        return ProjectRead.model_validate(project)
