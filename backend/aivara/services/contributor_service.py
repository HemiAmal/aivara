"""Contributor service for managing dataset/model contributors."""

from typing import List
from sqlalchemy.orm import Session

from aivara.database.models import ContributorModel, ProjectModel
from aivara.domain.schemas import ContributorRead, ContributorCreate
from aivara.core.exceptions import NotFoundException


class ContributorService:
    """Service for managing contributors within a project."""

    def __init__(self, db: Session):
        self.db = db

    def _require_project(self, project_id: str) -> None:
        project = self.db.query(ProjectModel).filter(ProjectModel.id == project_id).first()
        if not project:
            raise NotFoundException(f"Project '{project_id}' not found.")

    def list_contributors(self, project_id: str) -> List[ContributorRead]:
        self._require_project(project_id)
        contributors = (
            self.db.query(ContributorModel)
            .filter(ContributorModel.project_id == project_id)
            .all()
        )
        return [ContributorRead.model_validate(c) for c in contributors]

    def get_contributor(self, contributor_id: str) -> ContributorRead:
        contributor = self.db.query(ContributorModel).filter(ContributorModel.id == contributor_id).first()
        if not contributor:
            raise NotFoundException(f"Contributor '{contributor_id}' not found.")
        return ContributorRead.model_validate(contributor)

    def create_contributor(self, data: ContributorCreate) -> ContributorRead:
        self._require_project(data.project_id)
        contributor = ContributorModel(
            project_id=data.project_id,
            external_id=data.external_id,
            name=data.name,
            source=data.source,
            metadata_json=data.metadata_json,
        )
        self.db.add(contributor)
        self.db.commit()
        self.db.refresh(contributor)
        return ContributorRead.model_validate(contributor)
