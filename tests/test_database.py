"""Tests for SQLite database foundation and initialization."""

from sqlalchemy import text
from aivara.database.models import ProjectModel


def test_database_initialization_and_table_creation(test_db_session):
    """Verify SQLite connection is live and projects table exists."""
    result = test_db_session.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='projects';"))
    table_name = result.scalar()
    assert table_name == "projects"


def test_project_model_crud(test_db_session):
    """Verify basic CRUD on the foundational ProjectModel."""
    project = ProjectModel(
        name="Assurance Project Alpha",
        description="Offline CV Verification engagement",
        config_json={"sample_size": 500},
    )
    test_db_session.add(project)
    test_db_session.commit()

    retrieved = test_db_session.query(ProjectModel).filter_by(name="Assurance Project Alpha").first()
    assert retrieved is not None
    assert retrieved.id is not None
    assert retrieved.status == "active"
    assert retrieved.config_json["sample_size"] == 500
