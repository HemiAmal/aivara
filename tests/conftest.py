"""Pytest fixtures for AIVARA backend testing."""

import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from aivara.database.connection import Base, get_db
from aivara.main import app


@pytest.fixture(scope="session")
def test_temp_dir():
    """Create isolated temporary directory for test storage."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def test_settings(test_temp_dir):
    """Provide clean settings with test SQLite database."""
    from aivara.core.config import Settings
    return Settings(
        app_name="AIVARA_TEST",
        dev_mode=True,
        base_dir=test_temp_dir,
    )


@pytest.fixture
def test_db_session(tmp_path):
    """Provide isolated file SQLite database session for testing.

    Uses tmp_path (per-test unique) instead of session-scoped temp dir
    so each test gets a clean database. Foreign keys are enforced.
    """
    test_db_path = tmp_path / "test.db"
    test_engine = create_engine(
        f"sqlite:///{test_db_path}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(test_engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

    Base.metadata.create_all(bind=test_engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)
        test_engine.dispose()


@pytest.fixture
def client(test_db_session):
    """FastAPI TestClient with overridden database session."""
    def override_get_db():
        try:
            yield test_db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
