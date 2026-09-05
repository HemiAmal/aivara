"""SQLite Database connection and engine initialization for AIVARA."""

from typing import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from aivara.core.config import settings
from aivara.core.logging import get_logger

logger = get_logger(__name__)

# Base declarative class for ORM models
Base = declarative_base()

# SQLAlchemy engine configured for local SQLite with WAL mode
engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},
    echo=settings.dev_mode,
)


@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enforce foreign keys and WAL mode on every SQLite connection."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Initialize SQLite database file and schema foundation cleanly."""
    settings.ensure_directories()
    logger.info("Initializing database at: %s", settings.database_path)
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI database session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
