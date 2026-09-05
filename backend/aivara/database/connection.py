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


def reconcile_provenance_schema(db_engine=None) -> None:
    """Safely reconcile provenance_records schema on existing SQLite databases (Phase 4.11).

    Ensures that existing databases created prior to Phase 4.11 acquire the
    nullable 'nonce' and 'signer_key_id' columns and required unique indexes
    without destroying or recreating existing data.
    """
    target_engine = db_engine or engine
    from sqlalchemy import inspect, text

    inspector = inspect(target_engine)
    if "provenance_records" not in inspector.get_table_names():
        return

    existing_columns = {col["name"] for col in inspector.get_columns("provenance_records")}

    with target_engine.begin() as conn:
        if "nonce" not in existing_columns:
            logger.info("Reconciling schema: adding 'nonce' column to provenance_records")
            conn.execute(text("ALTER TABLE provenance_records ADD COLUMN nonce VARCHAR(64);"))

        if "signer_key_id" not in existing_columns:
            logger.info("Reconciling schema: adding 'signer_key_id' column to provenance_records")
            conn.execute(text("ALTER TABLE provenance_records ADD COLUMN signer_key_id VARCHAR(64);"))

        existing_indexes = {idx["name"]: idx for idx in inspector.get_indexes("provenance_records")}

        seq_idx = existing_indexes.get("ix_provenance_records_sequence")
        if seq_idx and not seq_idx.get("unique", False):
            logger.info("Upgrading ix_provenance_records_sequence to UNIQUE")
            conn.execute(text("DROP INDEX IF EXISTS ix_provenance_records_sequence;"))
            conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_provenance_records_sequence "
                "ON provenance_records (project_id, sequence_number);"
            ))
        elif not seq_idx:
            conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_provenance_records_sequence "
                "ON provenance_records (project_id, sequence_number);"
            ))

        if "ix_provenance_records_project_nonce" not in existing_indexes:
            logger.info("Creating unique index ix_provenance_records_project_nonce")
            conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_provenance_records_project_nonce "
                "ON provenance_records (project_id, nonce);"
            ))

        if "ix_provenance_records_project_record_hash" not in existing_indexes:
            logger.info("Creating unique index ix_provenance_records_project_record_hash")
            conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_provenance_records_project_record_hash "
                "ON provenance_records (project_id, record_hash);"
            ))


def init_db(db_engine=None) -> None:
    """Initialize SQLite database file and schema foundation cleanly."""
    target_engine = db_engine or engine
    settings.ensure_directories()
    logger.info("Initializing database at: %s", settings.database_path)
    Base.metadata.create_all(bind=target_engine)
    reconcile_provenance_schema(target_engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI database session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
