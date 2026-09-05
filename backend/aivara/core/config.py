"""Typed configuration system for AIVARA."""

from pathlib import Path
from typing import Literal
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def get_default_base_dir() -> Path:
    """Resolve base project directory from package location."""
    # backend/aivara/core/config.py -> parents: [core, aivara, backend, AiVara]
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "docs" / "ARCHITECTURE.md").exists():
            return parent
    return Path.cwd()


class Settings(BaseSettings):
    """AIVARA system settings with environment variable override support."""

    model_config = SettingsConfigDict(
        env_prefix="AIVARA_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "AIVARA"
    app_version: str = "0.1.0"
    dev_mode: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    # Server binding (localhost only by default)
    host: str = "127.0.0.1"
    port: int = 8000

    # Paths - resolved relative to project base directory
    base_dir: Path = Field(default_factory=get_default_base_dir)

    @property
    def data_dir(self) -> Path:
        return self.base_dir / "data"

    @property
    def database_path(self) -> Path:
        return self.data_dir / "aivara.db"

    @property
    def database_url(self) -> str:
        # SQLite URL format
        db_file = str(self.database_path.resolve()).replace("\\", "/")
        return f"sqlite:///{db_file}"

    @property
    def model_dir(self) -> Path:
        return self.data_dir / "models"

    @property
    def model_cache_dir(self) -> Path:
        return self.data_dir / "model_cache"

    @property
    def dataset_dir(self) -> Path:
        return self.data_dir / "datasets"

    @property
    def report_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def temp_dir(self) -> Path:
        return self.data_dir / "temp"

    @property
    def provenance_dir(self) -> Path:
        return self.data_dir / "provenance"

    def ensure_directories(self) -> None:
        """Ensure all required local data storage directories exist."""
        for directory in [
            self.data_dir,
            self.model_dir,
            self.model_cache_dir,
            self.dataset_dir,
            self.report_dir,
            self.temp_dir,
            self.provenance_dir,
        ]:
            directory.mkdir(parents=True, exist_ok=True)


# Global settings instance singleton
settings = Settings()
