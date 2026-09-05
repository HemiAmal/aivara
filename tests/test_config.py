"""Tests for typed configuration system."""

from pathlib import Path
from aivara.core.config import Settings


def test_default_configuration_paths(tmp_path):
    """Verify paths are dynamically resolved and relative to base directory."""
    test_settings = Settings(base_dir=tmp_path)

    assert test_settings.app_name == "AIVARA"
    assert test_settings.app_version == "0.1.0"
    assert test_settings.data_dir == tmp_path / "data"
    assert test_settings.database_path == tmp_path / "data" / "aivara.db"
    assert "sqlite:///" in test_settings.database_url
    assert test_settings.model_cache_dir == tmp_path / "data" / "model_cache"
    assert test_settings.report_dir == tmp_path / "data" / "reports"
    assert test_settings.keys_dir == tmp_path / "data" / "keys"


def test_ensure_directories_creates_all_subdirs(tmp_path):
    """Verify ensure_directories creates local folders without errors."""
    test_settings = Settings(base_dir=tmp_path)
    test_settings.ensure_directories()

    assert (tmp_path / "data").exists()
    assert (tmp_path / "data" / "models").exists()
    assert (tmp_path / "data" / "model_cache").exists()
    assert (tmp_path / "data" / "datasets").exists()
    assert (tmp_path / "data" / "reports").exists()
    assert (tmp_path / "data" / "temp").exists()
    assert (tmp_path / "data" / "provenance").exists()
    assert (tmp_path / "data" / "keys").exists()
