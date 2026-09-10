"""Abstract base class for dataset format parsers."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from aivara.dataset.schemas import CanonicalDatasetManifest, DatasetFormat


class DatasetParserBase(ABC):
    """Contract that all dataset format parsers must implement."""

    @property
    @abstractmethod
    def format(self) -> DatasetFormat:
        """Supported format enum."""
        pass

    @abstractmethod
    def parse(self, dataset_root: Path) -> CanonicalDatasetManifest:
        """Parse dataset at root and return an immutable CanonicalDatasetManifest."""
        pass
