"""Domain adapters package for Universal Evidence Normalization (Phase 12.2)."""

from aivara.universal.adapters.base import BaseEvidenceAdapter
from aivara.universal.adapters.registry import AdapterRegistry, get_default_adapter_registry
from aivara.universal.adapters.dataset_adapter import DatasetIntegrityEvidenceAdapter
from aivara.universal.adapters.contributor_adapter import ContributorRiskEvidenceAdapter
from aivara.universal.adapters.model_adapter import ModelIntegrityEvidenceAdapter
from aivara.universal.adapters.behavioral_adapter import BehavioralAnalysisEvidenceAdapter
from aivara.universal.adapters.backdoor_adapter import BackdoorTriggerEvidenceAdapter
from aivara.universal.adapters.inference_adapter import InferenceIntegrityEvidenceAdapter
from aivara.universal.adapters.drift_adapter import DistributionShiftEvidenceAdapter

__all__ = [
    "BaseEvidenceAdapter",
    "AdapterRegistry",
    "get_default_adapter_registry",
    "DatasetIntegrityEvidenceAdapter",
    "ContributorRiskEvidenceAdapter",
    "ModelIntegrityEvidenceAdapter",
    "BehavioralAnalysisEvidenceAdapter",
    "BackdoorTriggerEvidenceAdapter",
    "InferenceIntegrityEvidenceAdapter",
    "DistributionShiftEvidenceAdapter",
]
