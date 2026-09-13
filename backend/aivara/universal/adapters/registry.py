"""Deterministic Adapter Registry for Universal Evidence Normalization (Phase 12.2).

Enforces:
- Exactly seven registered production domains.
- Rejection of duplicate registrations.
- Rejection of unknown / unregistered domains.
- Thread-safe, deterministic domain lookup in canonical Phase 12.1 order.
"""

from __future__ import annotations

import threading
from typing import Dict, List, Optional

from aivara.universal.adapters.backdoor_adapter import BackdoorTriggerEvidenceAdapter
from aivara.universal.adapters.base import BaseEvidenceAdapter
from aivara.universal.adapters.behavioral_adapter import BehavioralAnalysisEvidenceAdapter
from aivara.universal.adapters.contributor_adapter import ContributorRiskEvidenceAdapter
from aivara.universal.adapters.dataset_adapter import DatasetIntegrityEvidenceAdapter
from aivara.universal.adapters.drift_adapter import DistributionShiftEvidenceAdapter
from aivara.universal.adapters.inference_adapter import InferenceIntegrityEvidenceAdapter
from aivara.universal.adapters.model_adapter import ModelIntegrityEvidenceAdapter
from aivara.universal.enums import SubsystemDomain
from aivara.universal.exceptions import DuplicateAdapterError, UnknownDomainError


class AdapterRegistry:
    """Registry maintaining domain-to-adapter bindings for universal normalization."""

    def __init__(self) -> None:
        self._adapters: Dict[SubsystemDomain, BaseEvidenceAdapter] = {}
        self._lock = threading.Lock()

    def register(self, adapter: BaseEvidenceAdapter) -> None:
        """Register a domain adapter. Rejects duplicates."""
        with self._lock:
            domain = adapter.domain
            if not isinstance(domain, SubsystemDomain):
                raise UnknownDomainError(f"Invalid subsystem domain: {domain}")
            if domain in self._adapters:
                raise DuplicateAdapterError(
                    f"Adapter for domain '{domain.value}' is already registered."
                )
            self._adapters[domain] = adapter

    def get_adapter(self, domain: SubsystemDomain) -> BaseEvidenceAdapter:
        """Retrieve the adapter for a specific domain. Rejects unknown domains."""
        with self._lock:
            if not isinstance(domain, SubsystemDomain) or domain not in self._adapters:
                domain_val = getattr(domain, "value", str(domain))
                raise UnknownDomainError(f"No adapter registered for domain: {domain_val}")
            return self._adapters[domain]

    def has_adapter(self, domain: SubsystemDomain) -> bool:
        """Check if an adapter exists for the given domain."""
        with self._lock:
            return domain in self._adapters

    def list_registered_domains(self) -> List[SubsystemDomain]:
        """Return registered domains strictly sorted by canonical Phase 12.1 domain ordering."""
        with self._lock:
            canonical_order = list(SubsystemDomain)
            return [d for d in canonical_order if d in self._adapters]

    def count(self) -> int:
        """Return count of registered adapters."""
        with self._lock:
            return len(self._adapters)


_DEFAULT_REGISTRY: Optional[AdapterRegistry] = None
_REGISTRY_LOCK = threading.Lock()


def get_default_adapter_registry() -> AdapterRegistry:
    """Get or initialize the authoritative default registry containing all 7 frozen adapters."""
    global _DEFAULT_REGISTRY
    with _REGISTRY_LOCK:
        if _DEFAULT_REGISTRY is None:
            registry = AdapterRegistry()
            registry.register(DatasetIntegrityEvidenceAdapter())
            registry.register(ContributorRiskEvidenceAdapter())
            registry.register(ModelIntegrityEvidenceAdapter())
            registry.register(BehavioralAnalysisEvidenceAdapter())
            registry.register(BackdoorTriggerEvidenceAdapter())
            registry.register(InferenceIntegrityEvidenceAdapter())
            registry.register(DistributionShiftEvidenceAdapter())
            _DEFAULT_REGISTRY = registry
        return _DEFAULT_REGISTRY
