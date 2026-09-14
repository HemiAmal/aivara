"""Phase 12.4 Ingestion Handler Registry.

Maps canonical assurance domains (Phases 5-11) to their respective domain ingestion handlers.
"""

from typing import Dict, Optional, Tuple

from aivara.universal.enums import SubsystemDomain
from aivara.universal.ingestion.exceptions import (
    DomainMismatchIngestionError,
    UniversalIngestionError,
)
from aivara.universal.ingestion.handlers import (
    BackdoorIngestionHandler,
    BaseDomainIngestionHandler,
    BehavioralIngestionHandler,
    ContributorIngestionHandler,
    DatasetIngestionHandler,
    DistributionIngestionHandler,
    InferenceIngestionHandler,
    ModelIngestionHandler,
)


class IngestionHandlerRegistry:
    """Authoritative registry for Phase 12.4 cross-subsystem ingestion handlers."""

    def __init__(self) -> None:
        self._handlers: Dict[SubsystemDomain, BaseDomainIngestionHandler] = {}
        self._register_default_handlers()

    def _register_default_handlers(self) -> None:
        """Register canonical handlers for all 7 upstream assurance domains."""
        self.register(SubsystemDomain.DATASET_INTEGRITY, DatasetIngestionHandler())
        self.register(SubsystemDomain.CONTRIBUTOR_RISK, ContributorIngestionHandler())
        self.register(SubsystemDomain.MODEL_INTEGRITY, ModelIngestionHandler())
        self.register(SubsystemDomain.BEHAVIORAL_ANALYSIS, BehavioralIngestionHandler())
        self.register(SubsystemDomain.BACKDOOR_TRIGGER, BackdoorIngestionHandler())
        self.register(SubsystemDomain.INFERENCE_INTEGRITY, InferenceIngestionHandler())
        self.register(SubsystemDomain.DISTRIBUTION_SHIFT, DistributionIngestionHandler())

    def register(
        self,
        domain: SubsystemDomain,
        handler: BaseDomainIngestionHandler,
    ) -> None:
        """Register a handler for a canonical domain."""
        if not isinstance(domain, SubsystemDomain):
            raise DomainMismatchIngestionError(
                f"Invalid domain type '{type(domain)}'. Must be SubsystemDomain instance."
            )
        if not isinstance(handler, BaseDomainIngestionHandler):
            raise UniversalIngestionError(
                f"Handler must inherit from BaseDomainIngestionHandler, got {type(handler)}."
            )
        if handler.domain != domain:
            raise DomainMismatchIngestionError(
                f"Handler domain '{handler.domain}' does not match registration domain '{domain}'."
            )
        self._handlers[domain] = handler

    def get_handler(self, domain: SubsystemDomain) -> BaseDomainIngestionHandler:
        """Retrieve the ingestion handler for a canonical domain."""
        if not isinstance(domain, SubsystemDomain):
            raise DomainMismatchIngestionError(
                f"Domain '{domain}' is not a valid SubsystemDomain."
            )
        handler = self._handlers.get(domain)
        if handler is None:
            raise DomainMismatchIngestionError(
                f"No ingestion handler registered for domain '{domain.value}'."
            )
        return handler

    def has_handler(self, domain: SubsystemDomain) -> bool:
        """Check if a handler is registered for a canonical domain."""
        return domain in self._handlers

    @property
    def registered_domains(self) -> Tuple[SubsystemDomain, ...]:
        """Return tuple of all registered canonical domains."""
        return tuple(self._handlers.keys())
