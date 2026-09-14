"""Controlled Domain Ingestion Handlers for the Seven Canonical Assurance Domains (Phase 12.4)."""

from __future__ import annotations

import abc
from typing import Any, Dict, Optional, Union
from pydantic import BaseModel

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.enums import SubsystemDomain
from aivara.universal.exceptions import AdapterMismatchError, InvalidEvidenceError, UnknownDomainError
from aivara.universal.hashing import compute_canonical_jcs_bytes
from aivara.universal.ingestion.exceptions import DomainMismatchIngestionError, IngestionValidationError
from aivara.universal.normalizer import UniversalEvidenceNormalizer
from aivara.universal.schemas import UniversalEvidenceEnvelope


class BaseDomainIngestionHandler(abc.ABC):
    """Abstract base handler for domain-specific controlled ingestion."""

    @property
    @abc.abstractmethod
    def domain(self) -> SubsystemDomain:
        """The canonical assurance domain managed by this handler."""
        pass

    def validate_and_normalize(
        self,
        raw_evidence: Union[Dict[str, Any], BaseModel],
        project_id: str,
        normalizer: UniversalEvidenceNormalizer,
        context: Optional[Dict[str, Any]] = None,
    ) -> UniversalEvidenceEnvelope:
        """Validate domain ownership and normalize into a canonical UniversalEvidenceEnvelope."""
        # Convert to dictionary if needed, filtering out None values to prevent key-presence collisions
        if hasattr(raw_evidence, "model_dump"):
            raw_dict = raw_evidence.model_dump(mode="python", exclude_none=True)
        elif hasattr(raw_evidence, "dict"):
            raw_dict = {k: v for k, v in raw_evidence.dict().items() if v is not None}
        elif isinstance(raw_evidence, dict):
            raw_dict = {k: v for k, v in raw_evidence.items() if v is not None}
        else:
            raise IngestionValidationError(f"Unsupported evidence type: {type(raw_evidence).__name__}")

        # Domain verification
        domain_val = raw_dict.get("domain") or raw_dict.get("subsystem_domain") or raw_dict.get("source_subsystem")
        if domain_val:
            if isinstance(domain_val, SubsystemDomain):
                item_domain = domain_val
            else:
                try:
                    clean_val = str(domain_val).split(".")[-1].upper()
                    item_domain = SubsystemDomain(clean_val)
                except ValueError:
                    raise DomainMismatchIngestionError(f"Unknown assurance domain: {domain_val}")
            
            if item_domain != self.domain:
                raise DomainMismatchIngestionError(
                    f"Domain mismatch: handler expects {self.domain.value}, received {item_domain.value}"
                )

        # Map asset fields if present
        if "asset_type" in raw_dict and "primary_asset_type" not in raw_dict and "target_asset_type" not in raw_dict:
            raw_dict["target_asset_type"] = raw_dict["asset_type"]
        if "asset_id" in raw_dict and "primary_asset_id" not in raw_dict and "target_asset_id" not in raw_dict:
            raw_dict["target_asset_id"] = raw_dict["asset_id"]

        # Ensure raw_bytes is provided in context for deterministic payload hash verification
        ctx = dict(context or {})
        if "raw_bytes" not in ctx and "data_json" in raw_dict:
            ctx["raw_bytes"] = compute_canonical_jcs_bytes(raw_dict["data_json"])

        # Perform domain-specific validation hook
        self._validate_domain_payload(raw_dict)

        # Route through Phase 12.2 Normalizer
        envelope = normalizer.normalize_single(
            raw_evidence=raw_dict,
            project_id=project_id,
            domain=self.domain,
            context=ctx,
        )
        return envelope

    def _validate_domain_payload(self, payload: Dict[str, Any]) -> None:
        """Domain-specific structural validation hook (overrideable)."""
        pass


class DatasetIngestionHandler(BaseDomainIngestionHandler):
    """Handler for Phase 5 Dataset Integrity evidence records."""
    @property
    def domain(self) -> SubsystemDomain:
        return SubsystemDomain.DATASET_INTEGRITY


class ContributorIngestionHandler(BaseDomainIngestionHandler):
    """Handler for Phase 6 Contributor Risk evidence records."""
    @property
    def domain(self) -> SubsystemDomain:
        return SubsystemDomain.CONTRIBUTOR_RISK


class ModelIngestionHandler(BaseDomainIngestionHandler):
    """Handler for Phase 7 Model Integrity evidence records."""
    @property
    def domain(self) -> SubsystemDomain:
        return SubsystemDomain.MODEL_INTEGRITY


class BehavioralIngestionHandler(BaseDomainIngestionHandler):
    """Handler for Phase 8 Behavioral Analysis evidence records."""
    @property
    def domain(self) -> SubsystemDomain:
        return SubsystemDomain.BEHAVIORAL_ANALYSIS


class BackdoorIngestionHandler(BaseDomainIngestionHandler):
    """Handler for Phase 9 Backdoor / Trigger evidence records."""
    @property
    def domain(self) -> SubsystemDomain:
        return SubsystemDomain.BACKDOOR_TRIGGER


class InferenceIngestionHandler(BaseDomainIngestionHandler):
    """Handler for Phase 10 Inference Integrity evidence records."""
    @property
    def domain(self) -> SubsystemDomain:
        return SubsystemDomain.INFERENCE_INTEGRITY


class DistributionIngestionHandler(BaseDomainIngestionHandler):
    """Handler for Phase 11 Distribution Shift evidence records."""
    @property
    def domain(self) -> SubsystemDomain:
        return SubsystemDomain.DISTRIBUTION_SHIFT
