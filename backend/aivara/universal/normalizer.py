"""Universal Evidence Normalizer Engine (Phase 12.2).

Orchestrates:
- Evidence ingestion across all seven upstream domains.
- Hard resource safety ceilings ($E_{\\max} = 5,000$).
- Strict multi-tenant project boundary validation.
- Domain adapter dispatch via AdapterRegistry.
- Deterministic deduplication via canonical envelope hashes.
- Fail-safe handling of missing / ambiguous ancestry.
- Canonical sorting for 100% repeatable output.
"""

from __future__ import annotations

import collections
import hmac
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
from pydantic import BaseModel

from aivara.universal.adapters.registry import (
    AdapterRegistry,
    get_default_adapter_registry,
)
from aivara.universal.enums import AncestryStatus, SubsystemDomain
from aivara.universal.exceptions import (
    InvalidEvidenceError,
    ProjectMismatchError,
    UniversalResourceLimitExceededError,
    UnknownDomainError,
)
from aivara.universal.schemas import (
    NormalizationReport,
    UniversalEvidenceEnvelope,
)

# Phase 12.1 frozen hard resource ceilings
MAX_EVIDENCE_ITEMS_LIMIT: int = 5000


class UniversalEvidenceNormalizer:
    """Orchestrator for normalizing multi-domain evidence into canonical Universal Evidence Envelopes."""

    def __init__(self, registry: Optional[AdapterRegistry] = None) -> None:
        self.registry = registry or get_default_adapter_registry()

    def normalize_single(
        self,
        raw_evidence: Union[Dict[str, Any], BaseModel],
        project_id: str,
        domain: Optional[Union[SubsystemDomain, str]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> UniversalEvidenceEnvelope:
        """Normalize a single raw evidence item into a canonical UniversalEvidenceEnvelope.
        
        Args:
            raw_evidence: Raw evidence dictionary or Pydantic model.
            project_id: Target project / tenant identifier.
            domain: Optional explicit domain; if None, extracted from raw_evidence.
            context: Optional contextual parameters.
            
        Returns:
            Normalized UniversalEvidenceEnvelope instance.
        """
        if not project_id:
            raise ProjectMismatchError("Target project_id must not be empty.")

        # Extract dict
        if hasattr(raw_evidence, "model_dump"):
            raw_dict = raw_evidence.model_dump(mode="python")
        elif hasattr(raw_evidence, "dict"):
            raw_dict = raw_evidence.dict()
        elif isinstance(raw_evidence, dict):
            raw_dict = dict(raw_evidence)
        else:
            raise InvalidEvidenceError(f"Unsupported evidence input type: {type(raw_evidence).__name__}")

        # Determine target domain
        target_domain: Optional[SubsystemDomain] = None
        if domain is not None:
            if isinstance(domain, SubsystemDomain):
                target_domain = domain
            elif isinstance(domain, str):
                try:
                    target_domain = SubsystemDomain(domain.upper())
                except ValueError:
                    raise UnknownDomainError(f"Unknown assurance domain: {domain}")
        else:
            domain_val = raw_dict.get("domain") or raw_dict.get("subsystem_domain") or raw_dict.get("source_subsystem")
            if domain_val:
                try:
                    target_domain = SubsystemDomain(str(domain_val).upper())
                except ValueError:
                    raise UnknownDomainError(f"Unknown assurance domain: {domain_val}")
            else:
                raise InvalidEvidenceError("No domain specified or found in evidence record.")

        # Dispatch to adapter
        adapter = self.registry.get_adapter(target_domain)
        envelope = adapter.normalize(raw_dict, project_id=project_id, context=context)
        return envelope

    def normalize_batch(
        self,
        evidence_items: Sequence[Union[Dict[str, Any], BaseModel]],
        project_id: str,
        default_domain: Optional[Union[SubsystemDomain, str]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> NormalizationReport:
        """Normalize a batch of heterogeneous evidence items with deduplication and safety ceilings.
        
        Args:
            evidence_items: Sequence of raw evidence items.
            project_id: Target project / tenant identifier.
            default_domain: Default domain if not specified per item.
            context: Optional contextual parameters.
            
        Returns:
            NormalizationReport with deduplicated envelopes and breakdown statistics.
        """
        if not project_id:
            raise ProjectMismatchError("Target project_id must not be empty.")

        total_ingested = len(evidence_items)
        if total_ingested > MAX_EVIDENCE_ITEMS_LIMIT:
            raise UniversalResourceLimitExceededError(
                f"Ingested evidence count ({total_ingested}) exceeds hard safety ceiling ({MAX_EVIDENCE_ITEMS_LIMIT})."
            )

        envelopes: List[UniversalEvidenceEnvelope] = []
        seen_hashes: Set[str] = set()
        domain_counts: Dict[str, int] = collections.defaultdict(int)
        rejections: List[Dict[str, Any]] = []
        deduplicated_count = 0

        for idx, item in enumerate(evidence_items):
            try:
                env = self.normalize_single(
                    raw_evidence=item,
                    project_id=project_id,
                    domain=default_domain,
                    context=context,
                )
                
                # Constant-time hash check for deduplication
                is_duplicate = False
                for seen in seen_hashes:
                    if hmac.compare_digest(env.canonical_hash, seen):
                        is_duplicate = True
                        break
                
                if is_duplicate:
                    deduplicated_count += 1
                else:
                    seen_hashes.add(env.canonical_hash)
                    envelopes.append(env)
                    domain_counts[env.domain.value] += 1

            except Exception as exc:
                rejections.append({
                    "item_index": idx,
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                })

        # Canonical deterministic multi-key sorting
        envelopes.sort(key=lambda e: (
            e.domain.value,
            e.primary_asset_type,
            e.primary_asset_id,
            e.canonical_hash,
        ))

        report = NormalizationReport(
            project_id=project_id,
            total_ingested=total_ingested,
            total_normalized=len(envelopes),
            total_deduplicated=deduplicated_count,
            total_rejected=len(rejections),
            domain_breakdown=dict(domain_counts),
            envelopes=envelopes,
            rejection_reasons=rejections,
        )
        return report
