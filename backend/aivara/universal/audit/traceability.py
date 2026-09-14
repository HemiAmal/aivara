"""Authoritative Traceability Model and Claim Grounding (Phase 12.11)."""

from __future__ import annotations

import collections
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field

from aivara.universal.audit.enums import TraceabilityNodeType
from aivara.universal.exceptions import ProjectMismatchError
from aivara.universal.hashing import compute_canonical_jcs_bytes, compute_sha256_digest


class TraceabilityLink(BaseModel):
    """Immutable directed edge connecting two authoritative assurance artifacts."""
    model_config = ConfigDict(frozen=True)

    source_type: TraceabilityNodeType
    source_id: str = Field(..., min_length=1, max_length=128)
    target_type: TraceabilityNodeType
    target_id: str = Field(..., min_length=1, max_length=128)
    relationship: str = Field(default="REFERENCES", min_length=1, max_length=64)
    canonical_hash: str = Field(default="", max_length=64)

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "relationship": self.relationship,
            "source_id": self.source_id,
            "source_type": self.source_type.value,
            "target_id": self.target_id,
            "target_type": self.target_type.value,
        }


class AuthoritativeClaim(BaseModel):
    """Grounding descriptor tying a specific material report claim to authoritative sources."""
    model_config = ConfigDict(frozen=True)

    claim_id: str = Field(..., min_length=1, max_length=128)
    claim_type: str = Field(..., min_length=1, max_length=64)
    summary: str = Field(..., min_length=1, max_length=512)
    project_id: str = Field(..., min_length=1, max_length=128)
    asset_id: Optional[str] = Field(default=None, max_length=128)
    evidence_id: Optional[str] = Field(default=None, max_length=128)
    finding_id: Optional[str] = Field(default=None, max_length=128)
    risk_hash: Optional[str] = Field(default=None, max_length=64)
    decision_hash: Optional[str] = Field(default=None, max_length=64)
    proof_hash: Optional[str] = Field(default=None, max_length=64)
    hierarchical_hash: Optional[str] = Field(default=None, max_length=64)
    claim_hash: str = Field(default="", max_length=64)

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id or "",
            "claim_id": self.claim_id,
            "claim_type": self.claim_type,
            "decision_hash": self.decision_hash or "",
            "evidence_id": self.evidence_id or "",
            "finding_id": self.finding_id or "",
            "hierarchical_hash": self.hierarchical_hash or "",
            "project_id": self.project_id,
            "proof_hash": self.proof_hash or "",
            "risk_hash": self.risk_hash or "",
            "summary": self.summary,
        }


class TraceabilityGraph:
    """Directed acyclic graph tracking end-to-end evidence lineage across all assurance tiers."""

    def __init__(self, project_id: str) -> None:
        if not project_id:
            raise ProjectMismatchError("TraceabilityGraph project_id must not be empty.")
        self.project_id = project_id
        self._nodes: Dict[Tuple[TraceabilityNodeType, str], Dict[str, Any]] = {}
        self._links: List[TraceabilityLink] = []
        self._claims: List[AuthoritativeClaim] = []

    def add_node(self, node_type: TraceabilityNodeType, node_id: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        key = (node_type, node_id)
        if key not in self._nodes:
            self._nodes[key] = metadata or {}

    def add_link(
        self,
        source_type: TraceabilityNodeType,
        source_id: str,
        target_type: TraceabilityNodeType,
        target_id: str,
        relationship: str = "REFERENCES",
    ) -> None:
        self.add_node(source_type, source_id)
        self.add_node(target_type, target_id)
        raw = {
            "relationship": relationship,
            "source_id": source_id,
            "source_type": source_type.value,
            "target_id": target_id,
            "target_type": target_type.value,
        }
        c_hash = compute_sha256_digest(compute_canonical_jcs_bytes(raw))
        link = TraceabilityLink(
            source_type=source_type,
            source_id=source_id,
            target_type=target_type,
            target_id=target_id,
            relationship=relationship,
            canonical_hash=c_hash,
        )
        self._links.append(link)

    def add_claim(
        self,
        claim_id: str,
        claim_type: str,
        summary: str,
        asset_id: Optional[str] = None,
        evidence_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        risk_hash: Optional[str] = None,
        decision_hash: Optional[str] = None,
        proof_hash: Optional[str] = None,
        hierarchical_hash: Optional[str] = None,
    ) -> AuthoritativeClaim:
        raw = {
            "asset_id": asset_id or "",
            "claim_id": claim_id,
            "claim_type": claim_type,
            "decision_hash": decision_hash or "",
            "evidence_id": evidence_id or "",
            "finding_id": finding_id or "",
            "hierarchical_hash": hierarchical_hash or "",
            "project_id": self.project_id,
            "proof_hash": proof_hash or "",
            "risk_hash": risk_hash or "",
            "summary": summary,
        }
        c_hash = compute_sha256_digest(compute_canonical_jcs_bytes(raw))
        claim = AuthoritativeClaim(
            claim_id=claim_id,
            claim_type=claim_type,
            summary=summary,
            project_id=self.project_id,
            asset_id=asset_id,
            evidence_id=evidence_id,
            finding_id=finding_id,
            risk_hash=risk_hash,
            decision_hash=decision_hash,
            proof_hash=proof_hash,
            hierarchical_hash=hierarchical_hash,
            claim_hash=c_hash,
        )
        self._claims.append(claim)
        return claim

    def get_links(self) -> List[TraceabilityLink]:
        return sorted(self._links, key=lambda l: (l.source_type.value, l.source_id, l.target_type.value, l.target_id))

    def get_claims(self) -> List[AuthoritativeClaim]:
        return sorted(self._claims, key=lambda c: c.claim_id)

    def resolve_ancestors(self, node_type: TraceabilityNodeType, node_id: str) -> Set[Tuple[TraceabilityNodeType, str]]:
        """Resolve all upstream ancestor artifacts reachable from target node."""
        visited: Set[Tuple[TraceabilityNodeType, str]] = set()
        adj: Dict[Tuple[TraceabilityNodeType, str], List[Tuple[TraceabilityNodeType, str]]] = collections.defaultdict(list)
        for link in self._links:
            adj[(link.target_type, link.target_id)].append((link.source_type, link.source_id))

        queue = [(node_type, node_id)]
        while queue:
            curr = queue.pop(0)
            if curr in visited:
                continue
            visited.add(curr)
            for parent in adj.get(curr, []):
                if parent not in visited:
                    queue.append(parent)
        visited.remove((node_type, node_id))
        return visited
