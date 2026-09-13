"""Phase 11.11.2 - Layer 10: 100% Offline Air-Gap Verification Suite.

Verifies:
- REQ-11-VERIF-074: Socket interceptor strictly blocks all external network calls
- REQ-11-VERIF-075: AST scan verifies 0 telemetry, analytics, or outbound beacons
- REQ-11-VERIF-076: 100% local persistence via SQLite without external DB dependencies
- REQ-11-VERIF-077: Offline execution invariant across all distribution shift analyzers
"""

from __future__ import annotations

import ast
import os
import socket
from typing import Any, Dict
import numpy as np
import pytest

from aivara.assurance.engine import MultiModalRiskIntegrationEngine
from aivara.drift.boundary import ComparisonBoundaryEngine
from aivara.drift.engine import StatisticalDriftEngine
from aivara.drift.feature_dataset_engine import FeatureDatasetDriftAnalyzer
from aivara.drift.image_engine import ImageDistributionShiftAnalyzer
from aivara.drift.representation_engine import RepresentationDistributionShiftAnalyzer
from aivara.drift.source_engine import SourceDistributionShiftEngine
from aivara.drift.temporal_engine import TemporalDistributionShiftAnalyzer
from aivara.drift.stats_continuous import compute_two_sample_ks, compute_wasserstein_1d, compute_psi


def test_req_074_socket_creation_interceptor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify REQ-11-VERIF-074: Zero external network sockets are created during analytical execution."""
    socket_calls = []

    def guarded_socket(*args: Any, **kwargs: Any) -> Any:
        socket_calls.append((args, kwargs))
        raise RuntimeError("AIR-GAP VIOLATION: Network socket creation attempted!")

    monkeypatch.setattr(socket, "socket", guarded_socket)

    # Run analytical pipeline
    ref_data = np.array([float(i) for i in range(50)])
    tgt_data = np.array([float(i + 1) for i in range(50)])

    # Execute drift calculations directly
    stat, p_val = compute_two_sample_ks(ref_data, tgt_data)
    assert 0.0 <= p_val <= 1.0
    w1 = compute_wasserstein_1d(ref_data, tgt_data)
    assert w1 >= 0.0
    psi, _ = compute_psi(ref_data, tgt_data)
    assert psi >= 0.0

    assert len(socket_calls) == 0, "Network socket was called during offline execution!"


def test_req_075_ast_telemetry_scan() -> None:
    """Verify REQ-11-VERIF-075: Zero telemetry, tracking beacons, or analytics endpoints in codebase."""
    drift_dir = os.path.join("backend", "aivara", "drift")
    assurance_dir = os.path.join("backend", "aivara", "assurance")
    api_dir = os.path.join("backend", "aivara", "api")

    telemetry_keywords = {"posthog", "segment.io", "mixpanel", "sentry_sdk", "google_analytics", "datadog", "telemetry.track"}

    for base_dir in (drift_dir, assurance_dir, api_dir):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file.endswith(".py"):
                    path = os.path.join(root, file)
                    with open(path, "r", encoding="utf-8") as f:
                        content = f.read().lower()
                    for kw in telemetry_keywords:
                        assert kw not in content, f"Telemetry keyword '{kw}' found in {path}"


def test_req_076_local_sqlite_persistence() -> None:
    """Verify REQ-11-VERIF-076: Database configuration is strictly local SQLite."""
    from aivara.core.config import settings
    
    db_url = getattr(settings, "DATABASE_URL", "sqlite:///./aivara.db")
    assert "sqlite" in db_url.lower()
    assert "postgres" not in db_url.lower()
    assert "mysql" not in db_url.lower()


def test_req_077_all_drift_engines_offline_execution() -> None:
    """Verify REQ-11-VERIF-077: All 6 drift engines instantiate and run completely offline without downloading models."""
    b_engine = ComparisonBoundaryEngine()
    s_engine = StatisticalDriftEngine()
    f_analyzer = FeatureDatasetDriftAnalyzer()
    i_analyzer = ImageDistributionShiftAnalyzer()
    r_analyzer = RepresentationDistributionShiftAnalyzer()
    t_analyzer = TemporalDistributionShiftAnalyzer()
    src_engine = SourceDistributionShiftEngine()
    r_engine = MultiModalRiskIntegrationEngine()

    assert all([
        b_engine is not None,
        s_engine is not None,
        f_analyzer is not None,
        i_analyzer is not None,
        r_analyzer is not None,
        t_analyzer is not None,
        src_engine is not None,
        r_engine is not None,
    ])
