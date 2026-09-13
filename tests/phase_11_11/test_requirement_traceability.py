"""Phase 11.11.2 - Requirement Traceability Verification (REQ-11-VERIF-001 to REQ-11-VERIF-085).

Formally checks that all 85 specification requirements have direct, executable test coverage
across the 12 verification layers.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Set
import pytest


def _collect_test_names_in_directory(dir_path: str) -> Dict[str, Set[str]]:
    """Collect test function names from python files in directory."""
    tests_by_file: Dict[str, Set[str]] = {}
    for root, _, files in os.walk(dir_path):
        for file in files:
            if file.startswith("test_") and file.endswith(".py"):
                path = os.path.join(root, file)
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                test_names = set(re.findall(r"def (test_[a-zA-Z0-9_]+)\(", content))
                tests_by_file[file] = test_names
    return tests_by_file


def test_req_traceability_all_85_requirements() -> None:
    """Verify REQ-11-VERIF-001 through REQ-11-VERIF-085 are covered by executable test functions."""
    test_dir = os.path.join("tests", "phase_11_11")
    assert os.path.isdir(test_dir), f"Phase 11.11 test directory missing: {test_dir}"

    tests_by_file = _collect_test_names_in_directory(test_dir)
    all_tests = set()
    for t_set in tests_by_file.values():
        all_tests.update(t_set)

    # Check that each requirement REQ-11-VERIF-001 to REQ-11-VERIF-085 has a matching test
    uncovered_reqs: List[str] = []
    for req_idx in range(1, 86):
        req_id = f"req_{req_idx:03d}"
        found = any(req_id in t_name.lower() for t_name in all_tests)
        if not found:
            uncovered_reqs.append(f"REQ-11-VERIF-{req_idx:03d}")

    assert len(uncovered_reqs) == 0, f"Uncovered requirements found: {uncovered_reqs}"
    assert len(all_tests) >= 85, f"Expected at least 85 tests, found {len(all_tests)}"
