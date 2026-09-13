"""Deterministic synthetic fixtures for Phase 11.11 Comprehensive Verification."""

from __future__ import annotations

import datetime
import io
import os
import random
from typing import Any, Dict, List, Tuple
import numpy as np
from PIL import Image
import pytest
from fastapi.testclient import TestClient

from aivara.main import app
from aivara.services.drift_service import get_drift_task_manager


@pytest.fixture(autouse=True)
def clean_task_manager() -> None:
    """Ensure in-memory task registry is clean before each test."""
    manager = get_drift_task_manager()
    manager.clear()


@pytest.fixture
def client() -> TestClient:
    """FastAPI TestClient for API endpoints."""
    return TestClient(app)


@pytest.fixture
def deterministic_rng() -> np.random.Generator:
    """Fixed seed RNG for perfectly reproducible synthetic data."""
    return np.random.default_rng(seed=42)


@pytest.fixture
def synthetic_tabular_data(deterministic_rng: np.random.Generator) -> Dict[str, Any]:
    """Provide stationary and shifted tabular feature matrices."""
    n_samples = 200
    ref_num_1 = deterministic_rng.normal(loc=0.0, scale=1.0, size=n_samples).tolist()
    ref_num_2 = deterministic_rng.exponential(scale=2.0, size=n_samples).tolist()
    ref_cat_1 = deterministic_rng.choice(["A", "B", "C"], size=n_samples, p=[0.5, 0.3, 0.2]).tolist()
    ref_labels = deterministic_rng.choice([0, 1], size=n_samples, p=[0.5, 0.5]).tolist()

    # Stationary target
    tgt_stat_rng = np.random.default_rng(seed=43)
    tgt_stat_num_1 = tgt_stat_rng.normal(loc=0.0, scale=1.0, size=n_samples).tolist()
    tgt_stat_num_2 = tgt_stat_rng.exponential(scale=2.0, size=n_samples).tolist()
    tgt_stat_cat_1 = tgt_stat_rng.choice(["A", "B", "C"], size=n_samples, p=[0.5, 0.3, 0.2]).tolist()
    tgt_stat_labels = tgt_stat_rng.choice([0, 1], size=n_samples, p=[0.5, 0.5]).tolist()

    # Shifted target (severe covariate & categorical shift)
    tgt_shift_rng = np.random.default_rng(seed=44)
    tgt_shift_num_1 = tgt_shift_rng.normal(loc=3.5, scale=1.0, size=n_samples).tolist()
    tgt_shift_num_2 = tgt_shift_rng.exponential(scale=8.0, size=n_samples).tolist()
    tgt_shift_cat_1 = tgt_shift_rng.choice(["A", "B", "C"], size=n_samples, p=[0.05, 0.05, 0.90]).tolist()
    tgt_shift_labels = tgt_shift_rng.choice([0, 1], size=n_samples, p=[0.1, 0.9]).tolist()

    return {
        "reference": {
            "num_1": ref_num_1,
            "num_2": ref_num_2,
            "cat_1": ref_cat_1,
            "labels": ref_labels,
        },
        "target_stationary": {
            "num_1": tgt_stat_num_1,
            "num_2": tgt_stat_num_2,
            "cat_1": tgt_stat_cat_1,
            "labels": tgt_stat_labels,
        },
        "target_shifted": {
            "num_1": tgt_shift_num_1,
            "num_2": tgt_shift_num_2,
            "cat_1": tgt_shift_cat_1,
            "labels": tgt_shift_labels,
        },
    }


@pytest.fixture
def synthetic_image_batches() -> Dict[str, List[bytes]]:
    """Provide synthetic valid RGB image bytes batches."""
    rng = np.random.default_rng(seed=42)
    ref_images = []
    for _ in range(10):
        arr = rng.integers(100, 150, size=(32, 32, 3), dtype=np.uint8)
        img = Image.fromarray(arr, mode="RGB")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        ref_images.append(buf.getvalue())

    # Darkened shifted images
    shifted_images = []
    for _ in range(10):
        arr = rng.integers(10, 40, size=(32, 32, 3), dtype=np.uint8)
        img = Image.fromarray(arr, mode="RGB")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        shifted_images.append(buf.getvalue())

    return {
        "reference": ref_images,
        "shifted": shifted_images,
    }


@pytest.fixture
def synthetic_representation_embeddings(deterministic_rng: np.random.Generator) -> Dict[str, np.ndarray]:
    """Provide normalized L2 embeddings."""
    dim = 64
    n_samples = 50
    # Reference unit vectors
    raw_ref = deterministic_rng.normal(0, 1, size=(n_samples, dim))
    ref_norm = raw_ref / np.linalg.norm(raw_ref, axis=1, keepdims=True)

    # Stationary target
    raw_stat = np.random.default_rng(seed=43).normal(0, 1, size=(n_samples, dim))
    stat_norm = raw_stat / np.linalg.norm(raw_stat, axis=1, keepdims=True)

    # Shifted target (translated cluster)
    raw_shift = np.random.default_rng(seed=44).normal(3.0, 1, size=(n_samples, dim))
    shift_norm = raw_shift / np.linalg.norm(raw_shift, axis=1, keepdims=True)

    return {
        "reference": ref_norm,
        "target_stationary": stat_norm,
        "target_shifted": shift_norm,
    }
