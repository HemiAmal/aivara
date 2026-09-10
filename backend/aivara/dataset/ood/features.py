"""Dual-Tier visual feature extraction engine for OOD analysis.

Tier 1: Guaranteed 100% offline, deterministic CPU statistical pixel descriptor (D = 128).
Tier 2: Semantic deep visual embeddings using frozen, locally-available pretrained models.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Callable, Optional, Tuple, Union

import numpy as np
from PIL import Image, ImageOps

from aivara.dataset.ood.exceptions import FeatureExtractionError
from aivara.dataset.ood.schemas import FeatureExtractionStatus


def extract_tier1_statistical_descriptor(rgb_array: np.ndarray) -> np.ndarray:
    """Extract deterministic 128-dimensional statistical pixel descriptor.
    
    Structure:
      - 32-bin normalized R channel histogram (32)
      - 32-bin normalized G channel histogram (32)
      - 32-bin normalized B channel histogram (32)
      - 16-bin normalized HSV Saturation histogram (16)
      - 16-bin normalized HSV Value/Brightness histogram (16)
      Total = 128 dimensions, L2-normalized.
    """
    if rgb_array.ndim != 3 or rgb_array.shape[2] < 3:
        raise FeatureExtractionError(f"Expected 3-channel RGB array, got shape {rgb_array.shape}")
    
    r = rgb_array[:, :, 0].ravel()
    g = rgb_array[:, :, 1].ravel()
    b = rgb_array[:, :, 2].ravel()
    
    # 32-bin histograms for R, G, B in [0, 256)
    hist_r, _ = np.histogram(r, bins=32, range=(0, 256), density=True)
    hist_g, _ = np.histogram(g, bins=32, range=(0, 256), density=True)
    hist_b, _ = np.histogram(b, bins=32, range=(0, 256), density=True)
    
    # HSV conversion for S and V
    rgb_norm = rgb_array[:, :, :3].astype(np.float32) / 255.0
    r_n = rgb_norm[:, :, 0]
    g_n = rgb_norm[:, :, 1]
    b_n = rgb_norm[:, :, 2]
    
    cmax = np.maximum(np.maximum(r_n, g_n), b_n)
    cmin = np.minimum(np.minimum(r_n, g_n), b_n)
    delta = cmax - cmin
    
    sat = np.where(cmax > 1e-6, delta / (cmax + 1e-6), 0.0).ravel()
    val = cmax.ravel()
    
    # 16-bin histograms for S and V in [0.0, 1.0]
    hist_s, _ = np.histogram(sat, bins=16, range=(0.0, 1.0), density=True)
    hist_v, _ = np.histogram(val, bins=16, range=(0.0, 1.0), density=True)
    
    feature_vector = np.concatenate([hist_r, hist_g, hist_b, hist_s, hist_v]).astype(np.float64)
    
    # Replace NaN/Inf defensively
    feature_vector = np.nan_to_num(feature_vector, nan=0.0, posinf=0.0, neginf=0.0)
    
    # L2 normalization
    norm = np.linalg.norm(feature_vector)
    if norm > 1e-7:
        feature_vector = feature_vector / norm
    else:
        feature_vector = np.zeros(128, dtype=np.float64)
        feature_vector[0] = 1.0
        
    return feature_vector


class VisualFeatureExtractor:
    """Orchestrator for Dual-Tier feature extraction."""

    def __init__(
        self,
        tier2_model: Optional[Callable[[Image.Image], np.ndarray]] = None,
        force_tier1: bool = False,
    ) -> None:
        self.tier2_model = tier2_model
        self.force_tier1 = force_tier1

    def extract(
        self,
        image_input: Union[Path, str, np.ndarray, Image.Image],
    ) -> Tuple[np.ndarray, FeatureExtractionStatus, str]:
        """Extract feature vector from image.
        
        Returns:
            Tuple of (feature_vector, status, method_name)
        """
        # Load and normalize PIL Image / numpy array
        try:
            if isinstance(image_input, (str, Path)):
                path_obj = Path(image_input)
                if not path_obj.exists() or not path_obj.is_file():
                    raise FeatureExtractionError(f"Image not found: {path_obj.name}")
                with Image.open(path_obj) as raw_img:
                    img = ImageOps.exif_transpose(raw_img) or raw_img
                    if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
                        rgba = img.convert("RGBA")
                        bg = Image.new("RGB", rgba.size, (255, 255, 255))
                        bg.paste(rgba, mask=rgba.split()[-1])
                        canonical_img = bg
                    else:
                        canonical_img = img.convert("RGB")
                    canonical_img.load()
                    pil_img = canonical_img
                    rgb_array = np.array(canonical_img, dtype=np.uint8)
            elif isinstance(image_input, Image.Image):
                img = ImageOps.exif_transpose(image_input) or image_input
                if img.mode in ("RGBA", "LA"):
                    rgba = img.convert("RGBA")
                    bg = Image.new("RGB", rgba.size, (255, 255, 255))
                    bg.paste(rgba, mask=rgba.split()[-1])
                    canonical_img = bg
                else:
                    canonical_img = img.convert("RGB")
                canonical_img.load()
                pil_img = canonical_img
                rgb_array = np.array(canonical_img, dtype=np.uint8)
            elif isinstance(image_input, np.ndarray):
                rgb_array = image_input
                if rgb_array.ndim == 2:
                    rgb_array = np.stack([rgb_array] * 3, axis=-1)
                elif rgb_array.shape[2] == 4:
                    rgb_array = rgb_array[:, :, :3]
                rgb_array = np.clip(rgb_array, 0, 255).astype(np.uint8)
                pil_img = Image.fromarray(rgb_array)
            else:
                raise FeatureExtractionError(f"Unsupported image input type: {type(image_input)}")

            # Check if Tier 2 model is available and enabled
            if self.tier2_model is not None and not self.force_tier1:
                try:
                    feat = self.tier2_model(pil_img)
                    if isinstance(feat, np.ndarray) and feat.ndim == 1 and feat.size > 0:
                        feat = np.nan_to_num(feat, nan=0.0, posinf=0.0, neginf=0.0)
                        norm = np.linalg.norm(feat)
                        if norm > 1e-7:
                            feat = feat / norm
                        return feat, FeatureExtractionStatus.TIER2_DEEP_EMBEDDING, "tier2_deep_embedding"
                except Exception:
                    # Clean fallback to Tier 1
                    pass

            # Fallback to Tier 1 deterministic statistical descriptor
            feat = extract_tier1_statistical_descriptor(rgb_array)
            status = (
                FeatureExtractionStatus.TIER1_STATISTICAL_ONLY
                if self.tier2_model is None
                else FeatureExtractionStatus.TIER1_FALLBACK
            )
            return feat, status, "tier1_spatial_histogram"

        except FeatureExtractionError:
            raise
        except Exception as exc:
            raise FeatureExtractionError(f"Feature extraction failed: {str(exc)}") from exc
