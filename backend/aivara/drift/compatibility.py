"""Compatibility validation for feature schemas, label vocabularies, image formats, and latent representations."""

from __future__ import annotations

import hashlib
from typing import List, Optional, Tuple

from aivara.crypto.canonical import canonicalize
from aivara.drift.enums import CompatibilityStatus, DataModality
from aivara.drift.schemas import (
    FeatureSchemaDescriptor,
    ImageSchemaDescriptor,
    LabelSchemaDescriptor,
    RepresentationDescriptor,
)


def compute_feature_descriptor_hash(desc: Optional[FeatureSchemaDescriptor]) -> Optional[str]:
    """Compute SHA-256 digest over canonical FeatureSchemaDescriptor."""
    if desc is None:
        return None
    canonical_dict = {
        "dimensions": desc.dimensions,
        "feature_names": sorted(desc.feature_names),
        "feature_types": {k: desc.feature_types[k] for k in sorted(desc.feature_types.keys())},
    }
    return hashlib.sha256(canonicalize(canonical_dict)).hexdigest()


def compute_label_descriptor_hash(desc: Optional[LabelSchemaDescriptor]) -> Optional[str]:
    """Compute SHA-256 digest over canonical LabelSchemaDescriptor."""
    if desc is None:
        return None
    canonical_dict = {
        "class_names": sorted(desc.class_names),
        "label_format": desc.label_format,
        "num_classes": desc.num_classes,
    }
    return hashlib.sha256(canonicalize(canonical_dict)).hexdigest()


def compute_representation_descriptor_hash(desc: Optional[RepresentationDescriptor]) -> Optional[str]:
    """Compute SHA-256 digest over canonical RepresentationDescriptor."""
    if desc is None:
        return None
    canonical_dict = {
        "embedding_dim": desc.embedding_dim or 0,
        "feature_extractor_version": desc.feature_extractor_version or "",
        "modality": desc.modality.value,
        "model_id": desc.model_id or "",
        "model_master_fingerprint": desc.model_master_fingerprint or "",
    }
    return hashlib.sha256(canonicalize(canonical_dict)).hexdigest()


def validate_feature_compatibility(
    ref_schema: FeatureSchemaDescriptor,
    target_schema: FeatureSchemaDescriptor,
) -> Tuple[CompatibilityStatus, List[str]]:
    """Validate compatibility between reference and target tabular/numeric feature schemas."""
    warnings: List[str] = []

    # 1. Dimensionality check
    if ref_schema.dimensions != target_schema.dimensions:
        return (
            CompatibilityStatus.INCOMPATIBLE_DIMENSIONS,
            [f"Feature dimensions mismatch: reference ({ref_schema.dimensions}) vs target ({target_schema.dimensions})."]
        )

    # 2. Feature names check
    if set(ref_schema.feature_names) != set(target_schema.feature_names):
        missing_in_target = set(ref_schema.feature_names) - set(target_schema.feature_names)
        extra_in_target = set(target_schema.feature_names) - set(ref_schema.feature_names)
        return (
            CompatibilityStatus.INCOMPATIBLE_SCHEMA,
            [f"Feature names mismatch: missing in target {sorted(list(missing_in_target))}, extra in target {sorted(list(extra_in_target))}."]
        )

    # 3. Feature types check
    for fname in ref_schema.feature_names:
        r_type = ref_schema.feature_types.get(fname)
        t_type = target_schema.feature_types.get(fname)
        if r_type and t_type and r_type != t_type:
            return (
                CompatibilityStatus.INCOMPATIBLE_SCHEMA,
                [f"Data type mismatch on feature '{fname}': reference '{r_type}' vs target '{t_type}'."]
            )

    return CompatibilityStatus.COMPATIBLE, warnings


def validate_label_compatibility(
    ref_labels: LabelSchemaDescriptor,
    target_labels: LabelSchemaDescriptor,
) -> Tuple[CompatibilityStatus, List[str]]:
    """Validate compatibility between reference and target class label vocabularies."""
    warnings: List[str] = []

    if ref_labels.label_format != target_labels.label_format:
        return (
            CompatibilityStatus.INCOMPATIBLE_SCHEMA,
            [f"Label format mismatch: reference ({ref_labels.label_format}) vs target ({target_labels.label_format})."]
        )

    ref_set = set(ref_labels.class_names)
    target_set = set(target_labels.class_names)

    unseen_classes = target_set - ref_set
    missing_classes = ref_set - target_set

    if unseen_classes:
        warnings.append(f"Target contains unseen classes not in reference: {sorted(list(unseen_classes))}.")
        return CompatibilityStatus.UNSEEN_CLASSES_PRESENT, warnings

    if missing_classes:
        warnings.append(f"Target does not contain reference classes: {sorted(list(missing_classes))}.")

    return CompatibilityStatus.COMPATIBLE, warnings


def validate_image_compatibility(
    ref_img: ImageSchemaDescriptor,
    target_img: ImageSchemaDescriptor,
) -> Tuple[CompatibilityStatus, List[str]]:
    """Validate compatibility between reference and target image descriptors."""
    warnings: List[str] = []

    if ref_img.channels != target_img.channels:
        return (
            CompatibilityStatus.INCOMPATIBLE_MODALITY,
            [f"Image channel count mismatch: reference ({ref_img.channels}) vs target ({target_img.channels})."]
        )

    if ref_img.color_space != target_img.color_space:
        return (
            CompatibilityStatus.INCOMPATIBLE_MODALITY,
            [f"Color space mismatch: reference ({ref_img.color_space}) vs target ({target_img.color_space})."]
        )

    return CompatibilityStatus.COMPATIBLE, warnings


def validate_representation_compatibility(
    ref_rep: RepresentationDescriptor,
    target_rep: RepresentationDescriptor,
) -> Tuple[CompatibilityStatus, List[str]]:
    """Validate compatibility between reference and target latent representations."""
    warnings: List[str] = []

    if ref_rep.modality != target_rep.modality:
        return (
            CompatibilityStatus.INCOMPATIBLE_MODALITY,
            [f"Data modality mismatch: reference ({ref_rep.modality}) vs target ({target_rep.modality})."]
        )

    if ref_rep.modality == DataModality.LATENT_EMBEDDING:
        if ref_rep.embedding_dim != target_rep.embedding_dim:
            return (
                CompatibilityStatus.INCOMPATIBLE_DIMENSIONS,
                [f"Embedding dimension mismatch: reference ({ref_rep.embedding_dim}) vs target ({target_rep.embedding_dim})."]
            )

        # Model binding check: embeddings from different models cannot be compared
        if ref_rep.model_id and target_rep.model_id and ref_rep.model_id != target_rep.model_id:
            return (
                CompatibilityStatus.INCOMPATIBLE_REPRESENTATION,
                [f"Latent embeddings generated by different models: reference ({ref_rep.model_id}) vs target ({target_rep.model_id})."]
            )

    return CompatibilityStatus.COMPATIBLE, warnings
