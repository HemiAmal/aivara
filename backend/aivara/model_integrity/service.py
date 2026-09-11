"""Model Ingestion and Safe Static Inspection Orchestrator (Phase 7.2).

Establishes the safe ingestion boundary, enforces format policies, dispatches
format-specific static parsers, and produces sealed inspection results.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Union

from aivara.model_integrity.exceptions import (
    ModelCorruptionError,
    ModelIntegrityError,
    ParsingError,
    ProhibitedFormatError,
    ResourceLimitExceededError,
    UntrustedArtifactSecurityError,
)
from aivara.model_integrity.format_detection import (
    POLICY_MAP,
    detect_model_format,
)
from aivara.model_integrity.limits import DEFAULT_LIMITS, ModelIngestionLimits
from aivara.model_integrity.normalization import build_normalized_metadata
from aivara.model_integrity.parsers import (
    BaseModelParser,
    ONNXParser,
    PyTorchStateDictParser,
    SafetensorsParser,
    TorchScriptParser,
)
from aivara.model_integrity.schemas import (
    FormatDetectionResult,
    InspectionPolicy,
    InspectionStatus,
    ModelFormat,
    ModelInspectionResult,
    NormalizedModelMetadata,
    ReasonCode,
)
from aivara.model_integrity.security import (
    compute_streaming_sha256,
    normalize_and_sanitize_path,
    validate_artifact_file,
)


class ModelIngestionService:
    """Safe ingestion and static inspection service for untrusted model artifacts."""

    def __init__(self, limits: Optional[ModelIngestionLimits] = None) -> None:
        self.limits = limits or DEFAULT_LIMITS
        self._safetensors_parser = SafetensorsParser()
        self._onnx_parser = ONNXParser()
        self._pytorch_parser = PyTorchStateDictParser()
        self._torchscript_parser = TorchScriptParser()

    def inspect_artifact(
        self,
        artifact_path: Union[str, Path],
        allowed_base_dir: Optional[Union[str, Path]] = None,
    ) -> ModelInspectionResult:
        """Execute full safe static inspection pipeline on an untrusted model artifact.

        Pipeline:
          1. Path & Filesystem Boundary Validation
          2. Streaming SHA-256 Hashing
          3. Deterministic Format & Policy Detection
          4. Policy Enforcement (Prohibited rejection)
          5. Safe Static Parser Dispatch
          6. Metadata Normalization & Canonical Sorting
          7. Inspection Result Sealing

        Args:
            artifact_path: Path or string to candidate model artifact.
            allowed_base_dir: Optional directory tree confinement boundary.

        Returns:
            ModelInspectionResult with format, status, normalized metadata, and reasons.
        """
        raw_path_str = str(artifact_path)

        # 1. Path validation & security boundary check
        try:
            validated_path = validate_artifact_file(
                artifact_path=artifact_path,
                allowed_base_dir=allowed_base_dir,
                limits=self.limits,
            )
            file_size = validated_path.stat().st_size
        except UntrustedArtifactSecurityError as e:
            reason = ReasonCode.FORBIDDEN_PATH_TYPE
            if e.code == "PATH_TRAVERSAL_ATTEMPT":
                reason = ReasonCode.PATH_TRAVERSAL_ATTEMPT
            elif e.code == "UNRESOLVABLE_SYMLINK":
                reason = ReasonCode.UNRESOLVABLE_SYMLINK
            elif e.code == "MISSING_ARTIFACT":
                reason = ReasonCode.MISSING_ARTIFACT
            elif e.code == "NOT_A_REGULAR_FILE":
                reason = ReasonCode.NOT_A_REGULAR_FILE

            return ModelInspectionResult(
                status=InspectionStatus.INVALID_ARTIFACT,
                format=ModelFormat.UNKNOWN,
                policy=InspectionPolicy.UNKNOWN,
                artifact_path=raw_path_str,
                artifact_size_bytes=0,
                artifact_hash_sha256=None,
                normalized_metadata=None,
                reason_codes=[reason],
                warnings=[f"Security boundary check failed: {e}"],
                details={"error_code": e.code, "details": e.details},
            )
        except ResourceLimitExceededError as e:
            return ModelInspectionResult(
                status=InspectionStatus.INVALID_ARTIFACT,
                format=ModelFormat.UNKNOWN,
                policy=InspectionPolicy.UNKNOWN,
                artifact_path=raw_path_str,
                artifact_size_bytes=0,
                artifact_hash_sha256=None,
                normalized_metadata=None,
                reason_codes=[ReasonCode.FILE_SIZE_LIMIT_EXCEEDED],
                warnings=[f"Resource limit exceeded: {e}"],
                details={"error_code": e.code, "details": e.details},
            )
        except Exception as e:
            return ModelInspectionResult(
                status=InspectionStatus.INVALID_ARTIFACT,
                format=ModelFormat.UNKNOWN,
                policy=InspectionPolicy.UNKNOWN,
                artifact_path=raw_path_str,
                artifact_size_bytes=0,
                artifact_hash_sha256=None,
                normalized_metadata=None,
                reason_codes=[ReasonCode.MISSING_ARTIFACT],
                warnings=[f"Unexpected path access failure: {e}"],
                details={"error": str(e)},
            )

        # 2. Compute Streaming SHA-256
        try:
            artifact_hash = compute_streaming_sha256(
                file_path=validated_path,
                max_bytes=self.limits.max_artifact_size_bytes,
            )
        except Exception as e:
            return ModelInspectionResult(
                status=InspectionStatus.INVALID_ARTIFACT,
                format=ModelFormat.UNKNOWN,
                policy=InspectionPolicy.UNKNOWN,
                artifact_path=str(validated_path),
                artifact_size_bytes=file_size,
                artifact_hash_sha256=None,
                normalized_metadata=None,
                reason_codes=[ReasonCode.CORRUPTED_CONTAINER],
                warnings=[f"Failed streaming hash computation: {e}"],
            )

        # 3. Format & Policy Detection
        detection = detect_model_format(validated_path, limits=self.limits)

        # 4. Enforce Safety Policy for Prohibited Formats (e.g. Arbitrary Pickle)
        if detection.policy == InspectionPolicy.PROHIBITED or detection.format == ModelFormat.PICKLE:
            return ModelInspectionResult(
                status=InspectionStatus.PROHIBITED,
                format=ModelFormat.PICKLE,
                policy=InspectionPolicy.PROHIBITED,
                artifact_path=str(validated_path),
                artifact_size_bytes=file_size,
                artifact_hash_sha256=artifact_hash,
                normalized_metadata=None,
                reason_codes=[
                    ReasonCode.PROHIBITED_FORMAT,
                    ReasonCode.ARBITRARY_CODE_EXECUTION_RISK,
                    ReasonCode.UNRESTRICTED_PICKLE_DETECTED,
                ],
                warnings=[
                    "Arbitrary pickle model format is prohibited due to arbitrary code execution risk.",
                    "Unrestricted deserialization rejected by Model Integrity policy.",
                ],
                details={
                    "detection_method": detection.detected_by,
                    "confidence": detection.confidence,
                },
            )

        # 5. Handle Corrupted or Unknown Formats
        if detection.format == ModelFormat.CORRUPTED:
            return ModelInspectionResult(
                status=InspectionStatus.INVALID_ARTIFACT,
                format=ModelFormat.CORRUPTED,
                policy=InspectionPolicy.UNKNOWN,
                artifact_path=str(validated_path),
                artifact_size_bytes=file_size,
                artifact_hash_sha256=artifact_hash,
                normalized_metadata=None,
                reason_codes=[ReasonCode.CORRUPTED_CONTAINER],
                warnings=["Artifact container is corrupted, truncated, or structurally malformed."],
                details={"detection_details": detection.details},
            )

        if detection.format == ModelFormat.UNKNOWN:
            return ModelInspectionResult(
                status=InspectionStatus.UNSUPPORTED_FORMAT,
                format=ModelFormat.UNKNOWN,
                policy=InspectionPolicy.UNKNOWN,
                artifact_path=str(validated_path),
                artifact_size_bytes=file_size,
                artifact_hash_sha256=artifact_hash,
                normalized_metadata=None,
                reason_codes=[ReasonCode.UNKNOWN_FORMAT],
                warnings=["Unrecognized model format; no safe static parser matches artifact."],
                details={"detection_details": detection.details},
            )

        # 6. Dispatch Format Parser
        try:
            if detection.format == ModelFormat.SAFETENSORS:
                parsed_data = self._safetensors_parser.parse(validated_path, limits=self.limits)
                status = InspectionStatus.SUCCESS
            elif detection.format == ModelFormat.ONNX:
                parsed_data = self._onnx_parser.parse(validated_path, limits=self.limits)
                status = InspectionStatus.SUCCESS
            elif detection.format == ModelFormat.PYTORCH_STATE_DICT:
                parsed_data = self._pytorch_parser.parse(validated_path, limits=self.limits)
                status = InspectionStatus.RESTRICTED
            elif detection.format == ModelFormat.TORCHSCRIPT:
                parsed_data = self._torchscript_parser.parse(validated_path, limits=self.limits)
                status = InspectionStatus.RESTRICTED
            else:
                return ModelInspectionResult(
                    status=InspectionStatus.UNSUPPORTED_FORMAT,
                    format=detection.format,
                    policy=detection.policy,
                    artifact_path=str(validated_path),
                    artifact_size_bytes=file_size,
                    artifact_hash_sha256=artifact_hash,
                    normalized_metadata=None,
                    reason_codes=[ReasonCode.SAFE_PARSER_UNAVAILABLE],
                    warnings=[f"No static parser configured for format '{detection.format}'."],
                )

        except ProhibitedFormatError as e:
            return ModelInspectionResult(
                status=InspectionStatus.PROHIBITED,
                format=detection.format,
                policy=InspectionPolicy.PROHIBITED,
                artifact_path=str(validated_path),
                artifact_size_bytes=file_size,
                artifact_hash_sha256=artifact_hash,
                normalized_metadata=None,
                reason_codes=[ReasonCode.PROHIBITED_FORMAT, ReasonCode.ARBITRARY_CODE_EXECUTION_RISK],
                warnings=[f"Security boundary violation during parser inspection: {e}"],
                details={"error_code": e.code, "details": e.details},
            )
        except ResourceLimitExceededError as e:
            reason = ReasonCode.FILE_SIZE_LIMIT_EXCEEDED
            if e.code == "HEADER_SIZE_LIMIT_EXCEEDED":
                reason = ReasonCode.HEADER_SIZE_LIMIT_EXCEEDED
            elif e.code == "TENSOR_COUNT_LIMIT_EXCEEDED":
                reason = ReasonCode.TENSOR_COUNT_LIMIT_EXCEEDED
            elif e.code == "DIMENSION_LIMIT_EXCEEDED":
                reason = ReasonCode.DIMENSION_LIMIT_EXCEEDED
            elif e.code == "ARCHIVE_MEMBER_COUNT_EXCEEDED":
                reason = ReasonCode.ARCHIVE_MEMBER_COUNT_EXCEEDED
            elif e.code == "ARCHIVE_BOMB_DETECTED":
                reason = ReasonCode.ARCHIVE_BOMB_DETECTED
            elif e.code == "STRING_LENGTH_LIMIT_EXCEEDED":
                reason = ReasonCode.STRING_LENGTH_LIMIT_EXCEEDED

            return ModelInspectionResult(
                status=InspectionStatus.INVALID_ARTIFACT,
                format=detection.format,
                policy=detection.policy,
                artifact_path=str(validated_path),
                artifact_size_bytes=file_size,
                artifact_hash_sha256=artifact_hash,
                normalized_metadata=None,
                reason_codes=[reason],
                warnings=[f"Resource limit exceeded during inspection: {e}"],
                details={"error_code": e.code, "details": e.details},
            )
        except (ModelCorruptionError, UntrustedArtifactSecurityError) as e:
            reason = ReasonCode.CORRUPTED_CONTAINER
            if e.code == "MALFORMED_HEADER":
                reason = ReasonCode.MALFORMED_HEADER
            elif e.code == "MALFORMED_PROTOBUF":
                reason = ReasonCode.MALFORMED_PROTOBUF
            elif e.code == "INVALID_TENSOR_OFFSET":
                reason = ReasonCode.INVALID_TENSOR_OFFSET
            elif e.code == "PATH_TRAVERSAL_ATTEMPT":
                reason = ReasonCode.PATH_TRAVERSAL_ATTEMPT

            return ModelInspectionResult(
                status=InspectionStatus.INVALID_ARTIFACT,
                format=detection.format,
                policy=detection.policy,
                artifact_path=str(validated_path),
                artifact_size_bytes=file_size,
                artifact_hash_sha256=artifact_hash,
                normalized_metadata=None,
                reason_codes=[reason],
                warnings=[f"Structural inspection failed: {e}"],
                details={"error_code": e.code, "details": e.details},
            )
        except Exception as e:
            return ModelInspectionResult(
                status=InspectionStatus.INVALID_ARTIFACT,
                format=detection.format,
                policy=detection.policy,
                artifact_path=str(validated_path),
                artifact_size_bytes=file_size,
                artifact_hash_sha256=artifact_hash,
                normalized_metadata=None,
                reason_codes=[ReasonCode.CORRUPTED_CONTAINER],
                warnings=[f"Unexpected static parser exception: {e}"],
                details={"error": str(e)},
            )

        # 7. Normalize Metadata Representation
        normalized = build_normalized_metadata(
            parsed_data=parsed_data,
            artifact_size_bytes=file_size,
            artifact_hash_sha256=artifact_hash,
            inspection_status=status,
        )

        return ModelInspectionResult(
            status=status,
            format=detection.format,
            policy=detection.policy,
            artifact_path=str(validated_path),
            artifact_size_bytes=file_size,
            artifact_hash_sha256=artifact_hash,
            normalized_metadata=normalized,
            reason_codes=normalized.reason_codes,
            warnings=normalized.warnings,
            details={
                "detection_method": detection.detected_by,
                "confidence": detection.confidence,
                "container_type": detection.container_type,
                **parsed_data.details,
            },
        )
