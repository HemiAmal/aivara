"""Safe static archive parser for TorchScript model artifacts.

Strictly inspects Zip container structure without calling torch.jit.load() or
executing model bytecode.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
import zipfile

from aivara.model_integrity.exceptions import (
    ModelCorruptionError,
    ResourceLimitExceededError,
    UntrustedArtifactSecurityError,
)
from aivara.model_integrity.limits import DEFAULT_LIMITS, ModelIngestionLimits
from aivara.model_integrity.parsers.base import BaseModelParser, ParsedModelData
from aivara.model_integrity.schemas import (
    ModelFormat,
    ReasonCode,
    TensorDescriptor,
)


class TorchScriptParser(BaseModelParser):
    """Static zip-container inspector for TorchScript models."""

    def parse(
        self,
        artifact_path: Path,
        limits: ModelIngestionLimits = DEFAULT_LIMITS,
    ) -> ParsedModelData:
        """Inspect TorchScript archive structure statically without execution."""
        file_size = artifact_path.stat().st_size
        limits.check_file_size(file_size, filename=artifact_path.name)

        if not zipfile.is_zipfile(artifact_path):
            raise ModelCorruptionError(
                "TorchScript artifact is not a valid Zip archive container.",
                code="CORRUPTED_CONTAINER",
                details={"path": str(artifact_path)},
            )

        metadata_props: Dict[str, str] = {}
        warnings: List[str] = [
            "TorchScript model inspected statically; runtime execution is prohibited."
        ]
        code_files: List[str] = []
        data_files: List[str] = []
        total_storage_bytes = 0

        try:
            with zipfile.ZipFile(artifact_path, "r") as zf:
                infolist = zf.infolist()
                limits.check_archive_members(len(infolist))

                # Zip bomb defense
                uncompressed_total = sum(i.file_size for i in infolist)
                compressed_total = sum(i.compress_size for i in infolist)
                limits.check_archive_bomb(compressed_total, uncompressed_total)

                # Zip slip defense & catalog members
                for info in infolist:
                    filename = info.filename
                    if ".." in filename or filename.startswith(("/", "\\")):
                        raise UntrustedArtifactSecurityError(
                            f"Path traversal sequence in archive member '{filename}'.",
                            code="PATH_TRAVERSAL_ATTEMPT",
                            details={"member": filename},
                        )

                    limits.check_string_length(filename, "archive_member_name")

                    if "/code/" in filename or filename.startswith("code/"):
                        code_files.append(filename)
                    elif "/data/" in filename or filename.startswith("data/"):
                        data_files.append(filename)
                        total_storage_bytes += info.file_size
                    elif filename.endswith("version"):
                        try:
                            with zf.open(info) as vf:
                                ver_str = vf.read(1024).decode("utf-8", errors="ignore").strip()
                                metadata_props["torchscript_version"] = ver_str
                        except Exception:
                            pass
                    elif filename.endswith("model.json"):
                        try:
                            limits.check_header_size(info.file_size, format_name="torchscript_model_json")
                            with zf.open(info) as mj:
                                raw_mj = mj.read()
                                mjson = json.loads(raw_mj.decode("utf-8", errors="replace"))
                                if isinstance(mjson, dict):
                                    for k, v in mjson.items():
                                        if isinstance(v, (str, int, float, bool)):
                                            metadata_props[f"model_{k}"] = str(v)
                        except Exception:
                            warnings.append("Could not parse model.json inside TorchScript archive.")

        except zipfile.BadZipFile as e:
            raise ModelCorruptionError(
                f"Corrupted TorchScript Zip archive: {e}",
                code="CORRUPTED_CONTAINER",
                details={"error": str(e)},
            )

        metadata_props["archive_member_count"] = str(len(infolist))
        metadata_props["storage_files_count"] = str(len(data_files))
        metadata_props["code_files_count"] = str(len(code_files))
        metadata_props["total_storage_bytes"] = str(total_storage_bytes)

        return ParsedModelData(
            format=ModelFormat.TORCHSCRIPT,
            tensors=[],  # TorchScript tensor extraction without execution is deferred to static storage analysis
            inputs=[],
            outputs=[],
            operators=[],
            metadata_props=metadata_props,
            warnings=warnings,
            reason_codes=[ReasonCode.RESTRICTED_INSPECTION_ONLY],
            details={
                "code_members": code_files[:50],
                "data_members_count": len(data_files),
                "uncompressed_bytes": uncompressed_total,
            },
        )
