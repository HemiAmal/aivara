"""Safe restricted PyTorch state_dict parser with strict AST / opcode whitelist.

Strictly prohibits unrestricted pickle.load(), arbitrary class instantiation,
and model code execution. Parses tensor keys, shapes, and dtypes safely.
"""

from __future__ import annotations

import io
import math
import pickle
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from aivara.model_integrity.exceptions import (
    ModelCorruptionError,
    ProhibitedFormatError,
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

# Whitelist of safe global modules and classes allowed during unpickling
SAFE_PICKLE_WHITELIST: Set[Tuple[str, str]] = {
    # Collections & Builtins
    ("collections", "OrderedDict"),
    ("collections", "defaultdict"),
    ("builtins", "dict"),
    ("builtins", "list"),
    ("builtins", "set"),
    ("builtins", "tuple"),
    ("builtins", "int"),
    ("builtins", "float"),
    ("builtins", "str"),
    ("builtins", "bytes"),
    ("builtins", "bytearray"),
    ("builtins", "bool"),
    ("builtins", "NoneType"),
    # PyTorch reconstruction helpers
    ("torch._utils", "_rebuild_tensor_v2"),
    ("torch._utils", "_rebuild_tensor"),
    ("torch._utils", "_rebuild_parameter"),
    ("torch._utils", "_rebuild_qtensor"),
    ("torch", "HalfStorage"),
    ("torch", "FloatStorage"),
    ("torch", "DoubleStorage"),
    ("torch", "BFloat16Storage"),
    ("torch", "CharStorage"),
    ("torch", "ShortStorage"),
    ("torch", "IntStorage"),
    ("torch", "LongStorage"),
    ("torch", "ByteStorage"),
    ("torch", "BoolStorage"),
    ("torch", "storage"),
    ("torch", "Tensor"),
    ("torch", "Size"),
}

STORAGE_DTYPE_MAP: Dict[str, Tuple[str, int]] = {
    "FloatStorage": ("F32", 4),
    "HalfStorage": ("F16", 2),
    "DoubleStorage": ("F64", 8),
    "BFloat16Storage": ("BF16", 2),
    "CharStorage": ("I8", 1),
    "ShortStorage": ("I16", 2),
    "IntStorage": ("I32", 4),
    "LongStorage": ("I64", 8),
    "ByteStorage": ("U8", 1),
    "BoolStorage": ("BOOL", 1),
}


class MockStorage:
    """Mock storage descriptor for safe tensor rebuilding."""

    def __init__(self, dtype_name: str, key: str, size: int) -> None:
        self.dtype_name = dtype_name
        self.key = key
        self.size = size


class MockTensor:
    """Mock tensor descriptor storing shape, dtype, and element count."""

    def __init__(
        self,
        storage: Any,
        storage_offset: int,
        size: Tuple[int, ...],
        stride: Tuple[int, ...],
        requires_grad: bool = False,
    ) -> None:
        self.storage = storage
        self.storage_offset = storage_offset
        self.size = list(size)
        self.stride = list(stride)
        self.requires_grad = requires_grad


def mock_rebuild_tensor_v2(storage, storage_offset, size, stride, requires_grad, backward_hooks):
    """Safe mock for torch._utils._rebuild_tensor_v2."""
    return MockTensor(storage, storage_offset, size, stride, requires_grad)


def mock_rebuild_tensor(storage, storage_offset, size, stride):
    """Safe mock for torch._utils._rebuild_tensor."""
    return MockTensor(storage, storage_offset, size, stride)


def mock_rebuild_parameter(data, requires_grad, backward_hooks=None):
    """Safe mock for torch._utils._rebuild_parameter."""
    return data


class SafeStateDictUnpickler(pickle.Unpickler):
    """Restricted Unpickler that strictly permits only whitelisted types."""

    def __init__(self, file, limits: ModelIngestionLimits) -> None:
        super().__init__(file)
        self.limits = limits

    def find_class(self, module: str, name: str) -> Any:
        """Enforce strict whitelist of classes; reject any executable/arbitrary class."""
        if (module, name) not in SAFE_PICKLE_WHITELIST:
            raise ProhibitedFormatError(
                f"Prohibited class/function '{module}.{name}' detected during state_dict inspection. "
                "Arbitrary code execution vectors are strictly rejected.",
                code="ARBITRARY_CODE_EXECUTION_RISK",
                details={"module": module, "class_name": name},
            )

        # Return safe mocks for PyTorch tensor reconstruction
        if module == "torch._utils" and name == "_rebuild_tensor_v2":
            return mock_rebuild_tensor_v2
        if module == "torch._utils" and name == "_rebuild_tensor":
            return mock_rebuild_tensor
        if module == "torch._utils" and name == "_rebuild_parameter":
            return mock_rebuild_parameter
        if module == "torch" and name in STORAGE_DTYPE_MAP:
            return lambda *args: MockStorage(name, *args)
        if module == "torch" and name == "Size":
            return tuple

        # Standard built-ins
        return super().find_class(module, name)


class PyTorchStateDictParser(BaseModelParser):
    """Restricted safe parser for PyTorch state_dict checkpoints."""

    def parse(
        self,
        artifact_path: Path,
        limits: ModelIngestionLimits = DEFAULT_LIMITS,
    ) -> ParsedModelData:
        """Parse state_dict checkpoint strictly via safe restricted unpickling."""
        file_size = artifact_path.stat().st_size
        limits.check_file_size(file_size, filename=artifact_path.name)

        tensors: List[TensorDescriptor] = []
        metadata_props: Dict[str, str] = {}
        warnings: List[str] = []

        is_zip = zipfile.is_zipfile(artifact_path)

        if is_zip:
            try:
                with zipfile.ZipFile(artifact_path, "r") as zf:
                    infolist = zf.infolist()
                    limits.check_archive_members(len(infolist))

                    # Check for zip bomb
                    uncompressed_total = sum(i.file_size for i in infolist)
                    compressed_total = sum(i.compress_size for i in infolist)
                    limits.check_archive_bomb(compressed_total, uncompressed_total)

                    # Check for path traversal in member names
                    for info in infolist:
                        if ".." in info.filename or info.filename.startswith(("/", "\\")):
                            raise UntrustedArtifactSecurityError(
                                f"Zip slip / path traversal in archive member '{info.filename}'.",
                                code="PATH_TRAVERSAL_ATTEMPT",
                                details={"member": info.filename},
                            )

                    # Look for data.pkl or */data.pkl
                    pkl_entry = None
                    for info in infolist:
                        if info.filename.endswith("data.pkl") or info.filename == "data.pkl":
                            pkl_entry = info
                            break

                    if not pkl_entry:
                        raise ModelCorruptionError(
                            "Zip archive is missing required PyTorch checkpoint entry 'data.pkl'.",
                            code="CORRUPTED_CONTAINER",
                        )

                    limits.check_header_size(pkl_entry.file_size, format_name="pytorch_state_dict")
                    with zf.open(pkl_entry) as pkl_file:
                        pkl_bytes = pkl_file.read()

            except zipfile.BadZipFile as e:
                raise ModelCorruptionError(
                    f"Malformed PyTorch zip container: {e}",
                    code="CORRUPTED_CONTAINER",
                    details={"error": str(e)},
                )
        else:
            # Raw legacy pickle stream
            with open(artifact_path, "rb") as f:
                pkl_bytes = f.read()

        # Unpickle strictly via SafeStateDictUnpickler
        try:
            unpickler = SafeStateDictUnpickler(io.BytesIO(pkl_bytes), limits=limits)
            data = unpickler.load()
        except ProhibitedFormatError:
            raise
        except Exception as e:
            raise ModelCorruptionError(
                f"Failed safe inspection of PyTorch state_dict: {e}",
                code="MALFORMED_HEADER",
                details={"error": str(e)},
            )

        if not isinstance(data, (dict, list)):
            raise ProhibitedFormatError(
                f"Root of PyTorch checkpoint must be a dictionary or OrderedDict, got {type(data).__name__}.",
                code="ARBITRARY_CODE_EXECUTION_RISK",
            )

        if isinstance(data, dict):
            # If wrapped in 'state_dict' or 'model'
            if "state_dict" in data and isinstance(data["state_dict"], dict):
                dict_to_parse = data["state_dict"]
            elif "model" in data and isinstance(data["model"], dict):
                dict_to_parse = data["model"]
            else:
                dict_to_parse = data

            limits.check_tensor_count(len(dict_to_parse))

            for key, val in dict_to_parse.items():
                k_str = str(key)
                limits.check_string_length(k_str, "tensor_name")

                if isinstance(val, MockTensor):
                    shape = val.size
                    limits.check_tensor_shape(shape, tensor_name=k_str)
                    dtype_str = "F32"
                    unit_bytes = 4
                    if hasattr(val.storage, "dtype_name"):
                        storage_dtype = val.storage.dtype_name
                        if storage_dtype in STORAGE_DTYPE_MAP:
                            dtype_str, unit_bytes = STORAGE_DTYPE_MAP[storage_dtype]

                    element_count = math.prod(shape) if shape else 1
                    byte_size = element_count * unit_bytes

                    tensors.append(
                        TensorDescriptor(
                            name=k_str,
                            shape=shape,
                            dtype=dtype_str,
                            element_count=element_count,
                            byte_size=byte_size,
                        )
                    )
                elif isinstance(val, (int, float, str, bool)):
                    metadata_props[k_str] = str(val)
                else:
                    warnings.append(f"Non-tensor entry '{k_str}' of type {type(val).__name__} recorded.")

        return ParsedModelData(
            format=ModelFormat.PYTORCH_STATE_DICT,
            tensors=tensors,
            inputs=[],
            outputs=[],
            operators=[],
            metadata_props=metadata_props,
            warnings=warnings,
            reason_codes=[ReasonCode.RESTRICTED_INSPECTION_ONLY],
            details={"is_zip_container": is_zip, "tensor_count": len(tensors)},
        )
