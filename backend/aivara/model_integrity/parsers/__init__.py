"""Format-specific static parsers for model integrity inspection."""

from aivara.model_integrity.parsers.base import BaseModelParser, ParsedModelData
from aivara.model_integrity.parsers.onnx_parser import ONNXParser
from aivara.model_integrity.parsers.pytorch_parser import PyTorchStateDictParser
from aivara.model_integrity.parsers.safetensors_parser import SafetensorsParser
from aivara.model_integrity.parsers.torchscript_parser import TorchScriptParser

__all__ = [
    "BaseModelParser",
    "ParsedModelData",
    "SafetensorsParser",
    "ONNXParser",
    "PyTorchStateDictParser",
    "TorchScriptParser",
]
