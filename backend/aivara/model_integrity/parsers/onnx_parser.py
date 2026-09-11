"""Safe static parser for ONNX model artifacts without ONNX Runtime or code execution.

Parses ONNX ModelProto directly from Protocol Buffer wire format in pure Python,
extracting computational graph metadata, tensor initializers, and I/O contracts.
"""

from __future__ import annotations

import io
import math
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from aivara.model_integrity.exceptions import (
    ModelCorruptionError,
    ResourceLimitExceededError,
)
from aivara.model_integrity.limits import DEFAULT_LIMITS, ModelIngestionLimits
from aivara.model_integrity.parsers.base import BaseModelParser, ParsedModelData
from aivara.model_integrity.schemas import (
    InputContractDescriptor,
    ModelFormat,
    OperatorDescriptor,
    OutputContractDescriptor,
    ReasonCode,
    TensorDescriptor,
)

# ONNX TensorProto DataType enum mapping
ONNX_DTYPE_MAP: Dict[int, Tuple[str, int]] = {
    1: ("F32", 4),       # FLOAT
    2: ("U8", 1),        # UINT8
    3: ("I8", 1),        # INT8
    4: ("U16", 2),       # UINT16
    5: ("I16", 2),       # INT16
    6: ("I32", 4),       # INT32
    7: ("I64", 8),       # INT64
    8: ("STRING", 0),    # STRING
    9: ("BOOL", 1),      # BOOL
    10: ("F16", 2),      # FLOAT16
    11: ("F64", 8),      # DOUBLE
    12: ("U32", 4),      # UINT32
    13: ("U64", 8),      # UINT64
    14: ("C64", 8),      # COMPLEX64
    15: ("C128", 16),    # COMPLEX128
    16: ("BF16", 2),     # BFLOAT16
}


def read_varint(stream: io.BytesIO, max_bytes: int = 10) -> int:
    """Read an unsigned LEB128 varint from a byte stream."""
    result = 0
    shift = 0
    bytes_read = 0

    while True:
        b = stream.read(1)
        if not b:
            raise EOFError("Unexpected EOF while reading varint")
        val = b[0]
        bytes_read += 1
        result |= (val & 0x7F) << shift
        if not (val & 0x80):
            break
        shift += 7
        if bytes_read > max_bytes:
            raise ModelCorruptionError(
                "Varint exceeds maximum allowed byte length (malformed protobuf).",
                code="MALFORMED_PROTOBUF",
            )

    return result


def skip_field(stream: io.BytesIO, wire_type: int) -> None:
    """Skip a field based on its wire type."""
    if wire_type == 0:  # Varint
        read_varint(stream)
    elif wire_type == 1:  # 64-bit
        data = stream.read(8)
        if len(data) < 8:
            raise EOFError("Unexpected EOF reading 64-bit field")
    elif wire_type == 2:  # Length-delimited
        length = read_varint(stream)
        data = stream.read(length)
        if len(data) < length:
            raise EOFError("Unexpected EOF reading length-delimited field")
    elif wire_type == 5:  # 32-bit
        data = stream.read(4)
        if len(data) < 4:
            raise EOFError("Unexpected EOF reading 32-bit field")
    else:
        raise ModelCorruptionError(
            f"Unsupported or corrupted protobuf wire type {wire_type}.",
            code="MALFORMED_PROTOBUF",
        )


def read_length_delimited(stream: io.BytesIO) -> bytes:
    """Read length-delimited bytes with bounds check."""
    length = read_varint(stream)
    if length < 0:
        raise ModelCorruptionError("Negative field length in protobuf.", code="MALFORMED_PROTOBUF")
    data = stream.read(length)
    if len(data) < length:
        raise EOFError(f"Unexpected EOF: expected {length} bytes, got {len(data)}")
    return data


def parse_tensor_shape_proto(data: bytes) -> Tuple[List[Optional[int]], bool]:
    """Parse TensorShapeProto into dimension list and dynamic flag."""
    stream = io.BytesIO(data)
    dims: List[Optional[int]] = []
    is_dynamic = False

    while True:
        tag_byte = stream.read(1)
        if not tag_byte:
            break
        stream.seek(-1, io.SEEK_CUR)
        tag = read_varint(stream)
        field_num = tag >> 3
        wire_type = tag & 0x07

        if field_num == 1 and wire_type == 2:  # dim (Dimension)
            dim_bytes = read_length_delimited(stream)
            dim_stream = io.BytesIO(dim_bytes)
            dim_val: Optional[int] = None

            while True:
                db = dim_stream.read(1)
                if not db:
                    break
                dim_stream.seek(-1, io.SEEK_CUR)
                dtag = read_varint(dim_stream)
                dfield = dtag >> 3
                dwire = dtag & 0x07

                if dfield == 1 and dwire == 0:  # dim_value (int64)
                    dim_val = read_varint(dim_stream)
                elif dfield == 2 and dwire == 2:  # dim_param (string e.g. 'batch')
                    dim_param_bytes = read_length_delimited(dim_stream)
                    is_dynamic = True
                    dim_val = None
                else:
                    skip_field(dim_stream, dwire)

            dims.append(dim_val)
        else:
            skip_field(stream, wire_type)

    return dims, is_dynamic


def parse_value_info_proto(data: bytes) -> Tuple[str, List[Optional[int]], str, bool]:
    """Parse ValueInfoProto into (name, shape, dtype_str, is_dynamic)."""
    stream = io.BytesIO(data)
    name = ""
    shape: List[Optional[int]] = []
    dtype_str = "UNKNOWN"
    is_dynamic = False

    while True:
        b = stream.read(1)
        if not b:
            break
        stream.seek(-1, io.SEEK_CUR)
        tag = read_varint(stream)
        field_num = tag >> 3
        wire_type = tag & 0x07

        if field_num == 1 and wire_type == 2:  # name
            name = read_length_delimited(stream).decode("utf-8", errors="replace")
        elif field_num == 2 and wire_type == 2:  # type (TypeProto)
            type_bytes = read_length_delimited(stream)
            tstream = io.BytesIO(type_bytes)
            while True:
                tb = tstream.read(1)
                if not tb:
                    break
                tstream.seek(-1, io.SEEK_CUR)
                ttag = read_varint(tstream)
                tfield = ttag >> 3
                twire = ttag & 0x07

                if tfield == 1 and twire == 2:  # tensor_type
                    tensor_type_bytes = read_length_delimited(tstream)
                    tt_stream = io.BytesIO(tensor_type_bytes)
                    while True:
                        ttb = tt_stream.read(1)
                        if not ttb:
                            break
                        tt_stream.seek(-1, io.SEEK_CUR)
                        tt_tag = read_varint(tt_stream)
                        tt_field = tt_tag >> 3
                        tt_wire = tt_tag & 0x07

                        if tt_field == 1 and tt_wire == 0:  # elem_type
                            elem_type_id = read_varint(tt_stream)
                            if elem_type_id in ONNX_DTYPE_MAP:
                                dtype_str = ONNX_DTYPE_MAP[elem_type_id][0]
                        elif tt_field == 2 and tt_wire == 2:  # shape (TensorShapeProto)
                            shape_bytes = read_length_delimited(tt_stream)
                            shape, is_dynamic = parse_tensor_shape_proto(shape_bytes)
                        else:
                            skip_field(tt_stream, tt_wire)
                else:
                    skip_field(tstream, twire)
        else:
            skip_field(stream, wire_type)

    return name, shape, dtype_str, is_dynamic


def parse_tensor_proto(data: bytes, limits: ModelIngestionLimits) -> TensorDescriptor:
    """Parse TensorProto initializer into TensorDescriptor."""
    stream = io.BytesIO(data)
    name = ""
    dims: List[int] = []
    dtype_id = 1
    raw_data_len = 0

    while True:
        b = stream.read(1)
        if not b:
            break
        stream.seek(-1, io.SEEK_CUR)
        tag = read_varint(stream)
        field_num = tag >> 3
        wire_type = tag & 0x07

        if field_num == 1:  # dims (repeated int64)
            if wire_type == 0:  # single varint
                dims.append(read_varint(stream))
            elif wire_type == 2:  # packed varints
                packed_bytes = read_length_delimited(stream)
                pstream = io.BytesIO(packed_bytes)
                while True:
                    pb = pstream.read(1)
                    if not pb:
                        break
                    pstream.seek(-1, io.SEEK_CUR)
                    dims.append(read_varint(pstream))
        elif field_num == 2 and wire_type == 0:  # data_type
            dtype_id = read_varint(stream)
        elif field_num == 4 and wire_type == 2:  # raw_data
            raw_bytes = read_length_delimited(stream)
            raw_data_len = len(raw_bytes)
        elif field_num == 7 and wire_type == 2:  # name
            name = read_length_delimited(stream).decode("utf-8", errors="replace")
        elif field_num == 9 and wire_type == 2:  # float_data (packed float32)
            flt_bytes = read_length_delimited(stream)
            raw_data_len = len(flt_bytes)
        elif field_num == 10 and wire_type == 2:  # int32_data (packed int32)
            i32_bytes = read_length_delimited(stream)
            raw_data_len = len(i32_bytes)
        elif field_num == 12 and wire_type == 2:  # int64_data (packed int64)
            i64_bytes = read_length_delimited(stream)
            raw_data_len = len(i64_bytes)
        elif field_num == 14 and wire_type == 2:  # double_data (packed double)
            f64_bytes = read_length_delimited(stream)
            raw_data_len = len(f64_bytes)
        else:
            skip_field(stream, wire_type)

    dtype_str, unit_bytes = ONNX_DTYPE_MAP.get(dtype_id, ("UNKNOWN", 4))
    element_count = math.prod(dims) if dims else (1 if raw_data_len > 0 else 0)
    byte_size = raw_data_len if raw_data_len > 0 else (element_count * unit_bytes)

    limits.check_string_length(name, "tensor_name")
    limits.check_tensor_shape(dims, tensor_name=name)

    return TensorDescriptor(
        name=name,
        shape=dims,
        dtype=dtype_str,
        element_count=element_count,
        byte_size=byte_size,
    )


def parse_node_proto(data: bytes) -> Tuple[str, str, str]:
    """Parse NodeProto into (name, op_type, domain)."""
    stream = io.BytesIO(data)
    name = ""
    op_type = ""
    domain = ""

    while True:
        b = stream.read(1)
        if not b:
            break
        stream.seek(-1, io.SEEK_CUR)
        tag = read_varint(stream)
        field_num = tag >> 3
        wire_type = tag & 0x07

        if field_num == 3 and wire_type == 2:  # name
            name = read_length_delimited(stream).decode("utf-8", errors="replace")
        elif field_num == 4 and wire_type == 2:  # op_type
            op_type = read_length_delimited(stream).decode("utf-8", errors="replace")
        elif field_num == 7 and wire_type == 2:  # domain
            domain = read_length_delimited(stream).decode("utf-8", errors="replace")
        else:
            skip_field(stream, wire_type)

    return name, op_type, domain


class ONNXParser(BaseModelParser):
    """Safe static Protobuf wire parser for ONNX models."""

    def parse(
        self,
        artifact_path: Path,
        limits: ModelIngestionLimits = DEFAULT_LIMITS,
    ) -> ParsedModelData:
        """Statically inspect ONNX ModelProto from protobuf wire stream."""
        file_size = artifact_path.stat().st_size
        limits.check_file_size(file_size, filename=artifact_path.name)

        with open(artifact_path, "rb") as f:
            raw_bytes = f.read()

        stream = io.BytesIO(raw_bytes)

        ir_version: Optional[int] = None
        producer_name: str = ""
        producer_version: str = ""
        model_version: Optional[int] = None
        doc_string: str = ""
        opset_imports: Dict[str, int] = {}
        metadata_props: Dict[str, str] = {}
        tensors: List[TensorDescriptor] = []
        inputs: List[InputContractDescriptor] = []
        outputs: List[OutputContractDescriptor] = []
        op_counts: Dict[Tuple[str, str], int] = {}
        warnings: List[str] = []

        try:
            while True:
                b = stream.read(1)
                if not b:
                    break
                stream.seek(-1, io.SEEK_CUR)
                tag = read_varint(stream)
                field_num = tag >> 3
                wire_type = tag & 0x07

                if field_num == 1 and wire_type == 0:  # ir_version
                    ir_version = read_varint(stream)
                elif field_num == 2 and wire_type == 2:  # producer_name
                    producer_name = read_length_delimited(stream).decode("utf-8", errors="replace")
                elif field_num == 3 and wire_type == 2:  # producer_version
                    producer_version = read_length_delimited(stream).decode("utf-8", errors="replace")
                elif field_num == 5 and wire_type == 0:  # model_version
                    model_version = read_varint(stream)
                elif field_num == 6 and wire_type == 2:  # doc_string
                    doc_string = read_length_delimited(stream).decode("utf-8", errors="replace")
                elif field_num == 7 and wire_type == 2:  # graph (GraphProto)
                    graph_bytes = read_length_delimited(stream)
                    g_stream = io.BytesIO(graph_bytes)
                    node_count = 0

                    while True:
                        gb = g_stream.read(1)
                        if not gb:
                            break
                        g_stream.seek(-1, io.SEEK_CUR)
                        gtag = read_varint(g_stream)
                        gfield = gtag >> 3
                        gwire = gtag & 0x07

                        if gfield == 1 and gwire == 2:  # node (NodeProto)
                            node_bytes = read_length_delimited(g_stream)
                            node_count += 1
                            if node_count > limits.max_graph_nodes:
                                raise ResourceLimitExceededError(
                                    f"ONNX graph node count exceeds limit of {limits.max_graph_nodes}.",
                                    code="GRAPH_COMPLEXITY_LIMIT_EXCEEDED",
                                )
                            _, op_type, domain = parse_node_proto(node_bytes)
                            if op_type:
                                op_key = (op_type, domain)
                                op_counts[op_key] = op_counts.get(op_key, 0) + 1
                        elif gfield == 5 and gwire == 2:  # initializer (TensorProto)
                            init_bytes = read_length_delimited(g_stream)
                            tensor = parse_tensor_proto(init_bytes, limits)
                            tensors.append(tensor)
                            limits.check_tensor_count(len(tensors))
                        elif gfield == 11 and gwire == 2:  # input (ValueInfoProto)
                            in_bytes = read_length_delimited(g_stream)
                            in_name, in_shape, in_dtype, in_dyn = parse_value_info_proto(in_bytes)
                            # In ONNX, graph inputs can also include initializers; filter or include
                            channel_order = None
                            if len(in_shape) == 4:
                                channel_order = "NCHW"
                            inputs.append(
                                InputContractDescriptor(
                                    name=in_name,
                                    shape=in_shape,
                                    dtype=in_dtype,
                                    channel_order=channel_order,
                                    is_dynamic=in_dyn,
                                )
                            )
                        elif gfield == 12 and gwire == 2:  # output (ValueInfoProto)
                            out_bytes = read_length_delimited(g_stream)
                            out_name, out_shape, out_dtype, _ = parse_value_info_proto(out_bytes)
                            outputs.append(
                                OutputContractDescriptor(
                                    name=out_name,
                                    shape=out_shape,
                                    dtype=out_dtype,
                                )
                            )
                        else:
                            skip_field(g_stream, gwire)

                elif field_num == 8 and wire_type == 2:  # opset_import (OperatorSetIdProto)
                    opset_bytes = read_length_delimited(stream)
                    opset_stream = io.BytesIO(opset_bytes)
                    domain = ""
                    version = 0
                    while True:
                        ob = opset_stream.read(1)
                        if not ob:
                            break
                        opset_stream.seek(-1, io.SEEK_CUR)
                        otag = read_varint(opset_stream)
                        ofield = otag >> 3
                        owire = otag & 0x07
                        if ofield == 1 and owire == 2:
                            domain = read_length_delimited(opset_stream).decode("utf-8", errors="replace")
                        elif ofield == 2 and owire == 0:
                            version = read_varint(opset_stream)
                        else:
                            skip_field(opset_stream, owire)
                    opset_imports[domain or "ai.onnx"] = version

                elif field_num == 14 and wire_type == 2:  # metadata_props (StringStringEntryProto)
                    prop_bytes = read_length_delimited(stream)
                    p_stream = io.BytesIO(prop_bytes)
                    key = ""
                    val = ""
                    while True:
                        pb = p_stream.read(1)
                        if not pb:
                            break
                        p_stream.seek(-1, io.SEEK_CUR)
                        ptag = read_varint(p_stream)
                        pfield = ptag >> 3
                        pwire = ptag & 0x07
                        if pfield == 1 and pwire == 2:
                            key = read_length_delimited(p_stream).decode("utf-8", errors="replace")
                        elif pfield == 2 and pwire == 2:
                            val = read_length_delimited(p_stream).decode("utf-8", errors="replace")
                        else:
                            skip_field(p_stream, pwire)
                    if key:
                        metadata_props[key] = val

                else:
                    skip_field(stream, wire_type)

        except EOFError as e:
            raise ModelCorruptionError(
                f"Truncated ONNX protobuf payload: {e}",
                code="MALFORMED_PROTOBUF",
                details={"error": str(e)},
            )
        except Exception as e:
            if isinstance(e, (ModelCorruptionError, ResourceLimitExceededError)):
                raise
            raise ModelCorruptionError(
                f"Failed parsing ONNX protobuf: {e}",
                code="MALFORMED_PROTOBUF",
                details={"error": str(e)},
            )

        # Store producer info in metadata props if present
        if producer_name:
            metadata_props["producer_name"] = producer_name
        if producer_version:
            metadata_props["producer_version"] = producer_version
        if ir_version is not None:
            metadata_props["ir_version"] = str(ir_version)

        # Build operators list
        operators = [
            OperatorDescriptor(op_type=op, count=cnt, domain=dom)
            for (op, dom), cnt in sorted(op_counts.items())
        ]

        # Separate initializers from graph inputs (in ONNX inputs often list initializers)
        init_names = {t.name for t in tensors}
        clean_inputs = [inp for inp in inputs if inp.name not in init_names]

        return ParsedModelData(
            format=ModelFormat.ONNX,
            tensors=tensors,
            inputs=clean_inputs or inputs,
            outputs=outputs,
            operators=operators,
            metadata_props=metadata_props,
            warnings=warnings,
            reason_codes=[ReasonCode.SAFE_INSPECTION_PASSED],
            details={
                "ir_version": ir_version,
                "opset_imports": opset_imports,
                "node_count": sum(op_counts.values()),
            },
        )
