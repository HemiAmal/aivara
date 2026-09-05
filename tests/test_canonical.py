"""Unit and integration tests for AIVARA's Canonical Serialization Engine (Phase 4.2).

Covers:
- TESTS 1 to 16 required by Phase 4.2 specification
- RFC 8785 / JCS reference test vectors (ECMA 262 numbers, UTF-16BE key sorting)
- Input immutability
- Type safety boundary and exception taxonomy
- Datetime canonicalization
- Representative provenance payload canonicalization
"""

import copy
import math
import pathlib
import uuid
from datetime import datetime, timezone
from decimal import Decimal

import pytest

from aivara.crypto import (
    CANONICAL_SCHEMA_VERSION,
    CanonicalizationError,
    DuplicateKeyError,
    InvalidNumberError,
    InvalidSchemaVersionError,
    InvalidStringError,
    MalformedStructureError,
    UnsupportedTypeError,
    canonicalize,
    canonicalize_provenance_payload,
    format_canonical_datetime,
    parse_canonical_json,
    validate_canonical_data,
)


class TestCanonicalSerialization:
    """Test suite covering Phase 4.2 Canonical Serialization Engine."""

    # -----------------------------------------------------------------
    # TEST 1: Same Object
    # -----------------------------------------------------------------
    def test_same_object_identical_bytes(self):
        """Input A and logically identical Input B must produce identical bytes."""
        a = {"a": 1, "b": 2}
        b = {"a": 1, "b": 2}
        assert canonicalize(a) == canonicalize(b)
        assert canonicalize(a) == b'{"a":1,"b":2}'

    # -----------------------------------------------------------------
    # TEST 2: Key Order Invariance
    # -----------------------------------------------------------------
    def test_key_order_invariance(self):
        """Objects with different key insertion orders must produce identical bytes."""
        a = {"a": 1, "b": 2}
        b = {"b": 2, "a": 1}
        c = {"z": 99, "m": 50, "a": 1, "b": 2}
        d = {"a": 1, "z": 99, "b": 2, "m": 50}

        assert canonicalize(a) == canonicalize(b)
        assert canonicalize(c) == canonicalize(d)
        assert canonicalize(c) == b'{"a":1,"b":2,"m":50,"z":99}'

    # -----------------------------------------------------------------
    # TEST 3: Whitespace Invariance
    # -----------------------------------------------------------------
    def test_whitespace_invariance(self):
        """Different whitespace formatting in input JSON strings must yield identical canonical bytes."""
        json_compact = '{"a":1,"b":2}'
        json_spaced = '{  "a" :  1 ,   "b" : 2  }'
        json_newlines = '{\n  "b": 2,\n  "a": 1\n}'

        obj1 = parse_canonical_json(json_compact)
        obj2 = parse_canonical_json(json_spaced)
        obj3 = parse_canonical_json(json_newlines)

        bytes1 = canonicalize(obj1)
        bytes2 = canonicalize(obj2)
        bytes3 = canonicalize(obj3)

        assert bytes1 == bytes2 == bytes3 == b'{"a":1,"b":2}'

    # -----------------------------------------------------------------
    # TEST 4: Nested Objects Key Ordering
    # -----------------------------------------------------------------
    def test_nested_objects_ordering(self):
        """Nested objects at multiple depths must have their keys sorted deterministically."""
        a = {
            "outer_b": {"inner_2": "val2", "inner_1": "val1"},
            "outer_a": {"sub": {"y": 2, "x": 1}},
        }
        b = {
            "outer_a": {"sub": {"x": 1, "y": 2}},
            "outer_b": {"inner_1": "val1", "inner_2": "val2"},
        }
        assert canonicalize(a) == canonicalize(b)
        assert canonicalize(a) == (
            b'{"outer_a":{"sub":{"x":1,"y":2}},'
            b'"outer_b":{"inner_1":"val1","inner_2":"val2"}}'
        )

    # -----------------------------------------------------------------
    # TEST 5: Array Ordering Preservation
    # -----------------------------------------------------------------
    def test_array_ordering_is_significant(self):
        """Array order must be preserved; [1, 2, 3] != [3, 2, 1]."""
        arr1 = [1, 2, 3]
        arr2 = [3, 2, 1]
        assert canonicalize(arr1) != canonicalize(arr2)
        assert canonicalize(arr1) == b"[1,2,3]"
        assert canonicalize(arr2) == b"[3,2,1]"

        # Nested in dictionary
        obj1 = {"list": [1, 2]}
        obj2 = {"list": [2, 1]}
        assert canonicalize(obj1) != canonicalize(obj2)

    # -----------------------------------------------------------------
    # TEST 6: String Values Sensitivity
    # -----------------------------------------------------------------
    def test_string_mutation_changes_bytes(self):
        """Changing any string value or key must change the output canonical bytes."""
        base = {"name": "model_v1", "action": "infer"}
        mod1 = {"name": "model_v2", "action": "infer"}
        mod2 = {"name": "model_v1", "action": "train"}

        assert canonicalize(base) != canonicalize(mod1)
        assert canonicalize(base) != canonicalize(mod2)

    # -----------------------------------------------------------------
    # TEST 7: Unicode Handling
    # -----------------------------------------------------------------
    def test_unicode_deterministic_utf8(self):
        """Valid Unicode strings must produce deterministic UTF-8 encoded bytes without spurious escaping."""
        data = {
            "english": "Hello World",
            "french": "Café & Crème",
            "japanese": "検証システム",
            "emoji": "🛡️🔒",
            "symbols": "α β γ δ € ¥ £",
        }
        b = canonicalize(data)
        decoded = b.decode("utf-8")
        assert "Café & Crème" in decoded
        assert "検証システム" in decoded
        assert "🛡️🔒" in decoded
        # Verify no unnecessary unicode escaping like \u00e9 for é
        assert "\\u00e9" not in decoded

    # -----------------------------------------------------------------
    # TEST 8: Boolean and Null
    # -----------------------------------------------------------------
    def test_boolean_and_null_handling(self):
        """true, false, and null must be serialized strictly per JSON standard."""
        data = {
            "active": True,
            "disabled": False,
            "missing": None,
        }
        b = canonicalize(data)
        assert b == b'{"active":true,"disabled":false,"missing":null}'

        # Ensure Python True/False are not serialized as 1/0
        assert b"True" not in b
        assert b"False" not in b
        assert b"None" not in b

    # -----------------------------------------------------------------
    # TEST 9: Numbers (Integers, Floats, Scientific Notation, -0.0)
    # -----------------------------------------------------------------
    def test_number_representations(self):
        """Test representative integers and floats according to RFC 8785 (ECMA 262)."""
        # Zero and negative zero
        assert canonicalize(0) == b"0"
        assert canonicalize(0.0) == b"0"
        assert canonicalize(-0.0) == b"0"

        # Positive and negative integers
        assert canonicalize(42) == b"42"
        assert canonicalize(-100) == b"-100"

        # Safe integer limits: 2^53 - 1 and -(2^53 - 1)
        max_safe = 2**53 - 1
        min_safe = -(2**53) + 1
        assert canonicalize(max_safe) == str(max_safe).encode("utf-8")
        assert canonicalize(min_safe) == str(min_safe).encode("utf-8")

        # Integers exceeding safe domain must raise InvalidNumberError
        with pytest.raises(InvalidNumberError):
            canonicalize(2**53 + 10)

        with pytest.raises(InvalidNumberError):
            canonicalize(-(2**53) - 10)

        # Standard floats
        assert canonicalize(0.5) == b"0.5"
        assert canonicalize(-12.34) == b"-12.34"

        # Whole floats drop trailing .0 per RFC 8785 / ECMA 262
        assert canonicalize(1.0) == b"1"
        assert canonicalize(100.0) == b"100"

        # Scientific notation
        assert canonicalize(1e21) == b"1e+21"
        assert canonicalize(1e-6) == b"0.000001"
        assert canonicalize(1e-7) == b"1e-7"

    # -----------------------------------------------------------------
    # TEST 10: Unsupported Python Objects Rejection
    # -----------------------------------------------------------------
    def test_unsupported_python_types_rejected(self):
        """Passing non-JSON types must immediately raise UnsupportedTypeError."""
        class CustomObj:
            def __init__(self):
                self.val = "test"

        unsupported_items = [
            datetime.now(timezone.utc),
            b"raw_bytes_data",
            bytearray(b"bytearray_data"),
            uuid.uuid4(),
            pathlib.Path("/tmp/aivara.txt"),
            Decimal("3.14159"),
            CustomObj(),
            set([1, 2, 3]),
        ]

        for item in unsupported_items:
            # Standalone
            with pytest.raises(UnsupportedTypeError):
                canonicalize(item)

            # In dictionary value
            with pytest.raises(UnsupportedTypeError):
                canonicalize({"key": item})

            # In array
            with pytest.raises(UnsupportedTypeError):
                canonicalize([1, item, 3])

        # Non-string dictionary keys
        with pytest.raises(UnsupportedTypeError):
            canonicalize({123: "val"})

        with pytest.raises(UnsupportedTypeError):
            canonicalize({("tuple", "key"): "val"})

    # -----------------------------------------------------------------
    # TEST 11: Input Immutability
    # -----------------------------------------------------------------
    def test_input_immutability(self):
        """Canonicalization must NEVER mutate the caller's input object."""
        original = {
            "z": 10,
            "a": [3, 2, 1],
            "nested": {"beta": "b", "alpha": "a"},
            "flag": True,
            "empty": None,
        }
        deep_copied = copy.deepcopy(original)

        # Execute canonicalization
        out_bytes = canonicalize(original)
        assert len(out_bytes) > 0

        # Exact structural and value equality preserved
        assert original == deep_copied
        assert list(original.keys()) == list(deep_copied.keys())
        assert list(original["nested"].keys()) == list(deep_copied["nested"].keys())
        assert original["a"] == [3, 2, 1]

    # -----------------------------------------------------------------
    # TEST 12: Determinism Across Repeated Invocations
    # -----------------------------------------------------------------
    def test_determinism_across_iterations(self):
        """Repeated canonicalization of complex data must produce bit-for-bit identical results."""
        complex_payload = {
            "model_id": "model_cv_resnet50_v1",
            "confidence": 0.987654,
            "bbox": [10.5, 20.0, 100.5, 200.0],
            "metadata": {
                "hardware": "air-gap-workstation-01",
                "batch_size": 1,
                "tags": ["assurance", "offline", "verified"],
            },
            "timestamp": "2026-09-05T12:00:00Z",
            "is_tampered": False,
            "audit_id": None,
        }

        reference = canonicalize(complex_payload)
        for _ in range(100):
            assert canonicalize(complex_payload) == reference

    # -----------------------------------------------------------------
    # TEST 13: Schema Version Differentiation
    # -----------------------------------------------------------------
    def test_schema_version_differentiation(self):
        """Different canonical schema versions must produce distinct bytes."""
        payload_v1 = {"_schema_version": "1.0", "action": "audit"}
        payload_v2 = {"_schema_version": "2.0", "action": "audit"}

        assert canonicalize(payload_v1) != canonicalize(payload_v2)

    # -----------------------------------------------------------------
    # TEST 14: Duplicate JSON Keys Detection
    # -----------------------------------------------------------------
    def test_duplicate_json_keys_rejected(self):
        """Duplicate keys in raw JSON text must raise DuplicateKeyError."""
        dup_json = '{"key": 1, "other": 2, "key": 3}'
        with pytest.raises(DuplicateKeyError) as exc_info:
            parse_canonical_json(dup_json)
        assert "Duplicate key detected" in str(exc_info.value)

        # Nested duplicate keys
        nested_dup = '{"outer": {"a": 1, "a": 2}}'
        with pytest.raises(DuplicateKeyError):
            parse_canonical_json(nested_dup)

        # Valid JSON without duplicate keys succeeds
        valid_json = '{"a": 1, "b": 2}'
        parsed = parse_canonical_json(valid_json)
        assert parsed == {"a": 1, "b": 2}

    # -----------------------------------------------------------------
    # TEST 15: Non-Finite Numbers Rejection (NaN, Infinity)
    # -----------------------------------------------------------------
    def test_non_finite_numbers_rejected(self):
        """NaN and Infinity must be strictly rejected as invalid cryptographic input."""
        with pytest.raises(InvalidNumberError):
            canonicalize({"val": float("nan")})

        with pytest.raises(InvalidNumberError):
            canonicalize({"val": float("inf")})

        with pytest.raises(InvalidNumberError):
            canonicalize({"val": float("-inf")})

        with pytest.raises(InvalidNumberError):
            canonicalize([1, 2, float("nan")])

    # -----------------------------------------------------------------
    # TEST 16: Representative Provenance Payload Canonicalization
    # -----------------------------------------------------------------
    def test_representative_provenance_payload(self):
        """Canonicalize representative Phase 4.1 provenance payload."""
        dt = datetime(2026, 9, 5, 12, 30, 45, tzinfo=timezone.utc)
        payload_bytes = canonicalize_provenance_payload(
            record_type="INFERENCE",
            project_id="proj_01918374-abcd-7000-8000-000000000001",
            actor="operator_alpha",
            action="verify_sample",
            sequence_number=1,
            nonce="a" * 64,
            timestamp=dt,
            signer_key_id="key_ed25519_primary_v1",
            target_type="Sample",
            target_id="samp_01918374-abcd-7000-8000-000000000099",
            input_hash="b" * 64,
            output_hash="c" * 64,
            model_id="model_resnet_cv_01",
            model_weight_digest="d" * 64,
            config_hash="e" * 64,
            previous_record_hash=None,
            metadata_json={"inference_mode": "batch", "quantized": False},
        )

        assert isinstance(payload_bytes, bytes)
        assert b'"_schema_version":"1.0"' in payload_bytes
        assert b'"timestamp":"2026-09-05T12:30:45Z"' in payload_bytes
        assert b'"previous_record_hash":null' in payload_bytes

        # Verify key order in output bytes: keys are sorted lexicographically
        # _schema_version comes first
        assert payload_bytes.startswith(b'{"_schema_version":"1.0"')

        # Calling again with identical parameters yields identical bytes
        repeat_bytes = canonicalize_provenance_payload(
            record_type="INFERENCE",
            project_id="proj_01918374-abcd-7000-8000-000000000001",
            actor="operator_alpha",
            action="verify_sample",
            sequence_number=1,
            nonce="a" * 64,
            timestamp=dt,
            signer_key_id="key_ed25519_primary_v1",
            target_type="Sample",
            target_id="samp_01918374-abcd-7000-8000-000000000099",
            input_hash="b" * 64,
            output_hash="c" * 64,
            model_id="model_resnet_cv_01",
            model_weight_digest="d" * 64,
            config_hash="e" * 64,
            previous_record_hash=None,
            metadata_json={"inference_mode": "batch", "quantized": False},
        )
        assert payload_bytes == repeat_bytes


class TestRFC8785ReferenceVectors:
    """Official and representative RFC 8785 / JCS test vectors."""

    def test_rfc8785_control_character_escaping(self):
        """Test escaping required by RFC 8785 §3.2.2.2."""
        data = {
            "\b": "b",
            "\f": "f",
            "\n": "n",
            "\r": "r",
            "\t": "t",
            "\"": "\"",
            "\\": "\\",
        }
        res = canonicalize(data)
        # In UTF-16/ASCII code unit order:
        # \b (0x08) < \t (0x09) < \n (0x0A) < \f (0x0C) < \r (0x0D) < " (0x22) < \ (0x5C)
        assert res == b'{"\\b":"b","\\t":"t","\\n":"n","\\f":"f","\\r":"r","\\"":"\\"","\\\\":"\\\\"}'

    def test_rfc8785_utf16_key_sorting_non_bmp(self):
        """Test UTF-16 code unit sorting order for Non-BMP characters (RFC 8785 §3.2.3).

        In UTF-16, astral plane character U+1F300 (cyclone) is encoded as
        surrogate pair 0xD83C 0xDF00.
        BMP character U+FFFF is encoded as 0xFFFF.
        In UTF-16 code unit order:
            0xD83C < 0xFFFF
        Therefore U+1F300 MUST sort BEFORE U+FFFF.
        """
        data = {
            "\uffff": "last_in_bmp",
            "\U0001f300": "cyclone_astral",
        }
        res = canonicalize(data)
        # "\U0001f300" comes first because 0xd83c < 0xffff in UTF-16
        expected_cyclone = "\U0001f300".encode("utf-8")
        expected_bmp = "\uffff".encode("utf-8")
        assert res == b'{"' + expected_cyclone + b'":"cyclone_astral","' + expected_bmp + b'":"last_in_bmp"}'

    def test_rfc8785_number_formatting(self):
        """RFC 8785 §3.2.2.3 number conversions."""
        # 1.0 -> 1
        assert canonicalize({"val": 1.0}) == b'{"val":1}'
        # 0.000001 -> 0.000001
        assert canonicalize({"val": 1e-6}) == b'{"val":0.000001}'
        # 0.0000001 -> 1e-7
        assert canonicalize({"val": 1e-7}) == b'{"val":1e-7}'
        # 100000000000000000000.0 -> 100000000000000000000
        assert canonicalize({"val": 1e20}) == b'{"val":100000000000000000000}'
        # 1000000000000000000000.0 -> 1e+21
        assert canonicalize({"val": 1e21}) == b'{"val":1e+21}'


class TestDatetimeFormatting:
    """Tests for format_canonical_datetime."""

    def test_utc_datetime_formatting(self):
        dt = datetime(2026, 9, 5, 14, 30, 0, tzinfo=timezone.utc)
        assert format_canonical_datetime(dt) == "2026-09-05T14:30:00Z"

    def test_naive_datetime_assumes_utc(self):
        dt = datetime(2026, 9, 5, 14, 30, 0)
        assert format_canonical_datetime(dt) == "2026-09-05T14:30:00Z"

    def test_non_utc_timezone_converts_to_utc(self):
        # UTC+5:30
        from datetime import timedelta
        tz_ist = timezone(timedelta(hours=5, minutes=30))
        dt = datetime(2026, 9, 5, 20, 0, 0, tzinfo=tz_ist)
        # 20:00 IST is 14:30 UTC
        assert format_canonical_datetime(dt) == "2026-09-05T14:30:00Z"

    def test_invalid_type_raises_unsupported_type(self):
        with pytest.raises(UnsupportedTypeError):
            format_canonical_datetime("2026-09-05T14:30:00Z")  # type: ignore
