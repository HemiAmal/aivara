"""Unit and integration tests for AIVARA's SHA-256 Hashing Engine (Phase 4.3).

Covers:
- TESTS 1 to 20 required by Phase 4.3 specification
- Standard NIST / RFC 4634 test vectors
- Avalanche behavior check
- Input immutability
- Type safety and exception taxonomy
- Canonicalization integration and separation of concerns
- Validation and constant-time comparison utilities
"""

import copy
from datetime import datetime, timezone

import pytest

from aivara.crypto import (
    SHA256_EMPTY_HEX,
    SHA256_HEX_LENGTH,
    InvalidNumberError,
    UnsupportedHashInputError,
    hash_canonical_data,
    hash_provenance_payload,
    is_valid_sha256,
    parse_canonical_json,
    secure_compare_hashes,
    sha256_bytes,
    sha256_text,
)


class TestSHA256Engine:
    """Test suite covering Phase 4.3 SHA-256 Hashing Engine."""

    # -----------------------------------------------------------------
    # TEST 1: Known Empty-Input Vector
    # -----------------------------------------------------------------
    def test_known_empty_input_vector(self):
        """SHA-256 of empty bytes must equal the standard NIST empty digest."""
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert sha256_bytes(b"") == expected
        assert sha256_text("") == expected
        assert SHA256_EMPTY_HEX == expected

    # -----------------------------------------------------------------
    # TEST 2: Known "abc" Vector
    # -----------------------------------------------------------------
    def test_known_abc_vector(self):
        """SHA-256 of b'abc' must equal the standard NIST test vector."""
        expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        assert sha256_bytes(b"abc") == expected
        assert sha256_text("abc") == expected

    # -----------------------------------------------------------------
    # TEST 3: Known Phrase Vector (RFC 4634)
    # -----------------------------------------------------------------
    def test_known_phrase_vector(self):
        """SHA-256 of standard test phrase must equal known published digest."""
        phrase = b"The quick brown fox jumps over the lazy dog"
        expected = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        assert sha256_bytes(phrase) == expected
        assert sha256_text("The quick brown fox jumps over the lazy dog") == expected

    # -----------------------------------------------------------------
    # TEST 4: Determinism
    # -----------------------------------------------------------------
    def test_determinism(self):
        """Hashing identical bytes repeatedly must produce identical digests."""
        data = b"aivara-assurance-provenance-test-payload-data"
        ref = sha256_bytes(data)
        for _ in range(100):
            assert sha256_bytes(data) == ref

    # -----------------------------------------------------------------
    # TEST 5: One-Byte Mutation
    # -----------------------------------------------------------------
    def test_one_byte_mutation(self):
        """Mutating a single byte must produce a completely different digest."""
        data1 = b"AIVARA_PAYLOAD_001"
        data2 = b"AIVARA_PAYLOAD_002"
        assert sha256_bytes(data1) != sha256_bytes(data2)

    # -----------------------------------------------------------------
    # TEST 6: Avalanche Behavior
    # -----------------------------------------------------------------
    def test_avalanche_behavior(self):
        """A single-bit flip must result in significant bit-level differences (avalanche effect)."""
        data1 = b"The quick brown fox jumps over the lazy dog."
        data2 = b"The quick brown fox jumps over the lazy dog,"  # flipped 1 byte/bit

        digest1 = bytes.fromhex(sha256_bytes(data1))
        digest2 = bytes.fromhex(sha256_bytes(data2))

        # Count differing bits across the 256 bits (32 bytes)
        diff_bits = 0
        for b1, b2 in zip(digest1, digest2):
            diff_bits += bin(b1 ^ b2).count("1")

        # Avalanche effect: approximately 50% of bits change (assert at least 35% and at most 65%)
        bit_diff_percentage = diff_bits / 256.0
        assert 0.35 <= bit_diff_percentage <= 0.65, (
            f"Avalanche bit diff was {bit_diff_percentage:.2%}, expected ~50%"
        )

    # -----------------------------------------------------------------
    # TEST 7: Binary Data
    # -----------------------------------------------------------------
    def test_binary_data(self):
        """Verify arbitrary binary bytes with null bytes and non-ASCII ranges hash properly."""
        raw_binary = bytes([0x00, 0x01, 0xFF, 0xFE, 0x80, 0x7F, 0x00, 0xAA, 0x55])
        digest = sha256_bytes(raw_binary)
        assert is_valid_sha256(digest)

        # Bytearray and memoryview support
        assert sha256_bytes(bytearray(raw_binary)) == digest
        assert sha256_bytes(memoryview(raw_binary)) == digest

    # -----------------------------------------------------------------
    # TEST 8: Empty Input Accepted
    # -----------------------------------------------------------------
    def test_empty_input_accepted(self):
        """Explicitly confirm empty input is accepted and returns a valid 64-char hex digest."""
        digest = sha256_bytes(b"")
        assert len(digest) == SHA256_HEX_LENGTH
        assert is_valid_sha256(digest)
        assert digest == SHA256_EMPTY_HEX

    # -----------------------------------------------------------------
    # TEST 9: Lowercase Representation
    # -----------------------------------------------------------------
    def test_lowercase_representation(self):
        """Returned hexadecimal digest must contain only lowercase hex characters."""
        data = b"Testing lowercase hex digest representation"
        digest = sha256_bytes(data)
        assert digest == digest.lower()
        assert not any(c.isupper() for c in digest)
        assert all(c in "0123456789abcdef" for c in digest)

    # -----------------------------------------------------------------
    # TEST 10: Digest Length
    # -----------------------------------------------------------------
    def test_digest_length(self):
        """Every returned digest must be exactly 64 characters long."""
        samples = [b"", b"a", b"long string with many characters" * 50, bytes(range(256))]
        for sample in samples:
            d = sha256_bytes(sample)
            assert len(d) == 64
            assert len(d) == SHA256_HEX_LENGTH

    # -----------------------------------------------------------------
    # TEST 11: Input Immutability
    # -----------------------------------------------------------------
    def test_input_immutability(self):
        """Hashing mutable byte buffers must not mutate the buffer."""
        original_bytes = bytearray(b"mutable-byte-buffer-data-12345")
        copy_bytes = copy.deepcopy(original_bytes)

        digest = sha256_bytes(original_bytes)
        assert is_valid_sha256(digest)
        assert original_bytes == copy_bytes

    # -----------------------------------------------------------------
    # TEST 12: Invalid Input
    # -----------------------------------------------------------------
    def test_invalid_input_rejected(self):
        """Passing non-bytes to sha256_bytes must raise UnsupportedHashInputError."""
        unsupported = [123, {"a": 1}, [1, 2], None, "unencoded_string"]
        for item in unsupported:
            with pytest.raises(UnsupportedHashInputError) as exc:
                sha256_bytes(item)  # type: ignore
            assert exc.value.code == "UNSUPPORTED_HASH_INPUT"

        with pytest.raises(UnsupportedHashInputError):
            sha256_text(123)  # type: ignore

    # -----------------------------------------------------------------
    # TEST 13: Canonicalization Integration
    # -----------------------------------------------------------------
    def test_canonicalization_integration(self):
        """Two logically equivalent dicts with different key insertion orders yield the same hash."""
        obj1 = {"model": "resnet", "batch_size": 32, "active": True}
        obj2 = {"active": True, "model": "resnet", "batch_size": 32}

        h1 = hash_canonical_data(obj1)
        h2 = hash_canonical_data(obj2)

        assert is_valid_sha256(h1)
        assert h1 == h2

    # -----------------------------------------------------------------
    # TEST 14: Semantic Mutation
    # -----------------------------------------------------------------
    def test_semantic_mutation(self):
        """Changing any protected field in structured data produces a different hash."""
        base = {"project_id": "proj_1", "action": "verify", "nonce": "abc"}
        mutated = {"project_id": "proj_1", "action": "tamper", "nonce": "abc"}

        assert hash_canonical_data(base) != hash_canonical_data(mutated)

    # -----------------------------------------------------------------
    # TEST 15: Whitespace Invariance
    # -----------------------------------------------------------------
    def test_whitespace_invariance_through_bridge(self):
        """Whitespace differences in input JSON strings yield identical hashes through canonical bridge."""
        json_compact = '{"a":1,"b":2}'
        json_spaced = '{\n  "b": 2,\n  "a": 1\n}'

        obj1 = parse_canonical_json(json_compact)
        obj2 = parse_canonical_json(json_spaced)

        h1 = hash_canonical_data(obj1)
        h2 = hash_canonical_data(obj2)

        assert h1 == h2

    # -----------------------------------------------------------------
    # TEST 16: Array Ordering
    # -----------------------------------------------------------------
    def test_array_ordering(self):
        """Altering array order changes the hash because array ordering is semantically significant."""
        obj1 = {"indices": [1, 2, 3]}
        obj2 = {"indices": [3, 2, 1]}

        assert hash_canonical_data(obj1) != hash_canonical_data(obj2)

    # -----------------------------------------------------------------
    # TEST 17: Unicode
    # -----------------------------------------------------------------
    def test_unicode_hashing(self):
        """Unicode characters hash deterministically."""
        unicode_str = "AIVARA 🛡️ Vérification: 日本語"
        h1 = sha256_text(unicode_str)
        h2 = sha256_bytes(unicode_str.encode("utf-8"))

        assert is_valid_sha256(h1)
        assert h1 == h2

    # -----------------------------------------------------------------
    # TEST 18: Non-Finite Numbers Rejected
    # -----------------------------------------------------------------
    def test_non_finite_numbers_rejected_before_hashing(self):
        """Non-finite numbers (NaN, Inf) must be rejected by canonical boundary before hashing."""
        with pytest.raises(InvalidNumberError):
            hash_canonical_data({"score": float("nan")})

        with pytest.raises(InvalidNumberError):
            hash_canonical_data({"score": float("inf")})

    # -----------------------------------------------------------------
    # TEST 19: Representative Provenance Payload
    # -----------------------------------------------------------------
    def test_representative_provenance_payload_hashing(self):
        """Hash a representative Phase 4.1/4.2 provenance payload and verify hash properties."""
        dt = datetime(2026, 9, 5, 14, 0, 0, tzinfo=timezone.utc)
        record_hash = hash_provenance_payload(
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

        assert is_valid_sha256(record_hash)
        assert len(record_hash) == 64

        # Repeating with same parameters produces identical hash
        repeat_hash = hash_provenance_payload(
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
        assert record_hash == repeat_hash

        # Modifying a single field (e.g. sequence number) alters the record hash
        modified_hash = hash_provenance_payload(
            record_type="INFERENCE",
            project_id="proj_01918374-abcd-7000-8000-000000000001",
            actor="operator_alpha",
            action="verify_sample",
            sequence_number=2,  # modified sequence number
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
        assert record_hash != modified_hash

    def test_provenance_payload_strict_schema_enforcement(self):
        """Verify that provenance payload hashing strictly enforces the defined schema.

        - Omission of any required field raises TypeError.
        - Injection of arbitrary unknown kwargs raises TypeError.
        - All 18 defined fields are bound deterministically.
        """
        dt = datetime(2026, 9, 5, 14, 0, 0, tzinfo=timezone.utc)
        valid_kwargs = {
            "record_type": "INFERENCE",
            "project_id": "proj_01",
            "actor": "system",
            "action": "infer",
            "sequence_number": 1,
            "nonce": "a" * 64,
            "timestamp": dt,
            "signer_key_id": "key_01",
            "target_type": "Sample",
            "target_id": "samp_01",
            "input_hash": "b" * 64,
            "output_hash": "c" * 64,
            "model_id": "model_01",
            "model_weight_digest": "d" * 64,
            "config_hash": "e" * 64,
            "previous_record_hash": "f" * 64,
            "metadata_json": {"k": "v"},
        }

        # 1. Missing required field (e.g. sequence_number, nonce, actor, project_id)
        for req_field in ["record_type", "project_id", "actor", "action", "sequence_number", "nonce", "timestamp", "signer_key_id"]:
            kwargs_missing = {k: v for k, v in valid_kwargs.items() if k != req_field}
            with pytest.raises(TypeError):
                hash_provenance_payload(**kwargs_missing)

        # 2. Arbitrary injected kwarg rejected
        kwargs_with_extra = dict(valid_kwargs, arbitrary_injected_field="malicious_data")
        with pytest.raises(TypeError):
            hash_provenance_payload(**kwargs_with_extra)

        # 3. Verify all 18 fields are present in the canonical payload
        from aivara.crypto.canonical import canonicalize_provenance_payload
        raw_canonical = canonicalize_provenance_payload(**valid_kwargs)
        parsed = parse_canonical_json(raw_canonical)
        expected_keys = {
            "_schema_version",
            "action",
            "actor",
            "config_hash",
            "input_hash",
            "metadata_json",
            "model_id",
            "model_weight_digest",
            "nonce",
            "output_hash",
            "previous_record_hash",
            "project_id",
            "record_type",
            "sequence_number",
            "signer_key_id",
            "target_id",
            "target_type",
            "timestamp",
        }
        assert set(parsed.keys()) == expected_keys
        assert len(parsed.keys()) == 18

    # -----------------------------------------------------------------
    # TEST 20: Canonicalization Separation
    # -----------------------------------------------------------------
    def test_canonicalization_separation(self):
        """Low-level sha256_bytes() hashes raw bytes as provided without implicit normalization."""
        raw_bytes_1 = b'{"b":2,"a":1}'
        raw_bytes_2 = b'{"a":1,"b":2}'

        # Raw bytes hashing produces different hashes because bytes are different
        assert sha256_bytes(raw_bytes_1) != sha256_bytes(raw_bytes_2)

        # In contrast, structured JSON passed through hash_canonical_data canonicalizes first
        obj1 = parse_canonical_json(raw_bytes_1)
        obj2 = parse_canonical_json(raw_bytes_2)
        assert hash_canonical_data(obj1) == hash_canonical_data(obj2)


class TestValidationAndComparison:
    """Tests for is_valid_sha256 and secure_compare_hashes."""

    def test_is_valid_sha256(self):
        valid = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
        assert is_valid_sha256(valid)

        # Invalid length
        assert not is_valid_sha256(valid[:-1])
        assert not is_valid_sha256(valid + "0")

        # Uppercase rejected (AIVARA canonical representation is lowercase only)
        assert not is_valid_sha256(valid.upper())

        # Non-hex characters
        assert not is_valid_sha256(valid[:-1] + "g")
        assert not is_valid_sha256(valid[:-1] + "z")

        # Prefixed strings rejected
        assert not is_valid_sha256(f"sha256:{valid}")

        # Non-strings
        assert not is_valid_sha256(123)  # type: ignore
        assert not is_valid_sha256(None)  # type: ignore

    def test_secure_compare_hashes(self):
        h1 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        h2 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        h3 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        assert secure_compare_hashes(h1, h2)
        assert not secure_compare_hashes(h1, h3)

        # Case-insensitive tolerance in secure comparison
        assert secure_compare_hashes(h1, h1.upper())

        # Non-string input
        assert not secure_compare_hashes(h1, None)  # type: ignore
        assert not secure_compare_hashes(123, h1)  # type: ignore
