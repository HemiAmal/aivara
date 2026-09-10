"""Domain exceptions for dataset fingerprinting and Merkle tree assurance (Phase 5.3)."""

from typing import Any, Optional
from aivara.core.exceptions import AivaraException


class FingerprintError(AivaraException, ValueError):
    """Base exception for dataset fingerprinting and integrity verification errors."""

    def __init__(
        self,
        message: str,
        code: str = "FINGERPRINT_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class MissingFileError(FingerprintError):
    """Raised when a referenced sample image file is missing on disk."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="MISSING_IMAGE_FILE", details=details)


class UnreadableFileError(FingerprintError):
    """Raised when an image file cannot be read due to filesystem/permission errors."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="UNREADABLE_IMAGE_FILE", details=details)


class InvalidImageDecodingError(FingerprintError):
    """Raised when image bytes cannot be decoded into a valid pixel grid."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_IMAGE_DECODING", details=details)


class UnsupportedImageEncodingError(FingerprintError):
    """Raised when an image uses an unsupported or unverified encoding."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="UNSUPPORTED_IMAGE_ENCODING", details=details)


class MalformedAnnotationFingerprintError(FingerprintError):
    """Raised when an annotation structure is invalid for canonical hashing."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="MALFORMED_ANNOTATION_FINGERPRINT", details=details)


class InvalidCanonicalInputError(FingerprintError):
    """Raised when input canonical objects are malformed or missing required fields."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_CANONICAL_INPUT", details=details)


class DuplicateSamplePathError(FingerprintError):
    """Raised when duplicate sample paths are encountered in leaf collation."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="DUPLICATE_SAMPLE_PATH", details=details)


class DuplicateSampleIdError(FingerprintError):
    """Raised when duplicate sample IDs are encountered in leaf collation."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="DUPLICATE_SAMPLE_ID", details=details)


class InvalidHashFormatError(FingerprintError):
    """Raised when a cryptographic hash format is invalid."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_HASH_FORMAT", details=details)


class MalformedMerkleTreeError(FingerprintError):
    """Raised when Merkle tree operations encounter inconsistent or corrupt state."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="MALFORMED_MERKLE_TREE", details=details)


class InvalidInclusionProofError(FingerprintError):
    """Raised when an inclusion proof is structurally malformed or fails verification."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_INCLUSION_PROOF", details=details)


class FingerprintVersionMismatchError(FingerprintError):
    """Raised when an incompatible fingerprint schema or algorithm version is encountered."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="FINGERPRINT_VERSION_MISMATCH", details=details)
