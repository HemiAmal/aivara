"""Fast, offline, sandboxed image header parsing and structural validation.

Extracts dimensions, channels, and color space from PNG, JPEG, WebP, BMP, and TIFF
without decompressing full pixel buffers into memory (preventing memory exhaustion).
"""

import struct
from pathlib import Path
from typing import NamedTuple, Set, Tuple

from aivara.dataset.exceptions import (
    CorruptedImageError,
    InvalidImageError,
)

SUPPORTED_IMAGE_EXTENSIONS: Set[str] = {
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".bmp",
    ".tif",
    ".tiff",
}


class ImageMetadata(NamedTuple):
    """Extracted lightweight image structural metadata."""
    width: int
    height: int
    channels: int
    color_space: str
    format_name: str
    file_size_bytes: int


def _parse_png(data: bytes, file_size: int) -> ImageMetadata:
    """Parse PNG header."""
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n":
        raise CorruptedImageError("Invalid PNG signature.")

    # Read IHDR chunk
    chunk_len, chunk_type = struct.unpack(">I4s", data[8:16])
    if chunk_type != b"IHDR" or chunk_len < 13:
        raise CorruptedImageError("Corrupted PNG: missing or malformed IHDR chunk.")

    width, height, bit_depth, color_type = struct.unpack(">IIBB", data[16:26])
    if width <= 0 or height <= 0:
        raise CorruptedImageError(f"Invalid PNG dimensions: {width}x{height}")

    # Color type mapping: 0=Grayscale, 2=RGB, 3=Palette, 4=Grayscale+Alpha, 6=RGBA
    color_map = {
        0: (1, "L"),
        2: (3, "RGB"),
        3: (3, "RGB"),
        4: (2, "LA"),
        6: (4, "RGBA"),
    }
    channels, color_space = color_map.get(color_type, (3, "RGB"))
    return ImageMetadata(
        width=width,
        height=height,
        channels=channels,
        color_space=color_space,
        format_name="PNG",
        file_size_bytes=file_size,
    )


def _parse_jpeg(data: bytes, file_size: int) -> ImageMetadata:
    """Parse JPEG/JPG header segments."""
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        raise CorruptedImageError("Invalid JPEG signature.")

    offset = 2
    sof_markers = {
        0xC0, 0xC1, 0xC2, 0xC3,
        0xC5, 0xC6, 0xC7,
        0xC9, 0xCA, 0xCB,
        0xCD, 0xCE, 0xCF,
    }

    while offset < len(data) - 4:
        marker, segment_type = struct.unpack(">BB", data[offset:offset + 2])
        if marker != 0xFF:
            raise CorruptedImageError("Corrupted JPEG: expected marker byte 0xFF.")

        if segment_type in sof_markers:
            if offset + 10 > len(data):
                raise CorruptedImageError("Truncated JPEG SOF segment.")
            _, precision, height, width, components = struct.unpack(
                ">HBHHB", data[offset + 2:offset + 10]
            )
            if width <= 0 or height <= 0:
                raise CorruptedImageError(f"Invalid JPEG dimensions: {width}x{height}")

            color_space = "RGB" if components == 3 else ("L" if components == 1 else "CMYK")
            return ImageMetadata(
                width=width,
                height=height,
                channels=components,
                color_space=color_space,
                format_name="JPEG",
                file_size_bytes=file_size,
            )

        if segment_type in (0xD9, 0xDA):  # EOI or SOS (start of scan)
            break

        segment_len = struct.unpack(">H", data[offset + 2:offset + 4])[0]
        if segment_len < 2:
            raise CorruptedImageError("Corrupted JPEG segment length.")
        offset += 2 + segment_len

    raise CorruptedImageError("Unable to locate SOF segment in JPEG.")


def _parse_webp(data: bytes, file_size: int) -> ImageMetadata:
    """Parse WebP header (VP8, VP8L, or VP8X)."""
    if len(data) < 16 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        raise CorruptedImageError("Invalid WebP signature.")

    chunk_type = data[12:16]
    if chunk_type == b"VP8 ":  # Lossy VP8
        if len(data) < 30 or data[23:26] != b"\x9d\x01\x2a":
            raise CorruptedImageError("Corrupted VP8 lossy WebP frame.")
        raw_w, raw_h = struct.unpack("<HH", data[26:30])
        width = raw_w & 0x3FFF
        height = raw_h & 0x3FFF
        return ImageMetadata(width, height, 3, "RGB", "WEBP", file_size)

    elif chunk_type == b"VP8L":  # Lossless VP8L
        if len(data) < 25 or data[20] != 0x2F:
            raise CorruptedImageError("Corrupted VP8L lossless WebP frame.")
        val = struct.unpack("<I", data[21:25])[0]
        width = 1 + (val & 0x3FFF)
        height = 1 + ((val >> 14) & 0x3FFF)
        has_alpha = bool((val >> 28) & 1)
        channels = 4 if has_alpha else 3
        color_space = "RGBA" if has_alpha else "RGB"
        return ImageMetadata(width, height, channels, color_space, "WEBP", file_size)

    elif chunk_type == b"VP8X":  # Extended VP8X
        if len(data) < 30:
            raise CorruptedImageError("Truncated VP8X extended WebP header.")
        width = 1 + struct.unpack("<I", data[24:27] + b"\x00")[0]
        height = 1 + struct.unpack("<I", data[27:30] + b"\x00")[0]
        has_alpha = bool(data[20] & 0x10)
        channels = 4 if has_alpha else 3
        color_space = "RGBA" if has_alpha else "RGB"
        return ImageMetadata(width, height, channels, color_space, "WEBP", file_size)

    raise CorruptedImageError(f"Unsupported WebP format chunk: {chunk_type}")


def _parse_bmp(data: bytes, file_size: int) -> ImageMetadata:
    """Parse BMP header."""
    if len(data) < 26 or data[:2] != b"BM":
        raise CorruptedImageError("Invalid BMP signature.")

    dib_size = struct.unpack("<I", data[14:18])[0]
    if dib_size >= 40:
        width, raw_height, planes, bpp = struct.unpack("<iiHH", data[18:30])
        height = abs(raw_height)
    elif dib_size == 12:
        width, height = struct.unpack("<HH", data[18:22])
        bpp = struct.unpack("<H", data[24:26])[0]
    else:
        raise CorruptedImageError(f"Unsupported BMP DIB header size: {dib_size}")

    if width <= 0 or height <= 0:
        raise CorruptedImageError(f"Invalid BMP dimensions: {width}x{height}")

    channels = 4 if bpp == 32 else (3 if bpp >= 24 else 1)
    color_space = "RGBA" if channels == 4 else ("RGB" if channels == 3 else "L")
    return ImageMetadata(width, height, channels, color_space, "BMP", file_size)


def _parse_tiff(data: bytes, file_size: int) -> ImageMetadata:
    """Parse TIFF header."""
    if len(data) < 8:
        raise CorruptedImageError("Truncated TIFF header.")

    endian = data[:2]
    if endian == b"II":
        endian_str = "<"
    elif endian == b"MM":
        endian_str = ">"
    else:
        raise CorruptedImageError("Invalid TIFF byte order indicator.")

    magic = struct.unpack(f"{endian_str}H", data[2:4])[0]
    if magic != 42:
        raise CorruptedImageError("Invalid TIFF magic number (expected 42).")

    ifd_offset = struct.unpack(f"{endian_str}I", data[4:8])[0]
    if ifd_offset + 2 > len(data):
        raise CorruptedImageError("Truncated TIFF IFD offset.")

    num_entries = struct.unpack(f"{endian_str}H", data[ifd_offset:ifd_offset + 2])[0]
    width, height, channels = None, None, 3

    curr = ifd_offset + 2
    for _ in range(num_entries):
        if curr + 12 > len(data):
            break
        tag, tag_type, count, val_offset = struct.unpack(f"{endian_str}HHI4s", data[curr:curr + 12])
        curr += 12

        # Value unpacker helper (short or long)
        def _get_val(offset_bytes: bytes, t_type: int) -> int:
            if t_type == 3:  # SHORT
                return struct.unpack(f"{endian_str}H", offset_bytes[:2])[0]
            elif t_type == 4:  # LONG
                return struct.unpack(f"{endian_str}I", offset_bytes)[0]
            return struct.unpack(f"{endian_str}I", offset_bytes)[0]

        if tag == 256:  # ImageWidth
            width = _get_val(val_offset, tag_type)
        elif tag == 257:  # ImageLength / Height
            height = _get_val(val_offset, tag_type)
        elif tag == 277:  # SamplesPerPixel
            channels = _get_val(val_offset, tag_type)

    if width is None or height is None or width <= 0 or height <= 0:
        raise CorruptedImageError("Failed to extract valid dimensions from TIFF header.")

    color_space = "RGBA" if channels == 4 else ("RGB" if channels == 3 else "L")
    return ImageMetadata(width, height, channels, color_space, "TIFF", file_size)


def inspect_image_file(file_path: Path) -> ImageMetadata:
    """Inspect and validate an image file on disk safely.

    Reads only the minimum necessary bytes from the start of the file.
    Rejects corrupted images, zero-byte files, and unsupported formats.
    """
    if not file_path.exists() or not file_path.is_file():
        raise InvalidImageError(
            f"Image file does not exist: {file_path.name}",
            details={"file": str(file_path.name)},
        )

    file_size = file_path.stat().st_size
    if file_size == 0:
        raise CorruptedImageError(
            f"Image file '{file_path.name}' is empty (0 bytes).",
            details={"file": str(file_path.name)},
        )

    ext = file_path.suffix.lower()
    if ext not in SUPPORTED_IMAGE_EXTENSIONS:
        raise InvalidImageError(
            f"Unsupported image extension '{ext}' for file '{file_path.name}'.",
            details={"extension": ext, "supported": sorted(list(SUPPORTED_IMAGE_EXTENSIONS))},
        )

    # Read the first 4096 bytes (sufficient for all standard image headers)
    try:
        with open(file_path, "rb") as f:
            header_bytes = f.read(4096)
    except OSError as e:
        raise InvalidImageError(
            f"Failed to read image file '{file_path.name}': {e}",
            details={"file": str(file_path.name)},
        )

    if ext == ".png":
        return _parse_png(header_bytes, file_size)
    elif ext in (".jpg", ".jpeg"):
        # For JPEG, if SOF is beyond 4KB (e.g. large EXIF thumbnails), read up to 64KB
        if len(header_bytes) < 4096 and file_size > len(header_bytes):
            pass
        try:
            return _parse_jpeg(header_bytes, file_size)
        except CorruptedImageError:
            if file_size > 4096:
                with open(file_path, "rb") as f:
                    large_header = f.read(min(file_size, 65536))
                return _parse_jpeg(large_header, file_size)
            raise
    elif ext == ".webp":
        return _parse_webp(header_bytes, file_size)
    elif ext == ".bmp":
        return _parse_bmp(header_bytes, file_size)
    elif ext in (".tif", ".tiff"):
        # For TIFF with large headers, read up to 64KB if needed
        try:
            return _parse_tiff(header_bytes, file_size)
        except CorruptedImageError:
            if file_size > 4096:
                with open(file_path, "rb") as f:
                    large_header = f.read(min(file_size, 65536))
                return _parse_tiff(large_header, file_size)
            raise

    raise InvalidImageError(
        f"Unsupported image file format '{ext}'.",
        details={"extension": ext},
    )
