"""A compact, structurally-verifiable on-disk cache of SHA-1 digests.

    header:  magic b"AMWK" | format_version (u8) | fingerprint (32) | count (u32 LE)
    body:    count * 20 raw SHA-1 digest bytes, sorted ascending, de-duplicated

A file that fails any structural check reads back as None so the caller
regenerates rather than trusting a short set. Writes are atomic: a temp sibling
is fsync'd and os.replace'd into place, so no reader sees a partial file.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

MAGIC = b"AMWK"
FORMAT_VERSION = 1
DIGEST_SIZE = 20
_HEADER = struct.Struct("<4sB32sI")  # 4 + 1 + 32 + 4 = 41 bytes


@dataclass(frozen=True)
class CacheFile:
    fingerprint: bytes
    digests: list[bytes]


def read_cache(path: str | os.PathLike[str]) -> CacheFile | None:
    try:
        with open(path, "rb") as handle:
            blob = handle.read()
    except OSError:
        return None
    if len(blob) < _HEADER.size:
        return None
    magic, version, fingerprint, count = _HEADER.unpack(blob[: _HEADER.size])
    if magic != MAGIC or version != FORMAT_VERSION:
        return None
    body = blob[_HEADER.size :]
    if len(body) != count * DIGEST_SIZE:
        return None
    digests = [body[i : i + DIGEST_SIZE] for i in range(0, len(body), DIGEST_SIZE)]
    return CacheFile(fingerprint, digests)


def write_cache(path: str | os.PathLike[str], fingerprint: bytes, digests: list[bytes]) -> None:
    if len(fingerprint) != 32:
        raise ValueError("fingerprint must be 32 bytes")
    tmp = f"{os.fspath(path)}.tmp.{os.getpid()}"
    with open(tmp, "wb") as handle:
        handle.write(_HEADER.pack(MAGIC, FORMAT_VERSION, fingerprint, len(digests)))
        for digest in digests:
            handle.write(digest)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
