"""Lossless, sequential archive of HMMAP records. See README.md for the format."""

import argparse
import hashlib
import math
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import BinaryIO, Callable, Iterator, Sequence

MAGIC = b"HMARCH1\n"
BLOCK = 64
FRONT = 0x80
LITERAL = 0xFF
WIDTHS = {"md5": 16, "sha1": 20, "sha256": 32, "bcrypt": 23}
Row = tuple[bytes, bytes]  # (key, stored digest); not a dictionary


class FormatError(ValueError):
    """An unsupported, malformed, incomplete or damaged input."""


def exact(src: BinaryIO, size: int) -> bytes:
    data = src.read(size)
    if len(data) != size:
        raise FormatError("unexpected end of file")
    return data


@dataclass(frozen=True)
class Header:
    raw: bytes
    algo: str
    width: int

    def predict(self, key: bytes) -> bytes:
        return hashlib.new(self.algo, key, usedforsecurity=False).digest()[:self.width]


def read_header(src: BinaryIO) -> Header:
    # Consume exactly the writer's header, never probe the binary record data
    # for header-looking lines. Copy these bytes; don't recreate them later.
    magic = exact(src, 8)
    if magic == b"HMMAP 1\n":
        return Header(magic, "md5", 16)
    if magic != b"HMMAP 2\n":
        raise FormatError("expected an HMMAP 1 or 2 header")
    algo_line = src.readline(32)
    width_line = src.readline(16)
    alg = re.fullmatch(rb"algo (md5|sha1|sha256|bcrypt)\n", algo_line)
    num = re.fullmatch(rb"dlen ([1-9][0-9]?)\n", width_line)
    if not alg or not num:
        raise FormatError("unsupported map header")
    algo = alg[1].decode("ascii")
    width = int(num[1])
    if width > WIDTHS[algo]:
        raise FormatError("digest width exceeds algorithm width")
    raw = magic + algo_line + width_line
    if algo == "bcrypt":
        salt_line = src.readline(80)
        if not re.fullmatch(rb"salt [^\r\n]{1,64}\n", salt_line):
            raise FormatError("expected a salt line")
        raw += salt_line  # opaque: never evaluate this algorithm or salt
    return Header(raw, algo, width)


def read_rows(src: BinaryIO, width: int) -> Iterator[Row]:
    while digest := src.read(width):
        if len(digest) != width:
            raise FormatError("incomplete map digest")
        length = exact(src, 1)[0]
        yield exact(src, length), digest


def map_bytes(rows: list[Row]) -> bytes:
    return b"".join(digest + bytes([len(key)]) + key for key, digest in rows)


def ways(base: int, n: int, k: int) -> int:
    """Number of residual words of length n with k misses, base choices/miss."""
    return math.comb(n, k) * base**k if 0 <= k <= n else 0


def byte_width(count: int) -> int:
    # Width of the largest valid rank, not of count. In particular 1 -> 0.
    return ((count - 1).bit_length() + 7) // 8


def rank(base: int, errors: Sequence[int | None]) -> int:
    """Number hits first, then one subinterval per possible miss digit."""
    r = k = 0
    for n, digit in enumerate(reversed(errors)):
        if digit is not None:
            r += ways(base, n, k + 1) + digit * ways(base, n, k)
            k += 1
    return r


def unrank(base: int, n: int, k: int, r: int) -> Iterator[int | None]:
    if not 0 <= r < ways(base, n, k):
        raise FormatError("rank outside its fixed-weight class")
    for remaining in reversed(range(n)):
        cut = ways(base, remaining, k)  # size of the hit subinterval
        if r < cut:
            yield None
        else:
            k -= 1
            digit, r = divmod(r - cut, ways(base, remaining, k))
            yield digit


def pack_keys(rows: list[Row]) -> tuple[int, bytes]:
    literal = b"".join(bytes([len(key)]) + key for key, _ in rows)
    front = bytearray()
    prev = b""
    for key, _ in rows:
        prefix = 0
        limit = min(len(prev), len(key))
        while prefix < limit and prev[prefix] == key[prefix]:
            prefix += 1
        front.extend((prefix, len(key) - prefix))
        front.extend(key[prefix:])
        prev = key
    return (FRONT, bytes(front)) if len(front) < len(literal) else (0, literal)


def unpack_keys(src: BinaryIO, n: int, front: bool) -> list[bytes]:
    keys = []
    prev = b""
    for _ in range(n):
        prefix = exact(src, 1)[0] if front else 0
        size = exact(src, 1)[0]
        if prefix > len(prev) or prefix + size > 255:
            raise FormatError("invalid key prefix or suffix length")
        prev = prev[:prefix] + exact(src, size)
        keys.append(prev)
    return keys


def pack_digests(rows: list[Row], header: Header) -> tuple[int, bytes]:
    if header.algo != "bcrypt":
        base = (1 << (8 * header.width)) - 1
        errors = []
        for key, actual in rows:
            pred = header.predict(key)
            # Big-endian byte order is integer order at a fixed width. Skip
            # the predicted symbol: it cannot be the value of an exception.
            digit = None if actual == pred else int.from_bytes(actual, "big") - (actual > pred)
            errors.append(digit)
        k = sum(e is not None for e in errors)
        if k == 0:
            return 0, b""  # one possible column; no rank bytes
        size = byte_width(ways(base, len(rows), k))
        if size < len(rows) * header.width:
            return k, rank(base, errors).to_bytes(size, "big")
    return LITERAL, b"".join(digest for _, digest in rows)


def unpack_digests(src: BinaryIO, keys: list[bytes], header: Header, k: int) -> list[bytes]:
    if k == LITERAL:
        return [exact(src, header.width) for _ in keys]
    if k > len(keys) or header.algo == "bcrypt":
        raise FormatError("invalid digest mode or exception count")
    if k == 0:
        return [header.predict(key) for key in keys]
    base = (1 << (8 * header.width)) - 1
    size = byte_width(ways(base, len(keys), k))
    r = int.from_bytes(exact(src, size), "big")
    digests = []
    for key, e in zip(keys, unrank(base, len(keys), k, r), strict=True):
        pred = header.predict(key)
        if e is None:
            digests.append(pred)
        else:
            actual = e + (e >= int.from_bytes(pred, "big"))
            digests.append(actual.to_bytes(header.width, "big"))
    return digests


def pack_block(rows: list[Row], k: int, digests: bytes) -> bytes:
    mode, keys = pack_keys(rows)
    return bytes([mode | len(rows), k]) + keys + digests


def unpack_block(src: BinaryIO, tag: int, header: Header) -> bytes:
    n = tag & ~FRONT
    if not 1 <= n <= BLOCK:
        raise FormatError("invalid block size")
    k = exact(src, 1)[0]
    keys = unpack_keys(src, n, bool(tag & FRONT))
    digests = unpack_digests(src, keys, header, k)
    return map_bytes(list(zip(keys, digests, strict=True)))


def pack_blocks(src: BinaryIO, dst: BinaryIO, magic: bytes, block_size: int,
                encode: Callable[[list[Row], Header], bytes]) -> None:
    header = read_header(src)
    checksum = hashlib.sha256(header.raw)
    dst.write(magic + header.raw)
    records = read_rows(src, header.width)
    while rows := list(islice(records, block_size)):
        dst.write(encode(rows, header))
        checksum.update(map_bytes(rows))
    dst.write(b"\x00" + checksum.digest())


def pack(src: BinaryIO, dst: BinaryIO) -> None:
    pack_blocks(src, dst, MAGIC, BLOCK,
                lambda rows, header: pack_block(rows, *pack_digests(rows, header)))


def unpack_blocks(src: BinaryIO, dst: BinaryIO,
                  decode: Callable[[BinaryIO, int, Header], bytes]) -> None:
    """Read the archive body *after* the caller has checked the magic."""
    header = read_header(src)
    checksum = hashlib.sha256(header.raw)
    dst.write(header.raw)
    while tag := exact(src, 1)[0]:
        data = decode(src, tag, header)
        checksum.update(data)
        dst.write(data)
    if exact(src, checksum.digest_size) != checksum.digest():
        raise FormatError("restored map checksum mismatch")
    if src.read(1):
        raise FormatError("trailing archive data")


def unpack(src: BinaryIO, dst: BinaryIO) -> None:
    if exact(src, len(MAGIC)) != MAGIC:
        raise FormatError("not an HMARCH1 archive")
    unpack_blocks(src, dst, unpack_block)


def convert_file(transform: Callable[[BinaryIO, BinaryIO], None], source: Path, dest: Path) -> None:
    # Publish only a complete, checked file and never overwrite the source or
    # a concurrently created destination. Staging in dest.parent keeps the
    # hard link on one filesystem.
    if os.path.lexists(dest):
        raise FileExistsError(f"destination already exists: {dest}")
    temp = None
    try:
        with source.open("rb") as src, tempfile.NamedTemporaryFile(dir=dest.parent, delete=False) as dst:
            temp = Path(dst.name)
            transform(src, dst)
        os.link(temp, dest)
    finally:
        if temp is not None:
            temp.unlink()


def convert(operation: str, source: Path, dest: Path) -> None:
    convert_file({"pack": pack, "unpack": unpack}[operation], source, dest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("pack", "unpack"))
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path, help="new file (never overwritten)")
    args = parser.parse_args()
    try:
        convert(args.operation, args.source, args.destination)
    except (OSError, ValueError) as exc:
        print(f"hmar: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
