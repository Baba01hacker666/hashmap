"""EVIL1: an experimental whole-file HMMAP archive using EVIL-coded keys.

Research only. HMARCH2 is the real codec; this exists to measure how far the
fixed nibble code (evil.py) takes whole files against the adaptive RSM1 lanes.
The digest lane is HMARCH1's exact prediction/ranked encoding, reused per
group, so the comparison isolates the key lane.

    "EVIL1\n", original HMMAP header bytes
    groups: u8 1, uv(n), uv(key lane bytes), n EVIL key fields,
            u8 digest mode + payload   (hmar.pack_digests over the group)
    end:    u8 0, SHA-256(original file)[32]
"""

import argparse
from pathlib import Path
import sys
from typing import BinaryIO

from research.evil_codec import evil
from research.map_archive import hmar

MAGIC = b"EVIL1\n"
GROUP = 4096
TAG_GROUP = 1
# uv(255) + mode + five nibbles (worst escape) per byte, padded
MAX_KEY_LANE = GROUP * (2 + 1 + (5 * 255 + 1) // 2)


def pack_group(rows: list[hmar.Row], header: hmar.Header) -> bytes:
    keys = b"".join(evil.pack_field(key) for key, _ in rows)
    k, digests = hmar.pack_digests(rows, header)
    return bytes([TAG_GROUP]) + evil.uv(len(rows)) + evil.uv(len(keys)) + keys + bytes([k]) + digests


def unpack_group(src: BinaryIO, tag: int, header: hmar.Header) -> bytes:
    if tag != TAG_GROUP:
        raise hmar.FormatError("unknown EVIL1 group tag")
    n = evil.read_uv(src)
    if not 1 <= n <= GROUP:
        raise hmar.FormatError("invalid EVIL1 group size")
    size = evil.read_uv(src)
    if not 1 <= size <= MAX_KEY_LANE:
        raise hmar.FormatError("invalid EVIL1 key lane size")
    reader = evil.Reader(hmar.exact(src, size))
    keys = [evil.unpack_field(reader) for _ in range(n)]
    reader.done()
    k = hmar.exact(src, 1)[0]
    digests = hmar.unpack_digests(src, keys, header, k)
    return hmar.map_bytes(list(zip(keys, digests, strict=True)))


def pack(src: BinaryIO, dst: BinaryIO) -> None:
    hmar.pack_blocks(src, dst, MAGIC, GROUP, pack_group)


def unpack(src: BinaryIO, dst: BinaryIO) -> None:
    if hmar.exact(src, len(MAGIC)) != MAGIC:
        raise hmar.FormatError("not an EVIL1 archive")
    hmar.unpack_blocks(src, dst, unpack_group)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("pack", "unpack"))
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path, help="new file (never overwritten)")
    args = parser.parse_args()
    try:
        transform = {"pack": pack, "unpack": unpack}[args.operation]
        hmar.convert_file(transform, args.source, args.destination)
    except (OSError, ValueError) as exc:
        print(f"evil: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
