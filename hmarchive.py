"""Pack an ordered HMMAP file for storage, or restore it byte for byte."""

import argparse
from itertools import pairwise
from pathlib import Path
import struct
import sys
from typing import BinaryIO

from research.map_archive import hmar
from research.rsm1 import rsm

MAGIC = b"HMARCH2\n"
GROUP = 1024  # multiple of HMARCH1's 64 rows: its exact block partition is a fallback
EXTENDED = 0x7f  # never a valid HMARCH1 block tag
GROUP_HEADER = struct.Struct(">HI")  # rows, key frame bytes (after EXTENDED)
MAX_KEY = 255
DIRECT, PREFIX, ELIAS_FANO, FULL_LENGTH = range(4)
TABLE, SUBBLOCKS = 253, 254  # 0 = predict all, 255 = literal, as in HMARCH1


def field_lane(fields: list[bytes]) -> bytes:
    return min(rsm.lane_candidates(fields, refit=True).values(), key=len)


def pack_keys(keys: list[bytes]) -> bytes:
    """RSM1 field lanes, but never sort, deduplicate, or turn rows into a map."""
    options = [bytes([DIRECT]) + field_lane(keys)]
    prefixes, suffixes = rsm.front_parts(keys)
    if any(prefixes):
        # The anchor would be a length outlier in the suffix lane. Keep it
        # verbatim. Often the original lengths are constant: knowing the suffix
        # length, either the prefix length OR the original length suffices.
        mode, shape = min(((PREFIX, rsm.shape(prefixes[1:])),
                           (FULL_LENGTH, rsm.shape([len(k) for k in keys[1:]]))),
                          key=lambda option: len(option[1]))
        options.append(bytes([mode, len(keys[0])]) + keys[0] + shape + field_lane(suffixes[1:]))
    if all(a < b for a, b in pairwise(keys)):
        ef = rsm.elias(keys)  # only eligible if already strictly increasing and fixed width
        if ef is not None:
            options.append(ef)
    return min(options, key=len)


def unpack_keys(frame: bytes, n: int) -> list[bytes]:
    inp = rsm.Reader(frame)
    mode = inp.byte()
    if mode == DIRECT:
        return rsm.read_lane(inp, n, max_field_bytes=MAX_KEY)
    if mode == ELIAS_FANO:
        return rsm.read_keys(frame, n)  # checks order, bit padding and width (<= 64)
    if mode not in (PREFIX, FULL_LENGTH) or n < 2:
        raise hmar.FormatError("invalid ordered key mode")
    keys = [inp.take(inp.byte())]
    sizes = rsm.unshape(inp, n - 1)
    suffixes = rsm.read_lane(inp, n - 1, max_field_bytes=MAX_KEY)
    for size, suffix in zip(sizes, suffixes, strict=True):
        p = size if mode == PREFIX else size - len(suffix)
        if not 0 <= p <= len(keys[-1]) or p + len(suffix) > MAX_KEY:
            raise hmar.FormatError("invalid reconstructed key length")
        keys.append(keys[-1][:p] + suffix)
    return keys


def index_layout(n: int, count: int) -> tuple[int, int, int]:
    """Index bit width, bitmap bytes (0 for dense), packed index bytes."""
    bits = (count - 1).bit_length()
    dense = (n * bits + 7) // 8
    mask = (n + 7) // 8
    refs = ((n - count) * bits + 7) // 8
    return (bits, mask, refs) if mask + refs < dense else (bits, 0, dense)


def digest_lane(rows: list[hmar.Row], width: int, chunks: list[tuple[int, bytes]]) -> bytes:
    if all(k == 0 for k, _ in chunks):
        return b"\x00"
    if all(k == hmar.LITERAL for k, _ in chunks):
        ranked = bytes([hmar.LITERAL]) + b"".join(data for _, data in chunks)
    else:
        ranked = bytes([SUBBLOCKS]) + b"".join(bytes([k]) + data for k, data in chunks)

    # A miss need not be random. For repeated opaque digests compare a local
    # literal table + packed row indices against the *complete* residual lane.
    ids = {d: i for i, d in enumerate(dict.fromkeys(d for _, d in rows))}
    count = len(ids)
    bits, mask_bytes, index_bytes = index_layout(len(rows), count)
    if 3 + count * width + mask_bytes + index_bytes >= len(ranked):
        return ranked
    stream = rsm.BitWriter()
    mask = bytearray(mask_bytes)
    next_new = 0
    for i, (_, digest) in enumerate(rows):
        index = ids[digest]
        if mask:
            if index == next_new:  # first occurrence: index is implied
                next_new += 1
                continue
            mask[i // 8] |= 1 << (i % 8)
        stream.put(index, bits)
    return bytes([TABLE]) + count.to_bytes(2, "big") + b"".join(ids) + mask + stream.finish()


def read_digests(src: BinaryIO, keys: list[bytes], header: hmar.Header) -> list[bytes]:
    mode = hmar.exact(src, 1)[0]
    if mode in (0, hmar.LITERAL):
        return hmar.unpack_digests(src, keys, header, mode)
    if mode == SUBBLOCKS:
        digests = []
        for i in range(0, len(keys), hmar.BLOCK):
            k = hmar.exact(src, 1)[0]
            digests.extend(hmar.unpack_digests(src, keys[i:i + hmar.BLOCK], header, k))
        return digests
    if mode != TABLE:
        raise hmar.FormatError("unknown group digest mode")
    count = int.from_bytes(hmar.exact(src, 2), "big")
    if not 1 <= count <= len(keys):
        raise hmar.FormatError("invalid digest table size")
    table = [hmar.exact(src, header.width) for _ in range(count)]
    width, mask_bytes, index_bytes = index_layout(len(keys), count)
    mask = hmar.exact(src, mask_bytes)
    if mask and len(keys) % 8 and mask[-1] >> (len(keys) % 8):
        raise hmar.FormatError("invalid table bitmap padding")
    bits = rsm.BitReader(hmar.exact(src, index_bytes))
    digests = []
    seen = set()
    next_new = 0
    for i in range(len(keys)):
        if mask and not mask[i // 8] & (1 << (i % 8)):
            index = next_new
            next_new += 1
            seen.add(index)
        else:
            index = bits.get(width)
            if mask:
                if index >= next_new:
                    raise hmar.FormatError("forward digest table reference")
            elif index not in seen:
                # Dense tables store every reference. The table is in
                # first-occurrence order, so a new index must be the next
                # entry; otherwise a reordered table silently restores the
                # rows in the wrong order.
                if index != next_new:
                    raise hmar.FormatError("digest table out of first-occurrence order")
                seen.add(index)
                next_new += 1
        if index >= count:
            raise hmar.FormatError("invalid digest table index")
        digests.append(table[index])
    if next_new != count:
        raise hmar.FormatError("incorrect number of table indices")
    bits.pad()
    return digests


def pack_group(rows: list[hmar.Row], header: hmar.Header) -> bytes:
    legacy = bytearray()
    chunks = []
    for i in range(0, len(rows), hmar.BLOCK):
        block = rows[i:i + hmar.BLOCK]
        chunk = hmar.pack_digests(block, header)
        chunks.append(chunk)
        legacy.extend(hmar.pack_block(block, *chunk))
    keys = pack_keys([key for key, _ in rows])
    digests = digest_lane(rows, header.width, chunks)
    grouped = bytes([EXTENDED]) + GROUP_HEADER.pack(len(rows), len(keys)) + keys + digests
    return grouped if len(grouped) < len(legacy) else bytes(legacy)


def unpack_group(src: BinaryIO, tag: int, header: hmar.Header) -> bytes:
    if tag != EXTENDED:
        return hmar.unpack_block(src, tag, header)
    n, size = GROUP_HEADER.unpack(hmar.exact(src, GROUP_HEADER.size))
    # The raw RSM field lane is always available: two selectors, at most
    # two shape header bytes, and at most two varint + 255 key bytes per row.
    if not 1 <= n <= GROUP or not 1 <= size <= 4 + (2 + MAX_KEY) * n:
        raise hmar.FormatError("invalid group row count or key frame size")
    keys = unpack_keys(hmar.exact(src, size), n)
    digests = read_digests(src, keys, header)
    return hmar.map_bytes(list(zip(keys, digests, strict=True)))


def pack(src: BinaryIO, dst: BinaryIO) -> None:
    hmar.pack_blocks(src, dst, MAGIC, GROUP, pack_group)


def unpack(src: BinaryIO, dst: BinaryIO) -> None:
    magic = hmar.exact(src, len(MAGIC))
    if magic not in (MAGIC, hmar.MAGIC):
        raise hmar.FormatError("expected an HMARCH1 or HMARCH2 archive")
    hmar.unpack_blocks(src, dst, unpack_group if magic == MAGIC else hmar.unpack_block)


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    commands = cli.add_subparsers(dest="command", required=True)
    encoder = commands.add_parser("pack", help="compress an existing HMMAP file")
    encoder.add_argument("--legacy", action="store_true", help="write HMARCH1 for older decoders")
    decoder = commands.add_parser("unpack", help="restore an HMARCH1 or HMARCH2 archive")
    for cmd in (encoder, decoder):
        cmd.add_argument("source", type=Path)
        cmd.add_argument("destination", type=Path, help="new file (never overwritten)")
    args = cli.parse_args()
    transform = unpack if args.command == "unpack" else (hmar.pack if args.legacy else pack)
    try:
        hmar.convert_file(transform, args.source, args.destination)
    except (OSError, ValueError) as exc:
        print(f"hashmap-archive: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
