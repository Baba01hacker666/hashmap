#!/usr/bin/env python3
"""Pack a large HMMAP into HMARCH2, encoding groups in parallel workers.

The archive format is a header, independent 1024-row groups, and a checksum
over the original HMMAP bytes. Groups can therefore be encoded concurrently;
this script keeps the row order and the global checksum the same as a normal
`hashmap-archive pack`, so its output is an ordinary HMARCH2 file.

    python3 -B tools/pack-map-parallel.py wordlist-map.hmmap wordlist-map.hmar -j 2
"""

import argparse
from concurrent.futures import ProcessPoolExecutor
from hashlib import sha256
from io import BytesIO
from itertools import islice
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import hmarchive as ar
from research.map_archive import hmar

CHUNK_ROWS = 64 * ar.GROUP  # a whole number of groups; several MB per task


def pack_rows(rows: list[hmar.Row], raw_header: bytes) -> bytes:
    """Encode one chunk of rows into the same groups a serial pack emits."""
    header = hmar.read_header(BytesIO(raw_header))
    out = bytearray()
    for i in range(0, len(rows), ar.GROUP):
        out += ar.pack_group(rows[i:i + ar.GROUP], header)
    return bytes(out)


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("source", type=Path)
    cli.add_argument("destination", type=Path, help="new file (never overwritten)")
    cli.add_argument("-j", "--workers", type=int, default=2)
    args = cli.parse_args()
    if args.workers < 1:
        raise SystemExit("at least one worker is required")
    if args.destination.exists():
        raise SystemExit(f"destination already exists: {args.destination}")

    with args.source.open("rb") as src, args.destination.open("wb") as dst:
        header = hmar.read_header(src)
        raw = header.raw
        checksum = sha256(raw)
        records = hmar.read_rows(src, header.width)
        dst.write(ar.MAGIC + raw)
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            while True:
                # Keep only one wave in flight: a full file's worth of rows
                # queued as futures would use gigabytes of RAM.
                wave = []
                for _ in range(args.workers):
                    rows = list(islice(records, CHUNK_ROWS))
                    if not rows:
                        break
                    checksum.update(hmar.map_bytes(rows))
                    wave.append(pool.submit(pack_rows, rows, raw))
                if not wave:
                    break
                for future in wave:
                    dst.write(future.result())
        dst.write(b"\x00" + checksum.digest())
    print(f"{args.destination}: {args.destination.stat().st_size:,} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
