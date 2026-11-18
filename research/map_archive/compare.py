"""Compare complete encodings of the *same ordered files*. No network or output files."""

from hashlib import sha256
from io import BytesIO
from pathlib import Path
import zlib

import hmarchive
from research.rsm1 import rsm
from . import experiment, hmar


def run(codec, data: bytes) -> bytes:
    dst = BytesIO()
    codec(BytesIO(data), dst)
    return dst.getvalue()


def measure(label: str, original: bytes) -> None:
    v1 = run(hmar.pack, original)
    v2 = run(hmarchive.pack, original)
    deflated = zlib.compress(v1, level=9)
    for archive in (v1, v2, zlib.decompress(deflated)):
        if run(hmarchive.unpack, archive) != original:
            raise AssertionError(f"{label}: restore differs from input")
    if len(v2) > len(v1):
        raise AssertionError(f"{label}: lost to the available HMARCH1 fallback")
    print(f"{label:<28} {len(original):>9,} {len(v1):>10,} {len(v2):>10,}"
          f" {1 - len(v2) / len(v1):>10.2%} {len(deflated):>11,}")


def main() -> None:
    print("case                             HMMAP    HMARCH1    HMARCH2  saved/v1   zlib9(v1)")
    for label, keys, period in experiment.cases():
        misses = hmar.BLOCK // period if period else 0
        measure(f"{label}, {misses}/64 misses", experiment.fixture(keys, period))
        if period == 1:
            # Keep the opaque keys AND their order fixed; only the number of
            # distinct stored values changes relative to the all-miss control.
            rows = [(k, sha256(bytes([i % 4])).digest()) for i, k in enumerate(keys)]
            header = b"HMMAP 2\nalgo sha256\ndlen 32\n"
            measure("four repeated opaque values", header + hmar.map_bytes(rows))
            measure("one opaque row", header + hmar.map_bytes(rows[:1]))

    data = Path(rsm.__file__).with_name("cpython-v3.13.0.tsv").read_bytes()
    if sha256(data).hexdigest() != "2ae7644e19f678e9cc7f6234264e7090eb3fcdac9ae133cb5570a77347e69454":
        raise ValueError("CPython fixture checksum mismatch")
    rows = [(key, bytes.fromhex(hex_id.decode("ascii"))) for line in data.splitlines()
            for key, hex_id in [line.rsplit(b"\t", 1)]]
    header = b"HMMAP 2\nalgo sha1\ndlen 20\n"
    original = header + hmar.map_bytes(rows)
    measure("CPython paths / blob IDs", original)

    # Bare RSM1 is comparable here ONLY because the original keys already
    # are sorted and unique and we supply the missing HMMAP header ourselves.
    logical = rsm.pack(dict(rows))
    mapping, cache = rsm.unpack(logical)
    if cache is not None or header + hmar.map_bytes(list(mapping.items())) != original:
        raise AssertionError("bare RSM1 + original header did not restore this fixture")
    print(f"Same CPython rows as a bare RSM1 map: {len(logical):,} bytes (no map header/checksum).")


if __name__ == "__main__":
    main()
