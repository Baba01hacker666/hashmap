"""Reproduce the size table on synthetic asset records, no downloaded data."""

from hashlib import sha256
from io import BytesIO

import hmar


def measure(keys: list[bytes], miss_every: int) -> tuple[int, int]:
    if len(set(keys)) != len(keys):
        raise AssertionError("fixture must have distinct keys")
    original = bytearray(b"HMMAP 2\nalgo sha256\ndlen 32\n")
    for i, key in enumerate(keys):
        digest = sha256(key).digest()
        if miss_every and i % miss_every == 0:
            other = sha256(b"different field\0" + key).digest()
            assert other != digest
            digest = other
        original.extend(digest + bytes([len(key)]) + key)
    archive, restored = BytesIO(), BytesIO()
    hmar.pack(BytesIO(original), archive)
    archive.seek(0)
    hmar.unpack(archive, restored)
    if restored.getvalue() != original:
        raise AssertionError("archive did not reproduce the input")
    return len(original), len(archive.getvalue())


def main() -> None:
    n = 4096
    labels = [f"asset/part-{i:06d}".encode() for i in range(n)]
    ids = [sha256(i.to_bytes(8, "big")).digest()[:len(labels[0])] for i in range(n)]
    print(f"{n} distinct rows; {len(labels[0])}-byte keys; 32-byte values; full files, including framing.")
    print("keys             misses/block  input bytes  archive bytes    saved")
    for label, keys, period in [("ordered labels", labels, 0), ("opaque IDs", ids, 0),
                                ("opaque IDs", ids, 64), ("opaque IDs", ids, 1)]:
        raw, size = measure(keys, period)
        k = hmar.BLOCK // period if period else 0
        print(f"{label:<16} {k:>12}  {raw:>11}  {size:>13}  {1-size/raw:>7.2%}")


if __name__ == "__main__":
    main()
