"""Measure the EVIL nibble codec against the adaptive codecs, whole files.

Every fixture is encoded with every codec and restored byte for byte. The
point is not that EVIL wins — it is to show exactly WHERE a fixed 4-bit code
with zero table overhead beats an adaptive code that must store its book.
"""

import hashlib
import math
import random
import zlib
from collections import Counter
from hashlib import sha256
from io import BytesIO
from pathlib import Path

import hmarchive
from research.evil_codec import evil, evilzip
from research.map_archive import hmar
from research.rsm1 import rsm

SHA256_HEADER = b"HMMAP 2\nalgo sha256\ndlen 32\n"


def run(codec, data: bytes) -> bytes:
    dst = BytesIO()
    codec(BytesIO(data), dst)
    return dst.getvalue()


def measure(label: str, original: bytes) -> dict:
    v1 = run(hmar.pack, original)
    v2 = run(hmarchive.pack, original)
    ev = run(evilzip.pack, original)
    deflated = zlib.compress(original, level=9)
    for archive in (v1, v2):
        if run(hmarchive.unpack, archive) != original:
            raise AssertionError(f"{label}: HMARCH restore differs")
    if zlib.decompress(deflated) != original:
        raise AssertionError(f"{label}: zlib restore differs")
    if run(evilzip.unpack, ev) != original:
        raise AssertionError(f"{label}: EVIL1 restore differs")
    print(f"{label:<24} {len(original):>9,} {len(ev):>9,} {len(v1):>10,} {len(v2):>10,} {len(deflated):>11,}")
    return {"label": label, "raw": len(original), "evil": len(ev), "v1": len(v1), "v2": len(v2)}


def pin_fixture(n: int) -> bytes:
    rows = [(f"{i:08d}".encode(), sha256(f"{i:08d}".encode()).digest()) for i in range(n)]
    return SHA256_HEADER + hmar.map_bytes(rows)


def wordlist_fixture(n: int, seed: int = 0xE711) -> tuple[bytes, bytes]:
    """Deterministic rockyou-ish words: weighted lowercase + digit suffixes."""
    rng = random.Random(seed)
    letters = "etaoinshrdlcumwfgypbvkjxqz"
    weights = [len(letters) - i for i in range(len(letters))]
    words = []
    for _ in range(n):
        word = "".join(rng.choices(letters, weights, k=rng.randrange(4, 11)))
        if rng.random() < 0.45:
            word += "".join(rng.choices("0123456789", k=rng.randrange(1, 4)))
        words.append(word.encode())
    rows = [(w, sha256(w).digest()) for w in words]
    return SHA256_HEADER + hmar.map_bytes(rows), b"".join(words)


def hex_key_fixture(n: int) -> bytes:
    rows = []
    for i in range(n):
        key = sha256(i.to_bytes(4, "big")).hexdigest().encode()  # hex TEXT, 64 chars
        rows.append((key, sha256(b"value:" + key).digest()))     # opaque values
    return SHA256_HEADER + hmar.map_bytes(rows)


def main() -> None:
    print("case                         HMMAP      EVIL1    HMARCH1    HMARCH2  zlib9(HMMAP)")

    pins = pin_fixture(4096)
    result = measure("8-digit PIN codes", pins)
    if result["evil"] >= result["raw"] // 2:
        raise AssertionError("EVIL must beat 2:1 on predicted digit rows")

    blob = wordlist_fixture(4096)[0]
    measure("wordlist words", blob)

    hexed = hex_key_fixture(2048)
    result = measure("hex-text keys, opaque", hexed)
    key_bytes = 2048 * (1 + 64)
    if result["evil"] >= result["raw"] - key_bytes // 4:
        raise AssertionError("EVIL-H should save at least 25% of the hex key bytes")

    measure("one short binary row",
            SHA256_HEADER + hmar.map_bytes([(b"\x00\x01\xff", bytes(range(32)))]))

    data = Path(rsm.__file__).with_name("cpython-v3.13.0.tsv").read_bytes()
    rows = [(key, bytes.fromhex(hex_id.decode("ascii"))) for line in data.splitlines()
            for key, hex_id in [line.rsplit(b"\t", 1)]]
    measure("CPython paths / blob IDs", b"HMMAP 2\nalgo sha1\ndlen 20\n" + hmar.map_bytes(rows))

    # Crossover: EVIL's fixed code has no table to amortize, RSM1's does.
    print("\ndigit keys, n rows       EVIL1    HMARCH2")
    for n in (16, 64, 256, 1024, 4096):
        fixture = pin_fixture(n)
        ev, v2 = run(evilzip.pack, fixture), run(hmarchive.pack, fixture)
        winner = "EVIL" if len(ev) < len(v2) else "HMARCH2"
        print(f"n = {n:>5,}           {len(ev):>9,} {len(v2):>10,}   <- {winner}")
        if run(evilzip.unpack, ev) != fixture or run(hmarchive.unpack, v2) != fixture:
            raise AssertionError("crossover fixture restore failed")

    # Bits per character vs the alphabet's entropy on each fixture's keys.
    print("\nkey lane cost            EVIL bits/char   entropy bits/char   alphabet")
    for label, keys in (("PIN codes", b"0123456789"), ("wordlist", wordlist_fixture(4096)[1]),
                        ("hex text", b"0123456789abcdef")):
        if label == "wordlist":
            sample = keys
        else:
            sample = keys * 64
        counts = Counter(sample)
        total = len(sample)
        entropy = -sum(c / total * math.log2(c / total) for c in counts.values())
        stats = evil.codec_stats(sample[:255])
        print(f"{label:<24} {stats:>13.2f} {entropy:>17.2f}   {len(counts)} symbols")

    # EVIL's ceiling: drop the per-field headers, one stream per file.
    print("\nEVIL ceiling, key bytes  raw keys   per-field EVIL   one-stream EVIL")
    for label, keys in (("PIN codes x4,096", [f"{i:08d}".encode() for i in range(4096)]),
                        ("hex text x2,048", [sha256(i.to_bytes(4, "big")).hexdigest().encode()
                                             for i in range(2048)])):
        per_field = sum(len(evil.pack_field(k)) for k in keys)
        one_stream = len(evil.pack_fields(keys))
        if evil.unpack_fields(evil.pack_fields(keys), [len(k) for k in keys]) != keys:
            raise AssertionError("lane restore failed")
        print(f"{label:<24} {sum(len(k) for k in keys):>9,} {per_field:>15,} {one_stream:>16,}")


if __name__ == "__main__":
    main()
