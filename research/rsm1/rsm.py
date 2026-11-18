"""Reconstruct-or-Store Map v1: an experimental lossless static bytes-map format.

No third-party dependencies. The format preserves key/value bytes, not insertion
order or physical hash-table state. The optional cache column has 32 bytes/row.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
from heapq import heappop, heappush
import json
from pathlib import Path
from typing import Mapping

MAGIC = b"RSM1"
MAX_EF_WIDTH = 64
MAX_TOKEN = 24
MAX_TOKENS = 96
DEFAULT_MAX_ENTRIES = 1_000_000


def uv(x: int) -> bytes:
    if not 0 <= x < 1 << 64:
        raise ValueError("unsigned varint out of range")
    out = bytearray()
    while x >= 128:
        out.append(128 | (x & 127))
        x >>= 7
    out.append(x)
    return bytes(out)


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        end = self.pos + n
        if n < 0 or end > len(self.data):
            raise ValueError("truncated frame")
        result = self.data[self.pos:end]
        self.pos = end
        return result

    def byte(self) -> int:
        return self.take(1)[0]

    def var(self) -> int:
        result = 0
        for shift in range(0, 70, 7):
            b = self.byte()
            result |= (b & 127) << shift
            if b < 128:
                if result >= 1 << 64 or (shift and b == 0):
                    raise ValueError("invalid varint")
                return result
        raise ValueError("invalid varint")

    def rest(self) -> bytes:
        return self.take(len(self.data) - self.pos)

    def end(self) -> None:
        if self.pos != len(self.data):
            raise ValueError("trailing bytes")


class BitWriter:
    def __init__(self):
        self.out = bytearray()
        self.buf = 0
        self.used = 0

    def put(self, x: int, width: int) -> None:
        self.buf = (self.buf << width) | x
        self.used += width
        while self.used >= 8:
            self.used -= 8
            self.out.append(self.buf >> self.used)
            self.buf &= (1 << self.used) - 1

    def zeros(self, length: int) -> None:
        if self.used:
            k = min(length, 8 - self.used)
            self.put(0, k)
            length -= k
        n, tail = divmod(length, 8)
        self.out.extend(b"\0" * n)
        self.put(0, tail)

    def finish(self) -> bytes:
        self.put(0, (-self.used) % 8)
        return bytes(self.out)


class BitReader:
    def __init__(self, data: bytes):
        self.data = data
        self.at = 0

    def get(self, width: int) -> int:
        end = self.at + width
        if end > 8 * len(self.data):
            raise ValueError("truncated bits")
        i, off = divmod(self.at, 8)
        self.at = end
        if not width:
            return 0
        if width == 1:
            return (self.data[i] >> (7 - off)) & 1
        j = (end + 7) // 8
        x = int.from_bytes(self.data[i:j], "big")
        return (x >> (j * 8 - end)) & ((1 << width) - 1)

    def pad(self) -> None:
        remaining = 8 * len(self.data) - self.at
        if remaining >= 8 or self.get(remaining) != 0:
            raise ValueError("invalid padding")


def frame(b: bytes) -> bytes:
    return uv(len(b)) + b


def shape(lengths: list[int]) -> bytes:
    """Scalar, varint vector, or bit-packed (min + offsets) vector."""
    if not lengths:
        return b"\x01"
    low, high = min(lengths), max(lengths)
    if low == high:
        return uv(low + 1)
    raw = b"\0\0" + b"".join(map(uv, lengths))
    width = (high - low).bit_length()
    header = b"\0\1" + uv(low) + bytes([width])
    if len(header) + (width * len(lengths) + 7) // 8 >= len(raw):
        return raw
    out = BitWriter()
    for x in lengths:
        out.put(x - low, width)
    return header + out.finish()


def unshape(inp: Reader, n: int) -> list[int]:
    width_code = inp.var()
    if width_code:
        return [width_code - 1] * n
    mode = inp.byte()
    if mode == 0:
        return [inp.var() for _ in range(n)]
    if mode == 1:
        low, width = inp.var(), inp.byte()
        if not 1 <= width <= 64:
            raise ValueError("invalid length-vector bit width")
        bits = BitReader(inp.take((width * n + 7) // 8))
        out = [low + bits.get(width) for _ in range(n)]
        bits.pad()
        return out
    raise ValueError("unknown length-vector mode")


def train_bpe(fields: list[bytes]) -> list[bytes]:
    """Learn bounded byte-pair merges on a deterministic spread-out sample.

    Raw bytes are the starting alphabet. Merges never cross a field boundary.
    Ten sample hits is a heuristic, not a bound on compression effectiveness.
    """
    n = len(fields)
    if n == 0:
        return []
    m = min(n, 768)
    weights = Counter(fields[i * n // m][:96] for i in range(m))
    work = [(list(s), weight) for s, weight in weights.items() if len(s) >= 2]
    text = [bytes([i]) for i in range(256)]
    ids = {s: i for i, s in enumerate(text)}
    for _ in range(MAX_TOKENS):
        pairs: Counter[tuple[int, int]] = Counter()
        for row, weight in work:
            for a, b in zip(row, row[1:]):
                pairs[a, b] += weight
        options = [(-count, a, b) for (a, b), count in pairs.items()
                   if count >= 10 and len(text[a]) + len(text[b]) <= MAX_TOKEN]
        if not options:
            break
        _, a, b = min(options)
        joined = text[a] + text[b]
        k = ids.get(joined)
        if k is None:
            k = len(text)
            ids[joined] = k
            text.append(joined)
        for idx, (row, weight) in enumerate(work):
            if len(row) < 2:
                continue
            merged = []
            i = 0
            while i < len(row):
                if i + 1 < len(row) and row[i] == a and row[i + 1] == b:
                    merged.append(k)
                    i += 2
                else:
                    merged.append(row[i])
                    i += 1
            work[idx] = (merged, weight)
    return sorted(text[256:])


def lengths_for(freq: Counter[int]) -> dict[int, int]:
    """Ordinary Huffman tree construction; ties are deterministic."""
    heap = []
    for i, (sid, count) in enumerate(sorted(freq.items())):
        heappush(heap, (count, i, sid))
    if not heap:
        return {}
    i = len(heap)
    while len(heap) > 1:
        a, _, left = heappop(heap)
        b, _, right = heappop(heap)
        heappush(heap, (a + b, i, (left, right)))
        i += 1
    out = {}
    todo = [(heap[0][2], 0)]
    while todo:
        node, d = todo.pop()
        if isinstance(node, int):
            out[node] = max(1, d)
        else:
            todo.extend((child, d + 1) for child in node)
    return out


def canonical(lengths: dict[int, int]) -> dict[int, tuple[int, int]]:
    out = {}
    code = prev = 0
    for sid, width in sorted(lengths.items(), key=lambda p: (p[1], p[0])):
        if not 1 <= width <= 63:
            raise ValueError("invalid Huffman code length")
        code <<= width - prev
        if code >= 1 << width:
            raise ValueError("overfull Huffman codebook")
        out[sid] = (code, width)
        code += 1
        prev = width
    return out


class Tokens:
    def __init__(self, vocab: list[bytes]):
        self.first: list[list[tuple[bytes, int]]] = [[] for _ in range(256)]
        for sid, t in enumerate(vocab, 256):
            self.first[t[0]].append((t, sid))
        for options in self.first:
            options.sort(key=lambda p: (-len(p[0]), p[1]))

    def greedy(self, s: bytes) -> list[int]:
        i = 0
        out = []
        while i < len(s):
            for t, sid in self.first[s[i]]:
                if s.startswith(t, i):
                    out.append(sid)
                    i += len(t)
                    break
            else:
                out.append(s[i])
                i += 1
        return out

    def optimal(self, s: bytes, lengths: dict[int, int]) -> list[int]:
        """Backward shortest path. Ties prefer the earlier candidate."""
        n = len(s)
        d = [0] * (n + 1)
        moves = [(0, 1)] * n
        for i in range(n - 1, -1, -1):
            literal = s[i]
            w, sid, span = lengths[literal] + d[i + 1], literal, 1
            for t, tok in self.first[literal]:
                end = i + len(t)
                if end <= n and s.startswith(t, i):
                    cost = lengths[tok] + d[end]
                    if cost < w:
                        w, sid, span = cost, tok, len(t)
            d[i], moves[i] = w, (sid, span)
        out = []
        i = 0
        while i < n:
            sid, span = moves[i]
            out.append(sid)
            i += span
        return out


def huff_header(lengths: dict[int, int], vocab: list[bytes]) -> bytes:
    bitmap = bytearray(32)
    lit = bytearray()
    for sid in range(256):
        if sid in lengths:
            bitmap[sid // 8] |= 1 << (sid % 8)
            lit.append(lengths[sid])
    extra = b"".join(uv(len(t)) + t + bytes([lengths[i]])
                     for i, t in enumerate(vocab, 256))
    return bytes(bitmap + lit) + uv(len(vocab)) + extra


def lane_candidates(fields: list[bytes]) -> dict[str, bytes]:
    shp = shape([len(s) for s in fields])
    flat = b"".join(fields)
    raw = b"\0" + shp + flat
    out = {"raw": raw}
    if len(flat) < 64:
        return out

    def keep(label: str, hist: Counter[int], lens: dict[int, int],
             vocab: list[bytes], stream) -> None:
        if max(lens.values(), default=0) > 63:
            return
        head = b"\1" + shp + huff_header(lens, vocab)
        size = len(head) + (sum(lens[s] * count for s, count in hist.items()) + 7) // 8
        if size >= len(raw):  # dominated by the same lane's raw form
            return
        codes = canonical(lens)
        writer = BitWriter()
        for sid in stream():
            writer.put(*codes[sid])
        out[label] = head + writer.finish()
        if len(out[label]) != size:
            raise AssertionError("encoded Huffman size differs from bit count")

    byte_hist = Counter(flat)
    keep("byte", byte_hist, lengths_for(byte_hist), [], lambda: iter(flat))
    if len(flat) < 512:
        return out
    vocab = train_bpe(fields)
    if not vocab:
        return out
    tokens = Tokens(vocab)
    freq = Counter(fields)
    greedy = {s: tokens.greedy(s) for s in freq}

    def hist_for(plans: dict[bytes, list[int]]) -> Counter[int]:
        h: Counter[int] = Counter()
        for s, weight in freq.items():
            for sid in plans[s]:
                h[sid] += weight
        return h

    g_hist = hist_for(greedy)
    smooth = Counter({sid: 1 for sid in byte_hist})
    smooth.update(range(256, 256 + len(vocab)))
    lens = lengths_for(g_hist + smooth)
    if max(lens.values()) > 63:
        return out
    optimal = {s: tokens.optimal(s, lens) for s in freq}
    o_hist = hist_for(optimal)
    if sum(o_hist[i] * lens[i] for i in o_hist) > sum(g_hist[i] * lens[i] for i in g_hist):
        raise AssertionError("shortest path lost to greedy")
    for label, plans, hist in (("greedy", greedy, g_hist), ("tokens", optimal, o_hist)):
        keep(label, hist, lens, vocab, lambda: (sid for s in fields for sid in plans[s]))
    return out


def read_huff(inp: Reader, expected: int) -> bytes:
    bitmap = inp.take(32)
    text = {}
    lens = {}
    for i in range(256):
        if bitmap[i // 8] & (1 << (i % 8)):
            lens[i] = inp.byte()
            text[i] = bytes([i])
    n = inp.var()
    if n > MAX_TOKENS:
        raise ValueError("too many tokens")
    prev = b""
    for sid in range(256, 256 + n):
        width = inp.var()
        if not 2 <= width <= MAX_TOKEN:
            raise ValueError("invalid token length")
        t = inp.take(width)
        if t <= prev:
            raise ValueError("unordered or duplicate token")
        prev = text[sid] = t
        lens[sid] = inp.byte()
    if not lens:
        raise ValueError("empty Huffman codebook")
    table = {(w, code): text[sid] for sid, (code, w) in canonical(lens).items()}
    limit = max(lens.values())
    bits = BitReader(inp.rest())
    out = bytearray()
    while len(out) < expected:
        x = 0
        for w in range(1, limit + 1):
            x = 2 * x + bits.get(1)
            t = table.get((w, x))
            if t is not None:
                if len(out) + len(t) > expected:
                    raise ValueError("Huffman overrun")
                out.extend(t)
                break
        else:
            raise ValueError("not a Huffman codeword")
    bits.pad()
    return bytes(out)


def read_lane(inp: Reader, n: int) -> list[bytes]:
    selector = inp.byte()
    lengths = unshape(inp, n)
    total = sum(lengths)
    if selector == 0:
        plain = inp.take(total)
    elif selector == 1:
        plain = read_huff(inp, total)
    else:
        raise ValueError("unknown field mode")
    inp.end()
    result = []
    pos = 0
    for length in lengths:
        result.append(plain[pos:pos + length])
        pos += length
    return result


def front_parts(keys: list[bytes]) -> tuple[list[int], list[bytes]]:
    prefixes, suffixes = [], []
    prev = b""
    for k in keys:
        i = 0
        while i < min(len(prev), len(k)) and prev[i] == k[i]:
            i += 1
        prefixes.append(i)
        suffixes.append(k[i:])
        prev = k
    return prefixes, suffixes


def elias(keys: list[bytes]) -> bytes | None:
    """Encode increasing fixed-width keys, as low bits then unary high gaps."""
    if not keys:
        return None
    n, w = len(keys), len(keys[0])
    if not 1 <= w <= MAX_EF_WIDTH or any(len(k) != w for k in keys):
        return None
    x = [int.from_bytes(k, "big") for k in keys]
    if any(a >= b for a, b in zip(x, x[1:])):
        raise ValueError("Elias-Fano requires strictly increasing keys")
    # Compare byte counts, including the integer ell in the header, before writing.
    ell = min(range(8 * w + 1), key=lambda l:
              len(uv(l)) + (n * (l + 1) + (x[-1] >> l) + 7) // 8)
    mask = (1 << ell) - 1
    out = BitWriter()
    for k in x:
        out.put(k & mask, ell)
    last = 0
    for k in x:
        high = k >> ell
        out.zeros(high - last)
        out.put(1, 1)
        last = high
    return b"\2" + uv(w) + uv(ell) + out.finish()


def unelias(inp: Reader, n: int) -> list[bytes]:
    w, ell = inp.var(), inp.var()
    if not (n and 1 <= w <= MAX_EF_WIDTH and ell <= 8 * w):
        raise ValueError("invalid Elias-Fano header")
    r = BitReader(inp.rest())
    low = [r.get(ell) for _ in range(n)]
    max_high = ((1 << (8 * w)) - 1) >> ell
    high = 0
    out = []
    for l in low:
        while r.get(1) == 0:
            high += 1
            if high > max_high:
                raise ValueError("Elias-Fano key out of range")
        out.append(((high << ell) | l).to_bytes(w, "big"))
    r.pad()
    return out


def key_candidates(keys: list[bytes]) -> dict[str, bytes]:
    out = {"direct/" + label: b"\0" + payload
           for label, payload in lane_candidates(keys).items()}
    prefixes, suffixes = front_parts(keys)
    head = b"\1" + shape(prefixes)
    out.update({"front/" + label: head + payload
                for label, payload in lane_candidates(suffixes).items()})
    ef = elias(keys)
    if ef is not None:
        out["elias-fano"] = ef
    return out


def read_keys(data: bytes, n: int) -> list[bytes]:
    inp = Reader(data)
    method = inp.byte()
    if method == 0:
        out = read_lane(inp, n)
    elif method == 1:
        prefixes = unshape(inp, n)
        suffixes = read_lane(inp, n)
        out = []
        prev = b""
        for p, s in zip(prefixes, suffixes, strict=True):
            if p > len(prev):
                raise ValueError("invalid front-code prefix")
            prev = prev[:p] + s
            out.append(prev)
    elif method == 2:
        out = unelias(inp, n)
    else:
        raise ValueError("unknown key mode")
    if any(a >= b for a, b in zip(out, out[1:])):
        raise ValueError("keys are not strictly increasing")
    return out


def cache_candidates(keys: list[bytes], cached: list[bytes]) -> dict[str, bytes]:
    out = {"raw": b"\0" + b"".join(cached)}
    exc = [i for i, (k, v) in enumerate(zip(keys, cached, strict=True))
           if sha256(k).digest() != v]
    if not exc:
        out["regenerate-all"] = b"\1"
        return out
    bitmap = bytearray((len(keys) + 7) // 8)
    positions = bytearray(uv(len(exc)))
    prev = -1
    for i in exc:
        bitmap[i // 8] |= 1 << (i % 8)
        positions.extend(uv(i - prev - 1))
        prev = i
    tail = b"".join(cached[i] for i in exc)
    out["bitmap-exceptions"] = b"\2" + bytes(bitmap) + tail
    out["sparse-exceptions"] = b"\3" + bytes(positions) + tail
    return out


def read_cache(data: bytes, keys: list[bytes]) -> list[bytes]:
    inp = Reader(data)
    mode = inp.byte()
    n = len(keys)
    if mode == 0:
        result = [inp.take(32) for _ in keys]
    elif mode == 1:
        result = [sha256(k).digest() for k in keys]
    elif mode == 2:
        bitmap = inp.take((n + 7) // 8)
        if n % 8 and bitmap[-1] >> (n % 8):
            raise ValueError("invalid exception bitmap padding")
        result = [inp.take(32) if bitmap[i // 8] & (1 << (i % 8)) else sha256(k).digest()
                  for i, k in enumerate(keys)]
    elif mode == 3:
        r = inp.var()
        if r > n:
            raise ValueError("too many cache exceptions")
        exc = []
        i = -1
        for _ in range(r):
            i += inp.var() + 1
            if i >= n:
                raise ValueError("invalid exception position")
            exc.append(i)
        result = [sha256(k).digest() for k in keys]
        for i in exc:
            result[i] = inp.take(32)
    else:
        raise ValueError("unknown cache mode")
    inp.end()
    return result


# A profile controls the admissible candidates, not the archive format.
PROFILES = {
    "plain": (False, False, {"raw"}, False),
    "structural": (True, True, {"raw"}, True),
    "byte-huff": (True, True, {"raw", "byte"}, True),
    "greedy": (True, True, {"raw", "byte", "greedy"}, True),
    "rsm": (True, True, {"raw", "byte", "tokens"}, True),
}


class Candidates:
    def __init__(self, mapping: Mapping[bytes, bytes], cache: Mapping[bytes, bytes] | None = None):
        if any(not isinstance(k, bytes) or not isinstance(v, bytes) for k, v in mapping.items()):
            raise TypeError("keys and values must be bytes")
        keys = sorted(mapping)
        self.n = len(keys)
        if cache is not None:
            if cache.keys() != mapping.keys() or any(not isinstance(v, bytes) or len(v) != 32
                                                      for v in cache.values()):
                raise ValueError("cache must supply one 32-byte value per key")
        self.key = key_candidates(keys)
        self.value = lane_candidates([mapping[k] for k in keys])
        self.cache = cache_candidates(keys, [cache[k] for k in keys]) if cache is not None else None

    def archive(self, profile: str = "rsm") -> tuple[bytes, dict[str, str | int]]:
        use_front, use_ef, lane_modes, use_cache = PROFILES[profile]

        def allowed(name: str) -> bool:
            if name == "elias-fano":
                return use_ef
            transform, lane = name.split("/")
            return lane in lane_modes and (transform == "direct" or use_front)

        def smallest(options, names):
            return min(names, key=lambda m: len(options[m]))

        km = smallest(self.key, (mode for mode in self.key if allowed(mode)))
        vm = smallest(self.value, (mode for mode in self.value if mode in lane_modes))
        k, v = self.key[km], self.value[vm]
        archive = MAGIC + bytes([self.cache is not None]) + uv(self.n) + frame(k) + frame(v)
        info = {"key_mode": km, "key_bytes": len(k), "value_mode": vm, "value_bytes": len(v),
                "cache_mode": "absent", "cache_bytes": 0}
        if self.cache is not None:
            cm = smallest(self.cache, self.cache) if use_cache else "raw"
            c = self.cache[cm]
            info.update(cache_mode=cm, cache_bytes=len(c))
            archive += frame(c)
        return archive, info


def pack(mapping: Mapping[bytes, bytes], cache: Mapping[bytes, bytes] | None = None) -> bytes:
    return Candidates(mapping, cache).archive()[0]


def unpack(data: bytes, *, max_entries: int = DEFAULT_MAX_ENTRIES) -> tuple[dict[bytes, bytes], dict[bytes, bytes] | None]:
    """Decode an archive. This research parser is not hardened for hostile input."""
    inp = Reader(data)
    if inp.take(4) != MAGIC:
        raise ValueError("not an RSM1 archive")
    flags, n = inp.byte(), inp.var()
    if flags not in (0, 1) or n > max_entries:
        raise ValueError("unsupported header")
    keys = read_keys(inp.take(inp.var()), n)
    values = read_lane(Reader(inp.take(inp.var())), n)
    cache = dict(zip(keys, read_cache(inp.take(inp.var()), keys), strict=True)) if flags else None
    inp.end()
    return dict(zip(keys, values, strict=True)), cache


def read_json(path: Path) -> tuple[dict[bytes, bytes], dict[bytes, bytes] | None]:
    j = json.loads(path.read_text(encoding="utf-8"))
    if type(j.get("cache")) is not bool:
        raise ValueError('JSON needs a boolean "cache" field')
    cache = {} if j["cache"] else None
    m = {}
    for row in j["entries"]:
        if len(row) != (3 if cache is not None else 2):
            raise ValueError("wrong number of columns")
        fields = [bytes.fromhex(x) for x in row]
        if fields[0] in m:
            raise ValueError("duplicate key")
        m[fields[0]] = fields[1]
        if cache is not None:
            cache[fields[0]] = fields[2]
    return m, cache


def write_json(path: Path, m: dict[bytes, bytes], cache: dict[bytes, bytes] | None) -> None:
    entries = [[k.hex(), m[k].hex()] + ([cache[k].hex()] if cache is not None else []) for k in sorted(m)]
    path.write_text(json.dumps({"cache": cache is not None, "entries": entries}, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("mode", choices=("pack", "unpack"))
    cli.add_argument("input", type=Path)
    cli.add_argument("output", type=Path)
    cli.add_argument("--max-entries", type=int, default=DEFAULT_MAX_ENTRIES,
                     help="decoder entry limit (default: %(default)s)")
    args = cli.parse_args()
    if args.mode == "pack":
        args.output.write_bytes(pack(*read_json(args.input)))
    else:
        write_json(args.output, *unpack(args.input.read_bytes(), max_entries=args.max_entries))


if __name__ == "__main__":
    main()
