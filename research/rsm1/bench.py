"""Reproducible test and byte-count suite for RSM1; Python 3.10+ stdlib only."""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from functools import lru_cache
from hashlib import sha256
from itertools import combinations, product
import json
import math
from pathlib import Path
import random
from urllib.request import Request, urlopen
import zlib

from rsm import (Candidates, PROFILES, Tokens, BitReader, BitWriter, Reader, cache_candidates,
                 elias, lane_candidates, pack, read_keys, read_lane, unpack)

HERE = Path(__file__).resolve().parent
CPYTHON_COMMIT = "60403a5409ff2c3f3b07dd2ca91a7a3e096839c7"
CPYTHON_API = f"https://api.github.com/repos/python/cpython/git/trees/{CPYTHON_COMMIT}?recursive=1"
CPYTHON_FIXTURE = HERE / "cpython-v3.13.0.tsv"
CPYTHON_FIXTURE_SHA256 = "2ae7644e19f678e9cc7f6234264e7090eb3fcdac9ae133cb5570a77347e69454"


def seeded_bytes(rng: random.Random, n: int) -> bytes:
    return rng.getrandbits(8 * n).to_bytes(n, "little")


def template_maps(n: int = 16_384):
    rng = random.Random(7429)
    text, mixed, cache = {}, {}, {}
    regions = ("us-west-1", "eu-north-2", "ap-south-1", "sa-east-3")
    names = ("a11y-events", "user-settings", "session-metrics", "request-logs", "service-alerts")
    types = ("application/json", "application/octet-stream", "text/plain; charset=utf-8")
    for i in range(n):
        tenant, device, user = rng.randrange(96), rng.randrange(1 << 28), rng.randrange(10**10)
        k = (f"/v2/tenants/{tenant:03d}/{regions[tenant % 4]}/{names[i % 5]}/"
             f"device-{device:07x}?slot={i:06d}&rev={(i * 17) % 997:03d}").encode("ascii")
        v = (f"op={['GET', 'POST', 'PATCH'][i % 3]}&state={['ready', 'queued', 'retry', 'ok'][i % 4]};"
             f"format={types[i % 3]}|user=U-{user:010d}#seq={i:06d}").encode("ascii")
        text[k] = v
        mixed[k] = seeded_bytes(rng, 32)
        expected = sha256(k).digest()
        if i % 16 == 0:
            actual = seeded_bytes(rng, 32)
            cache[k] = actual if actual != expected else bytes([actual[0] ^ 1]) + actual[1:]
        else:
            cache[k] = expected
    return text, mixed, cache


def opaque_map(n: int = 65_536) -> dict[bytes, bytes]:
    rng = random.Random(71_995)
    m: dict[bytes, bytes] = {}
    while len(m) < n:
        k = seeded_bytes(rng, 32)
        if k not in m:
            m[k] = seeded_bytes(rng, 32)
    return m


def cpython_from_tree(j: dict) -> dict[bytes, bytes]:
    if j.get("sha") != CPYTHON_COMMIT or j.get("truncated") is not False:
        raise ValueError("unexpected CPython commit or truncated tree")
    m = {s["path"].encode("utf-8"): bytes.fromhex(s["sha"])
         for s in j["tree"] if s["type"] == "blob"}
    if len(m) != 4882 or any(len(v) != 20 for v in m.values()):
        raise ValueError("unexpected CPython blob rows")
    return m


def get_cpython(tree: Path | None) -> dict[bytes, bytes]:
    if tree is not None:
        return cpython_from_tree(json.loads(tree.read_bytes()))
    if CPYTHON_FIXTURE.exists():
        data = CPYTHON_FIXTURE.read_bytes()
        if sha256(data).hexdigest() != CPYTHON_FIXTURE_SHA256:
            raise ValueError("CPython fixture checksum mismatch")
        return {k: bytes.fromhex(v.decode("ascii"))
                for row in data.split(b"\n") if row
                for k, v in [row.rsplit(b"\t", 1)]}
    req = Request(CPYTHON_API, headers={"User-Agent": "rsm-compression-bench"})
    with urlopen(req, timeout=30) as response:
        return cpython_from_tree(json.load(response))


def tests() -> dict[str, int]:
    count: Counter[str] = Counter()
    code_lens = {ord("a"): 3, ord("b"): 4, ord("c"): 4, 256: 2, 257: 1}
    toy = Tokens([b"ab", b"bc"])
    assert toy.greedy(b"abc") == [256, ord("c")]
    assert toy.optimal(b"abc", code_lens) == [ord("a"), 257]
    assert sum(code_lens[i] for i in toy.greedy(b"abc")) == 6
    assert sum(code_lens[i] for i in toy.optimal(b"abc", code_lens)) == 4
    count["greedy_counterexample"] += 1

    vocab = [b"00", b"01", b"010", b"10", b"11"]
    tokenized = Tokens(vocab)
    cost = {48: 4, 49: 3, 256: 2, 257: 5, 258: 2, 259: 4, 260: 3}
    expand = {48: b"0", 49: b"1", **dict(enumerate(vocab, 256))}

    @lru_cache(maxsize=None)
    def exhaustive_costs(s: bytes) -> tuple[int, ...]:
        if not s:
            return (0,)
        return tuple(cost[sid] + tail for sid, t in expand.items() if s.startswith(t)
                     for tail in exhaustive_costs(s[len(t):]))

    for n in range(9):
        for p in product(b"01", repeat=n):
            s = bytes(p)
            parse = tokenized.optimal(s, cost)
            assert b"".join(expand[sid] for sid in parse) == s
            assert sum(cost[sid] for sid in parse) == min(exhaustive_costs(s))
            count["segmentation_cases"] += 1

    numbers = [0, 1, 2, 3, 17, 128, 255]
    for n in range(1, len(numbers) + 1):
        for xs in combinations(numbers, n):
            keys = [bytes([x]) for x in xs]
            assert read_keys(elias(keys), len(keys)) == keys
            count["elias_fano_cases"] += 1

    for w in (1, 16, 32, 64):
        keys = [i.to_bytes(w, "big") for i in [0, 1, 3, 255, (1 << (8 * w)) - 2]]
        keys = sorted(set(keys))
        assert read_keys(elias(keys), len(keys)) == keys
        count["elias_fano_cases"] += 1

    for choices in product((None, b"", b"0", b"#", b"\x00\xff"), repeat=3):
        m = {k: v for k, v in zip((b"", b"a", b"a0"), choices) if v is not None}
        assert unpack(pack(m)) == (m, None)
        count["exhaustive_map_cases"] += 1

    rng = random.Random(3_211)
    for trial in range(256):
        m = {}
        for j in range(trial % 43):
            k = seeded_bytes(rng, rng.randrange(20))
            if trial % 3 == 0:
                k = b"path/01#alpha?k=" + k
            m[k] = seeded_bytes(rng, rng.randrange(60))
        cache = None
        if trial % 2 == 0:
            cache = {k: (seeded_bytes(rng, 32) if rng.randrange(4) == 0 else sha256(k).digest()) for k in m}
        assert unpack(pack(m, cache)) == (m, cache)
        count["randomized_map_cases"] += 1

    fields = [b"/alpha/007-!x?beta=42&z=99;" + str(i).encode() for i in range(768)]
    cf = lane_candidates(fields)
    assert {"raw", "byte", "greedy", "tokens"} <= cf.keys()
    for lane in cf.values():
        assert read_lane(Reader(lane), len(fields)) == fields
        count["forced_field_modes"] += 1

    m = {b"": b"", b"#?!\0": bytes(range(256)), b"0001": b"1.00", b"1": b"1",
         "é".encode(): "é".encode(), "e\u0301".encode(): "e\u0301".encode()}
    a = pack(m)
    assert unpack(a) == (m, None)
    assert pack(dict(reversed(list(m.items())))) == a
    count["exact_byte_and_order_cases"] += 1
    for i in range(len(a)):
        try:
            unpack(a[:i])
        except ValueError:
            count["truncation_cases"] += 1
        else:
            raise AssertionError(f"truncation at byte {i} was accepted")

    keys = [i.to_bytes(2, "big") for i in range(256)]
    m = {k: b"" for k in keys}
    for misses, wanted in [(set(), "regenerate-all"), ({1}, "sparse-exceptions"),
                           (set(range(0, 256, 2)), "bitmap-exceptions"),
                           (set(range(256)), "raw")]:
        vals = [seeded_bytes(rng, 32) if i in misses else sha256(k).digest()
                for i, k in enumerate(keys)]
        cache = dict(zip(keys, vals))
        cm = cache_candidates(keys, vals)
        assert min(cm, key=lambda v: len(cm[v])) == wanted
        archive, info = Candidates(m, cache).archive()
        assert info["cache_mode"] == wanted
        assert unpack(archive) == (m, cache)
        count["cache_selector_cases"] += 1

    return dict(count)


def evaluate(name: str, m, cache) -> list[dict]:
    candidates = Candidates(m, cache)
    packed = {p: candidates.archive(p) for p in PROFILES}
    base = len(packed["plain"][0])
    print(f"{name}: {len(m):,} entries (plain {base:,} bytes)", flush=True)
    out = []
    for profile, (archive, info) in packed.items():
        decoded = unpack(archive)
        if decoded != (m, cache):
            raise AssertionError(f"{name}/{profile} did not round-trip")
        if len(archive) > base:
            raise AssertionError(f"{name}/{profile} larger than its raw container")
        out.append({"dataset": name, "entries": len(m), "variant": profile,
                    "archive_bytes": len(archive), "saving_pct": round(100 * (base - len(archive)) / base, 4),
                    **info, "exact": True, "sha256": sha256(archive).hexdigest()})
        print(f"  {profile:16} {len(archive):10,} B  {info['key_mode']}/{info['value_mode']}/{info['cache_mode']}", flush=True)
    for profile in ("plain", "structural"):
        c = zlib.compress(packed[profile][0], level=9)
        if unpack(zlib.decompress(c)) != (m, cache):
            raise AssertionError("zlib baseline did not round-trip")
        out.append({"dataset": name, "entries": len(m), "variant": "zlib9/" + profile,
                    "archive_bytes": len(c), "saving_pct": round(100 * (base - len(c)) / base, 4),
                    "exact": True, "sha256": sha256(c).hexdigest()})
        print(f"  {'zlib9/' + profile:16} {len(c):10,} B", flush=True)
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, default=HERE / "results.csv")
    p.add_argument("--tree", type=Path, help="use raw GitHub tree JSON instead of local extracted fixture")
    p.add_argument("--synthetic-only", action="store_true")
    p.add_argument("--tests-only", action="store_true")
    args = p.parse_args()
    print("Checks passed:", json.dumps(tests(), sort_keys=True), flush=True)
    if args.tests_only:
        return
    text, mixed, cache = template_maps()
    sets = [("structured-text", text, None), ("mixed-cache", mixed, cache),
            ("opaque-digest-keys", opaque_map(), None)]
    if not args.synthetic_only:
        sets.append(("cpython-paths", get_cpython(args.tree), None))
    rows = [row for name, m, c in sets for row in evaluate(name, m, c)]
    with args.output.open("w", newline="", encoding="utf-8") as out:
        w = csv.DictWriter(out, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    print(f"Saved {len(rows)} measurements to {args.output.name}.", flush=True)
    n = 65_536
    # Sum of correction terms log2(1 - i/2**256) is negligible here (< 3e-68 bits total).
    print(f"Uniform 256-bit set bound: {256 - math.lgamma(n + 1) / (math.log(2) * n):.8f} bits/key (rounded).")


if __name__ == "__main__":
    main()
