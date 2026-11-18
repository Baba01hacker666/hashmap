"""Benchmark the C++ RSM1 port and verify bidirectional Python interoperability."""
from __future__ import annotations

import argparse
import csv
from hashlib import sha256
from pathlib import Path
from statistics import median
import subprocess
import tempfile
from time import perf_counter_ns
import zlib

from bench import get_cpython, opaque_map, template_maps
from rsm import (Candidates, MAGIC, PROFILES, elias, frame, lane_candidates, pack, read_json,
                 unpack, uv, write_json)

ROOT = Path(__file__).resolve().parent


def run(exe: Path, *args) -> float:
    start = perf_counter_ns()
    subprocess.run([exe, *args], check=True)
    return (perf_counter_ns() - start) / 1_000_000


def compare_dataset(exe: Path, work: Path, dataset: str, mapping, cache,
                    reference: dict, trials: int) -> dict:
    source, archive, recovered = (work / name for name in ("input.json", "archive.rsm", "restored.json"))
    py_file = work / "from-python.rsm"
    write_json(source, mapping, cache)
    cpp_archives = {}
    sizes = {}
    variants = Candidates(mapping, cache)
    for profile in (*PROFILES, "refit"):
        if profile == "refit":
            expected = pack(mapping, cache, refit=True)
            assert len(expected) <= sizes["rsm"], (dataset, "refit size regression")
        else:
            expected, _ = variants.archive(profile)
            assert sha256(expected).hexdigest() == reference[dataset, profile]["sha256"], (dataset, profile, "reference")
        run(exe, "pack", source, archive, "--profile", profile)
        actual = archive.read_bytes()
        assert actual == expected, (dataset, profile, "Python/C++ archive mismatch")
        assert unpack(actual) == (mapping, cache), (dataset, profile, "C++ → Python")
        py_file.write_bytes(expected)
        run(exe, "unpack", py_file, recovered)
        assert read_json(recovered) == (mapping, cache), (dataset, profile, "Python → C++")
        cpp_archives[profile] = actual
        sizes[profile] = len(actual)

    encode_ms = round(median(run(exe, "pack", source, archive) for _ in range(trials)), 3)
    assert archive.read_bytes() == cpp_archives["rsm"]
    decode_ms = round(median(run(exe, "unpack", archive, recovered) for _ in range(trials)), 3)
    assert read_json(recovered) == (mapping, cache)
    saved = sizes["plain"] - sizes["rsm"]
    return {"dataset": dataset, "entries": len(mapping), "plain_bytes": sizes["plain"],
            "structural_bytes": sizes["structural"], "byte_huff_bytes": sizes["byte-huff"],
            "greedy_bytes": sizes["greedy"], "rsm_bytes": sizes["rsm"], "refit_bytes": sizes["refit"], "saved_bytes": saved,
            "saved_pct": round(100 * saved / sizes["plain"], 4),
            "zlib9_structural_bytes": len(zlib.compress(cpp_archives["structural"], level=9)),
            "cpp_pack_ms_median": encode_ms, "cpp_unpack_ms_median": decode_ms,
            "timing_trials": trials, "exact_profile_matches": len(sizes),
            "rsm_sha256": sha256(cpp_archives["rsm"]).hexdigest()}


def cross_edge_cases(exe: Path, work: Path) -> int:
    """Exercise Elias–Fano decoding even when another key mode would win."""
    input_path, output = work / "ef-forced.rsm", work / "ef-out.json"
    cases = 0
    for width in [1, 2, 8, 16, 32, 64]:
        for ints in ((0, 1, 3, 17), (0, 1, 3, (1 << (8 * width)) - 1)):
            keys = [i.to_bytes(width, "big") for i in ints]
            value = [bytes([i, 255 - i]) for i in range(len(keys))]
            # Use the Python reference to force an EF lane into an otherwise
            # ordinary RSM1 envelope; no dependence on its adaptive selector.
            b = MAGIC + b"\0" + uv(len(keys)) + frame(elias(keys)) + frame(lane_candidates(value)["raw"])
            input_path.write_bytes(b)
            run(exe, "unpack", input_path, output)
            assert read_json(output) == (dict(zip(keys, value)), None)
            cases += 1
    return cases


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe", type=Path, default=ROOT / "build" / "rsm_cpp")
    p.add_argument("--trials", type=int, default=5)
    p.add_argument("--output", type=Path, default=ROOT / "results-cpp.csv")
    args = p.parse_args()
    if args.trials < 1:
        p.error("--trials must be positive")
    exe = args.exe.resolve()
    if not exe.is_file():
        p.error(f"{exe} not found; run make first")
    with (ROOT / "results.csv").open(newline="", encoding="utf-8") as f:
        reference = {(r["dataset"], r["variant"]): r for r in csv.DictReader(f)}
    text, mixed, cache = template_maps()
    datasets = [("structured-text", text, None), ("mixed-cache", mixed, cache),
                ("opaque-digest-keys", opaque_map(), None), ("cpython-paths", get_cpython(None), None)]
    with tempfile.TemporaryDirectory(prefix="rsm-cpp-") as d:
        work = Path(d)
        rows = []
        for name, m, c in datasets:
            row = compare_dataset(exe, work, name, m, c, reference, args.trials)
            rows.append(row)
            print(f"{name}: {row['plain_bytes']:,} → {row['rsm_bytes']:,} bytes; "
                  f"saved {row['saved_bytes']:,} ({row['saved_pct']:.2f}%); "
                  f"median {row['cpp_pack_ms_median']:.1f} ms pack / {row['cpp_unpack_ms_median']:.1f} ms unpack",
                  flush=True)
        corners = cross_edge_cases(exe, work)
    with args.output.open("w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"PASS: {sum(r['exact_profile_matches'] for r in rows)} byte-identical Python/C++ archives; "
          f"all round-tripped in both directions; {corners} extra forced Elias-Fano cases.")


if __name__ == "__main__":
    main()
