# RSM1 in C++20

The C++ library and CLI read and write the same RSM1 binary format as the Python research implementation. The port includes front coding, byte-pair token training, canonical Huffman coding, minimum-bit token segmentation, Elias–Fano keys, and exact cache regeneration with a raw fallback. The encoder uses no ZIP or DEFLATE library. OpenSSL is used only for the format's SHA-256 predictor.

## Space saved in the C++ run

The raw baseline is `--profile plain`, the same RSM1 envelope with uncompressed field data and shared fixed field widths where applicable. These are **complete archive bytes**, not estimates, and include all dictionaries and framing. This is a static storage comparison, not a RAM measurement of an active `std::unordered_map`.

| Dataset | Rows | Raw bytes | RSM1 bytes | Bytes saved | Saved |
|:--|--:|--:|--:|--:|--:|
| Synthetic structured text | 16,384 | 2,499,309 | 349,196 | 2,150,113 | **86.03%** |
| Synthetic mixed hash cache | 16,384 | 2,275,402 | 726,110 | 1,549,292 | **68.09%** |
| Synthetic opaque digest keys and values | 65,536 | 4,194,325 | 4,079,637 | 114,688 | **2.73%** |
| Real CPython paths → Git blob hashes | 4,882 | 252,092 | 130,748 | 121,344 | **48.13%** |

The port produced **byte-identical archives for all 20 Python/C++ comparisons** (four datasets × five profiles) and recovered the original logical maps when decoding in both directions. The language port did not change the compression ratio. It also passed 12 forced cross-language Elias–Fano cases, native tests for all four cache modes, 96 seeded maps, and checks for truncation and decode limits. `results-cpp.csv` lists the results and SHA-256 checksums. It also reports zlib-level-9 sizes on the structural prepass: RSM1 was smaller on the two structured synthetic datasets, but not on the opaque or CPython datasets.

| Dataset | C++ pack | C++ unpack |
|:--|--:|--:|
| Structured text | 179.2 ms | 30.4 ms |
| Mixed hash cache | 145.1 ms | 34.3 ms |
| Opaque digest keys and values | 136.3 ms | 57.4 ms |
| CPython paths | 32.7 ms | 8.0 ms |

Median wall-clock time of five runs with GCC 14.2 (`-O3`), OpenSSL 3.5.7, and a Linux Xeon sandbox. Includes subprocess startup, reading and writing files, and JSON conversion; excludes dataset generation and parity checks. Timings are environment-specific. The Lean files prove the mathematical core; they do not prove the C++ or Python parser implementations.

## Build and run

Requires a C++20 compiler, Make, and the OpenSSL development libraries (`libssl-dev` on Debian). Python 3.10+ is only required for the benchmark. No Python process is used by the C++ library or CLI.

```sh
make -j2
./build/rsm_cpp pack example.json packed.rsm
./build/rsm_cpp unpack packed.rsm restored.json
cmp example.json restored.json

./build/rsm_cpp pack example.json raw.rsm --profile plain
wc -c raw.rsm packed.rsm

make check         # native tests + exact wire compatibility on example.json
make bench         # regenerates results-cpp.csv; verifies actual bytes in both languages
make sanitize      # repeats native checks with AddressSanitizer and UBSan (Linux)
```

The JSON input is the same hex interchange schema as the Python CLI: `{"cache": false, "entries": [["key_hex", "value_hex"], …]}`. With `cache: true`, put the 32-byte cache value in a third hex string in every row. JSON whitespace, hex case and insertion order are not part of the logical map. The recovered keys and values are byte-exact. The archive does not support in-place updates or lookups without decoding. Use trusted archives; the format has no corruption checksum. The C++ decoder accepts `--max-entries` and `--max-bytes` to set logical decode budgets (defaults: 1,000,000 entries and 1 GiB of key/value/cache payload).

## Use as a library

```cpp
#include "rsm.hpp"

int main() {
    rsm::Map map;
    map.entries.push_back({"device#007", "value=0001", std::nullopt});
    const rsm::Bytes archive = rsm::pack(map);
    const rsm::Map recovered = rsm::unpack(archive);
    return recovered == map ? 0 : 1;
}
```

After `make`, link your program with `c++ -std=c++20 -Icpp my_app.cpp build/librsm1.a -lcrypto -o my_app`. The API accepts keys in any order, rejects duplicates, and returns decoded entries in unsigned-byte lexical order. `rsm::Bytes` is an owning `std::string` used as a byte container, including embedded zeros.
