# Development

## Layout

```
src/hashmap.h    shared types, limits, mode entry points
src/compat.h     platform feature-test macros (include it first)
src/util.c       timing, formatting, signals, portable getopt_long
src/charset.c    charset presets, unions, escapes
src/cpu.c        runtime CPU feature detection and SIMD autotuning
src/accelerator.c best-effort accelerator device detection
src/crypto.c     MD5 core, SHA-1, SHA-256 and SIMD kernels
src/match.c      exact multi-target digest index
src/engine.c     threaded keyspace walker, state save/load
src/digest.c     digest mode
src/brute.c      brute mode
src/map.c        map mode
src/hmar.c       streaming HMARCH1/HMARCH2 archive decoder for search
src/search.c     search mode
src/main.c       mode dispatch and usage texts
tests/run.sh     CLI test suite
tests/core.c     differential SIMD and matcher tests
docs/            the documentation you are reading
```

## Build targets

| target | what it does |
|--------|--------------|
| `make` | optimized build (`-O3 -flto`, runtime SIMD dispatch) |
| `make portable` | static binary, no `-march=native` (release artifacts) |
| `make debug` | ASan + UBSan build |
| `make test` | run the C test suite |
| `make hashmap-archive` / `make install-archive` | build / install the optional Python 3.10+ map archive companion |
| `make archive-test` | archive math, wire, round-trip, compatibility and CLI tests |
| `make archive-compare` | compare complete HMARCH1 / HMARCH2 sizes on the same ordered inputs |
| `make evil-test` / `make evil-compare` | EVIL nibble-codec research: strictness tests / measured ceiling vs the adaptive codecs |
| `make install` | install to `$PREFIX/bin` (default `/usr/local`) |
| `make install-hooks` | enable the co-author guard hooks for this clone |

The build is strict: `-Werror` plus `-Wall -Wextra -Wpedantic -Wshadow
-Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wundef -Wformat=2
-Wdouble-promotion -Wconversion -Wsign-conversion`. It has to stay clean under
both gcc and clang.

## Tests

```sh
make test
./tests/run.sh ./hashmap-debug      # same suite under the sanitizer build
```

The suite covers the digest vectors against `md5sum`/`sha1sum`/`sha256sum`,
brute hits and misses, salted modes, the map → search roundtrip, the state
file lifecycle and the CLI surface.

## No GNU extensions

The CLI uses its own `getopt_long` implementation (`src/util.c`) so the tool
builds with a plain C11 compiler everywhere — no `_GNU_SOURCE`, no glibc
extensions. The same goes for the platform shims (`hm_sleep_ms`, `hm_fsync`,
`hm_cpu_count`, the `signal()` fallback on Windows).

## Commit hygiene

`Co-Authored-By:` trailers are not accepted in this repository. Enable the
guard for your clone:

```sh
make install-hooks
```

It installs `.githooks/commit-msg` and `.githooks/prepare-commit-msg`, which
reject any commit message containing a co-author trailer or an AI-assistant
attribution trailer.
