# hashmap

Fast multi-threaded hash toolkit in pure C. No deps, no libraries — just `cc` and pthreads.

- **digest** — hash strings / files with MD5 / SHA-1 / SHA-256, optional salt (pre or post)
- **brute** — multithreaded MD5 plaintext recovery by pure brute force:
  length ranges, charset presets **and combos**, salted or not, multiple targets in
  one pass, live progress + rate, **resumable state files**
- **map** — build an exhaustive `digest -> plaintext` map file of a keyspace
- **search** — look up hashes in a map file instantly

Built for speed: fully unrolled MD5 transform, single-block fast path with midstate
precomputation when the salt prefix is block-aligned, and one worker thread per core.

## Build

```sh
make            # optimized build (-O3 -march=native -flto)
make portable   # static build for release tarballs
make debug      # ASan + UBSan build
make test       # run the test suite
```

Requires: a C11 compiler (gcc or clang), pthreads. Linux/macOS/BSD.

The build is **strict**: `-Werror` with `-Wall -Wextra -Wpedantic -Wshadow -Wcast-align
-Wstrict-prototypes -Wmissing-prototypes -Wundef -Wformat=2 -Wdouble-promotion
-Wconversion -Wsign-conversion`. It compiles clean under gcc and clang.

## Usage

### digest

```sh
hashmap digest -i hello
# 5d41402abc4b2a76b9719d911017c592

hashmap digest -a md5 -i hello -s pepsi -p pre     # md5("pepsi" .. "hello")
hashmap digest -a md5 -i hello -s pepsi -p post    # md5("hello" .. "pepsi")
hashmap digest -a sha1   -i hello
hashmap digest -a sha256 -i hello

printf 'a\nbb\nccc\n' | hashmap digest -i -        # hash every line, one hash each
hashmap digest -a md5 -f words.txt                 # hash a whole file
```

### brute (MD5)

```sh
# default: digits charset, length 1-6, all cores
hashmap brute -H 52c69e3a57331081823331c4e69d3f2e      # -> 999999

# charset combos: builtin names joined with '+', or literal chars
hashmap brute -H <hash> -c lower+digits               # [a-z0-9]
hashmap brute -H <hash> -c alpha+digits+special
hashmap brute -H <hash> -c "abcXYZ123|"

# length range
hashmap brute -H <hash> -c digits --min 4 --max 8

# salted
hashmap brute -H <hash> -c digits -s mycompany -p pre    # md5("mycompany" .. candidate)
hashmap brute -H <hash> -c digits -s mycompany -p post   # md5(candidate .. "mycompany")

# multiple targets in one pass, results to file
hashmap brute -f targets.txt -c alnum --max 4 -o cracked.txt
```

Exit codes: `0` all targets cracked, `1` exhausted keyspace without a full crack
(or interrupted), `2` usage error.

### map / search

```sh
# build a map of a keyspace (binary, one record per candidate)
hashmap map -o digs.hmmap -c digits --min 1 --max 4

# look hashes up in it
hashmap search -H 202cb962ac59075b964b07152d234b70 digs.hmmap
# 202cb962ac59075b964b07152d234b70:123

hashmap search -f targets.txt digs.hmmap        # many at once
```

Map file format: the header line `HMMAP 1`, then one record per candidate —
`[16B MD5 digest][1B plaintext length][plaintext bytes]`.

## Resume / continue (state files)

Long keyspaces do not fit into one session. `hashmap` saves its exact position
in a state file and continues from there later:

```sh
hashmap brute -H <hash> -c alnum --max 8 --state run.state -t 8
# ^C / SIGTERM / timeout  -> state saved, work not lost

hashmap brute -H <hash> -c alnum --max 8 --state run.state -t 8
# -> "[*] resumed from state", continues where it stopped
```

The state file is written atomically (tmp file + rename) and records the
charset, length range, salt, salt position, targets and the exact remaining
spans of the keyspace. Resuming covers every candidate **exactly once** — no
work is repeated or skipped. A mismatched config is refused; use `--fresh` to
start over. When the whole keyspace is covered the state file is removed
automatically.

## GitHub Actions

| workflow | what it does |
|----------|--------------|
| `ci.yml` | strict build (gcc + clang), test suite, sanitizer build, macOS build |
| `release.yml` | on tag `v*`: builds linux / linux-static / macOS / windows binaries, attaches them to a GitHub release |
| `farm.yml` | a long brute force that **resumes across runs**: each run picks up the state file from the previous run, works for a bounded time, then uploads a fresh state file as an artifact |

The farm workflow runs on a schedule (every 6 hours) or on demand:

```sh
gh workflow run farm.yml -f hash=<md5> -f charset=alnum -f max=7 -f minutes=300
```

Set the repository variable `FARM_HASH` (and optionally `FARM_SALT`) to let the
scheduled runs pick up a target automatically.

## Charsets

| name | chars |
|------|-------|
| `digits` | `0-9` |
| `lower` | `a-z` |
| `upper` | `A-Z` |
| `alpha` | `a-zA-Z` |
| `alnum` | `a-zA-Z0-9` |
| `hexlower` / `hexupper` | `0-9a-f` / `0-9A-F` |
| `special` | ASCII punctuation |
| `all` | alnum + special + space |

Combine any of them with `+` (e.g. `lower+digits`); anything that is not a builtin
name is taken as literal characters.

## Layout

```
src/hashmap.h    shared types + limits
src/util.c       timing, formatting, signal handling
src/charset.c    charset presets and combinations
src/crypto.c     MD5 core, SHA-1, SHA-256
src/engine.c     threaded keyspace walker, state save/load
src/digest.c     digest mode
src/brute.c      brute mode
src/map.c        map mode
src/search.c     search mode
src/main.c       mode dispatch
tests/run.sh     test suite (digest vectors, brute, map/search, resume)
```

## Speed

Scalar C, one thread per core, fully unrolled MD5 core. Rough numbers on a generic
8-core x86-64 box:

```
~7 MH/s per thread, ~56 MH/s with 8 threads (small plaintexts, no salt prefix)
```

When the salt prefix is block-aligned it is folded into an MD5 midstate, so each
candidate costs exactly one 64-byte block transform.

## Legal

For CTFs, own-infrastructure audits, and research. Cracking hashes you have no
authorization for is your own problem — the authors take no responsibility.

## License

MIT — see [LICENSE](LICENSE).
