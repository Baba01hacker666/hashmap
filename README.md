# hashmap

Fast multi-threaded hash toolkit in pure C. No deps, no libraries — just `cc` and pthreads.

- **digest** — hash strings with MD5 / SHA-1 / SHA-256, optional salt (pre or post)
- **brute** — multithreaded MD5 plaintext recovery by pure brute force:
  length ranges (1–6 digits by default), charset presets **and combos**, salted or not,
  multiple targets in one pass, live progress + rate

Built for speed: fully unrolled MD5 transform, single-block fast path with midstate
precomputation when a salt prefix is used, and one worker thread per core.

## Build

```sh
make            # optimized build (-O3 -march=native -flto)
make portable   # no -march=native, for release tarballs
make install PREFIX=/usr/local
```

Requires: a C11 compiler (gcc or clang), pthreads, libm. Linux/macOS/BSD.

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
hashmap digest -a md5 -f words.txt                 # hash each line of a file
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

Exit codes: `0` all targets cracked, `1` exhausted keyspace without full crack
(or interrupted), `2` usage error. Ctrl-C stops cleanly and keeps whatever was found.

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

## Speed

Scalar C, one thread per core, fully unrolled MD5 core. Rough numbers on a generic
8-core x86-64 box:

```
~7 MH/s per thread, ~58 MH/s with 8 threads (small plaintexts, no salt prefix)
```

When a `pre` salt is used, the constant prefix is folded into an MD5 midstate so
each candidate costs exactly one 64-byte block transform.

Roadmap ideas: SIMD (AVX2/NEON 4-way/8-way lanes), GPU offload, more hash algos
in brute mode, dictionary/rules attack.

## Legal

For CTFs, own-infrastructure audits, and research. Cracking hashes you have no
authorization for is your own problem — the authors take no responsibility.

## License

MIT — see [LICENSE](LICENSE).
