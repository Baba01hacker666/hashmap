# hashmap

Fast multi-threaded hash toolkit in pure C — no deps, just `cc` and pthreads.

- **digest** — hash a string or a file (MD5 / SHA-1 / SHA-256, salted or not)
- **brute** — crack MD5 hashes by brute force, over any charset and length range
- **map** — build an exhaustive `digest -> plaintext` map file of a keyspace
- **search** — look hashes up inside a map file

Every long run is **resumable**: stop it, and it continues exactly where it
left off — no candidate is ever tried twice or skipped.

## Build

```sh
make            # -O3 -march=native -flto, strict warnings as errors
make portable   # static binary for release tarballs
make debug      # ASan + UBSan build
make test       # run the test suite
```

Requires a C11 compiler (gcc or clang) and pthreads.

## Quick start

```sh
hashmap digest -i hello
# 5d41402abc4b2a76b9719d911017c592

hashmap brute -H 202cb962ac59075b964b07152d234b70
# [+] CRACKED  202cb962ac59075b964b07152d234b70  ->  123  (len 3)

hashmap map -o digs.hmmap -c digits --max 4
hashmap search -H 202cb962ac59075b964b07152d234b70 digs.hmmap
# 202cb962ac59075b964b07152d234b70:123
```

Pause and continue a long run:

```sh
hashmap brute -H <hash> -c alnum --max 8 --state run.state
hashmap brute -H <hash> -c alnum --max 8 --state run.state   # resumes
```

Exit codes: `0` done, `1` not solved / interrupted, `2` usage error.

## Documentation

| file | topic |
|------|-------|
| [docs/usage.md](docs/usage.md) | every mode and flag, charsets, map file format |
| [docs/maps.md](docs/maps.md) | prebuilt maps, how to build and use them |
| [docs/resume.md](docs/resume.md) | state files, exact resume, the farm workflow |
| [docs/workflows.md](docs/workflows.md) | CI, release artifacts, running the farm |
| [docs/development.md](docs/development.md) | source layout, build targets, tests, hooks |

## Legal

For CTFs, own-infrastructure audits, and research. Cracking hashes you have no
authorization for is your own problem — the authors take no responsibility.

## License

MIT — see [LICENSE](LICENSE).
