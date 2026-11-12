# hashmap

Fast multi-threaded hash toolkit in pure C — no deps, just `cc` and pthreads.

- **digest** — hash a string or a file (MD5 / SHA-1 / SHA-256, salted or not)
- **brute** — crack MD5 hashes by brute force, over any charset and length range
- **map** — build a `digest -> plaintext` map of a keyspace
- **search** — look hashes up inside a map file
- **wordlist** — match target hashes against a password list (MD5, SHA-256, bcrypt)

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

hashmap search -H 202cb962ac59075b964b07152d234b70 digs.hmmap
# 202cb962ac59075b964b07152d234b70:123
```

Crack a hash against the combined password list (34M candidates, ~1.5 s):

```sh
make wordlist-full                        # fetch + dedupe SecLists & RockYou
hashmap wordlist -H <md5hex> -w wordlists/combined.txt
```

The big list is never committed — it is fetched once and kept in the cloud
(the `wordlists` release), together with its **hashmaps** (every candidate with
its MD5 and SHA-256 digest, `maps` release). The workflows download them
instead of rebuilding them.

MD5, SHA-256 and bcrypt all work — the algorithm follows the hash you give
(32 hex chars = MD5, 64 = SHA-256, `$2b$...` = bcrypt):

```sh
hashmap brute -H <sha256hex> -c alnum --max 6
hashmap search -H <sha256hex> wordlist-map-sha256.hmmap
```

bcrypt carries its own salt, so it needs a fixed salt to be precomputed into
a map — see [docs/bcrypt.md](docs/bcrypt.md):

```sh
hashmap wordlist -H '$2b$12$...' -w wordlists/combined.txt
hashmap map -o bcrypt.hmmap --wordlist wordlists/combined.txt \
    --bcrypt --salt DCq7YPn5Rq63x1Lad4cll. --bcrypt-cost 12
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
| [docs/lookup.md](docs/lookup.md) | the lookup workflow: password list → brute force |
| [docs/wordlists.md](docs/wordlists.md) | the combined password list (SecLists + RockYou) |
| [docs/bcrypt.md](docs/bcrypt.md) | bcrypt: verification, and the fixed salt hashmap |
| [docs/resume.md](docs/resume.md) | state files, exact resume, the farm workflow |
| [docs/workflows.md](docs/workflows.md) | CI, release artifacts, running the farm |
| [docs/development.md](docs/development.md) | source layout, build targets, tests, hooks |

## Legal

For CTFs, own-infrastructure audits, and research. Cracking hashes you have no
authorization for is your own problem — the authors take no responsibility.

## License

MIT — see [LICENSE](LICENSE).
