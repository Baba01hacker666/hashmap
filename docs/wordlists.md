# Wordlists

The `wordlist` mode cracks a hash by hashing the candidates of a list instead
of walking a keyspace. For real-world passwords that is far cheaper than brute
force — and it covers passwords that no charset map would contain.

```sh
hashmap wordlist -H <md5hex> -w wordlists/common.txt
hashmap wordlist -F targets.txt -w combined.txt -o cracked.txt --first
```

## Getting the lists

The repository ships a small list (`wordlists/common.txt`, ~1,800 entries) for
a quick offline check. The real lists are **fetched, not committed** — the repo
stays small and the lists stay current:

```sh
make wordlist       # top lists only, ~4.6M candidates, ~12 s
make wordlist-full  # everything incl. RockYou, ~34M candidates, ~75 s
```

or directly:

```sh
tools/fetch-wordlists.sh --fast --out wordlists/combined.txt
tools/fetch-wordlists.sh --full --out wordlists/combined.txt
```

The script downloads from [SecLists](https://github.com/danielmiessler/SecLists)
(MIT) and combines:

| source | content |
|--------|---------|
| `rockyou.txt.tar.gz` | RockYou — the classic leak list (~14M) |
| `xato-net-10-million-passwords.txt` | xato's 10M list |
| `Pwdb_top-10000000.txt` | Pwdb top 10M |
| `darkc0de.txt`, `openwall.net-all.txt` | large community lists |
| `myspace`, `phpbb`, `honeynet`, `000webhost`, `md5decryptor`, … | per-site leaks |
| `10k/100k-most-common`, `probable-v2`, `1900-2020`, `months`, `seasons` | the usual suspects |

Everything is merged, CR-stripped, emptied lines dropped and **deduplicated
byte-exactly** (`LC_ALL=C sort -u`), so no candidate is hashed twice:

```
raw lines       : 43861164
unique lines    : 34008124
removed dupes   : 9853040
output          : wordlists/combined.txt (323M)
```

Downloads are cached in `~/.cache/hashmap/wordlists`, so a second run only
re-combines. Use `--no-cache` to clean up, `--cache <dir>` to move the cache.

## Speed

The wordlist mode uses one thread per core and hashes the candidates in
blocks:

```
$ time hashmap wordlist -H <md5 of 'princess'> -w wordlists/combined.txt -t 8
[+] CRACKED  8afa847f50a716e64932d995c8e7435a  ->  princess
real  0m1.496s
```

~22M candidates per second on 8 cores — the full 34M list is scanned in about
a second and a half.

## The workflow

`wordlists.yml` builds the combined list on GitHub's runners, optionally uses
it for a quick lookup, and attaches it to the **wordlists** release:

```sh
gh workflow run wordlists.yml -f profile=full -f hashes=<md5hex>
```

The combined list is also available in the `lookup` workflow by passing
`-f wordlist=combined` — it then builds the list itself before trying it.
