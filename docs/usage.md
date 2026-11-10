# CLI reference

```
hashmap <mode> [options]
```

| mode | what it does |
|------|--------------|
| `digest` | hash a string or a file |
| `brute` | crack MD5 hashes by brute force over a keyspace |
| `map` | write a `digest -> plaintext` map file for a whole keyspace |
| `search` | look hashes up inside a map file |
| `wordlist` | match target hashes against a wordlist |

`hashmap --help` shows the mode list and the shared flags,
`hashmap <mode> --help` shows everything that mode accepts.

## Shared flags

The same flag means the same thing in every mode.

| flag | meaning |
|------|---------|
| `-H, --hash <md5hex>` | a hash value (repeatable) |
| `-F, --hash-file <file>` | file of hashes, one per line (`#` starts a comment) |
| `-o, --out <file>` | output file |
| `-c, --charset <spec>` | charset, repeatable — the specs are unioned |
| `--min <n>` / `--max <n>` | candidate length range (default 1 – 6) |
| `-t, --threads <n>` | worker threads (default: all cores) |
| `-s, --salt <string>` | salt applied to every candidate |
| `-p, --salt-pos <pre\|post>` | salt placement (default: `pre`) |
| `--state <file>` | state file: pause/resume a long run |
| `--fresh` | ignore and delete an existing state file |
| `-h, --help` / `-v, --version` | help / version |

Long options accept both `--max 6` and `--max=6`.

## digest

```sh
hashmap digest -i hello
hashmap digest -a sha256 -i hello
hashmap digest -a md5 -i hello -s pepsi -p post   # md5("hello".."pepsi")
hashmap digest -f data.bin                        # hash a whole file
printf 'a\nb\n' | hashmap digest -i -             # hash every stdin line
```

| flag | meaning |
|------|---------|
| `-a, --algo <md5\|sha1\|sha256>` | algorithm (default `md5`) |
| `-i, --input <string>` | string to hash (`-` = stdin lines) |
| `-f, --file <file>` | hash the whole file |

Output is one hex digest per line (for stdin mode: `<digest>:<line>`).

## brute

```sh
hashmap brute -H 202cb962ac59075b964b07152d234b70
hashmap brute -H <hash> -c lower+digits --max 6 -t 8
hashmap brute -F targets.txt -c alnum --max 5
hashmap brute -H <hash> -s mycompany -p pre
hashmap brute -H <hash> -c digits --max 8 --state run.state
hashmap brute -H <hash> -o cracked.txt
```

The result line looks like:

```
[+] CRACKED  202cb962ac59075b964b07152d234b70  ->  123  (len 3)
```

With `-o` the same result is appended to the file as `<hash>:<plaintext>`.

## map

```sh
hashmap map -o digs.hmmap -c digits --min 1 --max 4
hashmap map -o digs.hmmap -c alnum --max 5 --state map.state
```

Writes one record per candidate:

```
"HMMAP 1\n"                       header
[16B MD5 digest][1B length][plaintext bytes]   repeated
```

The file can be searched later with `hashmap search`. A map run is resumable:
when a state file exists the map is **appended** to, so an interrupted map can
be continued without losing the records already written.

## search

```sh
hashmap search -H 202cb962ac59075b964b07152d234b70 digs.hmmap
hashmap search -F targets.txt digs.hmmap
hashmap search -H <md5hex> *.hmmap            # several shards
hashmap search -H <md5hex> /path/to/maps/     # every *.hmmap in a directory
```

Prints `<hash>:<plaintext>` for every hash found in the map. Exit code `1` if
some hash was not found. Scanning stops as soon as all requested hashes were
found, so a directory of shards is cheap when the answer is in an early one.

## wordlist

```sh
hashmap wordlist -H <md5hex> -w wordlists/common.txt
hashmap wordlist -F targets.txt -w big.txt -o cracked.txt --first
```

| flag | meaning |
|------|---------|
| `-w, --wordlist <file>` | wordlist, one candidate per line |
| `-o, --out <file>` | append the cracked results to this file |
| `-s, --salt <string>` | salt applied to every candidate |
| `-p, --salt-pos <pre\|post>` | salt placement (default `pre`) |
| `-t, --threads <n>` | worker threads (default: all cores) |
| `-f, --first` | stop at the first hit |

Exit code `0` when every target was found (`--first`: when one was).

A small list of the most common passwords ships with the tool:
`wordlists/common.txt`. The big list (SecLists + RockYou, deduplicated, ~34M
candidates) is fetched with `make wordlist-full` — see
[wordlists.md](wordlists.md).

## --first

`brute` and `wordlist` accept `--first`: they stop at the first hit instead
of waiting for every target, and exit `0` as soon as something was found.

## Charsets

| name | characters |
|------|------------|
| `digits` | `0-9` |
| `lower` | `a-z` |
| `upper` | `A-Z` |
| `alpha` | `a-zA-Z` |
| `alnum`, `default` | `a-zA-Z0-9` |
| `hexlower`, `hexupper` | `0-9a-f`, `0-9A-F` |
| `special`, `symbols` | ASCII punctuation — includes `@` and `!` |
| `all`, `full` | alnum + punctuation + space (95 characters) |

```sh
-c lower+digits      # join presets with '+'
-c lower -c digits   # repeat the flag - the specs are unioned
-c 'a\@b\!c'         # literal characters, '\' escapes the next one
```

Anything that is not a builtin name is taken literally. Duplicate characters are
removed automatically, so the keyspace is never inflated.
