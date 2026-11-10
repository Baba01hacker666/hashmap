# Lookup workflow

`lookup.yml` cracks hashes the cheap way first and only falls back to brute
force when the cheap stages fail:

1. **prebuilt maps** — the maps from the `maps` release (letters+digits, and
   letters+digits+specials), downloaded on the fly
2. **common passwords** — a wordlist (by default `wordlists/common.txt`)
3. **brute force** — the keyspace, as the last resort; the run is resumable, so
   the `farm` workflow can continue it later

Every stage is skipped when the previous one already solved all hashes.

## Running it

```sh
gh workflow run lookup.yml \
  -f hashes=202cb962ac59075b964b07152d234b70 \
  -f wordlist=wordlists/common.txt \
  -f charset=lower+digits -f min=1 -f max=6 \
  -f stop_first=false \
  -f store=artifact
```

| input | meaning |
|-------|---------|
| `hashes` | the hashes to look up, one md5 hex per line |
| `hash_file` | a file in the repository with hashes |
| `wordlist` | `combined` (from the release), a path, or `none` |
| `charset`, `min`, `max` | keyspace for the brute force fallback |
| `salt`, `saltpos` | salt for all stages |
| `stop_first` | stop as soon as one hash is cracked |
| `brute_minutes` | time budget for the brute force stage |
| `store` | `artifact`, `commit` (into `results/`) or `none` |
| `results_name` | name of the stored results file |

## Storing the results

- `store=artifact` — the cracked hashes are uploaded as the `lookup-results`
  artifact (also the unresolved hash list, so the run can be repeated)
- `store=commit` — the results are committed to `results/<results_name>` in
  the repository, so they accumulate over time
- `store=none` — nothing is kept

Whatever the stage, the cracked pairs are written as `<hash>:<plaintext>`.

## The stages in detail

### 1. the combined password list

```sh
gh release download wordlists --pattern 'combined.txt' --dir .
hashmap wordlist -F hashes.txt -w combined.txt -o hits-wordlist.txt
```

The list is built once by the `wordlists` workflow and then only downloaded.
If it is not published yet, the workflow builds the fast profile once.

The `wordlist` mode hashes every candidate of the list (one thread per core,
salted or not) and compares it against the targets — much cheaper than a
keyspace search, and it covers passwords that contain characters no map has.

### 2. brute force

```sh
hashmap brute -F hashes.txt -c lower+digits --min 1 --max 6 \
    --state lookup/brute.state -o hits-brute.txt
```

The state file makes this stage resumable: if the time budget runs out, the
`farm` workflow picks the state up and continues it in the next run.

## Doing it by hand

The same three stages work locally, without the workflow:

```sh
hashmap wordlist -H <md5hex> -w wordlists/combined.txt
hashmap brute -H <md5hex> -c alnum --max 6 --state run.state
```
