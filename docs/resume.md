# Resume and state files

A keyspace of 10^12 candidates does not fit into one session. `hashmap` keeps
its exact position in a **state file** and continues from there later.

```sh
hashmap brute -H <hash> -c alnum --max 8 --state run.state
# ^C, SIGTERM, or a timeout  ->  state saved

hashmap brute -H <hash> -c alnum --max 8 --state run.state
# [*] brute mode (resumed from state)  ->  continues where it stopped
```

## What is saved

The state file (`HMSTATE 2`, plain text) holds:

- the mode, charset, length range, salt and salt position
- the target hashes
- for every candidate length, the **spans of the keyspace that are still
  unfinished** (as `lo hi` ordinal pairs)

It is written atomically: a temporary file plus `rename()`, so a crash can
never leave a half-written state behind.

## Exactness

Resuming covers every candidate **exactly once** — nothing is repeated and
nothing is skipped. The engine splits each length's keyspace into spans, hands
them to the workers, and on stop records the unfinished tail of every in-flight
span. A run interrupted three times and resumed three times tries exactly as
many candidates as an uninterrupted run.

## Rules

- the state file is only used when the configuration matches (same charset,
  lengths, salt, targets) — a mismatch is refused
- `--fresh` deletes the state file and starts over
- when the keyspace is exhausted the state file is removed automatically
- `map` mode resumes by **appending** to the map file, so the records already
  written stay intact

## The farm workflow

`farm.yml` turns this into a job that keeps grinding across GitHub Actions
runs: each run picks up the state file from the previous run, works for a
bounded time and uploads a fresh state file as an artifact.

```sh
gh workflow run farm.yml -f hash=<md5> -f charset=alnum -f max=7 -f minutes=300
```

It also runs on a schedule every 6 hours; set the repository variable
`FARM_HASH` (and optionally `FARM_SALT`) for that.

See [workflows.md](workflows.md) for the details.
