# Prebuilt maps

A **map** is a file with every candidate of a keyspace together with its MD5
digest. Once it exists, looking a hash up is a file scan instead of a brute
force — instant, and reusable for any number of hashes.

```sh
hashmap map -o digs.hmmap -c alnum --min 1 --max 4
hashmap search -H <md5hex> digs.hmmap
```

## Ready-to-download maps

The `maps` workflow builds these and attaches them to the **maps** release of
the repository, so they can be downloaded and used directly:

| file | charset | lengths | candidates | size |
|------|---------|---------|------------|------|
| `alnum-1-4.hmmap` | letters + digits (`Aa1…Zz9`) | 1 – 4 | 15,018,570 | ~300 MB |
| `full-l1.hmmap` | letters + digits + specials | 1 | 95 | tiny |
| `full-l2.hmmap` | letters + digits + specials | 2 | 9,025 | tiny |
| `full-l3.hmmap` | letters + digits + specials | 3 | 857,375 | ~18 MB |
| `full-l4.hmmap` | letters + digits + specials | 4 | 81,450,625 | ~1.5 GB |

The big map is split per length so every file stays below the 2 GB asset limit.

```sh
gh release download maps --repo Baba01hacker666/hashmap
ls -lh *.hmmap
```

## Using them

```sh
hashmap search -H 202cb962ac59075b964b07152d234b70 alnum-1-4.hmmap
# 202cb962ac59075b964b07152d234b70:123

hashmap search -H <md5hex> *.hmmap          # several shards
hashmap search -H <md5hex> /path/to/maps/   # a whole directory
hashmap search -F targets.txt /path/to/maps/   # many hashes at once
```

`search` stops as soon as every requested hash was found, so scanning a
directory of shards is cheap when the answer sits in an early shard.

## Building your own

```sh
hashmap map -o my.hmmap -c lower+digits --min 4 --max 6 -t "$(nproc)"
```

Threads default to the number of cores; `-t` overrides it. The map run is
resumable like any other long run — with a state file it **appends** to the
existing map instead of rewriting it, so an interrupted build can be continued
without losing records.

## How far it goes

Size grows with `charset^length`, so the reachable sets are:

| charset | lengths 1-4 | lengths 1-5 | lengths 1-6 | lengths 1-8 |
|---------|-------------|-------------|-------------|-------------|
| digits (10) | 227 KB | 2.3 MB | 24 MB | 2.6 GB |
| alnum (62) | 300 MB | 19 GB | 1.2 TB | 5 PB |
| full (95) | 1.6 GB | 160 GB | 15 TB | 152 PB |

Length 10 with the full charset is 6·10^19 candidates — not physically
buildable, not on any hardware. The practical sweet spots are the ones above:
letters+digits up to length 4-5, or the full character set up to length 4.
