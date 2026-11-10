# GitHub Actions workflows

| workflow | trigger | what it does |
|----------|---------|--------------|
| `ci.yml` | push, pull request, manual | strict build with gcc **and** clang, the test suite, an ASan/UBSan build, a macOS build |
| `release.yml` | tag `v*`, manual | builds linux (native + static), macOS and windows binaries and attaches them to a GitHub release |
| `wordlists.yml` | manual, weekly | uses the combined password list from the `wordlists` release (downloads it, does not rebuild it) |
| `lookup.yml` | manual | looks hashes up: password list first, brute force as the fallback — see [lookup.md](lookup.md) |
| `farm.yml` | manual, every 6 hours | a brute force that resumes across runs — see [resume.md](resume.md) |

## Release

```sh
git tag -a v0.3.0 -m "v0.3.0"
git push origin v0.3.0
```

The workflow then builds every platform and publishes the artifacts:

```
hashmap-linux-x86_64.tar.gz
hashmap-linux-x86_64-static.tar.gz
hashmap-macos-arm64.tar.gz
hashmap-windows-x86_64.zip
```

Manual run with an explicit tag:

```sh
gh workflow run release.yml -f tag=v0.3.0
```

## Wordlists

The combined password list lives in the **wordlists** release (SecLists +
RockYou, deduplicated, ~34M candidates, MD5). It is built once and then only
downloaded:

```sh
gh workflow run wordlists.yml -f hashes=<md5hex>
gh release download wordlists --pattern 'combined.txt'
```

The list is never committed to the repository.

## Lookup

```sh
gh workflow run lookup.yml -f hashes=<md5hex> -f store=artifact
```

See [lookup.md](lookup.md).

## Farm

```sh
gh workflow run farm.yml \
  -f hash=202cb962ac59075b964b07152d234b70 \
  -f charset=alnum -f min=1 -f max=7 \
  -f salt= -f saltpos=pre \
  -f minutes=300 -f threads=4
```

Every run:

1. downloads the `farm-state` artifact of the previous run (if any)
2. runs the brute force for `minutes` minutes
3. reports how many candidates were tried, the elapsed time and the average speed
4. uploads the new state file and `found.txt` as the `farm-state` artifact

The scheduled runs use the repository variables `FARM_HASH` and `FARM_SALT`.

## Local check of a workflow

```sh
act -j farm 2>/dev/null || gh workflow run farm.yml -f hash=<md5> -f minutes=2
```
