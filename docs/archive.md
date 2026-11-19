# Archiving a finished map

`hashmap-archive` compresses an existing HMMAP 1 or 2 file **without truncating it**. Restoring yields the original header and record bytes, in order. Duplicate strings, duplicate digests, conflicting rows, embedded NULs and already-truncated fields survive. Use a finished file or a stable snapshot; the archive is not an appendable map or an index.

```sh
make hashmap-archive                         # Python 3.10+; standard library only
./hashmap-archive pack assets.hmmap assets.hmar
./hashmap-archive unpack assets.hmar restored.hmmap
cmp assets.hmmap restored.hmmap
```

The executable can be copied by itself to another machine with Python, or installed with `make install-archive`. In the checkout, `python3 hmarchive.py ...` works without a build. The default build and the C binary do not need Python.

## Searching an archive without restoring it

`hashmap search` recognises the HMARCH1/HMARCH2 magic and decodes the groups
in place, so the compressed maps in the `maps` release work as they are:

```sh
hashmap search -H 5f4dcc3b5aa765d61d8327deb882cf99 wordlist-map.hmar
hashmap search -H <sha256hex> wordlist-map-sha256.hmar
hashmap search -F targets.txt /path/to/maps/
```

`.hmmap` and `.hmar` files can be mixed in one call or one directory. The
streamed SHA-256 is verified; a damaged, truncated or unsupported archive is
an error, never a silent empty result. `unpack` is still the way to get a
byte-exact file for tools that need one.

Archives are decoded by several workers at once. `-t/--threads` controls how
many (default: all cores) and `--no-verify` skips the checksum pass, which is
the fastest mode because the SHA-256 stream is the only part that cannot run
in parallel:

```sh
hashmap search -t 8 -H <hex> wordlist-map.hmar           # parallel, checked
hashmap search -t 8 --no-verify -H <hex> wordlist-map.hmar  # parallel, fastest
```

Groups are handed to the workers in an interleaved order and re-hashed in
original order through a small ring buffer, so the checksum still covers the
same bytes in the same sequence. HMARCH1 archives fall back to a single
walker automatically.

The reader handles predicted digests, literal digest lanes, subblock lanes
and digest tables. An archive whose encoder chose **ranked digest
exceptions** is rejected with a message that asks for an unpack: that lane
can only occur when a stored digest is not the map algorithm's digest of its
key, which the `map` mode never produces. For MD5/SHA-1/SHA-256 maps the
search recomputes the digest from the decoded plaintext; bcrypt maps store
their literal 23-byte digests. The compared bytes are the ones `unpack`
would restore.

`hashmap map --archive` packs a map through this companion the moment the
keyspace finishes (see [usage](usage.md#archiving-the-map---archive)) — the
C tool writes the plain map to a staging file, the companion publishes the
HMARCH2 destination, and the plain map is removed.

`pack` writes **HMARCH2**. `unpack` detects HMARCH1 and HMARCH2; use `pack --legacy` for a recipient with only the original HMARCH1 decoder. Destinations must not exist. Output is staged in the destination directory and published by hard link only on success, so a bad checksum, truncated input or concurrently created destination does not publish a partial restore or clobber a file. This requires a filesystem with hard-link support. SHA-256 checks the restored bytes; it does not authenticate the sender.

## How much smaller?

`make archive-compare` encodes the same ordered inputs with both versions, restores them and compares **every byte**. The first four cases are the original [HMARCH1 experiment](../research/map_archive/README.md). The repeated-value case keeps the same opaque keys and order as the all-miss control and uses four distinct digest values. The last row uses the 4,882 paths and binary Git blob IDs from [RSM1's checked-in CPython fixture](../research/rsm1/README.md), not hashes of the paths.

| Input | HMMAP | HMARCH1 | HMARCH2 | Smaller than HMARCH1 | zlib-9 on HMARCH1 |
|---|---:|---:|---:|---:|---:|
| Ordered asset labels, all predicted | 204,828 | 13,948 | 3,329 | 76.13% | 656 |
| Opaque IDs, all predicted | 204,828 | 73,925 | 69,745 | 5.65% | 72,854 |
| Same IDs, one miss per 64 rows | 204,828 | 76,037 | 71,921 | 5.41% | 74,984 |
| Same IDs, all misses | 204,828 | 204,997 | 200,817 | 2.04% | 204,775 |
| Same IDs, four repeating opaque values | 204,828 | 204,997 | 71,289 | 65.22% | 73,949 |
| One opaque row | 78 | 121 | 121 | 0.00% | 132 |
| CPython paths → blob IDs | 252,707 | 161,449 | 129,774 | 19.62% | 129,824 |

These are **complete file sizes in bytes**, not lookup speeds, RAM usage or a universal advantage over DEFLATE. Token training trades packing time for space. In particular DEFLATE after HMARCH1 does better on the sequential labels. The bare default RSM1 encoding of the CPython map is 130,748 bytes (130,703 with `--refit`); it lacks the HMMAP header and checksum. It can reproduce the rows of *this* file given its header because its keys already happen to be sorted and unique. It is not a byte-exact substitute for archiving arbitrary HMMAP files.

## How the two codecs fit together

* **Strings:** Keep at most 1,024 rows per group. Try an [RSM1 field lane](../research/rsm1/FORMAT.md) on the strings in input order: compact field lengths, then raw bytes or byte/token Huffman codes. Also try storing the first key separately and coding the following suffixes. With a known suffix length, either the copied prefix length **or the original key length** determines the split; encode whichever length vector costs less. Keeping the first string outside these vectors avoids a long first suffix widening every offset. Elias–Fano is eligible only for *already* strictly increasing fixed-width keys; no sort or permutation is hidden in the comparison.
* **Digests:** Reuse HMARCH1's exact prediction and exception ranking in 64-row subblocks. A match is tested on every stored byte. MD5/SHA-1/SHA-256 use the stored key bytes and stored width; missing parameters can cause misses, never silent substitution. Bcrypt is always opaque. For repeated opaque values, also price a local table of literal digests. Its indices can be dense, or first occurrences can be implicit with references only for repeats.
* **Fallback:** Compare the entire framed group with the exact HMARCH1 blocks over those same rows; ties keep HMARCH1 blocks. Since 1,024 is a multiple of 64 and both file envelopes have the same size, **this encoder cannot exceed the HMARCH1 encoder on any supported input**. The bound versus the *input* is `input bytes + 41 + 2·ceil(rows/64)`; tiny inputs can grow. The old Lean results concern the modeled component algorithms, not this container or its I/O. `make archive-test` checks implementations and malformed inputs separately.

### HMARCH2 wire layout

```
"HMARCH2\n", original HMMAP header bytes
zero or more: HMARCH1 block | extended group
u8 0, SHA-256(original HMMAP byte stream) [32 bytes], EOF

extended group: u8 127, u16be n, u32be key_frame_bytes, key_frame, digest_lane
```

All ordinary blocks, headers and the terminator are as in [HMARCH1](../research/map_archive/README.md#hmarch1-wire-layout). Tag 127 is not a legal HMARCH1 block size. Extended groups require `1 ≤ n ≤ 1024` and `1 ≤ key_frame_bytes ≤ 4 + 257n` (the raw lane bound). Keys and reconstructed fields are at most 255 bytes. Invalid lengths, unknown modes, bad padding, dangling indices, truncation and trailing data are errors. Resource limits are per group, not a cap on the size of an entire restore.

**Key frame:** RSM1 shapes, field lanes and bit order are defined in [FORMAT.md](../research/rsm1/FORMAT.md). Tag `0` precedes one field lane of `n` strings. Tag `2` is the complete RSM1 Elias–Fano key frame (including that tag). Tags `1` and `3` require `n ≥ 2`: read `[u8 length][first key]`, a shape of `n−1` integers and a field lane of `n−1` suffixes. For tag `1` the integer is the prefix length `p`; for tag `3`, `p = integer − len(suffix)`. Require `0 ≤ p ≤ len(previous)` and emit `previous[:p] + suffix`. All modes consume the entire frame.

**Digest lane:** Let `d` be the width from the original header.

| Tag | Payload |
|---:|---|
| 0 | No bytes: all `n` digests are predicted. Invalid for bcrypt. |
| 255 | `n·d` literal bytes in row order. |
| 254 | For each successive slice of up to 64 keys: one HMARCH1 digest mode byte then its literal or ranked payload. |
| 253 | `u16be c` (`1 ≤ c ≤ n`), `c` literal digests of `d` bytes each in first-occurrence order, then table references as below. |

For tag 253 let `b = bit_length(c−1)`. Dense indices cost `ceil(nb/8)` bytes. The alternative costs `ceil(n/8) + ceil((n−c)b/8)`: a bitmap (least-significant bit first in each byte) followed by indices **only** for set bits. A clear bit consumes the next new table entry; a set bit must refer to an entry already seen. Exactly `c` new entries must be consumed. Use the bitmap only when strictly cheaper, so no extra mode tag is needed. Indices are `b` bits each, most significant bit first, and must be `< c`. All padding is zero. A single-entry table needs no index bits.
