# Compress the relationship, not the hashes

A map row stores both a byte string `x` and a digest `a`. Even if every row is unique, once `x` is known there may be **only one possible value** for `a`. Store `x` and encode only what the prediction `F(x)` gets wrong. Unpacking recovers the original byte stream, not just an equivalent set of entries. Two rows with the same digest, two different digests for one string, repeated rows and their order all survive.

This is an experimental **archive**, not a new lookup table. It operates on an existing file and doesn't change the C tools. No external dictionary, original wordlist, sorting, ZIP or digest truncation is involved.

This page describes **HMARCH1**, which remains readable and writable. The [`hashmap-archive` companion](../../docs/archive.md) combines these blocks with RSM1 field lanes in HMARCH2; `make archive-compare` measures both versions on the same files.

## Measured result

`experiment.py` writes 4,096 distinct synthetic asset records in the repository's HMMAP 2 layout, packs them, unpacks them and compares every restored byte. The keys are 17 bytes and the digest column is 32 bytes wide in every case. Sizes include the complete headers and checksum.

| Keys in input order | Wrong predictions per 64 rows | Original bytes | Archive bytes | Saved |
|---|---:|---:|---:|---:|
| Sequential asset labels | 0 | 204,828 | 13,948 | 93.19% |
| Opaque asset IDs | 0 | 204,828 | 73,925 | 63.91% |
| Same opaque IDs | 1 | 204,828 | 76,037 | 62.88% |
| Same opaque IDs | 64 | 204,828 | 204,997 | −0.08% |

The middle two rows isolate the price of exceptions: **2,112 bytes** for 64 exceptional 32-byte values *and their positions*. The last row is the negative control: neither model saves a byte. The archive grows by 169 bytes of framing. These are measurements of these inputs, not a ratio promised for other maps.

## Count the possible originals

Fix the ordered strings of one block and the predictor known to both sides. Here `F(x)` is the first `d` bytes of the header's named digest of **exactly the stored string bytes**. This is a prediction, not an assertion about how the file was made. Packing compares the full stored field to `F(x)` on each row. For an input already truncated to `d` bytes, those `d` bytes are the original field; the archive cannot recover bytes absent from the input.

Let `n` be the row count, `q = 256^d` the number of possible field values and `k` the number of wrong predictions. How many digest columns remain possible?

```
W(n,k) = binom(n,k) · (q − 1)^k
```

Choose the `k` positions; at each, any value **except the prediction** is possible. There is no independence, uniformity or collision-resistance assumption. A fixed-width field representing every member of this class needs at least `ceil(log₂ W)` bits: fewer bits have fewer distinct codes than originals. Number the members `0 .. W−1` and this bound is attained. On a byte stream the exact width is `ceil(bit_length(W−1) / 8)`, including **zero bytes when W = 1**. This is optimal for the digest payload *conditional on the strings, rule and k*, not a global optimality claim for the file.

For 64 SHA-256 rows with one miss, `W = 64 · (2^256 − 1)`. The 2,048-byte digest column needs **33 bytes**, plus the block header and the strings. A 64-bit exception bitmap plus the literal value would need 40 bytes. With zero misses there is no digest payload at all. Across *all* values of `k`, the binomial sum is `q^n`: without useful side information there is no lossless way to shorten every possible column.

### How to compute the number without listing the class

Interpret fixed-width digest bytes as unsigned big-endian integers. For a prediction `p` and actual value `a`, encode equality as a hit. Otherwise encode the miss digit `e = a` if `a < p`, or `a−1` if `a > p`. This skips exactly one symbol. Given a miss, restore `a = e` if `e < p`, or `e+1` otherwise.

Partition the class by the first row. With `m = n−1` rows after it:

* A hit occupies the first `cut = W(m,k)` ranks. Its rank is the tail's rank.
* A miss occupies one of `q−1` subsequent intervals of size `stride = W(m,k−1)`. Its rank is `cut + e · stride + tail_rank`.

Here `W(0,0)=1` and impossible weights have count zero. The encoder walks the rows backwards, accumulating these offsets. The decoder walks forwards: below `cut` it emits a hit; otherwise division and remainder of `rank−cut` by `stride` recover the digit and tail rank. The latter branch can only be reached with positive stride on a valid rank. Neither direction enumerates possibilities.

This design applies a known idea to the map's two fields; it does not claim to invent enumerative coding. Background: T. M. Cover, “Enumerative Source Encoding,” *IEEE Transactions on Information Theory* 19(1), 73–77 (1973) [1](https://isl.stanford.edu/~cover/cover-papers.html).

## Account for the rest of the file

`x` above is the stored string, **not** the lookup digest. We keep one string per input row. For each block, compare two exact byte costs: literal strings cost `L = Σ(1 + len(x))`; copying a prefix from the preceding string costs `P = Σ(2 + len(x) − shared_prefix_len)`. The first predecessor is empty. The two length bytes are the copied prefix length and the literal suffix length. Use prefix coding **only if `P < L`**, in the original order.

Uniqueness alone is weaker than a predictor. If all we know about `n` distinct strings is that they come from a universe of size `U`, there are still `U · (U−1) · … · (U−n+1)` possible **ordered** lists. Encoding only the set would lose the choice of permutation. Prefix copying instead exploits bytes that actually agree, without changing order.

The digest field similarly goes literal if the ranked payload doesn't save a byte. An expensive bcrypt column is always opaque/literal; its salt header is copied and never evaluated. A missing parameter that makes a cheap predictor wrong produces exceptions, not silently “corrected” data.

For `N` rows, the encoder makes `B = ceil(N/64)` blocks. For each block it writes precisely `2 + min(L,P) + min(n·d, rank_bytes)` bytes (use `n·d` for opaque values). The original map header is copied. The only other cost is 41 bytes per file. Thus even an all-literal archive is at most **original size + 41 + 2B**. Tiny inputs can grow. Both directions make one sequential pass with at most 64 rows buffered; the trade for storage is recomputing a forward digest per row of a modeled block on restore. The prototype doesn't infer arbitrary hidden functions or provide random access.

## What Lean checks

[`Archive.lean`](Archive.lean) is a core-only Lean 4 model:

| Theorem(s) | Statement |
|---|---|
| `restore_delta`, `delta_restore` | Skipping the predicted symbol is reversible. |
| `ways_formula`, `rank_lt` | The interval recurrence equals the binomial formula and each valid word ranks inside it. |
| `unrank_rank`, `unrank_spec` | Both inverses: every valid word is recovered, and **every** rank in the interval represents a valid word of the specified length and weight. |
| `byteWidth_le_iff` | The integer byte-width calculation fits in `t` bytes exactly when `count ≤ 256^t`. |
| `block_roundtrip`, `keys_roundtrip` | Ordered rows are recovered for **any** in-range predictor, and prefix copying recovers the ordered strings. |

The proof is about the codec mathematics, not Python's parser, I/O or `hashlib`. [`test_hmar.py`](test_hmar.py) checks the byte implementation separately, including exhaustive small alphabets, rank boundaries, a hand-computed wire vector, mixed and duplicate records, malformed inputs and interrupted files.

## Reproduce or use

From the repository root (Python 3.10+, standard library only):

```sh
make archive-test
make archive-experiment
make archive-proof   # Lean 4.35.0; with elan the local lean-toolchain selects it

python3 research/map_archive/hmar.py pack input.hmmap archive.hmar
python3 research/map_archive/hmar.py unpack archive.hmar restored.hmmap
cmp input.hmmap restored.hmmap
```

Destinations must be new paths. The CLI stages output in the destination directory, then publishes by hard link only after successful completion (requires a filesystem supporting hard links). A parse or checksum failure does not replace an existing file or publish a partial restore.

### HMARCH1 wire layout

```
"HMARCH1\n"
original HMMAP header bytes
repeat: u8 (n | key_flag), u8 digest_mode, n strings, digest payload
u8 0, SHA-256(original HMMAP byte stream) [32 bytes], EOF
```

* Headers follow the writer: `HMMAP 1\n` implies MD5/16; `HMMAP 2\n` has `algo NAME\n`, `dlen D\n`, and for bcrypt a `salt ...\n` line. Recognized names are `md5`, `sha1`, `sha256`, `bcrypt`. Unknown layouts and incomplete records are rejected, not guessed. Binary record bytes are never scanned for header lines.
* `n` is 1–64. `key_flag=0` means `[u8 len][bytes]`; `0x80` means `[u8 prefix_len][u8 suffix_len][suffix bytes]`. Each reconstructed string is at most 255 bytes. The predecessor resets every block.
* `digest_mode=255` means `n` literal `d`-byte fields in row order. Otherwise the mode is `k` in `0..n`; the only payload is the fixed-width unsigned big-endian rank. No bitmap, offsets or separately stored exceptions.
* Zero as the entire block tag is the terminator. Invalid ranks (including unused padding values), invalid lengths, truncation, trailing bytes and checksum mismatches are errors. The checksum detects accidental damage; it is not authentication.
