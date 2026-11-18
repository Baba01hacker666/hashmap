# RSM1 · Exact compression for mixed hash maps

**Result:** a working lossless format that can regenerate a predictable field, retain every exception, tokenize repeated byte strings, and compress even opaque digest keys when they form an unordered set. Every benchmark recovered the original keys, values and optional cached hashes exactly. Lean 4.19.0 checked the mathematical core separately from the Python implementation.

RSM1 stores a **static logical map** `bytes → bytes`, with an optional 32-byte cache field per key. It preserves neither insertion order nor the original hash table's buckets, seed, or tombstones. Decode and rebuild the map for lookups. The encoder and decoder do not use DEFLATE, a ZIP library, or an LLM.

## Measured results

Full archive bytes, including mode tags, framing, length tables, vocabulary, Huffman lengths and exception positions. The raw baseline uses the same sorted column format and already shares fixed field widths. The stronger general-purpose comparison is **DEFLATE-9 after the same structural prepass**. All 28 archives across seven variants were decoded and compared for exact equality; these are not estimates.

| Dataset | Entries | Raw bytes | RSM1 bytes | Saved vs raw | DEFLATE-9 on raw | DEFLATE-9 after structure |
|:---|---:|---:|---:|---:|---:|---:|
| Synthetic structured keys and values | 16,384 | 2,499,309 | **349,196** | 86.03% | 398,665 | 362,237 |
| Synthetic structured keys, opaque values, mostly predictable hash cache | 16,384 | 2,275,402 | **726,110** | 68.09% | 1,258,481 | 729,635 |
| Synthetic opaque 256-bit keys and opaque 256-bit values | 65,536 | 4,194,325 | **4,079,637** | 2.73% | 4,190,958 | 4,079,199 |
| Real CPython `v3.13.0` paths → binary Git blob IDs | 4,882 | 252,092 | **130,748** | 48.13% | 128,778 | 123,261 |

The real data comes from [the published Git tree](https://api.github.com/repos/python/cpython/git/trees/60403a5409ff2c3f3b07dd2ca91a7a3e096839c7?recursive=1). Only blob rows are used; the path alone is not the input to the Git blob hash, and RSM1 does not attempt to regenerate it. The synthetic generators use fixed seeds for repeatability; the decoder receives neither a seed nor a dataset-specific generator.

**What the tokenizer added.** The ablation keeps all the structural options identical and changes how repeated strings are encoded. All sizes below are full archives, not token counts.

| Coder | Structured text | Mixed cache | CPython paths |
|:---|---:|---:|---:|
| Structure only | 1,739,802 | 1,025,401 | 157,941 |
| Single-byte Huffman | 1,101,258 | 837,060 | 136,658 |
| Byte-pair vocabulary, greedy longest match | 349,199 | 726,113 | 130,846 |
| Byte-pair vocabulary, shortest-bit parse | **349,196** | **726,110** | **130,748** |

The vocabulary accounts for most of the tokenizer gain. Optimal parsing saved only 3, 3 and 98 bytes over greedy on these runs. Against the stronger DEFLATE baseline, RSM1 was 3.60% and 0.48% smaller on the two structured synthetic cases, and larger on the opaque and real cases. This does not establish a generally better compressor.

## Construction and proof

**1. Use sorted rank to keep the lanes aligned.** Sort unique keys once; row *i* in every other lane belongs to sorted key *i*. For string keys, one candidate stores `(common-prefix length p, suffix of the current key starting at p)`. The decoder takes `previous[:p] + suffix`, which equals the original key by the definition of `p`. Each next row therefore sees the same previous key as the encoder. A key and its value are never deduplicated just because other records share their contents.

**2. Tokenize the bytes, not the meaning.** Learn bounded byte-pair merges within fields. A token may include any combination of digits, letters, punctuation and other bytes. Include every observed literal byte as a fallback. Fit canonical Huffman lengths to the resulting token counts with smoothing; then, for the fixed codebook, parse each field by minimizing its actual bit cost. If `s[i:]` starts with token `t`, add the edge `i → i+|t|` at cost `L(t)`, its code length. The recurrence is:

```text
D[|s|] = 0
D[i]   = min over matching t  { L(t) + D[i + |t|] }
```

Every valid parse takes one of these edges first, and each edge strictly advances; a backward induction proves both that the minimum is attainable and that no other parse is cheaper. This is optimal **for a fixed vocabulary and codebook**, not optimal vocabulary or model training. The prefix decoder recovers literal token expansions until it reaches the known decoded byte count. The field lengths split the concatenated bytes back into the original fields, including empty ones. For example, with `bc=0`, `ab=10`, `a=110`, `b=1110`, `c=1111`, greedy parses `abc` as `ab|c` (6 bits), while the recurrence finds `a|bc` (4 bits).

**3. Regenerate only exact predictions.** With retained key `k`, the versioned predictor is `f(k) = SHA-256(k)` (binary, 32 bytes). The encoder compares the supplied cache value with `f(k)` byte-for-byte. On a match the decoder computes `f(k)`; on a miss it reads the exact supplied value. No inversion of a hash is involved. RSM1 compares a raw cache, an all-match tag, a bitmap with exceptions, and delta-coded exception positions with exceptions. For `n` rows and `r` misses, the bitmap takes `1 + ceil(n/8) + 32r` bytes before outer framing. The mixed run had 1,024 misses and stored **33,795** cache-lane bytes instead of **524,289**. Unknown digests, keyed hashes without the original parameters, and arbitrary value bytes are not silently replaced by predictions.

**4. Use order, not prediction, for opaque digest keys.** A sorted, fixed-width key is treated as a big-endian integer. Write `xᵢ = 2^ℓ hᵢ + lᵢ`, retain the low `ℓ` bits `lᵢ`, and represent the nondecreasing high parts with unary gaps `0^(hᵢ − hᵢ₋₁) 1`, starting at `h₋₁=0`. Summing zeros recovers each `hᵢ`; recombination recovers every key including its leading zero bytes. For a nonempty lane the payload bit count is exactly:

```text
n·ℓ + n + floor(max(key) / 2^ℓ)
```

The encoder chooses `ℓ` by actual byte cost, including the `ℓ` header. For 65,536 opaque 256-bit keys the representation used **242.00 bits/key** before its small header, saving **14 bits/key**. The uniform set has entropy `log₂ binomial(2^256, 65536) / 65536 ≈ 241.44255` bits/key. You are saving on the representation of the **set**, not compressing independent random digests in a prescribed order. For a fixed set of `n` keys with arbitrary `b`-bit values, there are `2^(nb)` value assignments: no lossless code can make them all shorter than `nb` bits (only `2^(nb) − 1` shorter bit strings exist). In the opaque run the value lane remained raw.

**5. Compare serialized sizes, not predictions of size.** Use the smallest eligible representation separately for keys, values and cache. Each lane admits its raw representation, and the length prefix takes no more bytes for a smaller lane. Thus RSM1 is never larger than its own raw container with the same fields. This is not a guarantee against the size of some other format.

## What Lean checked

| Lean theorem | Checked statement |
|:---|:---|
| `front_roundtrip`, `structured_roundtrip` | Exact front-coded key recovery and preservation of key/value/cache association in the structured model. |
| `pred_roundtrip`, `sparse_mask_roundtrip` | Predictions plus exact exceptions recover the original rows; a gap-coded exception mask reconstructs exactly. |
| `ef_roundtrip`, `ef_high_length` | Elias–Fano's quotient/remainder and unary gaps recover every sorted integer; its high-bit length formula holds. |
| `tokens_roundtrip`, `tokenized_fields_roundtrip` | Valid prefix-tree encodings restore all token expansions and original field boundaries. |
| `bellman_exact`, `raw_fallback` | The shortest-bit recurrence is attainable and minimal; selection cannot exceed an available raw candidate. |
| `no_collision_of_roundtrip`, `not_all_shorten` | A round-trip encoder is injective; not all fixed-width bit strings can be shortened. |

The Lean run exited **0**, with warnings treated as errors. `lean-check.txt` reports theorem dependencies; no proof holes were used. The proof models prefix trees, field boundaries, and the recurrences; it does **not** verify the Python byte parser, Huffman tree construction, SHA-256 implementation, or sorting implementation. These are exercised by executable tests instead.

## Prior work and scope

Compressed string dictionaries already combine front coding with entropy or grammar coding [2](https://users.dcc.uchile.cl/~gnavarro/algoritmos/ps/sea11.1.pdf). The tokenizer draws on byte-pair encoding, used for subword vocabularies by Sennrich et al. [1](https://aclanthology.org/P16-1162/). Weighted shortest paths for bit-optimal parsing have prior art in Lempel–Ziv work [1](https://arxiv.org/pdf/0802.0835). Elias–Fano's high/low representation for monotone sequences is described by Vigna [3](https://vigna.di.unimi.it/algoweb/EliasFano.pdf). The contribution here is a tested map format that combines those techniques with an exact regenerate-or-store cache lane and a measured raw fallback. No claim of priority for the combination or of a new universal compression theorem is made.

## C++20 implementation

The C++20 CLI and standalone library write the same format and produced byte-identical archives on all 20 cross-language benchmark profiles. See [the C++ build instructions and measurements](CPP.md) or run `make check` and `make bench`.

## Reproduce

From the project folder, with Python 3.10+ and Lean 4.19.0 (`lean-toolchain` pins the version for Elan):

```sh
python3 bench.py                          # writes results.csv; uses local CPython fixture
lean -DwarningAsError=true Codec.lean     # Std only, no Mathlib needed
python3 rsm.py pack example.json demo.rsm
python3 rsm.py unpack demo.rsm restored.json
cmp example.json restored.json
```

The checked run used Python 3.13.18 and zlib 1.3.1. The suite includes 511 exhaustive comparisons of the shortest-bit parser against all legal segmentations of short binary strings, 125 exhaustive small-map cases, 256 randomized map cases, and explicit binary, Unicode, cache mode and truncation tests. The example tests that `0007` and `7` remain distinct, and contains one nonmatching cache value. For custom input use `{"cache": false, "entries": [["key_hex", "value_hex"], …]}`; with `cache: true`, include the 32-byte cache as the third hex string in every row. Programmatically, `unpack(pack(mapping, cache)) == (mapping, cache)` compares the original byte maps. Use only trusted archives with this research parser. `FORMAT.md` documents the wire layout.
