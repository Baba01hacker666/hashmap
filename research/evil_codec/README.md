# EVIL codec — Escaped Variable-width Integer Lexicon

**Status: research.** An experiment in replacing ASCII with a custom fixed
code for HMMAP keys, exactly as brainstormed: `0x0` is `0`, `0x1` is `1`,
… `0x9` is `9`, with nibbles left over for letters and specials. It is evil
only to bytes. The main C tool and the HMARCH formats are untouched; this
directory measures *how much* the idea can compress and where its ceiling is.

## The code

One field is `uv(count) u8 mode payload`. Modes: **RAW** (verbatim),
**EVIL-A** (the tiered nibble code), **EVIL-H** (pure hex text, one nibble
per character). The encoder picks the cheapest. Framing is `uv(count)` plus
one mode byte, so the overhead over verbatim is at most two bytes for fields
of length 0–127, and three bytes for lengths 128–255 (the count takes two
bytes there).

EVIL-A tiers — all codes are whole nibbles, most-significant first:

| Code | Symbol(s) | Cost |
|---|---|---:|
| `0x0`–`0x9` | `0`–`9` | 4 bits |
| `0xA`–`0xE` | `.` `-` `_` `/` space | 4 bits |
| `F t` | `a`–`o` (t = 0–E) | 8 bits |
| `F F t` | `p`–`z`, `A`–`D` | 12 bits |
| `F F F hi lo` | any raw byte | 20 bits |

`evilzip.py` wraps this into **EVIL1**, a toy whole-file archive (per-row key
fields + HMARCH1's digest prediction, SHA-256 footer) purely so the numbers
below are end-to-end. Reproduce everything with `make evil-compare`; tests
with `make evil-test`.

## Measured: whole files (bytes, every restore byte-exact)

| Case | HMMAP | EVIL1 | HMARCH1 | HMARCH2 | zlib-9(HMMAP) |
|---|---:|---:|---:|---:|---:|
| 8-digit PIN codes ×4,096 | 167,964 | 24,650 | 13,372 | **3,293** | 143,107 |
| Wordlist words ×4,096 | 167,602 | 40,411 | 36,699 | **22,156** | 165,458 |
| Hex-text keys ×2,048, opaque values | 198,684 | 135,242 | 198,789 | **131,261** | 157,342 |
| One short binary row | 64 | 108 | 107 | 107 | **72** |
| CPython paths / blob IDs | 252,707 | 257,599 | 161,449 | **129,774** | 139,374 |

## Measured: bits per character vs entropy

| Data | EVIL | Entropy | Alphabet |
|---|---:|---:|---:|
| PIN codes | 4.02 | 3.32 | 10 symbols |
| Wordlist words | 8.00 | 4.65 | 33 symbols |
| Hex text | 4.02 | 4.00 | 16 symbols |

## Why it loses — and the one place it is *optimal*

1. **16 short slots, 36+ common symbols.** Digits and five specials fill the
   4-bit tier; every letter then costs 8–12 bits — the same as, or worse
   than, the ASCII it replaced. The measured 8.00 bits/char on wordlist text
   (entropy 4.65) is this effect exactly: a nibble is too small a currency
   for a 36-symbol alphabet.
2. **A fixed code can't adapt.** Digit entropy is 3.32 bits, so even on its
   best alphabet EVIL sits 21% above entropy; adaptive byte-Huffman sits on
   it. Worse, RSM1's *tokens* capture what no per-character code can:
   `0000`-style runs and shared prefixes. That is why HMARCH2 encodes the
   PIN file in 0.8 bits per digit and wins at **every** size — the crossover
   scan (`n` = 16 … 4,096) never once favors EVIL.
3. **Per-field framing.** Two header bytes per row (`uv` + mode) cost more
   than the nibble savings on short keys, and there is no cross-row
   structure. Removing it (`pack_fields`: one header per file) gives EVIL's
   ceiling: PIN keys 24,576 → 16,388 = exactly 4.0 bits/digit; hex keys
   69,632 → 65,540.
4. **The win:** on uniform hex text EVIL-H *is* the entropy bound — 4.00
   bits/char with zero codebook, beating even its own one-stream ceiling by
   nothing and matching theory exactly. If a format is stuck storing hashes
   as hex *text*, nibble packing halves it. (HMMAP already stores binary
   digests, so this does not apply to the main tool.)

## Verdict

Fun name, honest result: the fixed-code idea tops out at a perfect 4
bits/char on 16-symbol alphabets and loses everywhere else, because letters
don't fit in nibbles and adaptivity + tokenization dominate per-character
codes. RSM1/HMARCH2's learned lanes already subsume it, so EVIL stays here
as documentation-by-measurement of *why* — and as a tiny strict decoder
(60 lines) for nibble-packed hex if one is ever needed.
