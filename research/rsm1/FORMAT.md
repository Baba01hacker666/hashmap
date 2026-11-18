# RSM1 binary layout

This is an experimental, self-contained **static byte-map** archive. Raw bytes are never normalized. The version fixes the only predictor to binary `SHA-256(original key bytes)`. There is no integrity checksum, compressed-domain lookup index, or mutation support. The research parser is for trusted archives. Consult `rsm.py` for the reference implementation.

## Primitives

- `uv`: canonical unsigned base-128 little-endian varint (LEB128), up to 64 bits.
- `frame(b)`: `uv(len(b))` followed by `b`.
- Bitstreams write the most significant bit of a field first, into the most significant available bit of the current byte. Finish with zero bits up to the next byte boundary. Cache bitmaps and literal-presence masks instead use the least significant bit of each byte for the earliest index in that byte.
- Keys are strictly increasing in **lexicographic byte** order; values and cache entries use the identical ranks. `n` is the number of rows.

## Envelope

ASCII `RSM1`, one flags byte (`0`: no cache, `1`: cache present), `uv(n)`, `frame(keys)`, `frame(values)`, and optionally `frame(cache)`. The value frame is a field lane. The key frame begins with one tag byte:

| Tag | Following bytes |
|---:|---|
| 0 | Field lane containing the original keys. |
| 1 | Shape descriptor for `n` prefix lengths, then field lane of `n` suffixes. The initial previous key is the empty string. |
| 2 | `uv(key width in bytes)`, `uv(ell)`, then one bitstream: `n` low remainders of `ell` bits each, followed by `n` high quotient gaps (`gap` zero bits then a one bit). Start at high quotient zero. Keys are fixed width in this lane. |

## Shape descriptor and field lanes

A shape descriptor contains `uv(length + 1)` if all `n` lengths are equal (when `n = 0`, the encoder writes `1`). Otherwise write `uv(0)` and a one-byte vector tag. Tag `0` is `n` lengths as `uv`s. Tag `1` is `uv(minimum length)`, a one-byte bit width, and a separate padded bitstream of `n` fixed-width offsets from the minimum.

A field lane begins with a one-byte codec tag, followed by its shape descriptor (one decoded byte length per field). Codec tag `0` stores the concatenated raw fields. Codec tag `1` stores:

1. A 32-byte literal-presence mask for byte IDs 0–255, and then one code length byte for each present literal, ascending by ID.
2. `uv(number of multi-byte tokens)`, then one entry per token: `uv(token byte length)`, literal token bytes, and one code length byte. Token byte strings are in strict lexicographic order and get consecutive IDs beginning at 256. V1 limits the model to 96 multi-byte tokens of at most 24 bytes.
3. The padded Huffman bitstream. Codes are canonical, sorted first by code length, then by numeric ID. Code lengths are 1–63. Decode expansions until the sum of the decoded field lengths is reached, then check padding and split using those lengths. The wire decoder does not need to know whether the encoder used a greedy or minimum-bit token parse.

## Optional cache frame

Each original cache entry is 32 bytes. The frame begins with a one-byte mode tag:

| Tag | Following bytes |
|---:|---|
| 0 | `n` raw cache entries in rank order. |
| 1 | Nothing. All entries are regenerated. |
| 2 | `ceil(n/8)` bitmap bytes and one raw entry for each set bit, in rank order. A set bit is an exception. |
| 3 | `uv(exception count)`, then one `uv` per exception giving the number of nonexception rows since the preceding exception (`initial previous rank = −1`), then the raw exception entries in rank order. |

RSM1 represents the logical key/value/cache mappings, not the runtime hash table. There is no external dictionary or dataset dependency in the decoder.
