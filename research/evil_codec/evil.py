"""EVIL — Escaped Variable-width Integer Lexicon: a fixed nibble codec.

An experiment, not a new map format. The idea: instead of one ASCII byte per
character, give common characters short fixed codes, starting from

    0x0 = '0', 0x1 = '1', ..., 0x9 = '9'

and escaping to wider codes for everything else. A 16-symbol alphabet fits in
4 bits per character (2:1 over ASCII). Wider escape tiers cover the remaining
letters and arbitrary bytes at a rising cost, which is exactly the trade-off
this research measures: a fixed code has ZERO table overhead, but only the
first 16 symbols are truly cheap. Adaptive coders (RSM1's byte Huffman) must
store a codebook yet match the data. See README.md for the measured outcome.

Wire layout of one field:

    uv(count)  u8 mode  payload

mode 0 (RAW):   payload is count bytes verbatim.
mode 1 (EVIL-A): count symbols from the tiered nibble code below, packed
                most-significant nibble first; one zero pad nibble if odd.
mode 2 (EVIL-H): count lowercase hex characters, one nibble each.

EVIL-A tiers (all codes are whole nibbles):

    0x0..0x9          -> '0'..'9'
    0xA 0xB 0xC 0xD 0xE -> '.' '-' '_' '/' ' '
    0xF t             -> TIER2[t], t = 0x0..0xE   (a..o)
    0xF 0xF t         -> TIER3[t], t = 0x0..0xE   (p..z, 'A'..'D')
    0xF 0xF 0xF hi lo -> the raw byte hi<<4 | lo  (anything else)
"""

from typing import Optional

RAW, EVIL_A, EVIL_H = 0, 1, 2
MAX_FIELD = 255  # HMMAP key width; callers may pass a different bound

TIER1 = b"0123456789.-_/ "
TIER2 = b"abcdefghijklmno"
TIER3 = b"pqrstuvwxyzABCD"
HEX = b"0123456789abcdef"

_ESC = 0xF
_INDEX_A = {c: i for i, c in enumerate(TIER1)}
_INDEX_A.update({c: (0x100 | i) for i, c in enumerate(TIER2)})
_INDEX_A.update({c: (0x200 | i) for i, c in enumerate(TIER3)})
_HEX_SET = frozenset(HEX)


class EvilError(ValueError):
    """A malformed, truncated or non-canonical EVIL field."""


def uv(n: int) -> bytes:
    out = bytearray()
    while True:
        n, bits = divmod(n, 128)
        out.append(bits | (0x80 if n else 0))
        if not n:
            return bytes(out)


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if n > len(self.data) - self.pos:
            raise EvilError("unexpected end of field")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def byte(self) -> int:
        return self.take(1)[0]

    def read_uv(self) -> int:
        value = shift = 0
        for _ in range(5):
            b = self.byte()
            value |= (b & 0x7F) << shift
            if b < 0x80:
                return value
            shift += 7
        raise EvilError("varint too long")

    def done(self) -> None:
        if self.pos != len(self.data):
            raise EvilError("trailing bytes after last field")


def read_uv(src) -> int:
    """Read one varint from a binary stream (group headers live on streams)."""
    value = shift = 0
    for _ in range(5):
        b = src.read(1)
        if len(b) != 1:
            raise EvilError("unexpected end of stream")
        value |= (b[0] & 0x7F) << shift
        if b[0] < 0x80:
            return value
        shift += 7
    raise EvilError("varint too long")


def _nibbles(code: int) -> list[int]:
    if code < 0x10:
        return [code]
    if code < 0x110:
        return [_ESC, code & 0xF]
    if code < 0x210:
        return [_ESC, _ESC, code & 0xF]
    byte = code - 0x300
    return [_ESC, _ESC, _ESC, byte >> 4, byte & 0xF]


def _pack_nibbles(nibs: list[int]) -> bytes:
    if len(nibs) % 2:
        nibs = nibs + [0]
    return bytes(nibs[i] << 4 | nibs[i + 1] for i in range(0, len(nibs), 2))


def _encode_a(data: bytes) -> bytes:
    nibs: list[int] = []
    for c in data:
        nibs += _nibbles(_INDEX_A.get(c, 0x300 + c))
    return _pack_nibbles(nibs)


def _encode_best(data: bytes) -> bytes:
    best = bytes([RAW]) + data
    lane = bytes([EVIL_A]) + _encode_a(data)
    if len(lane) < len(best):
        best = lane
    if all(c in _HEX_SET for c in data):
        lane = bytes([EVIL_H]) + _pack_nibbles([c - 0x30 if c <= 0x39
                                                else c - 0x61 + 10 for c in data])
        if len(lane) < len(best):
            best = lane
    return best


def pack_field(data: bytes) -> bytes:
    """Encode one field with the cheapest of RAW / EVIL-A / EVIL-H."""
    if len(data) > MAX_FIELD:
        raise EvilError("field too long")
    return uv(len(data)) + _encode_best(data)


def pack_fields(fields: list[bytes]) -> bytes:
    """EVIL's ceiling: ONE header + one nibble stream for concatenated fields.

    Field boundaries are not in the stream; the caller keeps the lengths.
    This removes the per-field header that pack_field pays, at the cost of
    looking exactly like an RSM1 field lane with a fixed codebook.
    """
    blob = b"".join(fields)
    return uv(len(blob)) + _encode_best(blob)


def _take_nibble(payload: bytes, i: int) -> int:
    if i >= 2 * len(payload):
        raise EvilError("truncated nibble code")
    byte = payload[i // 2]
    return byte >> 4 if i % 2 == 0 else byte & 0xF


def _decode_a(payload: bytes, count: int) -> tuple[bytes, int]:
    out = bytearray()
    i = 0
    while len(out) < count:
        nib = _take_nibble(payload, i)
        i += 1
        if nib < _ESC:
            out.append(TIER1[nib])
            continue
        t = _take_nibble(payload, i)
        i += 1
        if t < _ESC:
            out.append(TIER2[t])
            continue
        t = _take_nibble(payload, i)
        i += 1
        if t < _ESC:
            out.append(TIER3[t])
            continue
        hi, lo = _take_nibble(payload, i), _take_nibble(payload, i + 1)
        i += 2
        out.append(hi << 4 | lo)
    if i % 2 and _take_nibble(payload, i):
        raise EvilError("non-zero padding nibble")
    return bytes(out), (i + 1) // 2


def _decode_h(payload: bytes, count: int) -> tuple[bytes, int]:
    out = bytearray(HEX[_take_nibble(payload, i)] for i in range(count))
    if count % 2 and _take_nibble(payload, count):
        raise EvilError("non-zero padding nibble")
    return bytes(out), (count + 1) // 2


def _decode_mode(reader: Reader, mode: int, count: int) -> bytes:
    if mode == RAW:
        return reader.take(count)
    # A view avoids copying the rest of the key lane for every field: nibble
    # modes self-terminate after `count` symbols, so the unused suffix is
    # never read but used to be sliced into a fresh bytes object each time.
    payload = memoryview(reader.data)[reader.pos:]
    if mode == EVIL_A:
        field, used = _decode_a(payload, count)
    elif mode == EVIL_H:
        field, used = _decode_h(payload, count)
    else:
        raise EvilError("unknown EVIL field mode")
    reader.pos += used
    return bytes(field)


def unpack_field(reader: Reader, max_len: int = MAX_FIELD) -> bytes:
    count = reader.read_uv()
    if count > max_len:
        raise EvilError("declared field length exceeds the limit")
    return _decode_mode(reader, reader.byte(), count)


def unpack_fields(wire: bytes, lengths: list[int]) -> list[bytes]:
    if any(length < 0 for length in lengths):
        raise EvilError("negative field length")
    reader = Reader(wire)
    if reader.read_uv() != sum(lengths):
        raise EvilError("length table does not match the stream")
    blob = _decode_mode(reader, reader.byte(), sum(lengths))
    reader.done()
    fields = []
    pos = 0
    for length in lengths:
        fields.append(blob[pos:pos + length])
        pos += length
    return fields


def codec_stats(data: bytes) -> Optional[float]:
    """Bits per character for the best EVIL mode, or None for empty input."""
    if not data:
        return None
    return 8.0 * (len(pack_field(data)) - len(uv(len(data))) - 1) / len(data)
