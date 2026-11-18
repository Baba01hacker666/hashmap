"""EVIL codec tests: golden nibbles, tier coverage, strictness, EVIL1 files."""

import hashlib
import random
import unittest
from io import BytesIO

from research.evil_codec import evil, evilzip
from research.map_archive import hmar


def field(data: bytes) -> bytes:
    reader = evil.Reader(evil.pack_field(data))
    out = evil.unpack_field(reader)
    reader.done()
    assert out == data
    return evil.pack_field(data)


def unpacks(wire: bytes) -> bytes:
    reader = evil.Reader(wire)
    out = evil.unpack_field(reader)
    reader.done()
    return out


class GoldenTests(unittest.TestCase):
    def test_digits_are_nibbles(self):
        self.assertEqual(field(b"0123456789"),
                         b"\x0a\x01" + bytes([0x01, 0x23, 0x45, 0x67, 0x89]))
        self.assertEqual(field(b"77"), b"\x02\x01\x77")

    def test_tier1_specials(self):
        # 0xA..0xE are '.', '-', '_', '/', ' '; doubled so the nibble mode wins.
        for char, nib in zip(b".-_/ ", (0xA, 0xB, 0xC, 0xD, 0xE)):
            pair = bytes([char, char])
            self.assertEqual(field(pair), b"\x02\x01" + bytes([nib << 4 | nib]))

    def test_letter_tiers_decode(self):
        # The decoder must accept every tier, but with digits holding the 16
        # short slots a letter costs 8-12 bits, so pack_field keeps verbatim.
        self.assertEqual(unpacks(b"\x01\x01\xf0"), b"a")          # F 0
        self.assertEqual(unpacks(b"\x01\x01\xfe"), b"o")          # F E
        self.assertEqual(unpacks(b"\x01\x01\xff\x00"), b"p")      # F F 0, pad
        self.assertEqual(unpacks(b"\x01\x01\xff\xa0"), b"z")
        self.assertEqual(unpacks(b"\x01\x01\xff\xb0"), b"A")
        self.assertEqual(unpacks(b"\x01\x01\xff\xe0"), b"D")
        self.assertEqual(field(b"abcdefghijklmnopqrstuvwxyz"),
                         b"\x1a\x00abcdefghijklmnopqrstuvwxyz")

    def test_raw_escape_inside_nibble_mode(self):
        # 'E' = 0x45 is not in the tiers: F F F 4 5 after ten digit nibbles.
        self.assertEqual(field(b"1111111111E"),
                         b"\x0b\x01" + bytes([0x11] * 5 + [0xFF, 0xF4, 0x50]))
        self.assertEqual(unpacks(b"\x01\x01\xff\xf0\x00"), b"\x00")

    def test_hex_mode_exact_halving(self):
        self.assertEqual(field(b"deadbeef"), b"\x08\x02\xde\xad\xbe\xef")
        self.assertEqual(field(b"0123456789abcdef"),
                         b"\x10\x02\x01#Eg\x89\xab\xcd\xef")

    def test_raw_fallback_for_binary(self):
        blob = bytes([0xFF, 0x00, 0x99, 0x80])
        self.assertEqual(field(blob), b"\x04\x00" + blob)
        self.assertEqual(field(b""), b"\x00\x00")

    def test_cheapest_mode_wins(self):
        # Pure text with no digits: the nibble code cannot beat verbatim.
        self.assertEqual(field(b"hello"), b"\x05\x00hello")
        # Digit runs flip the choice: 8 nibbles + 2 header < 10 raw.
        self.assertEqual(field(b"90210")[2:], b"\x90\x21\x00")


class RoundTripTests(unittest.TestCase):
    def test_field_lanes(self):
        rng = random.Random(0xE711)
        for _ in range(200):
            alphabet = rng.choice([b"0123456789", b"0123456789abcdef", bytes(range(256))])
            fields = [bytes(rng.choice(alphabet) for _ in range(rng.randrange(0, 30)))
                      for _ in range(rng.randrange(0, 60))]
            wire = evil.pack_fields(fields)
            self.assertEqual(evil.unpack_fields(wire, [len(f) for f in fields]), fields)
        # A lane of hex keys costs one header for the whole stream.
        keys = [f"{i:064x}".encode() for i in range(64)]
        self.assertEqual(evil.pack_fields(keys), evil.uv(64 * 64) + b"\x02"
                         + evil._pack_nibbles([int(c, 16) for k in keys for c in k.decode()]))
        self.assertLessEqual(len(evil.pack_fields(keys)), 3 + 64 * 32)
        with self.assertRaises(evil.EvilError):
            evil.unpack_fields(evil.pack_fields([b"ab", b"cd"]), [3])

    def test_seeded_alphabets(self):
        rng = random.Random(0xE711)
        alphabets = [b"0123456789", b"0123456789abcdef", b"abcdefghijklmnopqrstuvwxyz .-_/",
                     bytes(range(256)), b"ABCxyz09.-_ /\x00\xff"]
        for alphabet in alphabets:
            for _ in range(300):
                field(bytes(rng.choice(alphabet) for _ in range(rng.randrange(0, 40))))

    def test_every_byte_escapes(self):
        for value in range(256):
            field(bytes([value]))
        field(bytes(range(255)))  # 255 is the per-field cap


class StrictnessTests(unittest.TestCase):
    def rejects(self, wire: bytes):
        with self.assertRaises(evil.EvilError):
            unpacks(wire)

    def test_truncation_at_every_point(self):
        wire = evil.pack_field(b"a1/pZ\x00")
        for cut in range(len(wire)):
            with self.assertRaises(evil.EvilError, msg=f"cut at {cut}"):
                unpacks(wire[:cut])

    def test_bad_mode(self):
        self.rejects(b"\x01\x03\x00")

    def test_dangling_escapes(self):
        self.rejects(b"\x01\x01\xf0\x00")   # 'a' plus trailing garbage byte
        self.rejects(b"\x01\x01\xff")       # F F then end
        self.rejects(b"\x01\x01\xff\xf0")   # F F F then end

    def test_nonzero_padding(self):
        self.rejects(b"\x01\x01\x7f")       # '7' + pad nibble 0xF
        self.rejects(b"\x03\x02\xde\xaf")   # hex 'dea' + pad nibble 0xF

    def test_count_bound(self):
        with self.assertRaises(evil.EvilError):
            evil.unpack_field(evil.Reader(evil.pack_field(b"ab")), max_len=1)

    def test_field_too_long_to_pack(self):
        with self.assertRaises(evil.EvilError):
            evil.pack_field(b"x" * 256)


class FileTests(unittest.TestCase):
    def roundtrip(self, original: bytes):
        packed = BytesIO()
        evilzip.pack(BytesIO(original), packed)
        restored = BytesIO()
        evilzip.unpack(BytesIO(packed.getvalue()), restored)
        self.assertEqual(restored.getvalue(), original)
        return packed.getvalue()

    def test_pin_codes(self):
        header = b"HMMAP 2\nalgo sha256\ndlen 32\n"
        rows = [(f"{i:08d}".encode(), hashlib.sha256(f"{i:08d}".encode()).digest())
                for i in range(500)]
        original = header + hmar.map_bytes(rows)
        packed = self.roundtrip(original)
        self.assertLess(len(packed), len(original) // 2)  # digits pack 2:1, digests predicted

    def test_bcrypt_and_binary_keys(self):
        header = b"HMMAP 2\nalgo bcrypt\ndlen 23\nsalt $2b$12$example\n"
        rng = random.Random(7)
        rows = [(bytes(rng.randrange(256) for _ in range(rng.randrange(1, 20))),
                 bytes(rng.randrange(256) for _ in range(23))) for _ in range(40)]
        self.roundtrip(header + hmar.map_bytes(rows))

    def test_header_only_and_one_row(self):
        header = b"HMMAP 1\n"
        self.roundtrip(header)
        self.roundtrip(header + hashlib.md5(b"x").digest() + b"\x01x")

    def test_multi_group(self):
        header = b"HMMAP 2\nalgo sha1\ndlen 20\n"
        rows = [(f"user-{i:06d}".encode(), hashlib.sha1(f"u{i}".encode()).digest())
                for i in range(evilzip.GROUP + 7)]
        self.roundtrip(header + hmar.map_bytes(rows))

    def corrupt_rejects(self, original: bytes):
        packed = BytesIO()
        evilzip.pack(BytesIO(original), packed)
        blob = bytearray(packed.getvalue())
        for i in range(len(blob)):
            mutated = bytes(blob[:i]) + bytes([blob[i] ^ 0x40]) + bytes(blob[i + 1:])
            with self.assertRaises(ValueError, msg=f"flip at {i}"):
                out = BytesIO()
                evilzip.unpack(BytesIO(mutated), out)

    def test_corruption_everywhere_is_caught(self):
        header = b"HMMAP 2\nalgo sha256\ndlen 32\n"
        rows = [(b"abc123", hashlib.sha256(b"abc123").digest()),
                (b"zz", bytes(range(32)))]
        self.corrupt_rejects(header + hmar.map_bytes(rows))

    def test_truncation_and_trailing(self):
        header = b"HMMAP 1\n"
        original = header + hashlib.md5(b"k").digest() + b"\x01k"
        packed = BytesIO()
        evilzip.pack(BytesIO(original), packed)
        blob = packed.getvalue()
        for cut in range(len(blob)):
            with self.assertRaises(ValueError):
                evilzip.unpack(BytesIO(blob[:cut]), BytesIO())
        with self.assertRaises(ValueError):
            evilzip.unpack(BytesIO(blob + b"\x00"), BytesIO())

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            evilzip.unpack(BytesIO(b"EVIL2\n" + b"\x00" * 40), BytesIO())


if __name__ == "__main__":
    unittest.main()
