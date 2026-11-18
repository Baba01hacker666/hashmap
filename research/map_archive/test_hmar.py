import hashlib
import io
import itertools
import tempfile
import unittest
from pathlib import Path

import hmar


V1 = b"HMMAP 1\n"
SHORT = b"HMMAP 2\nalgo sha256\ndlen 1\n"
SHA = b"HMMAP 2\nalgo sha256\ndlen 32\n"
OPAQUE = b"HMMAP 2\nalgo bcrypt\ndlen 23\nsalt $2b$12$" + b"." * 22 + b"\n"


def record(key, digest):
    return digest + bytes([len(key)]) + key


def run(op, data):
    out = io.BytesIO()
    op(io.BytesIO(data), out)
    return out.getvalue()


class MathTests(unittest.TestCase):
    def test_exhaustive_bijection(self):
        for base in (1, 2, 3):
            for n in range(6):
                ranks = [set() for _ in range(n + 1)]
                for word in itertools.product([None, *range(base)], repeat=n):
                    k = n - word.count(None)
                    r = hmar.rank(base, word)
                    ranks[k].add(r)
                    self.assertEqual(tuple(hmar.unrank(base, n, k, r)), word)
                for k, seen in enumerate(ranks):
                    self.assertEqual(seen, set(range(hmar.ways(base, n, k))))

    def test_full_width_rank_boundaries(self):
        base = 256**32 - 1
        for k in (0, 1, 2, 31, 32, 33, 63, 64):
            count = hmar.ways(base, 64, k)
            for r in {0, count // 2, count - 1}:
                errors = list(hmar.unrank(base, 64, k, r))
                self.assertEqual(errors.count(None), 64 - k)
                self.assertTrue(all(0 <= e < base for e in errors if e is not None))
                self.assertEqual(hmar.rank(base, errors), r)

    def test_integer_widths(self):
        for i in range(1, 33):
            self.assertEqual(hmar.byte_width(256**i), i)
            self.assertEqual(hmar.byte_width(256**i + 1), i + 1)
        b = 256**32 - 1
        self.assertEqual(hmar.byte_width(hmar.ways(b, 64, 0)), 0)
        self.assertEqual(hmar.byte_width(hmar.ways(b, 64, 1)), 33)
        self.assertEqual(hmar.byte_width(hmar.ways(b, 64, 64)), 2048)


class FileTests(unittest.TestCase):
    def roundtrip(self, original, n):
        archive = run(hmar.pack, original)
        self.assertEqual(run(hmar.unpack, archive), original)
        self.assertLessEqual(len(archive), len(original) + 41 + 2 * ((n + 63) // 64))
        return archive

    def test_wire_vector(self):
        # SHA-256 prefixes for a,b,c,d: ca,3e,2e,18. At b, bc > 3e,
        # so the miss digit is 187. Its rank is 2*255 + 187 = 697.
        original = SHORT + b"\xca\x01a\xbc\x01b\x2e\x01c\x18\x01d"
        expected = (hmar.MAGIC + SHORT + b"\x04\x01\x01a\x01b\x01c\x01d\x02\xb9\x00"
                    + hashlib.sha256(original).digest())
        self.assertEqual(self.roundtrip(original, 4), expected)
        for i in range(len(expected)):
            with self.assertRaises(hmar.FormatError):
                run(hmar.unpack, expected[:i])
        with self.assertRaisesRegex(hmar.FormatError, "rank"):
            run(hmar.unpack, expected[:-35] + b"\x03\xfc" + expected[-33:])  # 1020, first invalid

    def test_algorithms_widths_and_binary_rows(self):
        # Duplicate row, conflicting value for one key, colliding values for
        # different keys, and binary keys at both ends of the length range.
        keys = [b"", b"\xff\0\n", b"same", b"same", b"same", b"other", bytes(range(255))]
        for algo, width in [("md5", 16), ("md5", 3), ("sha1", 20), ("sha256", 32), ("sha256", 1)]:
            header = f"HMMAP 2\nalgo {algo}\ndlen {width}\n".encode()
            digests = [hashlib.new(algo, key, usedforsecurity=False).digest()[:width] for key in keys]
            digests[4] = digests[5] = bytes(width)
            data = b"".join(record(k, d) for k, d in zip(keys, digests))
            self.roundtrip(header + data, len(keys))
            if algo == "md5" and width == 16:
                self.roundtrip(V1 + data, len(keys))

    def test_every_miss_value(self):
        # Check both sides of the excluded symbol, including 00 and ff.
        key = b"part"
        pred = hashlib.sha256(key).digest()[:1]
        for a in range(256):
            data = record(key, pred) * 3 + record(key, bytes([a]))
            self.roundtrip(SHORT + data, 4)

    def test_prefix_blocks_and_short_last_block(self):
        keys = [b"a" * 255] * 65 + [b"a" * 254 + b"\x00", b""]
        raw = SHA + b"".join(record(k, hashlib.sha256(k).digest()) for k in keys)
        archive = self.roundtrip(raw, len(keys))
        self.assertLess(len(archive), len(raw) // 8)
        at = len(hmar.MAGIC + SHA)
        self.assertEqual(archive[at:at+2], bytes([64 | hmar.FRONT, 0]))

    def test_all_miss_and_opaque(self):
        for header, width in [(SHA, 32), (OPAQUE, 23)]:
            for n in (0, 1, 63, 64, 65, 128):
                # Even header-looking bytes at the start of a digest are data.
                dg = b"salt literal\n".ljust(width, b"\0")
                raw = header + b"".join(record(bytes([i]), dg) for i in range(n))
                archive = self.roundtrip(raw, n)
                self.assertEqual(len(archive), len(raw) + 41 + 2 * ((n + 63) // 64))
                if n:
                    at = len(hmar.MAGIC + header)
                    self.assertEqual(archive[at:at+2], bytes([min(n, 64), hmar.LITERAL]))

    def test_corrupt_archive(self):
        pre = hmar.MAGIC + SHORT
        for part in [b"\x80", b"\x41", b"\x01\x02\x00", b"\x81\x00\x01\x00",
                     b"\x82\x00\x00\xff" + bytes(255) + b"\xff\x01"]:
            with self.assertRaises(hmar.FormatError):
                run(hmar.unpack, pre + part)
        with self.assertRaisesRegex(hmar.FormatError, "mode"):
            run(hmar.unpack, hmar.MAGIC + OPAQUE + b"\x01\x00\x00")
        good = run(hmar.pack, SHORT + record(b"a", b"\xca"))
        for bad in (good + b"x", good[:-1] + bytes([good[-1] ^ 1]), b"not hmar" + good):
            with self.assertRaises(hmar.FormatError):
                run(hmar.unpack, bad)
        # Structurally valid key substitution must also be detected.
        with self.assertRaisesRegex(hmar.FormatError, "checksum"):
            run(hmar.unpack, good.replace(b"\x01a", b"\x01b", 1))

    def test_reject_malformed_sources(self):
        for data in (b"notamap\n", V1 + bytes(15), V1 + bytes(16), V1 + bytes(16) + b"\xffx",
                     SHA.replace(b"32", b"0"), SHA.replace(b"32", b"33"),
                     SHA.replace(b"sha256", b"sha99"), OPAQUE.split(b"salt")[0]):
            with self.assertRaises(hmar.FormatError):
                run(hmar.pack, data)

    def test_publish_only_complete_new_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            src, dest = root / "src", root / "out"
            src.write_bytes(V1 + b"partial")
            with self.assertRaises(hmar.FormatError):
                hmar.convert("pack", src, dest)
            self.assertEqual(set(root.iterdir()), {src})
            src.write_bytes(run(hmar.pack, V1)[:-1])
            with self.assertRaises(hmar.FormatError):
                hmar.convert("unpack", src, dest)
            self.assertEqual(set(root.iterdir()), {src})
            src.write_bytes(V1)
            hmar.convert("pack", src, dest)
            with self.assertRaises(FileExistsError):
                hmar.convert("unpack", dest, src)
            self.assertEqual(src.read_bytes(), V1)
            hmar.convert("unpack", dest, root / "restored")
            self.assertEqual((root / "restored").read_bytes(), V1)


if __name__ == "__main__":
    unittest.main()
