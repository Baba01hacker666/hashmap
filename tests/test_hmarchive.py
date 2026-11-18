"""Ordered HMMAP -> archive -> byte-identical HMMAP, including both wire versions."""

from hashlib import sha256
import hashlib
from io import BytesIO
from pathlib import Path
import random
import subprocess
import tempfile
import unittest

import hmarchive as ar
from research.map_archive import hmar
from research.rsm1 import rsm

SHORT = b"HMMAP 2\nalgo sha256\ndlen 1\n"
SHA = b"HMMAP 2\nalgo sha256\ndlen 32\n"
OPAQUE = b"HMMAP 2\nalgo bcrypt\ndlen 23\nsalt $2b$12$" + b"." * 22 + b"\n"
EXE = Path(__file__).resolve().parents[1] / "hashmap-archive"


def run(op, data):
    out = BytesIO()
    op(BytesIO(data), out)
    return out.getvalue()


def group(n, frame, digests):
    return bytes([ar.EXTENDED]) + ar.GROUP_HEADER.pack(n, len(frame)) + frame + digests


class ArchiveTests(unittest.TestCase):
    def roundtrip(self, original):
        v1 = run(hmar.pack, original)
        v2 = run(ar.pack, original)
        self.assertLessEqual(len(v2), len(v1))
        self.assertEqual(run(ar.unpack, v1), original)
        self.assertEqual(run(ar.unpack, v2), original)
        return v2

    def test_wire_vector(self):
        # 16 one-byte keys, one repeated opaque value, no table index bits.
        flat = b"xy" * 8
        original = SHORT + b"".join(b"\xff\x01" + bytes([k]) for k in flat)
        expected = (b"HMARCH2\n" + SHORT + b"\x7f\x00\x10\x00\x00\x00\x13\x00\x00\x02" + flat
                    + b"\xfd\x00\x01\xff\x00" + sha256(original).digest())
        self.assertEqual(self.roundtrip(original), expected)
        for i in range(len(expected)):
            with self.subTest(cut=i), self.assertRaises(ValueError):
                run(ar.unpack, expected[:i])
        for bad in (expected + b"!", expected.replace(flat, flat[::-1]),
                    expected.replace(ar.MAGIC, hmar.MAGIC), expected.replace(ar.MAGIC, b"HMARCH3\n")):
            with self.assertRaises(ValueError):
                run(ar.unpack, bad)
        with self.assertRaises(hmar.FormatError):
            run(hmar.unpack, expected)  # old readers must not misinterpret extended blocks

    def test_boundaries_and_order(self):
        rng = random.Random(962)
        pool = [b"", b"\xff\0\n", b"salt not a header\n", b"0007", b"7", bytes(range(255))]
        for n in (0, 1, 63, 64, 65, 1023, 1024, 1025, 2049):
            keys = rng.choices(pool, k=n)
            # Repeated rows, one key with different values, and the same value
            # for different keys; a dictionary or sorting here would lose data.
            rows = [(k, sha256(k).digest() if i % 7 else bytes(32)) for i, k in enumerate(keys)]
            with self.subTest(rows=n):
                self.roundtrip(SHA + hmar.map_bytes(rows))

    def test_randomized_headers_and_fields(self):
        rng = random.Random(1729)
        headers = [SHORT, SHA, b"HMMAP 1\n", b"HMMAP 2\nalgo sha1\ndlen 7\n", OPAQUE]
        for trial in range(40):
            raw = headers[trial % len(headers)]
            header = hmar.read_header(BytesIO(raw))
            keys = [rng.randbytes(rng.randrange(18)) for _ in range(rng.randrange(2, 85))]
            rows = [(k, rng.randbytes(header.width) if header.algo == "bcrypt" or rng.randrange(4) == 0
                     else header.predict(k)) for k in keys]
            self.roundtrip(raw + hmar.map_bytes(rows))

    def test_legacy_tail(self):
        keys = [f"asset/part-{i:06d}".encode() for i in range(ar.GROUP)] + [b""]
        original = SHA + hmar.map_bytes([(k, sha256(k).digest()) for k in keys])
        src = BytesIO(self.roundtrip(original)[len(ar.MAGIC):])
        header = hmar.read_header(src)
        self.assertEqual(src.read(1), bytes([ar.EXTENDED]))
        ar.unpack_group(src, ar.EXTENDED, header)
        self.assertEqual(src.read(1), b"\x01")  # one-row HMARCH1 literal-key block

    def test_key_modes(self):
        examples = {
            ar.DIRECT: [sha256(bytes([i])).digest()[:8] for i in range(250)],
            ar.PREFIX: [b"assets/common/" + bytes([i]) * (1 + i % 19) for i in range(220)],
            ar.FULL_LENGTH: [f"asset/part-{i:06d}".encode() for i in range(256)],
            ar.ELIAS_FANO: [i.to_bytes(4, "big") for i in range(250)],
        }
        for mode, keys in examples.items():
            frame = ar.pack_keys(keys)
            self.assertEqual(frame[0], mode)
            self.assertEqual(ar.unpack_keys(frame, len(keys)), keys)
        # A repeated interior phrase, not just a prefix or restricted alphabet.
        keys = [bytes([i]) + b"/section-123/data/report/" + bytes([250-i]) for i in range(250)]
        frame = ar.pack_keys(keys)
        self.assertEqual(frame[:2], b"\x00\x01")  # direct + RSM1 canonical Huffman lane
        self.assertEqual(ar.unpack_keys(frame, len(keys)), keys)

    def test_digest_modes(self):
        header = hmar.read_header(BytesIO(SHA))
        keys = [i.to_bytes(2, "little") for i in range(257)]
        hits = [header.predict(k) for k in keys]
        opaque = [sha256(b"opaque" + k).digest() for k in keys]
        for mode, digests in [(0, hits), (hmar.LITERAL, opaque),
                              (ar.SUBBLOCKS, [d if i % 64 else opaque[i] for i, d in enumerate(hits)]),
                              (ar.TABLE, [opaque[i % 3] for i in range(len(keys))]),
                              (ar.TABLE, [opaque[i % 200] for i in range(len(keys))])]:
            rows = list(zip(keys, digests, strict=True))
            parts = [hmar.pack_digests(rows[i:i+64], header) for i in range(0, len(rows), 64)]
            lane = ar.digest_lane(rows, header.width, parts)
            self.assertEqual(lane[0], mode)
            inp = BytesIO(lane)
            self.assertEqual(ar.read_digests(inp, keys, header), digests)
            self.assertEqual(inp.read(), b"")
        self.assertEqual(ar.index_layout(len(keys), 3)[1], 0)  # dense indices
        self.assertGreater(ar.index_layout(len(keys), 200)[1], 0)  # first occurrences implied

    def test_reject_invalid_groups(self):
        def bad(body, header=SHORT):
            with self.assertRaises(ValueError):
                run(ar.unpack, ar.MAGIC + header + body + b"\0" + bytes(32))

        for n, size in [(0, 1), (ar.GROUP+1, 1), (1, 0), (1, 262)]:
            with self.assertRaisesRegex(hmar.FormatError, "frame size"):
                run(ar.unpack, ar.MAGIC + SHORT + b"\x7f" + ar.GROUP_HEADER.pack(n, size))
        # No huge allocation/inflation from a claimed field length, even if
        # the outer frame is short. Check before decoding the Huffman model.
        for codec in (0, 1):
            with self.assertRaisesRegex(ValueError, "field length exceeds limit"):
                run(ar.unpack, ar.MAGIC + SHORT + group(1, bytes([ar.DIRECT, codec]) + rsm.uv(2**63), b""))
        for frame in (b"\xff", b"\x01\x00\x02\x00\x01",  # prefix longer than anchor
                      b"\x03\x00\x01\x00\x02a",          # full length < suffix length
                      b"\x01\xff" + bytes(255) + rsm.uv(256) + b"\x00\x02a"):  # >255 total
            with self.assertRaises(ValueError):
                ar.unpack_keys(frame, 2)
        bad(group(2, b"\x00\x00\x01", b"\x00"), OPAQUE)  # cannot predict bcrypt
        for mode in (b"\xfc", b"\xfe\x03", b"\xfd\x00\x00", b"\xfd\x00\x03"):
            bad(group(2, b"\x00\x00\x01", mode))

    def test_table_validation(self):
        header = hmar.read_header(BytesIO(SHORT))
        # Dense 3-entry table: index 3 invalid; final padding must be zero.
        for packed in (b"\xc0", b"\x19"):
            with self.assertRaises(ValueError):
                ar.read_digests(BytesIO(b"\xfd\x00\x03abc" + packed), [b""] * 3, header)
        # n=9, count=8: 2-byte bitmap + a single 3-bit reference. The
        # reference must point backwards, and exactly eight entries must open.
        for mask in (b"\x01\x00", b"\x00\x03", b"\x00\x00", b"\xc0\x00"):
            with self.assertRaises(ValueError):
                ar.read_digests(BytesIO(b"\xfd\x00\x08abcdefgh" + mask + b"\x00"), [b""] * 9, header)

    def test_dense_table_requires_first_occurrence_order(self):
        header = hmar.read_header(BytesIO(SHORT))
        # n=3, count=3, dense 2-bit indices: canonical first-occurrence [0,1,2].
        lane = b"\xfd\x00\x03abc" + b"\x18"
        inp = BytesIO(lane)
        self.assertEqual(ar.read_digests(inp, [b""] * 3, header), [b"a", b"b", b"c"])
        self.assertEqual(inp.read(), b"")
        # [1,0,...] reorders the table and silently restores the wrong rows.
        with self.assertRaises(ValueError):
            ar.read_digests(BytesIO(b"\xfd\x00\x03abc" + b"\x44"), [b""] * 3, header)
        # A table entry that is never referenced must also be rejected.
        with self.assertRaises(ValueError):
            ar.read_digests(BytesIO(b"\xfd\x00\x03abc" + b"\x10"), [b""] * 3, header)

    def test_cli_staging_and_versions(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src, packed, restored = (root / s for s in ("input map", "archive", "output"))
            src.write_bytes(SHA + hmar.map_bytes([(b"asset", bytes(32))] * 256))

            def cli(*args, ok=True):
                result = subprocess.run([EXE, *args], cwd=d, capture_output=True)
                self.assertEqual(result.returncode, 0 if ok else 1, result.stderr)

            for flags, magic in [((), ar.MAGIC), (("--legacy",), hmar.MAGIC)]:
                cli("pack", *flags, src, packed)
                self.assertTrue(packed.read_bytes().startswith(magic))
                cli("unpack", packed, restored)
                self.assertEqual(restored.read_bytes(), src.read_bytes())
                packed.unlink()
                restored.unlink()
            cli("pack", src, packed)
            cli("unpack", packed, src, ok=False)  # existing source is not overwritten
            packed.write_bytes(packed.read_bytes()[:-1] + bytes([packed.read_bytes()[-1] ^ 1]))
            cli("unpack", packed, restored, ok=False)
            src.write_bytes(SHA + bytes(31))
            cli("pack", src, restored, ok=False)
            self.assertEqual(set(root.iterdir()), {packed, src})


BIN = EXE.with_name("hashmap")


@unittest.skipUnless(BIN.exists() and EXE.exists(), "needs the C binary and the zipapp")
class ToolArchiveTests(unittest.TestCase):
    """The C tool's --archive flag packs map output through the companion."""

    def run_tool(self, *args, env_tool=str(EXE)):
        import os
        env = dict(os.environ, HM_ARCHIVE=env_tool)
        return subprocess.run([str(BIN), *args], env=env, capture_output=True)

    def test_map_archive_roundtrip_and_staging(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            dest, state = root / "digs.hmar", root / "run.state"
            result = self.run_tool("map", "-o", str(dest), "--archive", "-c", "digits",
                                   "--min", "1", "--max", "2", "--state", str(state))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(dest.exists())
            self.assertFalse((root / "digs.hmar.hmmap.tmp").exists())  # staging removed
            self.assertFalse(state.exists())                           # finished run cleans up

            restored = root / "restored.hmmap"
            self.assertEqual(subprocess.run([str(EXE), "unpack", str(dest), str(restored)],
                                            capture_output=True).returncode, 0)
            data = restored.read_bytes()
            stream = BytesIO(data)
            header = hmar.read_header(stream)
            rows = list(hmar.read_rows(stream, header.width))
            self.assertEqual(len(rows), 110)  # digits 1..2 long
            self.assertIn((b"42", hashlib.md5(b"42").digest()), rows)

            again = self.run_tool("map", "-o", str(dest), "--archive", "-c", "digits",
                                  "--max", "2", "--state", str(root / "two.state"))
            self.assertEqual(again.returncode, 2)      # never overwrite an archive
            self.assertIn(b"never overwritten", again.stderr)

    def test_map_archive_missing_companion_keeps_map(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            dest = root / "digs.hmar"
            result = self.run_tool("map", "-o", str(dest), "--archive", "-c", "digits",
                                   "--max", "2", "--state", str(root / "run.state"),
                                   env_tool="/nonexistent/hashmap-archive")
            self.assertEqual(result.returncode, 1)
            self.assertFalse(dest.exists())
            self.assertIn(b"not found", result.stderr)
            staging = root / "digs.hmar.hmmap.tmp"
            self.assertTrue(staging.exists())          # the complete map survives
            packed, out = root / "late.hmar", root / "late.hmmap"
            self.assertEqual(subprocess.run([str(EXE), "pack", str(staging), str(packed)],
                                            capture_output=True).returncode, 0)
            self.assertEqual(subprocess.run([str(EXE), "unpack", str(packed), str(out)],
                                            capture_output=True).returncode, 0)
            self.assertEqual(out.read_bytes(), staging.read_bytes())


if __name__ == "__main__":
    unittest.main()
