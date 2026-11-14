"""Test publication checks for embedded metadata and unsafe links without exposing values."""
import base64
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
import urllib.parse
import zlib

spec = importlib.util.spec_from_file_location("publication", Path(__file__).parents[1] / "check_publication.py")
publication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publication)


def png(text):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"tEXt", b"mxfile\0" + text.encode()) + chunk(b"IEND", b"")


class PublicationTests(unittest.TestCase):
    def test_compressed_diagram_is_scanned_without_disclosing_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            value = "AK" + "IA" + "A" * 16
            xml = f'<mxGraphModel><root><mxCell value="{value}"/></root></mxGraphModel>'
            compressor = zlib.compressobj(wbits=-15)
            compressed = compressor.compress(urllib.parse.quote(xml).encode()) + compressor.flush()
            text = f"<mxfile><diagram>{base64.b64encode(compressed).decode()}</diagram></mxfile>"
            (root / "docs/figure.png").write_bytes(png(text))
            result = publication.scan(root)
            self.assertIn({"path": "docs/figure.png", "rule": "aws-access-key"}, result["findings"])
            self.assertNotIn(value, str(result))

    def test_links_and_symlinks_must_stay_inside(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("[missing](missing.md)\n[outside](../outside.md)\n")
            (root / "link").symlink_to("/etc/hostname")
            rules = [x["rule"] for x in publication.scan(root)["findings"]]
            self.assertEqual(rules.count("missing-or-outside-link"), 2)
            self.assertIn("symlink", rules)

    def test_private_artifacts_fail_and_build_directories_are_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            (root / "docs/test.log").write_text("private")
            (root / "target").mkdir()
            (root / "target/test.key").write_text("build artifact")
            result = publication.scan(root)
            self.assertEqual(result["files_checked"], 1)
            self.assertEqual(result["findings"], [{"path": "docs/test.log", "rule": "private-artifact"}])


if __name__ == "__main__":
    unittest.main()
