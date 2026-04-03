# Developer: pendatkill
# Module: tests.test_file_forensics
# Description: Unit tests for FileForensics using temp files and in-memory data

import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from file_forensics.forensics import FileForensics, FITZ_AVAILABLE


class TestFileForensicsAnalyze(unittest.TestCase):

    def setUp(self):
        self.forensics = FileForensics()
        self.tmpdir = tempfile.mkdtemp()

    def _write_temp(self, content: bytes, suffix: str = ".txt") -> str:
        path = os.path.join(self.tmpdir, f"test{suffix}")
        with open(path, "wb") as fh:
            fh.write(content)
        return path

    # ------------------------------------------------------------------
    # analyze()
    # ------------------------------------------------------------------

    def test_analyze_returns_expected_keys(self):
        path = self._write_temp(b"hello world")
        result = self.forensics.analyze(path)
        for key in ("filename", "size", "mime_type", "created", "modified", "md5", "sha256"):
            self.assertIn(key, result, f"Key '{key}' missing from analyze() result")

    def test_analyze_correct_size(self):
        data = b"A" * 512
        path = self._write_temp(data)
        result = self.forensics.analyze(path)
        self.assertEqual(result["size"], 512)

    def test_analyze_correct_md5(self):
        data = b"pendatkill test data"
        path = self._write_temp(data)
        expected_md5 = hashlib.md5(data).hexdigest()
        result = self.forensics.analyze(path)
        self.assertEqual(result["md5"], expected_md5)

    def test_analyze_correct_sha256(self):
        data = b"pendatkill sha256 check"
        path = self._write_temp(data)
        expected_sha256 = hashlib.sha256(data).hexdigest()
        result = self.forensics.analyze(path)
        self.assertEqual(result["sha256"], expected_sha256)

    def test_analyze_filename(self):
        path = self._write_temp(b"data", suffix=".txt")
        result = self.forensics.analyze(path)
        self.assertEqual(result["filename"], os.path.basename(path))

    def test_analyze_missing_file_returns_empty(self):
        result = self.forensics.analyze("/no/such/file.txt")
        self.assertEqual(result, {})

    def test_analyze_mime_type_text(self):
        path = self._write_temp(b"some text", suffix=".txt")
        result = self.forensics.analyze(path)
        self.assertIn("text", result["mime_type"])

    # ------------------------------------------------------------------
    # compute_entropy()
    # ------------------------------------------------------------------

    def test_entropy_all_zeros_is_zero(self):
        path = self._write_temp(b"\x00" * 1000)
        entropy = self.forensics.compute_entropy(path)
        self.assertAlmostEqual(entropy, 0.0, places=5)

    def test_entropy_all_same_byte_is_zero(self):
        path = self._write_temp(b"\xff" * 500)
        entropy = self.forensics.compute_entropy(path)
        self.assertAlmostEqual(entropy, 0.0, places=5)

    def test_entropy_random_bytes_is_high(self):
        import os as _os
        data = _os.urandom(4096)
        path = self._write_temp(data)
        entropy = self.forensics.compute_entropy(path)
        # Random data should have entropy close to 8
        self.assertGreater(entropy, 6.0)

    def test_entropy_two_byte_alternating(self):
        data = bytes([0x00, 0xFF] * 500)
        path = self._write_temp(data)
        entropy = self.forensics.compute_entropy(path)
        # Two equally probable symbols → entropy = 1 bit/byte... wait,
        # Shannon entropy over 256 symbols: only two non-zero, each 0.5 → 1.0 bit
        self.assertAlmostEqual(entropy, 1.0, places=5)

    def test_entropy_empty_file_is_zero(self):
        path = self._write_temp(b"")
        entropy = self.forensics.compute_entropy(path)
        self.assertAlmostEqual(entropy, 0.0, places=5)

    def test_entropy_missing_file_is_zero(self):
        entropy = self.forensics.compute_entropy("/no/such/file.bin")
        self.assertAlmostEqual(entropy, 0.0, places=5)

    # ------------------------------------------------------------------
    # get_pdf_metadata()
    # ------------------------------------------------------------------

    @unittest.skipIf(FITZ_AVAILABLE, "PyMuPDF is installed; skip graceful-skip test")
    def test_get_pdf_metadata_returns_empty_without_fitz(self):
        path = self._write_temp(b"%PDF-1.4 fake", suffix=".pdf")
        result = self.forensics.get_pdf_metadata(path)
        self.assertIsInstance(result, dict)
        self.assertEqual(result, {})

    def test_get_pdf_metadata_missing_file_returns_empty(self):
        result = self.forensics.get_pdf_metadata("/no/such/file.pdf")
        self.assertIsInstance(result, dict)
        self.assertEqual(result, {})

    # ------------------------------------------------------------------
    # get_office_metadata()
    # ------------------------------------------------------------------

    def test_get_office_metadata_unsupported_ext_returns_empty(self):
        path = self._write_temp(b"dummy", suffix=".txt")
        result = self.forensics.get_office_metadata(path)
        self.assertIsInstance(result, dict)
        self.assertEqual(result, {})

    def test_get_office_metadata_missing_file_returns_empty(self):
        result = self.forensics.get_office_metadata("/no/such/file.docx")
        self.assertIsInstance(result, dict)
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()
