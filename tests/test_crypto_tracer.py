# Developer: pendatkill
# Module: tests.test_crypto_tracer
# Description: Unit tests for CryptoTracer covering hashing, entropy, encryption detection, and steganography hints

import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from PIL import Image
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

from crypto_tracer.tracer import CryptoTracer


class TestCryptoTracerHashFile(unittest.TestCase):

    def setUp(self):
        self.tracer = CryptoTracer()
        self.tmpdir = tempfile.mkdtemp()

    def _write_temp(self, content: bytes, suffix: str = ".bin") -> str:
        path = os.path.join(self.tmpdir, f"test{suffix}")
        with open(path, "wb") as fh:
            fh.write(content)
        return path

    # ------------------------------------------------------------------
    # hash_file()
    # ------------------------------------------------------------------

    def test_hash_file_returns_expected_keys(self):
        path = self._write_temp(b"hello")
        result = self.tracer.hash_file(path)
        for key in ("md5", "sha1", "sha256", "sha512"):
            self.assertIn(key, result)

    def test_hash_file_md5_correct(self):
        data = b"pendatkill"
        path = self._write_temp(data)
        result = self.tracer.hash_file(path)
        self.assertEqual(result["md5"], hashlib.md5(data).hexdigest())

    def test_hash_file_sha256_correct(self):
        data = b"test sha256 data"
        path = self._write_temp(data)
        result = self.tracer.hash_file(path)
        self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())

    def test_hash_file_sha512_correct(self):
        data = b"sha512 check"
        path = self._write_temp(data)
        result = self.tracer.hash_file(path)
        self.assertEqual(result["sha512"], hashlib.sha512(data).hexdigest())

    def test_hash_file_returns_hex_strings(self):
        path = self._write_temp(b"hex check")
        result = self.tracer.hash_file(path)
        for key, val in result.items():
            self.assertRegex(val, r"^[0-9a-f]+$", f"{key} is not a valid hex string")

    def test_hash_file_missing_file_returns_empty(self):
        result = self.tracer.hash_file("/no/such/file.bin")
        self.assertEqual(result, {})

    # ------------------------------------------------------------------
    # measure_entropy()
    # ------------------------------------------------------------------

    def test_entropy_all_zeros_is_zero(self):
        entropy = self.tracer.measure_entropy(b"\x00" * 1000)
        self.assertAlmostEqual(entropy, 0.0, places=5)

    def test_entropy_all_same_is_zero(self):
        entropy = self.tracer.measure_entropy(b"\xAA" * 500)
        self.assertAlmostEqual(entropy, 0.0, places=5)

    def test_entropy_diverse_bytes_is_high(self):
        # All 256 byte values equally → entropy = 8.0
        data = bytes(range(256)) * 4
        entropy = self.tracer.measure_entropy(data)
        self.assertGreater(entropy, 6.0)

    def test_entropy_random_data_is_high(self):
        data = os.urandom(2048)
        entropy = self.tracer.measure_entropy(data)
        self.assertGreater(entropy, 6.0)

    def test_entropy_empty_bytes_is_zero(self):
        entropy = self.tracer.measure_entropy(b"")
        self.assertAlmostEqual(entropy, 0.0, places=5)

    def test_entropy_two_symbols(self):
        data = bytes([0x00, 0xFF] * 500)
        entropy = self.tracer.measure_entropy(data)
        self.assertAlmostEqual(entropy, 1.0, places=5)

    # ------------------------------------------------------------------
    # detect_encryption_signature()
    # ------------------------------------------------------------------

    def _finding_text(self, f) -> str:
        """Normalise a finding to a searchable string (handles str or dict)."""
        if isinstance(f, dict):
            return (f.get("type", "") + " " + f.get("detail", "")).lower()
        return str(f).lower()

    def test_detect_pgp_ascii_armor(self):
        data = b"-----BEGIN PGP MESSAGE-----\nVersion: GnuPG v2\n\nhQIMA..."
        path = self._write_temp(data, suffix=".asc")
        findings = self.tracer.detect_encryption_signature(path)
        self.assertIsInstance(findings, list)
        self.assertTrue(
            any("pgp" in self._finding_text(f) for f in findings),
            f"Expected PGP finding, got: {findings}"
        )

    def test_detect_openssl_salted(self):
        data = b"Salted__" + b"\x00" * 504
        path = self._write_temp(data, suffix=".enc")
        findings = self.tracer.detect_encryption_signature(path)
        self.assertTrue(
            any("openssl" in self._finding_text(f) or "salted" in self._finding_text(f)
                for f in findings),
            f"Expected OpenSSL finding, got: {findings}"
        )

    def test_detect_plain_text_no_findings(self):
        data = b"Hello, this is a normal text file with no encryption."
        path = self._write_temp(data, suffix=".txt")
        findings = self.tracer.detect_encryption_signature(path)
        # Plain ASCII text should be low entropy — no high-entropy finding
        high_entropy_findings = [f for f in findings if "entropy" in self._finding_text(f)]
        self.assertEqual(
            high_entropy_findings, [],
            f"Unexpected entropy finding on plain text: {findings}"
        )

    def test_detect_high_entropy_data(self):
        data = os.urandom(512)
        path = self._write_temp(data, suffix=".bin")
        findings = self.tracer.detect_encryption_signature(path)
        self.assertTrue(
            any("entropy" in self._finding_text(f) or "encrypted" in self._finding_text(f)
                for f in findings),
            f"Expected high-entropy finding, got: {findings}"
        )

    def test_detect_missing_file_returns_empty(self):
        findings = self.tracer.detect_encryption_signature("/no/such/file.bin")
        self.assertEqual(findings, [])

    # ------------------------------------------------------------------
    # check_steganography_hints()
    # ------------------------------------------------------------------

    @unittest.skipUnless(PILLOW_AVAILABLE, "Pillow not installed")
    def test_stego_hints_on_plain_png(self):
        """A freshly generated solid-colour PNG should have low suspicion."""
        img = Image.new("RGB", (100, 100), color=(128, 200, 100))
        path = os.path.join(self.tmpdir, "plain.png")
        img.save(path, format="PNG")

        result = self.tracer.check_steganography_hints(path)

        self.assertIn("suspicion_score", result)
        self.assertIn("reasons", result)
        self.assertIn("supported", result)
        self.assertTrue(result["supported"])
        self.assertIsInstance(result["suspicion_score"], float)
        self.assertGreaterEqual(result["suspicion_score"], 0.0)
        self.assertLessEqual(result["suspicion_score"], 1.0)

    @unittest.skipUnless(PILLOW_AVAILABLE, "Pillow not installed")
    def test_stego_hints_unsupported_format(self):
        path = self._write_temp(b"fake data", suffix=".gif")
        result = self.tracer.check_steganography_hints(path)
        self.assertFalse(result["supported"])

    def test_stego_hints_missing_file(self):
        result = self.tracer.check_steganography_hints("/no/such/image.png")
        self.assertIn("suspicion_score", result)
        self.assertIn("reasons", result)


if __name__ == "__main__":
    unittest.main()
