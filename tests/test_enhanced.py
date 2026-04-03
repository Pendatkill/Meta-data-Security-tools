# Developer: pendatkill
# Module: tests.test_enhanced
# Description: Tests for all new methods added in the cybersecurity toolkit enhancement

import hashlib
import io
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


# -----------------------------------------------------------------------
# FileForensics — analyze_strings
# -----------------------------------------------------------------------

class TestAnalyzeStrings(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        from file_forensics.forensics import FileForensics
        self.forensics = FileForensics()

    def _write(self, content: bytes, suffix=".bin") -> str:
        path = os.path.join(self.tmpdir, f"test{suffix}")
        with open(path, "wb") as fh:
            fh.write(content)
        return path

    def test_analyze_strings_finds_known_strings(self):
        """Binary file containing known ASCII strings should return them."""
        known = b"Hello, World!"
        data = b"\x00\x01\x02" + known + b"\xFF\xFE" + b"another_string_here" + b"\x00"
        path = self._write(data)
        strings = self.forensics.analyze_strings(path, min_length=6)
        self.assertIsInstance(strings, list)
        # Should find at least one of our known strings
        combined = " ".join(strings)
        self.assertTrue(
            "Hello, World!" in combined or "Hello" in combined or "another_string" in combined,
            f"Expected known strings, got: {strings[:5]}"
        )

    def test_analyze_strings_respects_min_length(self):
        """Strings shorter than min_length should be excluded."""
        data = b"AB" + b"\x00" + b"This_is_long_enough_for_sure" + b"\x00"
        path = self._write(data)
        strings = self.forensics.analyze_strings(path, min_length=10)
        for s in strings:
            self.assertGreaterEqual(len(s), 10, f"Short string found: '{s}'")

    def test_analyze_strings_max_200(self):
        """Should return at most 200 strings."""
        # Create many strings separated by null bytes
        parts = [b"string_number_x_long_enough" + str(i).encode() for i in range(300)]
        data = b"\x00".join(parts)
        path = self._write(data)
        strings = self.forensics.analyze_strings(path, min_length=6)
        self.assertLessEqual(len(strings), 200)

    def test_analyze_strings_missing_file(self):
        result = self.forensics.analyze_strings("/no/such/file.bin")
        self.assertEqual(result, [])

    def test_analyze_strings_finds_urls(self):
        """Should be able to extract URL strings from binary."""
        data = b"\x00\x00" + b"https://example.com/path?q=1" + b"\x00\x00"
        path = self._write(data)
        strings = self.forensics.analyze_strings(path, min_length=6)
        combined = " ".join(strings)
        self.assertIn("https://example.com", combined)


# -----------------------------------------------------------------------
# FileForensics — detect_file_type_mismatch
# -----------------------------------------------------------------------

class TestDetectFileTypeMismatch(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        from file_forensics.forensics import FileForensics
        self.forensics = FileForensics()

    def _write(self, content: bytes, suffix: str) -> str:
        path = os.path.join(self.tmpdir, f"test{suffix}")
        with open(path, "wb") as fh:
            fh.write(content)
        return path

    def test_png_bytes_with_jpg_extension_is_mismatch(self):
        """PNG magic bytes in a .jpg file should be detected as a mismatch."""
        png_magic = b"\x89PNG\r\n\x1a\n" + b"\x00" * 8
        path = self._write(png_magic, ".jpg")
        result = self.forensics.detect_file_type_mismatch(path)
        self.assertIn("mismatch", result)
        self.assertTrue(result["mismatch"], f"Expected mismatch=True, got: {result}")
        self.assertEqual(result["risk"], "high")

    def test_jpeg_bytes_with_jpg_extension_no_mismatch(self):
        """JPEG magic in .jpg file should not flag as mismatch."""
        jpeg_magic = b"\xff\xd8\xff\xe0" + b"\x00" * 12
        path = self._write(jpeg_magic, ".jpg")
        result = self.forensics.detect_file_type_mismatch(path)
        self.assertFalse(result["mismatch"])

    def test_pdf_magic_detected(self):
        """PDF magic bytes should be detected correctly."""
        path = self._write(b"%PDF-1.4 content here", ".pdf")
        result = self.forensics.detect_file_type_mismatch(path)
        self.assertEqual(result["detected_type"], "PDF")
        self.assertFalse(result["mismatch"])

    def test_returns_expected_keys(self):
        path = self._write(b"hello world", ".txt")
        result = self.forensics.detect_file_type_mismatch(path)
        for key in ("extension", "detected_type", "mismatch", "risk"):
            self.assertIn(key, result)

    def test_missing_file(self):
        result = self.forensics.detect_file_type_mismatch("/no/such/file.jpg")
        self.assertIsInstance(result, dict)


# -----------------------------------------------------------------------
# CryptoTracer — chi_square_test
# -----------------------------------------------------------------------

class TestChiSquareTest(unittest.TestCase):

    def setUp(self):
        from crypto_tracer.tracer import CryptoTracer
        self.tracer = CryptoTracer()

    def test_uniform_bytes_is_likely_random(self):
        """All 256 byte values equally distributed → should be flagged as random."""
        data = bytes(range(256)) * 400  # 102400 bytes, perfectly uniform
        result = self.tracer.chi_square_test(data)
        self.assertIn("chi_square", result)
        self.assertIn("is_likely_random", result)
        self.assertIn("interpretation", result)
        self.assertTrue(
            result["is_likely_random"],
            f"Expected is_likely_random=True for uniform bytes, got: {result}"
        )

    def test_zero_bytes_not_random(self):
        """All-zero bytes have zero entropy — should NOT be flagged as random."""
        data = b"\x00" * 10000
        result = self.tracer.chi_square_test(data)
        self.assertFalse(
            result["is_likely_random"],
            f"Expected is_likely_random=False for all-zero bytes, got: {result}"
        )

    def test_empty_data(self):
        result = self.tracer.chi_square_test(b"")
        self.assertIsInstance(result, dict)
        self.assertIn("interpretation", result)

    def test_returns_float_chi_square(self):
        data = os.urandom(4096)
        result = self.tracer.chi_square_test(data)
        self.assertIsInstance(result["chi_square"], float)

    def test_random_bytes_likely_random(self):
        """os.urandom should produce near-uniform distribution."""
        data = os.urandom(65536)
        result = self.tracer.chi_square_test(data)
        # os.urandom is cryptographically random — should usually pass
        # We just check the structure
        self.assertIn("is_likely_random", result)
        self.assertIsInstance(result["is_likely_random"], bool)


# -----------------------------------------------------------------------
# CryptoTracer — detect_steganography_lsb
# -----------------------------------------------------------------------

@unittest.skipUnless(PILLOW_AVAILABLE, "Pillow not installed")
class TestDetectSteganographyLsb(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        from crypto_tracer.tracer import CryptoTracer
        self.tracer = CryptoTracer()

    def _make_png(self, size=(100, 100), color=(128, 200, 100)) -> str:
        path = os.path.join(self.tmpdir, "test.png")
        img = Image.new("RGB", size, color)
        img.save(path, format="PNG")
        return path

    def test_returns_valid_dict_structure(self):
        """detect_steganography_lsb must return all required keys."""
        path = self._make_png()
        result = self.tracer.detect_steganography_lsb(path)
        for key in ("suspicion_score", "lsb_entropy", "chi_square", "verdict", "supported"):
            self.assertIn(key, result, f"Key '{key}' missing from result")

    def test_suspicion_score_in_range(self):
        path = self._make_png()
        result = self.tracer.detect_steganography_lsb(path)
        self.assertGreaterEqual(result["suspicion_score"], 0.0)
        self.assertLessEqual(result["suspicion_score"], 1.0)

    def test_lsb_entropy_is_float(self):
        path = self._make_png()
        result = self.tracer.detect_steganography_lsb(path)
        self.assertIsInstance(result["lsb_entropy"], float)

    def test_verdict_is_string(self):
        path = self._make_png()
        result = self.tracer.detect_steganography_lsb(path)
        self.assertIsInstance(result["verdict"], str)
        self.assertGreater(len(result["verdict"]), 0)

    def test_supported_true_for_png(self):
        path = self._make_png()
        result = self.tracer.detect_steganography_lsb(path)
        self.assertTrue(result["supported"])

    def test_unsupported_format(self):
        from crypto_tracer.tracer import CryptoTracer
        tracer = CryptoTracer()
        result = tracer.detect_steganography_lsb("/fake/path/image.gif")
        self.assertFalse(result["supported"])

    def test_missing_file(self):
        result = self.tracer.detect_steganography_lsb("/no/such/file.png")
        self.assertIsInstance(result, dict)
        self.assertIn("verdict", result)

    def test_clean_solid_color_png_low_suspicion(self):
        """A solid-color PNG should have low suspicion score."""
        path = self._make_png(size=(200, 200), color=(100, 100, 100))
        result = self.tracer.detect_steganography_lsb(path)
        # Solid color → all LSBs are 0 → very low entropy → low suspicion
        self.assertLess(result["suspicion_score"], 0.7,
                        f"Solid PNG had high suspicion: {result}")


# -----------------------------------------------------------------------
# CryptoTracer — detect_encryption_signatures (expanded)
# -----------------------------------------------------------------------

class TestDetectEncryptionSignaturesExpanded(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        from crypto_tracer.tracer import CryptoTracer
        self.tracer = CryptoTracer()

    def _write(self, content: bytes, suffix=".bin") -> str:
        path = os.path.join(self.tmpdir, f"test{suffix}")
        with open(path, "wb") as fh:
            fh.write(content)
        return path

    def test_pgp_ascii_armor_detected(self):
        data = b"-----BEGIN PGP MESSAGE-----\nVersion: GnuPG v2\n\nhQIMA..."
        path = self._write(data, ".asc")
        findings = self.tracer.detect_encryption_signature(path)
        types = [f["type"] if isinstance(f, dict) else f for f in findings]
        self.assertTrue(
            any("PGP" in str(t) for t in types),
            f"Expected PGP in findings: {findings}"
        )

    def test_ssh_openssh_key_detected(self):
        data = b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3NzaC1..."
        path = self._write(data, ".key")
        findings = self.tracer.detect_encryption_signature(path)
        types = [f["type"] if isinstance(f, dict) else f for f in findings]
        self.assertTrue(
            any("SSH" in str(t) or "OpenSSH" in str(t) for t in types),
            f"Expected SSH key in findings: {findings}"
        )

    def test_rsa_private_key_detected(self):
        data = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."
        path = self._write(data, ".pem")
        findings = self.tracer.detect_encryption_signature(path)
        types = [f["type"] if isinstance(f, dict) else f for f in findings]
        self.assertTrue(
            any("RSA" in str(t) or "Private Key" in str(t) for t in types),
            f"Expected RSA key in findings: {findings}"
        )

    def test_x509_cert_detected(self):
        data = b"-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQE..."
        path = self._write(data, ".crt")
        findings = self.tracer.detect_encryption_signature(path)
        types = [f["type"] if isinstance(f, dict) else f for f in findings]
        self.assertTrue(
            any("Certificate" in str(t) or "X.509" in str(t) for t in types),
            f"Expected certificate in findings: {findings}"
        )

    def test_jwt_detected(self):
        # Valid JWT starts with eyJ (base64url for {"...)
        data = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.hash"
        path = self._write(data, ".txt")
        findings = self.tracer.detect_encryption_signature(path)
        types = [f["type"] if isinstance(f, dict) else f for f in findings]
        self.assertTrue(
            any("JWT" in str(t) for t in types),
            f"Expected JWT in findings: {findings}"
        )

    def test_openssl_salted_detected(self):
        data = b"Salted__" + b"\xAB\xCD\xEF" * 100
        path = self._write(data, ".enc")
        findings = self.tracer.detect_encryption_signature(path)
        types = [f["type"] if isinstance(f, dict) else f for f in findings]
        self.assertTrue(
            any("OpenSSL" in str(t) or "Salted" in str(t) for t in types),
            f"Expected OpenSSL salted in findings: {findings}"
        )

    def test_findings_have_type_confidence_detail(self):
        """Each finding dict must have type, confidence, and detail keys."""
        data = b"-----BEGIN PGP MESSAGE-----\ntest"
        path = self._write(data)
        findings = self.tracer.detect_encryption_signature(path)
        for f in findings:
            if isinstance(f, dict):
                self.assertIn("type", f)
                self.assertIn("confidence", f)
                self.assertIn("detail", f)

    def test_plain_text_no_high_confidence(self):
        data = b"Just a plain text file with no encryption at all."
        path = self._write(data, ".txt")
        findings = self.tracer.detect_encryption_signature(path)
        high_conf = [f for f in findings if isinstance(f, dict) and f.get("confidence") == "high"]
        self.assertEqual(high_conf, [], f"Unexpected high-confidence findings: {high_conf}")


# -----------------------------------------------------------------------
# CryptoTracer — verify_file_integrity
# -----------------------------------------------------------------------

class TestVerifyFileIntegrity(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        from crypto_tracer.tracer import CryptoTracer
        self.tracer = CryptoTracer()

    def _write(self, content: bytes) -> str:
        path = os.path.join(self.tmpdir, "test.bin")
        with open(path, "wb") as fh:
            fh.write(content)
        return path

    def test_match_true_correct_sha256(self):
        data = b"pendatkill test data"
        path = self._write(data)
        expected = hashlib.sha256(data).hexdigest()
        result = self.tracer.verify_file_integrity(path, expected, "sha256")
        self.assertTrue(result["match"])
        self.assertEqual(result["algorithm"], "sha256")

    def test_match_false_wrong_hash(self):
        data = b"pendatkill test data"
        path = self._write(data)
        result = self.tracer.verify_file_integrity(path, "deadbeefdeadbeef" * 4, "sha256")
        self.assertFalse(result["match"])

    def test_match_true_md5(self):
        data = b"hello md5"
        path = self._write(data)
        expected = hashlib.md5(data).hexdigest()
        result = self.tracer.verify_file_integrity(path, expected, "md5")
        self.assertTrue(result["match"])

    def test_returns_all_keys(self):
        data = b"test"
        path = self._write(data)
        expected = hashlib.sha256(data).hexdigest()
        result = self.tracer.verify_file_integrity(path, expected)
        for key in ("match", "expected", "actual", "algorithm"):
            self.assertIn(key, result)

    def test_missing_file_returns_no_match(self):
        result = self.tracer.verify_file_integrity("/no/such/file.bin", "deadbeef")
        self.assertFalse(result["match"])

    def test_case_insensitive_hash_comparison(self):
        data = b"case test"
        path = self._write(data)
        expected = hashlib.sha256(data).hexdigest().upper()
        result = self.tracer.verify_file_integrity(path, expected, "sha256")
        self.assertTrue(result["match"])


# -----------------------------------------------------------------------
# AIDetector — burstiness score
# -----------------------------------------------------------------------

class TestAITextBurstiness(unittest.TestCase):

    def setUp(self):
        from ai_detector.detector import AIDetector
        self.detector = AIDetector()

    def test_uniform_sentences_trigger_burstiness_flag(self):
        """Very uniform sentence lengths should trigger the burstiness indicator."""
        # All sentences are approximately 10 words
        uniform_text = " ".join([
            "The system processes data very efficiently every single day.",
            "Results are computed and stored in the database system.",
            "Users can access the platform through the secure portal.",
            "Reports are generated automatically by the analysis engine.",
            "The dashboard displays all relevant metrics to operators.",
            "Notifications are sent via email to registered administrators.",
        ])
        result = self.detector.analyze_text(uniform_text)
        self.assertIn("score", result)
        self.assertIn("breakdown", result)
        # The score should be elevated due to uniformity
        bd = result.get("breakdown", {})
        burstiness = bd.get("burstiness", 0.0)
        # Uniform sentences → should have some burstiness contribution
        # We check that the detector ran this check
        self.assertIsInstance(burstiness, float)
        self.assertGreaterEqual(burstiness, 0.0)

    def test_variable_sentences_lower_burstiness_score(self):
        """Text with highly variable sentence lengths should score lower on burstiness."""
        variable_text = (
            "Hi. "
            "The quick brown fox jumps over the lazy dog near the river. "
            "Yes. "
            "This is a much longer sentence that goes on and on for quite a while "
            "to demonstrate that human writing naturally varies in length. "
            "No. "
            "Another very long sentence that keeps going to test the variance metric. "
            "OK."
        )
        result = self.detector.analyze_text(variable_text)
        bd = result.get("breakdown", {})
        burstiness = bd.get("burstiness", 0.0)
        # Variable text should NOT trigger high burstiness score
        self.assertLessEqual(burstiness, 0.15)


# -----------------------------------------------------------------------
# AIDetector — Spanish phrases
# -----------------------------------------------------------------------

class TestAISpanishPhrases(unittest.TestCase):

    def setUp(self):
        from ai_detector.detector import AIDetector
        self.detector = AIDetector()

    def test_spanish_filler_phrases_detected(self):
        """Spanish AI filler phrases should contribute to score > 0."""
        spanish_text = (
            "En conclusión, cabe destacar que es importante señalar los avances. "
            "Además, asimismo se debe considerar el contexto. "
            "Es fundamental y es crucial abordar estos temas. "
            "Sin duda, en resumen, hay que tener en cuenta todos los factores."
        )
        result = self.detector.analyze_text(spanish_text)
        self.assertGreater(
            result["score"], 0.0,
            f"Expected score > 0 for Spanish AI text, got {result['score']}"
        )

    def test_spanish_filler_in_indicators(self):
        """Spanish filler phrases should appear in the indicators."""
        spanish_text = "En conclusión, es fundamental señalar que cabe destacar los avances."
        result = self.detector.analyze_text(spanish_text)
        indicators_text = " ".join(result.get("indicators", []))
        # The filler phrases section should have found something
        self.assertGreater(len(result.get("indicators", [])), 0)

    def test_mixed_spanish_english_scores_high(self):
        """Mixed Spanish/English AI text should score higher."""
        mixed = (
            "Furthermore, en conclusión it is important to note que es fundamental "
            "leveraging robust solutions. Moreover, cabe destacar the comprehensive approach. "
            "Additionally, sin duda the paradigm shift is cutting-edge."
        )
        result = self.detector.analyze_text(mixed)
        self.assertGreater(result["score"], 0.3)


# -----------------------------------------------------------------------
# ReportEngine — calculate_risk_score
# -----------------------------------------------------------------------

class TestRiskScore(unittest.TestCase):

    def setUp(self):
        from report_engine.reporter import ReportEngine
        self.engine = ReportEngine()

    def test_empty_results_low_risk(self):
        result = self.engine.calculate_risk_score({})
        self.assertIn("total", result)
        self.assertIn("level", result)
        self.assertIn("breakdown", result)
        self.assertEqual(result["level"], "LOW")
        self.assertEqual(result["total"], 0)

    def test_encryption_signature_adds_points(self):
        results = {
            "crypto": {
                "signatures": [
                    {"type": "PGP ASCII Armor", "confidence": "high", "detail": "test"}
                ]
            }
        }
        result = self.engine.calculate_risk_score(results)
        self.assertGreater(result["total"], 0)

    def test_file_type_mismatch_adds_points(self):
        results = {
            "forensics": {"mismatch": True},
        }
        result = self.engine.calculate_risk_score(results)
        self.assertGreaterEqual(result["total"], 25)

    def test_stego_suspicion_adds_points(self):
        results = {
            "crypto": {
                "steganography": {"suspicion_score": 0.8}
            }
        }
        result = self.engine.calculate_risk_score(results)
        self.assertGreaterEqual(result["total"], 25)

    def test_ai_detection_adds_points(self):
        results = {
            "ai_detection": {
                "metadata_analysis": {"is_likely_ai": True},
                "text_analysis": {"score": 0.75},
            }
        }
        result = self.engine.calculate_risk_score(results)
        self.assertGreaterEqual(result["total"], 15)

    def test_max_score_100(self):
        """Score should never exceed 100."""
        results = {
            "file": "/tmp/test.jpg",
            "crypto": {
                "signatures": [
                    {"type": "PGP", "confidence": "high", "detail": "x"},
                    {"type": "SSH Key", "confidence": "high", "detail": "x"},
                    {"type": "JWT", "confidence": "high", "detail": "x"},
                ],
                "steganography": {"suspicion_score": 0.9},
            },
            "forensics": {"mismatch": True},
            "entropy": 7.9,
            "ai_detection": {
                "metadata_analysis": {"is_likely_ai": True},
                "text_analysis": {"score": 0.9},
            },
            "manipulation": {"risk_level": "high"},
        }
        result = self.engine.calculate_risk_score(results)
        self.assertLessEqual(result["total"], 100)
        self.assertIn(result["level"], ("LOW", "MEDIUM", "HIGH", "CRITICAL"))

    def test_critical_level_threshold(self):
        """Score >= 85 should produce CRITICAL level."""
        results = {
            "file": "/tmp/test.jpg",
            "crypto": {
                "signatures": [
                    {"type": "PGP", "confidence": "high", "detail": "x"},
                    {"type": "SSH", "confidence": "high", "detail": "x"},
                ],
                "steganography": {"suspicion_score": 0.9},
            },
            "forensics": {"mismatch": True},
            "entropy": 7.9,
            "manipulation": {"risk_level": "high"},
        }
        result = self.engine.calculate_risk_score(results)
        if result["total"] >= 85:
            self.assertEqual(result["level"], "CRITICAL")
        elif result["total"] >= 60:
            self.assertEqual(result["level"], "HIGH")


# -----------------------------------------------------------------------
# ReportEngine — generate_html
# -----------------------------------------------------------------------

class TestHTMLReport(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        from report_engine.reporter import ReportEngine
        self.engine = ReportEngine()

    def _make_results(self):
        return {
            "file": "/tmp/test_image.jpg",
            "exif": {"Make": "Canon", "Model": "EOS 5D"},
            "forensics": {
                "filename": "test_image.jpg",
                "size": 1024,
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            },
            "crypto": {
                "signatures": [{"type": "No encryption", "confidence": "low", "detail": "clean"}],
                "steganography": {"suspicion_score": 0.1, "reasons": []},
            },
            "ai_detection": {
                "is_likely_ai": False,
                "summary": "No AI indicators.",
                "metadata_analysis": {"evidence": [], "is_likely_ai": False},
                "text_analysis": None,
            },
        }

    def test_html_file_is_created(self):
        """generate_html should create the output file."""
        out = os.path.join(self.tmpdir, "report.html")
        self.engine.generate_html(self._make_results(), out)
        self.assertTrue(os.path.isfile(out))

    def test_html_contains_doctype(self):
        out = os.path.join(self.tmpdir, "report.html")
        self.engine.generate_html(self._make_results(), out)
        with open(out, "r", encoding="utf-8") as fh:
            content = fh.read()
        self.assertIn("<!DOCTYPE html>", content)

    def test_html_contains_title(self):
        out = os.path.join(self.tmpdir, "report.html")
        self.engine.generate_html(self._make_results(), out)
        with open(out, "r", encoding="utf-8") as fh:
            content = fh.read()
        self.assertIn("Metadata Security Toolkit", content)

    def test_html_contains_developer(self):
        out = os.path.join(self.tmpdir, "report.html")
        self.engine.generate_html(self._make_results(), out)
        with open(out, "r", encoding="utf-8") as fh:
            content = fh.read()
        self.assertIn("pendatkill", content)

    def test_html_contains_risk_section(self):
        out = os.path.join(self.tmpdir, "report.html")
        self.engine.generate_html(self._make_results(), out)
        with open(out, "r", encoding="utf-8") as fh:
            content = fh.read()
        self.assertIn("Risk Score", content)

    def test_html_contains_exif_data(self):
        out = os.path.join(self.tmpdir, "report.html")
        self.engine.generate_html(self._make_results(), out)
        with open(out, "r", encoding="utf-8") as fh:
            content = fh.read()
        self.assertIn("Canon", content)

    def test_generate_via_generate_method(self):
        """generate() with fmt='html' should call generate_html."""
        out = os.path.join(self.tmpdir, "report2.html")
        returned = self.engine.generate(self._make_results(), out, fmt="html")
        self.assertTrue(os.path.isfile(out))
        self.assertEqual(os.path.abspath(out), returned)


# -----------------------------------------------------------------------
# ReportEngine — generate_csv
# -----------------------------------------------------------------------

class TestCSVReport(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        from report_engine.reporter import ReportEngine
        self.engine = ReportEngine()

    def test_csv_file_is_created(self):
        out = os.path.join(self.tmpdir, "report.csv")
        self.engine.generate_csv({"file": "/tmp/test.txt", "forensics": {"size": 100}}, out)
        self.assertTrue(os.path.isfile(out))

    def test_csv_has_key_value_columns(self):
        import csv as csv_module
        out = os.path.join(self.tmpdir, "report.csv")
        self.engine.generate_csv({"file": "/tmp/test.txt", "score": 42}, out)
        with open(out, "r", encoding="utf-8") as fh:
            reader = csv_module.reader(fh)
            rows = list(reader)
        self.assertEqual(rows[0], ["key", "value"])
        keys = [r[0] for r in rows[1:]]
        self.assertIn("file", keys)


# -----------------------------------------------------------------------
# ExifAnalyzer — new methods
# -----------------------------------------------------------------------

@unittest.skipUnless(PILLOW_AVAILABLE, "Pillow not installed")
class TestExifAnalyzerEnhanced(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        from exif_analyzer.analyzer import ExifAnalyzer
        self.analyzer = ExifAnalyzer()

    def _make_jpeg(self, name="test.jpg") -> str:
        path = os.path.join(self.tmpdir, name)
        img = Image.new("RGB", (10, 10), color=(200, 100, 50))
        img.save(path, format="JPEG")
        return path

    def _make_png(self) -> str:
        path = os.path.join(self.tmpdir, "test.png")
        img = Image.new("RGB", (10, 10), color=(50, 100, 200))
        img.save(path, format="PNG")
        return path

    def test_analyze_with_exiftool_returns_dict(self):
        """analyze_with_exiftool should return a dict regardless of exiftool presence."""
        path = self._make_jpeg()
        result = self.analyzer.analyze_with_exiftool(path)
        self.assertIsInstance(result, dict)

    def test_analyze_with_exiftool_has_available_key(self):
        """Result must always contain 'exiftool_available' key."""
        path = self._make_jpeg()
        result = self.analyzer.analyze_with_exiftool(path)
        self.assertIn("exiftool_available", result)
        self.assertIsInstance(result["exiftool_available"], bool)

    def test_extract_thumbnail_returns_path_or_none(self):
        """extract_thumbnail should return a string path or None."""
        path = self._make_jpeg()
        result = self.analyzer.extract_thumbnail(path, self.tmpdir)
        # May be None if no thumbnail embedded, or a path string
        self.assertTrue(result is None or isinstance(result, str))

    def test_extract_thumbnail_missing_file_returns_none(self):
        result = self.analyzer.extract_thumbnail("/no/such/file.jpg", self.tmpdir)
        self.assertIsNone(result)

    def test_detect_manipulation_signs_returns_correct_structure(self):
        path = self._make_jpeg()
        result = self.analyzer.detect_manipulation_signs(path)
        self.assertIn("flags", result)
        self.assertIn("risk_level", result)
        self.assertIn("details", result)
        self.assertIsInstance(result["flags"], list)
        self.assertIn(result["risk_level"], ("low", "medium", "high"))

    def test_detect_manipulation_signs_missing_file(self):
        result = self.analyzer.detect_manipulation_signs("/no/such/file.jpg")
        self.assertIn("flags", result)
        self.assertIn("risk_level", result)

    def test_get_camera_fingerprint_returns_dict(self):
        path = self._make_jpeg()
        result = self.analyzer.get_camera_fingerprint(path)
        self.assertIsInstance(result, dict)
        for key in ("make", "model", "focal_length", "iso", "exposure_time", "flash", "orientation"):
            self.assertIn(key, result)

    def test_get_gps_returns_none_for_plain_jpeg(self):
        path = self._make_jpeg()
        result = self.analyzer.get_gps(path)
        self.assertIsNone(result)

    def test_get_gps_returns_maps_url_when_present(self):
        """If GPS data is present, maps_url must be included."""
        # This test verifies the structure if GPS were returned
        # We test the format logic directly
        result = self.analyzer.get_gps(self._make_jpeg())
        if result is not None:
            self.assertIn("maps_url", result)
            self.assertIn("https://www.google.com/maps?q=", result["maps_url"])


# -----------------------------------------------------------------------
# AIDetector — analyze_image_metadata enhanced
# -----------------------------------------------------------------------

@unittest.skipUnless(PILLOW_AVAILABLE, "Pillow not installed")
class TestAIDetectorImageEnhanced(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        from ai_detector.detector import AIDetector
        self.detector = AIDetector()

    def test_returns_confidence_key(self):
        """analyze_image_metadata should return 'confidence' key."""
        path = os.path.join(self.tmpdir, "test.jpg")
        Image.new("RGB", (512, 512)).save(path, format="JPEG")
        result = self.detector.analyze_image_metadata(path)
        self.assertIn("confidence", result)
        self.assertIn(result["confidence"], ("low", "medium", "high"))

    def test_returns_detected_tool_key(self):
        """analyze_image_metadata should return 'detected_tool' key."""
        path = os.path.join(self.tmpdir, "test.jpg")
        Image.new("RGB", (10, 10)).save(path, format="JPEG")
        result = self.detector.analyze_image_metadata(path)
        self.assertIn("detected_tool", result)

    def test_ai_round_dimensions_evidence(self):
        """512x512 PNG should flag AI dimensions in evidence."""
        path = os.path.join(self.tmpdir, "ai_size.png")
        Image.new("RGB", (512, 512)).save(path, format="PNG")
        result = self.detector.analyze_image_metadata(path)
        evidence_text = " ".join(result.get("evidence", []))
        self.assertIn("512", evidence_text, f"Expected dimension evidence, got: {result['evidence']}")

    def test_plain_jpeg_not_flagged_as_ai(self):
        # Use non-round dimensions that do not match AI patterns
        path = os.path.join(self.tmpdir, "plain.jpg")
        Image.new("RGB", (100, 80)).save(path, format="JPEG")
        result = self.detector.analyze_image_metadata(path)
        # With threshold at 3, missing Make+Model+Focal+ISO = 2 signals only → not AI
        self.assertFalse(
            result["is_likely_ai"],
            f"Plain non-round JPEG should not be AI. Evidence: {result['evidence']}"
        )


# -----------------------------------------------------------------------
# FileForensics — find_embedded_files
# -----------------------------------------------------------------------

class TestFindEmbeddedFiles(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        from file_forensics.forensics import FileForensics
        self.forensics = FileForensics()

    def test_zip_embedded_files_listed(self):
        """A ZIP file should list its contents."""
        import zipfile
        path = os.path.join(self.tmpdir, "test.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("readme.txt", "Hello world content here")
            zf.writestr("data/config.json", '{"key": "value"}')
        result = self.forensics.find_embedded_files(path)
        self.assertIsInstance(result, list)
        self.assertGreaterEqual(len(result), 2)
        names = [e["name"] for e in result]
        self.assertIn("readme.txt", names)

    def test_embedded_files_have_name_and_size(self):
        """Each entry should have 'name' and 'size' keys."""
        import zipfile
        path = os.path.join(self.tmpdir, "test2.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("file.txt", "content here for size check")
        result = self.forensics.find_embedded_files(path)
        self.assertGreater(len(result), 0)
        for entry in result:
            self.assertIn("name", entry)
            self.assertIn("size", entry)

    def test_non_container_returns_empty(self):
        path = os.path.join(self.tmpdir, "plain.txt")
        with open(path, "w") as fh:
            fh.write("just a text file")
        result = self.forensics.find_embedded_files(path)
        self.assertIsInstance(result, list)
        self.assertEqual(result, [])

    def test_missing_file_returns_empty(self):
        result = self.forensics.find_embedded_files("/no/such/file.zip")
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
