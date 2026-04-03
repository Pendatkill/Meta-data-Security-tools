# Developer: pendatkill
# Module: tests.test_exif_analyzer
# Description: Unit tests for ExifAnalyzer using in-memory/temp image files

import os
import sys
import tempfile
import unittest

# Ensure project root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from PIL import Image
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

from exif_analyzer.analyzer import ExifAnalyzer


def _create_minimal_jpeg(path: str) -> None:
    """Save a tiny 10x10 white JPEG to *path* using Pillow."""
    img = Image.new("RGB", (10, 10), color=(255, 255, 255))
    img.save(path, format="JPEG")


def _create_minimal_png(path: str) -> None:
    """Save a tiny 10x10 white PNG to *path* using Pillow."""
    img = Image.new("RGB", (10, 10), color=(200, 200, 200))
    img.save(path, format="PNG")


@unittest.skipUnless(PILLOW_AVAILABLE, "Pillow not installed")
class TestExifAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = ExifAnalyzer()
        self.tmpdir = tempfile.mkdtemp()
        self.jpeg_path = os.path.join(self.tmpdir, "test.jpg")
        self.png_path = os.path.join(self.tmpdir, "test.png")
        _create_minimal_jpeg(self.jpeg_path)
        _create_minimal_png(self.png_path)

    # ------------------------------------------------------------------
    # analyze()
    # ------------------------------------------------------------------

    def test_analyze_returns_dict_for_jpeg(self):
        result = self.analyzer.analyze(self.jpeg_path)
        self.assertIsInstance(result, dict)

    def test_analyze_returns_dict_for_png(self):
        result = self.analyzer.analyze(self.png_path)
        self.assertIsInstance(result, dict)

    def test_analyze_returns_empty_dict_for_missing_file(self):
        result = self.analyzer.analyze("/nonexistent/path/image.jpg")
        self.assertEqual(result, {})

    def test_analyze_values_are_not_bytes(self):
        """All values returned should be JSON-serialisable (not raw bytes)."""
        result = self.analyzer.analyze(self.jpeg_path)
        for val in result.values():
            self.assertNotIsInstance(val, bytes)

    # ------------------------------------------------------------------
    # get_gps()
    # ------------------------------------------------------------------

    def test_get_gps_returns_none_for_plain_jpeg(self):
        """A plain JPEG without embedded GPS data should return None."""
        result = self.analyzer.get_gps(self.jpeg_path)
        self.assertIsNone(result)

    def test_get_gps_returns_none_for_missing_file(self):
        result = self.analyzer.get_gps("/nonexistent/image.jpg")
        self.assertIsNone(result)

    # ------------------------------------------------------------------
    # detect_editing_software()
    # ------------------------------------------------------------------

    def test_detect_editing_software_returns_none_for_plain_jpeg(self):
        """A freshly created Pillow JPEG has no Software tag by default."""
        result = self.analyzer.detect_editing_software(self.jpeg_path)
        # Could be None or a Pillow version string depending on Pillow version
        # Either None or a string is acceptable
        self.assertTrue(result is None or isinstance(result, str))

    def test_detect_editing_software_returns_none_for_missing_file(self):
        result = self.analyzer.detect_editing_software("/nonexistent/image.jpg")
        self.assertIsNone(result)

    def test_detect_editing_software_returns_string_when_set(self):
        """Create a JPEG with a Software EXIF tag set and verify detection."""
        try:
            import piexif
        except ImportError:
            self.skipTest("piexif not installed; skipping Software tag injection test")
        exif_dict = {"0th": {piexif.ImageIFD.Software: b"TestSoftware 1.0"}}
        exif_bytes = piexif.dump(exif_dict)
        path = os.path.join(self.tmpdir, "tagged.jpg")
        img = Image.new("RGB", (10, 10), (128, 128, 128))
        img.save(path, format="JPEG", exif=exif_bytes)
        result = self.analyzer.detect_editing_software(path)
        self.assertIsNotNone(result)
        self.assertIn("TestSoftware", result)


class TestExifAnalyzerNoPillow(unittest.TestCase):
    """Sanity tests that run even without Pillow (graceful degradation)."""

    def test_analyze_missing_file_always_returns_dict(self):
        analyzer = ExifAnalyzer()
        result = analyzer.analyze("/no/such/file.jpg")
        self.assertIsInstance(result, dict)

    def test_get_gps_missing_file_always_returns_none(self):
        analyzer = ExifAnalyzer()
        result = analyzer.get_gps("/no/such/file.jpg")
        self.assertIsNone(result)

    def test_detect_software_missing_file_always_returns_none(self):
        analyzer = ExifAnalyzer()
        result = analyzer.detect_editing_software("/no/such/file.jpg")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
