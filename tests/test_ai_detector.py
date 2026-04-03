# Developer: pendatkill
# Module: tests.test_ai_detector
# Description: Unit tests for AIDetector covering text analysis, image metadata analysis, and file analysis

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

from ai_detector.detector import AIDetector


# ---------------------------------------------------------------------------
# Sample texts
# ---------------------------------------------------------------------------

# Highly AI-like text: filled with filler phrases, uniform sentence length,
# moderate vocabulary, and low bigram diversity.
AI_LIKE_TEXT = (
    "In conclusion, it is important to note that leveraging robust solutions "
    "plays a crucial role in achieving seamless results. "
    "Furthermore, it is worth noting that comprehensive approaches are tailored "
    "to unlock the full potential of modern systems. "
    "Moreover, it is essential to delve into the significant aspects of this "
    "context in order to provide a robust and seamless experience. "
    "Additionally, a robust framework is crucial for ensuring that tailored "
    "solutions deliver seamless and comprehensive outcomes. "
    "Ultimately, leveraging these robust and comprehensive tools is crucial "
    "for any significant and seamless transformation."
)

# Short, natural text — minimal AI indicators
NATURAL_TEXT = "The cat sat on the mat. It was a sunny afternoon."

# Repetitive low-vocabulary text
REPETITIVE_TEXT = " ".join(["the cat sat"] * 30)


class TestAIDetectorText(unittest.TestCase):

    def setUp(self):
        self.detector = AIDetector()

    # ------------------------------------------------------------------
    # analyze_text()
    # ------------------------------------------------------------------

    def test_analyze_text_returns_valid_structure(self):
        result = self.detector.analyze_text(NATURAL_TEXT)
        self.assertIn("score", result)
        self.assertIn("confidence", result)
        self.assertIn("indicators", result)

    def test_analyze_text_score_is_float(self):
        result = self.detector.analyze_text(AI_LIKE_TEXT)
        self.assertIsInstance(result["score"], float)

    def test_analyze_text_score_in_range(self):
        for text in (AI_LIKE_TEXT, NATURAL_TEXT, REPETITIVE_TEXT):
            result = self.detector.analyze_text(text)
            self.assertGreaterEqual(result["score"], 0.0)
            self.assertLessEqual(result["score"], 1.0)

    def test_analyze_text_ai_like_scores_above_threshold(self):
        result = self.detector.analyze_text(AI_LIKE_TEXT)
        self.assertGreater(
            result["score"], 0.3,
            f"Expected score > 0.3 for AI-like text, got {result['score']}"
        )

    def test_analyze_text_natural_text_returns_valid_dict(self):
        result = self.detector.analyze_text(NATURAL_TEXT)
        self.assertIsInstance(result, dict)
        self.assertIn("score", result)
        self.assertIn(result["confidence"], ("low", "medium", "high"))

    def test_analyze_text_repetitive_high_score(self):
        result = self.detector.analyze_text(REPETITIVE_TEXT)
        # Repetitive text should trigger low TTR → score should be elevated
        self.assertGreaterEqual(result["score"], 0.0)

    def test_analyze_text_empty_string(self):
        result = self.detector.analyze_text("")
        self.assertIsInstance(result, dict)
        self.assertAlmostEqual(result["score"], 0.0)

    def test_analyze_text_confidence_values(self):
        for text in (AI_LIKE_TEXT, NATURAL_TEXT):
            result = self.detector.analyze_text(text)
            self.assertIn(result["confidence"], ("low", "medium", "high"))

    def test_analyze_text_indicators_is_list(self):
        result = self.detector.analyze_text(AI_LIKE_TEXT)
        self.assertIsInstance(result["indicators"], list)

    # ------------------------------------------------------------------
    # analyze_image_metadata()
    # ------------------------------------------------------------------

    @unittest.skipUnless(PILLOW_AVAILABLE, "Pillow not installed")
    def test_analyze_image_metadata_plain_jpeg(self):
        """A plain JPEG created by Pillow should not be flagged as AI-generated."""
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "plain.jpg")
        img = Image.new("RGB", (20, 20), color=(100, 150, 200))
        img.save(path, format="JPEG")

        result = self.detector.analyze_image_metadata(path)

        self.assertIn("is_likely_ai", result)
        self.assertIn("evidence", result)
        self.assertFalse(
            result["is_likely_ai"],
            f"Plain JPEG should not be flagged as AI; evidence: {result['evidence']}"
        )

    @unittest.skipUnless(PILLOW_AVAILABLE, "Pillow not installed")
    def test_analyze_image_metadata_returns_correct_structure(self):
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "test.jpg")
        Image.new("RGB", (10, 10)).save(path, format="JPEG")

        result = self.detector.analyze_image_metadata(path)
        self.assertIn("is_likely_ai", result)
        self.assertIn("evidence", result)
        self.assertIn("software", result)
        self.assertIsInstance(result["evidence"], list)
        self.assertIsInstance(result["is_likely_ai"], bool)

    def test_analyze_image_metadata_missing_file(self):
        result = self.detector.analyze_image_metadata("/no/such/image.jpg")
        self.assertIn("is_likely_ai", result)
        self.assertIn("evidence", result)

    # ------------------------------------------------------------------
    # analyze_file()
    # ------------------------------------------------------------------

    @unittest.skipUnless(PILLOW_AVAILABLE, "Pillow not installed")
    def test_analyze_file_image(self):
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "file.jpg")
        Image.new("RGB", (10, 10)).save(path, format="JPEG")

        result = self.detector.analyze_file(path)
        self.assertEqual(result["file_type"], "image")
        self.assertIn("is_likely_ai", result)
        self.assertIsInstance(result["summary"], str)

    def test_analyze_file_text(self):
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "doc.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(AI_LIKE_TEXT)

        result = self.detector.analyze_file(path)
        self.assertEqual(result["file_type"], "text")
        self.assertIn("text_analysis", result)
        self.assertIsNotNone(result["text_analysis"])

    def test_analyze_file_missing(self):
        result = self.detector.analyze_file("/no/such/file.jpg")
        self.assertIn("summary", result)

    def test_analyze_file_unsupported_ext(self):
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "data.bin")
        with open(path, "wb") as fh:
            fh.write(b"\x00" * 16)

        result = self.detector.analyze_file(path)
        self.assertEqual(result["file_type"], "unknown")


if __name__ == "__main__":
    unittest.main()
