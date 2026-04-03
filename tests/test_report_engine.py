# Developer: pendatkill
# Module: tests.test_report_engine
# Description: Unit tests for ReportEngine covering JSON/text generation and summarization

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from report_engine.reporter import ReportEngine


# ---------------------------------------------------------------------------
# Sample results dict used across tests
# ---------------------------------------------------------------------------

SAMPLE_RESULTS = {
    "file": "/tmp/sample_image.jpg",
    "exif": {
        "Make": "Canon",
        "Model": "EOS 5D",
        "Software": "Adobe Photoshop",
        "DateTime": "2024:01:15 10:30:00",
    },
    "forensics": {
        "filename": "sample_image.jpg",
        "size": 204800,
        "mime_type": "image/jpeg",
        "created": "2024-01-15T10:30:00",
        "modified": "2024-01-15T11:00:00",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    "crypto": {
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "signatures": ["No encryption signatures detected."],
        "steganography": {
            "suspicion_score": 0.1,
            "reasons": [],
            "supported": True,
        },
    },
    "ai_detection": {
        "filepath": "/tmp/sample_image.jpg",
        "file_type": "image",
        "is_likely_ai": False,
        "summary": "No strong AI generation indicators found in image metadata.",
        "metadata_analysis": {
            "is_likely_ai": False,
            "evidence": ["No camera Make or Model found in EXIF — typical of AI-generated images."],
            "software": None,
        },
        "text_analysis": None,
    },
}

MINIMAL_RESULTS = {
    "file": "/tmp/file.txt",
    "exif": {},
    "forensics": {},
    "crypto": {},
    "ai_detection": {},
}


class TestReportEngineGenerate(unittest.TestCase):

    def setUp(self):
        self.engine = ReportEngine()
        self.tmpdir = tempfile.mkdtemp()

    # ------------------------------------------------------------------
    # generate() — JSON
    # ------------------------------------------------------------------

    def test_generate_json_creates_file(self):
        output = os.path.join(self.tmpdir, "report.json")
        returned_path = self.engine.generate(SAMPLE_RESULTS, output, fmt="json")
        self.assertTrue(os.path.isfile(output))
        self.assertEqual(os.path.abspath(output), returned_path)

    def test_generate_json_valid_json_content(self):
        output = os.path.join(self.tmpdir, "report.json")
        self.engine.generate(SAMPLE_RESULTS, output, fmt="json")
        with open(output, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertIsInstance(data, dict)

    def test_generate_json_contains_file_key(self):
        output = os.path.join(self.tmpdir, "report.json")
        self.engine.generate(SAMPLE_RESULTS, output, fmt="json")
        with open(output, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertIn("file", data)

    def test_generate_json_preserves_exif(self):
        output = os.path.join(self.tmpdir, "report.json")
        self.engine.generate(SAMPLE_RESULTS, output, fmt="json")
        with open(output, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["exif"]["Make"], "Canon")

    # ------------------------------------------------------------------
    # generate() — text
    # ------------------------------------------------------------------

    def test_generate_text_creates_file(self):
        output = os.path.join(self.tmpdir, "report.txt")
        returned_path = self.engine.generate(SAMPLE_RESULTS, output, fmt="text")
        self.assertTrue(os.path.isfile(output))
        self.assertEqual(os.path.abspath(output), returned_path)

    def test_generate_text_content_is_nonempty(self):
        output = os.path.join(self.tmpdir, "report.txt")
        self.engine.generate(SAMPLE_RESULTS, output, fmt="text")
        with open(output, "r", encoding="utf-8") as fh:
            content = fh.read()
        self.assertGreater(len(content), 50)

    def test_generate_text_contains_header(self):
        output = os.path.join(self.tmpdir, "report.txt")
        self.engine.generate(SAMPLE_RESULTS, output, fmt="text")
        with open(output, "r", encoding="utf-8") as fh:
            content = fh.read()
        self.assertIn("METADATA SECURITY TOOLKIT", content)

    # ------------------------------------------------------------------
    # generate() — invalid format
    # ------------------------------------------------------------------

    def test_generate_invalid_format_raises(self):
        output = os.path.join(self.tmpdir, "report.xml")
        with self.assertRaises(ValueError):
            self.engine.generate(SAMPLE_RESULTS, output, fmt="xml")

    # ------------------------------------------------------------------
    # generate() — minimal results
    # ------------------------------------------------------------------

    def test_generate_minimal_results_json(self):
        output = os.path.join(self.tmpdir, "minimal.json")
        self.engine.generate(MINIMAL_RESULTS, output, fmt="json")
        self.assertTrue(os.path.isfile(output))
        with open(output, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertIsInstance(data, dict)

    # ------------------------------------------------------------------
    # generate() — creates parent directories
    # ------------------------------------------------------------------

    def test_generate_creates_nested_directories(self):
        output = os.path.join(self.tmpdir, "subdir", "nested", "report.json")
        self.engine.generate(MINIMAL_RESULTS, output, fmt="json")
        self.assertTrue(os.path.isfile(output))


class TestReportEngineSummarize(unittest.TestCase):

    def setUp(self):
        self.engine = ReportEngine()

    # ------------------------------------------------------------------
    # summarize()
    # ------------------------------------------------------------------

    def test_summarize_returns_string(self):
        result = self.engine.summarize(SAMPLE_RESULTS)
        self.assertIsInstance(result, str)

    def test_summarize_nonempty(self):
        result = self.engine.summarize(SAMPLE_RESULTS)
        self.assertGreater(len(result), 0)

    def test_summarize_contains_target_file(self):
        result = self.engine.summarize(SAMPLE_RESULTS)
        self.assertIn(SAMPLE_RESULTS["file"], result)

    def test_summarize_contains_section_headers(self):
        result = self.engine.summarize(SAMPLE_RESULTS)
        self.assertIn("EXIF", result)
        self.assertIn("Forensics", result)
        self.assertIn("Crypto", result)
        self.assertIn("AI Detection", result)

    def test_summarize_minimal_results_nonempty(self):
        result = self.engine.summarize(MINIMAL_RESULTS)
        self.assertGreater(len(result), 0)

    def test_summarize_empty_dict_returns_string(self):
        result = self.engine.summarize({})
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    def test_summarize_ai_detection_positive(self):
        results = dict(SAMPLE_RESULTS)
        results["ai_detection"] = {
            "is_likely_ai": True,
            "summary": "Likely AI-generated image.",
            "metadata_analysis": {"evidence": ["Software matches Midjourney"], "is_likely_ai": True},
            "text_analysis": None,
        }
        summary = self.engine.summarize(results)
        self.assertIn("YES", summary)

    def test_summarize_crypto_signatures_listed(self):
        results = dict(SAMPLE_RESULTS)
        summary = self.engine.summarize(results)
        self.assertIn("No encryption signatures detected.", summary)


if __name__ == "__main__":
    unittest.main()
