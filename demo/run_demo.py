# Developer: pendatkill
# Module: demo.run_demo
# Description: Demonstration script — runs every toolkit module on in-memory test files
#              and prints formatted output.  Run from the repo root:
#                  python demo/run_demo.py

import os
import sys
import tempfile
import textwrap

# ── make sure project root is importable regardless of cwd ──────────────────
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# ── toolkit imports ──────────────────────────────────────────────────────────
from exif_analyzer.analyzer import ExifAnalyzer
from file_forensics.forensics import FileForensics
from crypto_tracer.tracer import CryptoTracer
from ai_detector.detector import AIDetector
from report_engine.reporter import ReportEngine

# ── Pillow (required for image creation) ────────────────────────────────────
try:
    from PIL import Image
    import struct, io
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _section(title: str) -> None:
    width = 60
    print()
    print("=" * width)
    print(f"  {title}")
    print("=" * width)


def _subsection(title: str) -> None:
    print(f"\n  -- {title} --")


def _pp(label: str, value) -> None:
    """Pretty-print a single result value."""
    if isinstance(value, dict):
        print(f"  {label}:")
        for k, v in value.items():
            # truncate very long strings for readability
            sv = str(v)
            if len(sv) > 80:
                sv = sv[:77] + "..."
            print(f"    {k}: {sv}")
    elif isinstance(value, list):
        print(f"  {label}:")
        if value:
            for item in value:
                print(f"    - {item}")
        else:
            print("    (none)")
    else:
        print(f"  {label}: {value}")


# ─────────────────────────────────────────────────────────────────────────────
# Test-file factories
# ─────────────────────────────────────────────────────────────────────────────

def _make_test_jpeg(path: str) -> None:
    """Create a minimal JPEG with a fake EXIF Software tag if piexif is available."""
    if not PILLOW_AVAILABLE:
        # Write a minimal valid JPEG manually (SOI + APP0 + EOI)
        with open(path, "wb") as f:
            f.write(bytes([0xFF, 0xD8, 0xFF, 0xD9]))
        return

    img = Image.new("RGB", (64, 64), color=(100, 149, 237))  # cornflower blue

    # Try to embed a Software EXIF tag via piexif
    try:
        import piexif
        exif_dict = {
            "0th": {
                piexif.ImageIFD.Software: b"Demo Toolkit 1.0",
                piexif.ImageIFD.ImageDescription: b"Test image for metadata-security-toolkit demo",
                piexif.ImageIFD.Make: b"DemoCamera",
                piexif.ImageIFD.Model: b"Model-X1",
            }
        }
        exif_bytes = piexif.dump(exif_dict)
        img.save(path, format="JPEG", exif=exif_bytes)
    except ImportError:
        # piexif not available — save plain JPEG
        img.save(path, format="JPEG")


def _make_test_text(path: str) -> None:
    """Create a text file that contains typical AI-generated filler phrases."""
    content = textwrap.dedent("""\
        In conclusion, it is important to note that this analysis is comprehensive.
        Furthermore, it is worth noting that the results are robust and seamlessly
        integrated. Moreover, the framework leverages a tailored approach that
        significantly improves performance. Ultimately, it is crucial to delve into
        these findings to unlock the full potential of the system.
        Additionally, the solution provides a seamless experience for all users.
        It is essential to understand that the methodology plays a crucial role in
        the overall pipeline, and the outcomes are both significant and meaningful.
    """)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


# ─────────────────────────────────────────────────────────────────────────────
# Main demo
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print()
    print("*" * 60)
    print("  metadata-security-toolkit — DEMO")
    print("  Developer: pendatkill")
    print("  For educational and research purposes only.")
    print("*" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        jpeg_path = os.path.join(tmpdir, "demo_image.jpg")
        text_path = os.path.join(tmpdir, "demo_text.txt")

        # ── create test files ────────────────────────────────────────────────
        _make_test_jpeg(jpeg_path)
        _make_test_text(text_path)

        # ────────────────────────────────────────────────────────────────────
        # 1. EXIF ANALYZER
        # ────────────────────────────────────────────────────────────────────
        _section("EXIF ANALYZER")
        exif_analyzer = ExifAnalyzer()

        _subsection("analyze()")
        exif_data = exif_analyzer.analyze(jpeg_path)
        if exif_data:
            _pp("EXIF tags found", exif_data)
        else:
            print("  (no EXIF data embedded in this test image)")

        _subsection("get_gps()")
        gps = exif_analyzer.get_gps(jpeg_path)
        _pp("GPS coordinates", gps if gps else "None (no GPS data in test image)")

        _subsection("detect_editing_software()")
        software = exif_analyzer.detect_editing_software(jpeg_path)
        _pp("Detected software", software if software else "None")

        # ────────────────────────────────────────────────────────────────────
        # 2. FILE FORENSICS
        # ────────────────────────────────────────────────────────────────────
        _section("FILE FORENSICS")
        ff = FileForensics()

        _subsection("analyze() — JPEG")
        forensics_data = ff.analyze(jpeg_path)
        _pp("Forensic summary", forensics_data)

        _subsection("compute_entropy() — JPEG")
        entropy_img = ff.compute_entropy(jpeg_path)
        print(f"  Entropy (image): {entropy_img:.4f} bits/byte")

        _subsection("analyze() — text file")
        forensics_txt = ff.analyze(text_path)
        _pp("Forensic summary", forensics_txt)

        _subsection("compute_entropy() — text file")
        entropy_txt = ff.compute_entropy(text_path)
        print(f"  Entropy (text):  {entropy_txt:.4f} bits/byte")

        # ────────────────────────────────────────────────────────────────────
        # 3. CRYPTO TRACER
        # ────────────────────────────────────────────────────────────────────
        _section("CRYPTO TRACER")
        ct = CryptoTracer()

        _subsection("hash_file() — JPEG")
        hashes = ct.hash_file(jpeg_path)
        _pp("File hashes", hashes)

        _subsection("measure_entropy() — raw bytes of JPEG header")
        with open(jpeg_path, "rb") as fh:
            header_bytes = fh.read(512)
        header_entropy = ct.measure_entropy(header_bytes)
        print(f"  Header entropy (first 512 bytes): {header_entropy:.4f} bits/byte")

        _subsection("measure_entropy() — synthetic high-entropy data")
        import os as _os
        random_data = _os.urandom(512)
        rand_entropy = ct.measure_entropy(random_data)
        print(f"  Entropy (512 random bytes):       {rand_entropy:.4f} bits/byte")

        _subsection("detect_encryption_signature() — JPEG")
        signatures_jpeg = ct.detect_encryption_signature(jpeg_path)
        _pp("Encryption signatures", signatures_jpeg if signatures_jpeg else ["(none detected)"])

        _subsection("detect_encryption_signature() — simulated OpenSSL header")
        openssl_path = os.path.join(tmpdir, "fake_openssl.bin")
        with open(openssl_path, "wb") as fh:
            fh.write(b"Salted__" + _os.urandom(504))
        signatures_ssl = ct.detect_encryption_signature(openssl_path)
        _pp("Encryption signatures (OpenSSL header)", signatures_ssl)

        _subsection("check_steganography_hints() — JPEG (unsupported format)")
        stego_jpeg = ct.check_steganography_hints(jpeg_path)
        _pp("Steganography result", stego_jpeg)

        if PILLOW_AVAILABLE:
            _subsection("check_steganography_hints() — PNG")
            png_path = os.path.join(tmpdir, "demo_image.png")
            img = Image.new("RGB", (64, 64), color=(200, 100, 50))
            img.save(png_path, format="PNG")
            stego_png = ct.check_steganography_hints(png_path)
            _pp("Steganography result (PNG)", stego_png)

        # ────────────────────────────────────────────────────────────────────
        # 4. AI DETECTOR
        # ────────────────────────────────────────────────────────────────────
        _section("AI DETECTOR")
        ai = AIDetector()

        _subsection("analyze_text() — AI-filler-rich text")
        with open(text_path, "r", encoding="utf-8") as fh:
            sample_text = fh.read()
        text_result = ai.analyze_text(sample_text)
        print(f"  Score:      {text_result['score']:.4f}")
        print(f"  Confidence: {text_result['confidence']}")
        _pp("Indicators", text_result["indicators"])

        _subsection("analyze_text() — natural / human-like text")
        human_text = (
            "The cat sat by the window all morning. "
            "Rain hammered the glass. "
            "She hadn't slept since Tuesday and the coffee was cold."
        )
        human_result = ai.analyze_text(human_text)
        print(f"  Score:      {human_result['score']:.4f}")
        print(f"  Confidence: {human_result['confidence']}")
        _pp("Indicators", human_result["indicators"])

        _subsection("analyze_image_metadata() — test JPEG")
        img_meta_result = ai.analyze_image_metadata(jpeg_path)
        print(f"  is_likely_ai: {img_meta_result['is_likely_ai']}")
        print(f"  software:     {img_meta_result['software']}")
        _pp("Evidence", img_meta_result["evidence"])

        _subsection("analyze_file() — JPEG (combined)")
        file_result_img = ai.analyze_file(jpeg_path)
        print(f"  file_type:    {file_result_img['file_type']}")
        print(f"  is_likely_ai: {file_result_img['is_likely_ai']}")
        print(f"  summary:      {file_result_img['summary']}")

        _subsection("analyze_file() — text file (combined)")
        file_result_txt = ai.analyze_file(text_path)
        print(f"  file_type:    {file_result_txt['file_type']}")
        print(f"  is_likely_ai: {file_result_txt['is_likely_ai']}")
        print(f"  summary:      {file_result_txt['summary']}")

        # ────────────────────────────────────────────────────────────────────
        # 5. REPORT ENGINE
        # ────────────────────────────────────────────────────────────────────
        _section("REPORT ENGINE")
        engine = ReportEngine()

        combined_results = {
            "file": jpeg_path,
            "exif": exif_data,
            "forensics": forensics_data,
            "crypto": {
                **hashes,
                "signatures": signatures_jpeg,
                "header_entropy": round(header_entropy, 4),
            },
            "ai_detection": file_result_img,
        }

        _subsection("summarize() — plain-text report")
        summary_text = engine.summarize(combined_results)
        print(summary_text)

        _subsection("generate() — JSON report saved to tempdir")
        json_report_path = os.path.join(tmpdir, "report.json")
        saved_path = engine.generate(combined_results, json_report_path, fmt="json")
        print(f"  JSON report written to: {saved_path}")
        json_size = os.path.getsize(saved_path)
        print(f"  Report size: {json_size} bytes")

        _subsection("generate() — text report saved to tempdir")
        txt_report_path = os.path.join(tmpdir, "report.txt")
        saved_txt_path = engine.generate(combined_results, txt_report_path, fmt="text")
        print(f"  Text report written to: {saved_txt_path}")

    # ── done ─────────────────────────────────────────────────────────────────
    print()
    print("=" * 60)
    print("  DEMO COMPLETE")
    print("  All modules executed successfully.")
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()
