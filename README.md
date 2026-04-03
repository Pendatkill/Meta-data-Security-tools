# metadata-security-toolkit

![Python](https://img.shields.io/badge/python-3.8%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Purpose](https://img.shields.io/badge/purpose-educational%20%26%20research-orange)
![Author](https://img.shields.io/badge/author-pendatkill-lightgrey)
![Tests](https://img.shields.io/badge/tests-157%20passed-brightgreen)

```
  _ __  ___ _           ___ ___ ___
 | '  \/ -_) |_ __ _ __/ __| __/ __|
 | |\/| \__ \  _/ _` (_-<\__ \__ \__|
 |_|  |_|___/\__\__,_/__/|___/___\___|
  _           _ _   _ _
 | |_ ___  __| | |_(_) |_
 |  _/ _ \/ _` | / / |  _|
  \__\___/\__,_|_\_\_|\__|

        metadata-security-toolkit         v0.1.0
          Developer: pendatkill
  [ Educational use only - not for illegal activity ]
```

A modular Python toolkit for forensic metadata analysis: EXIF extraction, file forensics, cryptographic tracing, and heuristic AI-generated content detection — fully offline, no external APIs.

---

## DISCLAIMER / AVISO LEGAL

> **[ES]** Este proyecto es de uso **exclusivamente educativo y de investigación**. El desarrollador (**pendatkill**) no asume ninguna responsabilidad por el uso indebido que terceros puedan hacer de este software. El usuario final es el único responsable del uso que haga de esta herramienta y de las consecuencias legales derivadas. **No está permitido su uso para actividades ilegales.**
>
> **[EN]** This project is intended **strictly for educational and research purposes**. The developer (**pendatkill**) accepts no liability for misuse by third parties. The end user assumes full legal responsibility for how this tool is used. **Use for illegal activities is strictly prohibited.**

See [DISCLAIMER.md](DISCLAIMER.md) for the full legal disclaimer.

---

## Features

| Module | Capability |
|---|---|
| **EXIF Analyzer** | GPS coordinates + Google Maps link, camera fingerprint, thumbnail extraction, manipulation detection, exiftool integration |
| **File Forensics** | MD5/SHA256, MIME vs magic bytes mismatch, Shannon entropy, ASCII strings extraction, embedded file listing, PDF/video metadata |
| **Crypto Tracer** | Multi-algorithm hashing, 12+ encryption signature detectors (PGP, OpenSSL, SSH, JWT, 7-Zip, RAR...), chi-square randomness test, LSB steganography analysis, integrity verification |
| **AI Detector** | 60+ AI filler phrases (EN+ES), burstiness analysis, n-gram repetition, paragraph uniformity, hapax ratio, 15+ AI tool signatures (Midjourney, SD, DALL-E, ComfyUI...) |
| **Report Engine** | JSON, TXT, HTML (dark theme, self-contained), CSV export, risk score 0-100 with breakdown (LOW/MEDIUM/HIGH/CRITICAL) |
| **Unified CLI** | Single entry point with ANSI color output, module selection flags, risk badge |

---

## Installation

```bash
git clone https://github.com/pendatkill/metadata-security-toolkit.git
cd metadata-security-toolkit
pip install -r requirements.txt
```

> Optional: virtual environment
> ```bash
> python -m venv venv
> source venv/bin/activate      # Windows: venv\Scripts\activate
> pip install -r requirements.txt
> ```

### Optional dependencies (enhance functionality)

| Tool | Purpose | Install |
|---|---|---|
| `exiftool` | Full metadata extraction (images, video, RAW) | [exiftool.org](https://exiftool.org) |
| `ffprobe` | Video metadata | Part of [ffmpeg.org](https://ffmpeg.org) |
| `PyMuPDF` | Advanced PDF analysis | `pip install PyMuPDF` |
| `python-docx` | Word document metadata | `pip install python-docx` |

---

## Quick Start — CLI

```bash
# Analyze any file (all modules)
python cli.py photo.jpg

# Specific modules
python cli.py document.pdf --forensics --crypto

# Generate HTML report
python cli.py suspicious.png --all --report html --output report.html

# Verbose output
python cli.py image.jpg --all --verbose

# No color (for piping/logging)
python cli.py file.bin --all --no-color > output.txt
```

CLI flags:

```
  filepath              File to analyze
  --all                 Run all modules (default)
  --exif                EXIF analysis only
  --forensics           File forensics only
  --crypto              Crypto/encryption/stego only
  --ai                  AI detection only
  --report FORMAT       Output report: json | txt | html | csv
  --output PATH         Report output path
  --verbose             Extended output
  --no-color            Disable ANSI colors
```

---

## Module Usage

### EXIF Analyzer

```python
from exif_analyzer.analyzer import ExifAnalyzer

a = ExifAnalyzer()

# All EXIF tags
print(a.analyze("photo.jpg"))

# GPS with decimal coords + Maps link
gps = a.get_gps("photo.jpg")
# {"lat": 40.4168, "lon": -3.7038, "maps_url": "https://www.google.com/maps?q=40.4168,-3.7038"}

# Camera fingerprint
fp = a.get_camera_fingerprint("photo.jpg")
# {"make": "Apple", "model": "iPhone 14", "iso": 100, ...}

# Manipulation signs
manip = a.detect_manipulation_signs("photo.jpg")
# {"flags": ["Software tag present: Adobe Photoshop"], "risk_level": "medium"}

# Extract embedded thumbnail
a.extract_thumbnail("photo.jpg", output_dir="/tmp/thumbs")

# Full exiftool output (requires exiftool in PATH)
a.analyze_with_exiftool("photo.jpg")
```

### File Forensics

```python
from file_forensics.forensics import FileForensics

ff = FileForensics()

# Full forensic summary (hashes, MIME, size, timestamps)
print(ff.analyze("file.pdf"))

# Shannon entropy — >7.5 suggests encryption/compression
print(ff.compute_entropy("archive.bin"))

# Detect extension vs magic bytes mismatch
mismatch = ff.detect_file_type_mismatch("suspicious.jpg")
# {"extension": ".jpg", "detected_type": "PNG", "mismatch": True, "risk": "high"}

# Extract printable strings from binary
strings = ff.analyze_strings("binary.exe", min_length=6)

# List files embedded inside ZIP/DOCX/XLSX/PDF
embedded = ff.find_embedded_files("document.docx")

# PDF metadata (requires PyMuPDF)
pdf = ff.get_pdf_metadata("report.pdf")
# {"author": "...", "has_javascript": True, "is_encrypted": False, ...}

# Video metadata (requires ffprobe)
ff.get_video_metadata("clip.mp4")
```

### Crypto Tracer

```python
from crypto_tracer.tracer import CryptoTracer

ct = CryptoTracer()

# MD5, SHA1, SHA256, SHA512
hashes = ct.hash_file("file.bin")

# Detect 12+ encryption/crypto signatures
sigs = ct.detect_encryption_signature("data.gpg")
# [{"type": "PGP ASCII armor", "confidence": "high", "detail": "..."}]

# Chi-square uniformity test (encrypted data is statistically uniform)
result = ct.chi_square_test(data_bytes)
# {"chi_square": 261.4, "is_likely_random": True, "interpretation": "..."}

# LSB steganography analysis (PNG/BMP)
stego = ct.detect_steganography_lsb("image.png")
# {"suspicion_score": 0.72, "lsb_entropy": 0.94, "chi_square": 142.3, "verdict": "..."}

# Verify file integrity
ct.verify_file_integrity("file.bin", expected_hash="abc123...", algorithm="sha256")
```

### AI Detector

```python
from ai_detector.detector import AIDetector

ai = AIDetector()

# Text analysis (EN + ES)
result = ai.analyze_text("In conclusion, it is worth noting that...")
# {"score": 0.75, "confidence": "high", "indicators": [...], "breakdown": {...}}

# Image metadata analysis
meta = ai.analyze_image_metadata("image.png")
# {"is_likely_ai": True, "detected_tool": "Stable Diffusion", "evidence": [...]}

# Document analysis (.txt / .pdf / .docx)
ai.analyze_document("report.pdf")

# Combined file analysis
ai.analyze_file("unknown.jpg")
```

### Report Engine

```python
from report_engine.reporter import ReportEngine

engine = ReportEngine()

results = {"file": "photo.jpg", "forensics": {...}, "crypto": {...}, "ai_detection": {...}}

# Risk score
risk = engine.calculate_risk_score(results)
# {"total": 55, "level": "MEDIUM", "breakdown": ["Encryption detected: +30", ...]}

# Generate reports
engine.generate(results, "report.json",  fmt="json")
engine.generate(results, "report.txt",   fmt="text")
engine.generate(results, "report.html",  fmt="html")   # self-contained dark theme
engine.generate(results, "report.csv",   fmt="csv")
```

---

## Risk Score

The report engine calculates a 0–100 risk score based on findings:

| Factor | Points |
|---|---|
| Encryption signature detected | +30 |
| File type / extension mismatch | +25 |
| Steganography suspicion > 0.5 | +25 |
| High entropy (>7.5 bits/byte) | +20 |
| Manipulation signs in EXIF | +20 |
| AI detection score > 0.6 | +15 |
| No camera EXIF in JPEG | +10 |

Levels: `LOW` (0–29) · `MEDIUM` (30–59) · `HIGH` (60–84) · `CRITICAL` (85–100)

---

## Running Tests

```bash
python -m pytest tests/ -v
```

157 tests, 1 skipped (optional `piexif` dependency).

---

## Running the Demo

```bash
python demo/run_demo.py
```

Full sample output: [demo/sample_outputs.txt](demo/sample_outputs.txt)  
Terminal screenshots: [demo/screenshots/](demo/screenshots/)

---

## Project Structure

```
metadata-security-toolkit/
├── cli.py                        <- Unified CLI entry point
├── exif_analyzer/
│   ├── __init__.py
│   └── analyzer.py               <- ExifAnalyzer
├── file_forensics/
│   ├── __init__.py
│   └── forensics.py              <- FileForensics
├── crypto_tracer/
│   ├── __init__.py
│   └── tracer.py                 <- CryptoTracer
├── ai_detector/
│   ├── __init__.py
│   └── detector.py               <- AIDetector
├── report_engine/
│   ├── __init__.py
│   └── reporter.py               <- ReportEngine
├── tests/
│   ├── test_exif_analyzer.py
│   ├── test_file_forensics.py
│   ├── test_crypto_tracer.py
│   ├── test_ai_detector.py
│   ├── test_report_engine.py
│   └── test_enhanced.py          <- Tests for enhanced features
├── demo/
│   ├── run_demo.py
│   ├── sample_outputs.txt
│   ├── screenshots/              <- Terminal demo captures
│   └── generate_screenshots.py
├── requirements.txt
├── setup.py
├── LICENSE
├── DISCLAIMER.md
├── CONTRIBUTING.md
└── README.md
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.  
Copyright (c) 2026 **pendatkill**
