# metadata-security-toolkit

![Python](https://img.shields.io/badge/python-3.8%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Purpose](https://img.shields.io/badge/purpose-educational%20%26%20research-orange)
![Author](https://img.shields.io/badge/author-pendatkill-lightgrey)

A modular Python toolkit for forensic metadata analysis: EXIF extraction, file forensics, cryptographic tracing, and heuristic AI-generated content detection — all running fully offline.

---

## DISCLAIMER / AVISO LEGAL

> **[ES]** Este proyecto es de uso **exclusivamente educativo y de investigación**. El desarrollador (**pendatkill**) no asume ninguna responsabilidad por el uso indebido que terceros puedan hacer de este software. El usuario final es el único responsable del uso que haga de esta herramienta y de las consecuencias legales derivadas. **No está permitido su uso para actividades ilegales.**
>
> **[EN]** This project is intended **strictly for educational and research purposes**. The developer (**pendatkill**) accepts no liability for misuse by third parties. The end user assumes full legal responsibility for how this tool is used. **Use for illegal activities is strictly prohibited.**

See [DISCLAIMER.md](DISCLAIMER.md) for the full legal disclaimer.

---

## Description

`metadata-security-toolkit` is a collection of independent Python modules designed for security researchers, digital forensics students, and CTF practitioners who need to inspect hidden metadata, measure file entropy, trace cryptographic signatures, and identify AI-generated content — without sending any data to external APIs.

| Capability | What it does |
|---|---|
| EXIF analysis | Extracts camera, GPS, software, and creation metadata from images |
| File forensics | Hashes, MIME detection, timestamps, entropy, PDF/Office metadata |
| Crypto tracing | Multi-algorithm hashing, encryption signature detection, steganography hints |
| AI detection | Heuristic text and image-metadata analysis for AI-generated content |
| Report engine | Generates JSON or plain-text reports from combined module results |

---

## Module Overview

| Module | Class | Key methods |
|---|---|---|
| `exif_analyzer` | `ExifAnalyzer` | `analyze()`, `get_gps()`, `detect_editing_software()` |
| `file_forensics` | `FileForensics` | `analyze()`, `compute_entropy()`, `get_pdf_metadata()`, `get_office_metadata()` |
| `crypto_tracer` | `CryptoTracer` | `hash_file()`, `measure_entropy()`, `detect_encryption_signature()`, `check_steganography_hints()` |
| `ai_detector` | `AIDetector` | `analyze_text()`, `analyze_image_metadata()`, `analyze_file()` |
| `report_engine` | `ReportEngine` | `summarize()`, `generate()` |

---

## Installation

```bash
git clone https://github.com/pendatkill/metadata-security-toolkit.git
cd metadata-security-toolkit
pip install -r requirements.txt
```

> Optional: use a virtual environment first.
> ```bash
> python -m venv venv
> source venv/bin/activate   # Windows: venv\Scripts\activate
> pip install -r requirements.txt
> ```

---

## Usage Examples

### EXIF Analyzer

```python
from exif_analyzer.analyzer import ExifAnalyzer

analyzer = ExifAnalyzer()

# Extract all EXIF tags
exif_data = analyzer.analyze("photo.jpg")
print(exif_data)

# Get GPS coordinates
gps = analyzer.get_gps("photo.jpg")
if gps:
    print(f"Latitude: {gps['latitude']}, Longitude: {gps['longitude']}")

# Detect editing software
software = analyzer.detect_editing_software("photo.jpg")
print(f"Created/edited with: {software}")
```

### File Forensics

```python
from file_forensics.forensics import FileForensics

ff = FileForensics()

# General forensic summary (hashes, MIME, timestamps)
summary = ff.analyze("document.pdf")
print(summary)

# Shannon entropy (high value suggests encryption or compression)
entropy = ff.compute_entropy("archive.bin")
print(f"Entropy: {entropy:.4f} bits/byte")

# PDF metadata
pdf_meta = ff.get_pdf_metadata("report.pdf")

# Office document metadata
office_meta = ff.get_office_metadata("contract.docx")
```

### Crypto Tracer

```python
from crypto_tracer.tracer import CryptoTracer

ct = CryptoTracer()

# Multi-algorithm file hashes
hashes = ct.hash_file("suspicious.bin")
print(hashes["sha256"])

# Measure entropy of raw bytes
with open("data.bin", "rb") as f:
    data = f.read()
entropy = ct.measure_entropy(data)

# Detect encryption/crypto signatures
findings = ct.detect_encryption_signature("encrypted.gpg")
for finding in findings:
    print(finding)

# Steganography hints (PNG/BMP only)
stego = ct.check_steganography_hints("image.png")
print(f"Suspicion score: {stego['suspicion_score']}")
```

### AI Detector

```python
from ai_detector.detector import AIDetector

ai = AIDetector()

# Analyse text for AI-generation likelihood
result = ai.analyze_text("In conclusion, it is important to note that leverage...")
print(f"Score: {result['score']}, Confidence: {result['confidence']}")
print(result["indicators"])

# Check image metadata for AI generator signatures
meta_result = ai.analyze_image_metadata("image.jpg")
print(f"Likely AI: {meta_result['is_likely_ai']}")

# Combined file analysis (auto-detects type)
file_result = ai.analyze_file("unknown_file.jpg")
print(file_result["summary"])
```

### Report Engine

```python
from report_engine.reporter import ReportEngine

engine = ReportEngine()

results = {
    "file": "photo.jpg",
    "exif": exif_data,
    "forensics": summary,
    "crypto": {"md5": "...", "sha256": "...", "signatures": []},
    "ai_detection": file_result,
}

# Print plain-text summary
print(engine.summarize(results))

# Save JSON report
engine.generate(results, "reports/output.json", fmt="json")

# Save text report
engine.generate(results, "reports/output.txt", fmt="text")
```

---

## Running the Demo

```bash
python demo/run_demo.py
```

Sample output is saved to [demo/sample_outputs.txt](demo/sample_outputs.txt).

---

## Tests

```bash
python -m pytest tests/ -v
```

---

## Project Structure

```
metadata-security-toolkit/
├── ai_detector/
│   ├── __init__.py
│   └── detector.py
├── crypto_tracer/
│   ├── __init__.py
│   └── tracer.py
├── exif_analyzer/
│   ├── __init__.py
│   └── analyzer.py
├── file_forensics/
│   ├── __init__.py
│   └── forensics.py
├── report_engine/
│   ├── __init__.py
│   └── reporter.py
├── tests/
│   ├── test_ai_detector.py
│   ├── test_crypto_tracer.py
│   ├── test_exif_analyzer.py
│   ├── test_file_forensics.py
│   └── test_report_engine.py
├── demo/
│   ├── run_demo.py
│   └── sample_outputs.txt
├── requirements.txt
├── setup.py
├── DISCLAIMER.md
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

Copyright (c) 2026 pendatkill
