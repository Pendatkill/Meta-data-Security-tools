#!/usr/bin/env python3
# Developer: pendatkill
# Module: cli
# Description: Unified command-line interface for the metadata-security-toolkit

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime

# Ensure project root is on path when run directly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from exif_analyzer.analyzer import ExifAnalyzer
from file_forensics.forensics import FileForensics
from crypto_tracer.tracer import CryptoTracer
from ai_detector.detector import AIDetector
from report_engine.reporter import ReportEngine


# -----------------------------------------------------------------------
# ANSI color helpers
# -----------------------------------------------------------------------

def _supports_color(no_color: bool) -> bool:
    """Return True if terminal supports ANSI color codes."""
    if no_color:
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        # Windows: try to enable ANSI via Virtual Terminal Processing
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # Enable VIRTUAL_TERMINAL_PROCESSING (0x0004) on stdout handle
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
            # Also set UTF-8 output mode
            try:
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
            return True
        except Exception:
            return False
    return True


class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"
    GREY    = "\033[90m"


def _c(text: str, color: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{color}{text}{Colors.RESET}"


# -----------------------------------------------------------------------
# Print helpers
# -----------------------------------------------------------------------

_ASCII_BANNER = r"""
  _ __  ___ _           ___ ___ ___
 | '  \/ -_) |_ __ _ __/ __| __/ __|
 | |\/| \__ \  _/ _` (_-<\__ \__ \__|
 |_|  |_|___/\__\__,_/__/|___/___\___|
  _           _ _   _ _
 | |_ ___  __| | |_(_) |_
 |  _/ _ \/ _` | / / |  _|
  \__\___/\__,_|_\_\_|\__|
"""

def _header(use_color: bool):
    print(_c(_ASCII_BANNER, Colors.CYAN, use_color))
    meta_line  = f"  {'metadata-security-toolkit':^46}  v0.1.0"
    dev_line   = f"  {'Developer: pendatkill':^46}"
    disc_line  = f"  {'[ Educational use only - not for illegal activity ]':^46}"
    sep        = "  " + "-" * 52
    print(_c(meta_line,  Colors.BOLD + Colors.CYAN,    use_color))
    print(_c(dev_line,   Colors.GREY,                  use_color))
    print(_c(disc_line,  Colors.YELLOW,                use_color))
    print(_c(sep,        Colors.CYAN,                  use_color))


def _section(title: str, use_color: bool):
    print()
    print(_c(f"── {title} {'─' * max(0, 60 - len(title) - 4)}", Colors.MAGENTA, use_color))


def _kv(key: str, value, use_color: bool, mono: bool = False):
    key_str = _c(f"  {key:<30}", Colors.GREY, use_color)
    val_str = str(value)
    if mono:
        val_str = _c(val_str, Colors.CYAN, use_color)
    print(f"{key_str} {val_str}")


def _print_risk(risk: dict, use_color: bool):
    level = risk["level"]
    total = risk["total"]

    if total >= 85:
        color = Colors.RED + Colors.BOLD
        badge = "[CRITICAL]"
    elif total >= 60:
        color = Colors.RED
        badge = "[HIGH]"
    elif total >= 30:
        color = Colors.YELLOW
        badge = "[MEDIUM]"
    else:
        color = Colors.GREEN
        badge = "[LOW]"

    print()
    print(_c("=" * 70, color, use_color))
    print(_c(f"  RISK SCORE: {total}/100  {badge}", color, use_color))
    print(_c("=" * 70, color, use_color))
    for item in risk.get("breakdown", []):
        print(_c(f"    + {item}", color, use_color))
    if not risk.get("breakdown"):
        print(_c("    No significant risk factors detected.", Colors.GREEN, use_color))


# -----------------------------------------------------------------------
# Module runners
# -----------------------------------------------------------------------

def run_exif(filepath: str, results: dict, use_color: bool, verbose: bool):
    _section("EXIF Analyzer", use_color)
    analyzer = ExifAnalyzer()

    exif = analyzer.analyze(filepath)
    results["exif"] = exif
    if exif:
        shown = list(exif.items())[:20 if verbose else 10]
        for k, v in shown:
            _kv(k, v, use_color)
        if len(exif) > len(shown):
            print(_c(f"  ... and {len(exif) - len(shown)} more fields (use --verbose)", Colors.GREY, use_color))
    else:
        print(_c("  No EXIF data found.", Colors.GREY, use_color))

    # GPS
    gps = analyzer.get_gps(filepath)
    if gps:
        print()
        print(_c("  GPS Location:", Colors.BOLD, use_color))
        _kv("Latitude", gps["lat"], use_color)
        _kv("Longitude", gps["lon"], use_color)
        _kv("Maps URL", gps["maps_url"], use_color)
        results["gps"] = gps

    # Camera fingerprint
    fp = analyzer.get_camera_fingerprint(filepath)
    has_fp = any(v is not None for v in fp.values())
    if has_fp:
        print()
        print(_c("  Camera Fingerprint:", Colors.BOLD, use_color))
        for k, v in fp.items():
            if v is not None:
                _kv(k, v, use_color)
        results["camera_fingerprint"] = fp

    # Manipulation signs
    manip = analyzer.detect_manipulation_signs(filepath)
    results["manipulation"] = manip
    if manip["flags"]:
        print()
        print(_c(f"  Manipulation Risk: {manip['risk_level'].upper()}", Colors.YELLOW, use_color))
        for flag in manip["flags"]:
            print(_c(f"    ! {flag}", Colors.YELLOW, use_color))
    else:
        print(_c("  No manipulation signs detected.", Colors.GREEN, use_color))

    # Exiftool (if available)
    if verbose:
        et = analyzer.analyze_with_exiftool(filepath)
        if et.get("exiftool_available"):
            print()
            print(_c("  ExifTool output (selected fields):", Colors.BOLD, use_color))
            for k, v in list(et.items())[:15]:
                if k not in ("SourceFile", "ExifToolVersion", "exiftool_available"):
                    _kv(k, v, use_color)


def run_forensics(filepath: str, results: dict, use_color: bool, verbose: bool):
    _section("File Forensics", use_color)
    forensics = FileForensics()

    info = forensics.analyze(filepath)
    results["forensics"] = info
    if info:
        for k, v in info.items():
            mono = k in ("md5", "sha256")
            _kv(k, v, use_color, mono=mono)

    entropy = forensics.compute_entropy(filepath)
    results["entropy"] = entropy
    entropy_color = Colors.RED if entropy > 7.5 else (Colors.YELLOW if entropy > 6.5 else Colors.GREEN)
    print(_c(f"  {'Entropy':<30} {entropy:.4f} bits/byte", entropy_color, use_color))

    mismatch = forensics.detect_file_type_mismatch(filepath)
    results["type_mismatch"] = mismatch
    if mismatch.get("mismatch"):
        print(_c(
            f"  TYPE MISMATCH: extension={mismatch['extension']} detected={mismatch['detected_type']} — risk={mismatch['risk'].upper()}",
            Colors.RED, use_color
        ))
    else:
        print(_c(f"  File type OK: {mismatch.get('detected_type', 'unknown')} matches {mismatch.get('extension', '')}", Colors.GREEN, use_color))

    if verbose:
        # Strings
        strings = forensics.analyze_strings(filepath, min_length=6)
        if strings:
            print()
            print(_c("  Extracted strings (first 20):", Colors.BOLD, use_color))
            for s in strings[:20]:
                print(_c(f"    {s}", Colors.GREY, use_color))
        results["strings"] = strings

        # Embedded files
        embedded = forensics.find_embedded_files(filepath)
        if embedded:
            print()
            print(_c(f"  Embedded files ({len(embedded)}):", Colors.BOLD, use_color))
            for ef in embedded[:10]:
                _kv(ef.get("name", "?"), f"{ef.get('size', 0)} bytes", use_color)
        results["embedded_files"] = embedded

    # PDF metadata
    ext = os.path.splitext(filepath)[1].lower()
    if ext == ".pdf":
        pdf_meta = forensics.get_pdf_metadata(filepath)
        if pdf_meta:
            print()
            print(_c("  PDF Metadata:", Colors.BOLD, use_color))
            for k, v in pdf_meta.items():
                _kv(k, v, use_color)
        results["pdf_metadata"] = pdf_meta

    # Video metadata
    if ext in (".mp4", ".mov", ".avi", ".mkv", ".m4v", ".webm"):
        vid = forensics.get_video_metadata(filepath)
        if vid.get("ffprobe_available") is not False:
            print()
            print(_c("  Video Metadata:", Colors.BOLD, use_color))
            for k, v in vid.items():
                if v is not None and k != "ffprobe_available":
                    _kv(k, v, use_color)
        results["video_metadata"] = vid


def run_crypto(filepath: str, results: dict, use_color: bool, verbose: bool):
    _section("Crypto Tracer", use_color)
    tracer = CryptoTracer()

    hashes = tracer.hash_file(filepath)
    results.setdefault("crypto", {}).update(hashes)
    for alg in ("md5", "sha1", "sha256", "sha512"):
        if alg in hashes:
            _kv(alg.upper(), hashes[alg], use_color, mono=True)

    sigs = tracer.detect_encryption_signature(filepath)
    results["crypto"]["signatures"] = sigs
    if sigs:
        print()
        print(_c("  Encryption/Crypto Signatures:", Colors.BOLD, use_color))
        for s in sigs:
            if isinstance(s, dict):
                conf = s.get("confidence", "?").upper()
                color = {"HIGH": Colors.RED, "MEDIUM": Colors.YELLOW, "LOW": Colors.GREEN}.get(conf, Colors.GREY)
                print(_c(f"    [{conf}] {s.get('type','?')}: {s.get('detail','')}", color, use_color))
            else:
                print(_c(f"    - {s}", Colors.YELLOW, use_color))
    else:
        print(_c("  No encryption signatures detected.", Colors.GREEN, use_color))

    # Steganography
    ext = os.path.splitext(filepath)[1].lower()
    if ext in (".png", ".bmp"):
        stego = tracer.detect_steganography_lsb(filepath)
        results["crypto"]["steganography"] = stego
        stego_color = Colors.RED if stego["suspicion_score"] > 0.5 else (Colors.YELLOW if stego["suspicion_score"] > 0.2 else Colors.GREEN)
        print()
        print(_c(f"  Steganography (LSB): suspicion={stego['suspicion_score']:.2f}  entropy={stego['lsb_entropy']:.2f}  chi2={stego['chi_square']:.2f}", stego_color, use_color))
        print(_c(f"    Verdict: {stego['verdict']}", stego_color, use_color))

    if verbose:
        # Chi-square on full file
        try:
            with open(filepath, "rb") as fh:
                data = fh.read(65536)  # first 64KB
            chi = tracer.chi_square_test(data)
            print()
            _kv("Chi-square (64KB)", f"{chi['chi_square']:.2f}  random={chi['is_likely_random']}", use_color)
            print(_c(f"    {chi['interpretation']}", Colors.GREY, use_color))
            results["crypto"]["chi_square"] = chi
        except Exception:
            pass


def run_ai(filepath: str, results: dict, use_color: bool, verbose: bool):
    _section("AI Detector", use_color)
    detector = AIDetector()

    file_result = detector.analyze_file(filepath)
    results["ai_detection"] = file_result

    is_ai = file_result.get("is_likely_ai", False)
    ai_color = Colors.RED if is_ai else Colors.GREEN
    print(_c(f"  Likely AI-generated: {'YES' if is_ai else 'NO'}", ai_color, use_color))
    print(_c(f"  {file_result.get('summary', '')}", Colors.GREY, use_color))

    meta = file_result.get("metadata_analysis") or {}
    for ev in meta.get("evidence", []):
        print(_c(f"    [meta] {ev}", Colors.YELLOW, use_color))

    text = file_result.get("text_analysis") or {}
    if text:
        print(_c(f"  Text AI score: {text.get('score', 0.0):.2f}  confidence: {text.get('confidence', '?')}", ai_color, use_color))
        if verbose:
            for ind in text.get("indicators", []):
                print(_c(f"    [text] {ind}", Colors.GREY, use_color))
            bd = text.get("breakdown", {})
            if bd:
                print(_c("  Per-indicator scores:", Colors.BOLD, use_color))
                for k, v in bd.items():
                    _kv(k, f"{v:.3f}", use_color)


# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description=(
            "metadata-security-toolkit | Developer: pendatkill | Educational use only\n"
            "Unified forensic analysis CLI for metadata, crypto, AI detection, and more."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("filepath", help="Path to the file to analyze")
    parser.add_argument("--all", action="store_true", default=False,
                        help="Run all analysis modules (default if no module flag given)")
    parser.add_argument("--exif", action="store_true", help="Run EXIF analysis")
    parser.add_argument("--forensics", action="store_true", help="Run file forensics")
    parser.add_argument("--crypto", action="store_true", help="Run crypto/encryption tracing")
    parser.add_argument("--ai", action="store_true", help="Run AI content detection")
    parser.add_argument("--report", choices=["json", "txt", "html", "csv"],
                        help="Generate a report file in the specified format")
    parser.add_argument("--output", metavar="PATH",
                        help="Output path for the report (default: auto-generated in current dir)")
    parser.add_argument("--verbose", action="store_true", help="Show extended output")
    parser.add_argument("--no-color", action="store_true", dest="no_color",
                        help="Disable ANSI color output")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    filepath = os.path.abspath(args.filepath)
    if not os.path.isfile(filepath):
        print(f"ERROR: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    use_color = _supports_color(args.no_color)

    # If no specific module flag, run all
    run_all = args.all or not any([args.exif, args.forensics, args.crypto, args.ai])

    _header(use_color)
    print(_c(f"\nAnalyzing: {filepath}", Colors.BOLD, use_color))
    print(_c(f"Timestamp: {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}", Colors.GREY, use_color))

    results = {"file": filepath}

    if run_all or args.exif:
        try:
            run_exif(filepath, results, use_color, args.verbose)
        except Exception as exc:
            print(_c(f"  EXIF error: {exc}", Colors.RED, use_color))

    if run_all or args.forensics:
        try:
            run_forensics(filepath, results, use_color, args.verbose)
        except Exception as exc:
            print(_c(f"  Forensics error: {exc}", Colors.RED, use_color))

    if run_all or args.crypto:
        try:
            run_crypto(filepath, results, use_color, args.verbose)
        except Exception as exc:
            print(_c(f"  Crypto error: {exc}", Colors.RED, use_color))

    if run_all or args.ai:
        try:
            run_ai(filepath, results, use_color, args.verbose)
        except Exception as exc:
            print(_c(f"  AI Detector error: {exc}", Colors.RED, use_color))

    # Risk score
    try:
        engine = ReportEngine()
        risk = engine.calculate_risk_score(results)
        _print_risk(risk, use_color)
    except Exception as exc:
        print(_c(f"  Risk score error: {exc}", Colors.RED, use_color))

    # Report generation
    if args.report:
        fmt_map = {"txt": "text", "json": "json", "html": "html", "csv": "csv"}
        fmt = fmt_map[args.report]

        if args.output:
            out_path = os.path.abspath(args.output)
        else:
            base = os.path.splitext(os.path.basename(filepath))[0]
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            ext_map = {"text": ".txt", "json": ".json", "html": ".html", "csv": ".csv"}
            out_path = os.path.join(os.getcwd(), f"report_{base}_{ts}{ext_map[fmt]}")

        try:
            engine = ReportEngine()
            saved = engine.generate(results, out_path, fmt=fmt)
            print()
            print(_c(f"  Report saved: {saved}", Colors.GREEN, use_color))
        except Exception as exc:
            print(_c(f"  Report generation error: {exc}", Colors.RED, use_color))

    print()


if __name__ == "__main__":
    # On Windows, ensure stdout handles Unicode safely
    if os.name == "nt":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    main()
