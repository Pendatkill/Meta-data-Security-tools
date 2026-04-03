# Developer: pendatkill
# Module: report_engine.reporter
# Description: Generates structured JSON and plain-text reports from analysis results

import json
import os
from datetime import datetime


class ReportEngine:
    """
    Generates reports from the combined results produced by the toolkit modules.

    Expected results dict structure::

        {
            "file": "/path/to/analysed/file",
            "exif": {...},           # from ExifAnalyzer.analyze()
            "forensics": {...},      # from FileForensics.analyze()
            "crypto": {...},         # from CryptoTracer.hash_file() etc.
            "ai_detection": {...},   # from AIDetector.analyze_file()
        }
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, results: dict, output_path: str, fmt: str = "json") -> str:
        """
        Saves a report to disk.

        Args:
            results:     The combined results dict from toolkit modules.
            output_path: Destination file path for the report.
            fmt:         Output format — 'json' or 'text'.

        Returns:
            The absolute path to the written report file.

        Raises:
            ValueError: If fmt is not 'json' or 'text'.
        """
        fmt = fmt.lower().strip()
        if fmt not in ("json", "text"):
            raise ValueError(f"Unsupported format '{fmt}'. Choose 'json' or 'text'.")

        # Ensure parent directory exists
        parent = os.path.dirname(os.path.abspath(output_path))
        os.makedirs(parent, exist_ok=True)

        if fmt == "json":
            content = self._to_json(results)
        else:
            content = self.summarize(results)

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(content)

        return os.path.abspath(output_path)

    def summarize(self, results: dict) -> str:
        """
        Produces a human-readable plain-text summary of the analysis results.

        Args:
            results: The combined results dict.

        Returns:
            A multi-line string summarising all findings.
        """
        lines = []
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        lines.append("=" * 60)
        lines.append("  METADATA SECURITY TOOLKIT — ANALYSIS REPORT")
        lines.append(f"  Generated: {timestamp}")
        lines.append("=" * 60)

        # File path
        target_file = results.get("file", "N/A")
        lines.append(f"\nTarget file : {target_file}\n")

        # ---- EXIF section ----
        exif = results.get("exif")
        lines.append("--- EXIF Metadata ---")
        if exif:
            for key, val in exif.items():
                lines.append(f"  {key}: {val}")
        else:
            lines.append("  No EXIF data found or module not run.")

        # ---- Forensics section ----
        forensics = results.get("forensics")
        lines.append("\n--- File Forensics ---")
        if forensics:
            for key, val in forensics.items():
                lines.append(f"  {key}: {val}")
        else:
            lines.append("  No forensics data found or module not run.")

        # ---- Crypto section ----
        crypto = results.get("crypto")
        lines.append("\n--- Crypto / Encryption ---")
        if crypto:
            hashes = {k: v for k, v in crypto.items() if k in ("md5", "sha1", "sha256", "sha512")}
            for alg, digest in hashes.items():
                lines.append(f"  {alg.upper()}: {digest}")
            signatures = crypto.get("signatures", [])
            if signatures:
                lines.append("  Encryption/signature findings:")
                for finding in signatures:
                    lines.append(f"    - {finding}")
            stego = crypto.get("steganography", {})
            if stego:
                lines.append(
                    f"  Steganography suspicion score: {stego.get('suspicion_score', 0.0):.2f}"
                )
                for reason in stego.get("reasons", []):
                    lines.append(f"    - {reason}")
        else:
            lines.append("  No crypto data found or module not run.")

        # ---- AI Detection section ----
        ai = results.get("ai_detection")
        lines.append("\n--- AI Detection ---")
        if ai:
            is_ai = ai.get("is_likely_ai", False)
            lines.append(f"  Likely AI-generated: {'YES' if is_ai else 'NO'}")
            summary_str = ai.get("summary", "")
            if summary_str:
                lines.append(f"  Summary: {summary_str}")
            meta_analysis = ai.get("metadata_analysis") or {}
            for ev in meta_analysis.get("evidence", []):
                lines.append(f"    [metadata] {ev}")
            text_analysis = ai.get("text_analysis") or {}
            if text_analysis:
                lines.append(
                    f"  Text AI score: {text_analysis.get('score', 0.0):.2f} "
                    f"(confidence: {text_analysis.get('confidence', 'unknown')})"
                )
                for ind in text_analysis.get("indicators", []):
                    lines.append(f"    [text] {ind}")
        else:
            lines.append("  No AI detection data found or module not run.")

        lines.append("\n" + "=" * 60)
        lines.append("  END OF REPORT")
        lines.append("=" * 60)

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_json(results: dict) -> str:
        """Serialises results to a pretty-printed JSON string."""

        def _default_serialiser(obj):
            """Fallback serialiser for non-JSON-native types."""
            if isinstance(obj, bytes):
                return obj.hex()
            if hasattr(obj, "__dict__"):
                return obj.__dict__
            return str(obj)

        return json.dumps(results, indent=2, default=_default_serialiser, ensure_ascii=False)
