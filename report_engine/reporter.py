# Developer: pendatkill
# Module: report_engine.reporter
# Description: Generates structured JSON, plain-text, HTML, and CSV reports from analysis results

import csv
import io
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

    DEVELOPER = "pendatkill"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, results: dict, output_path: str, fmt: str = "json") -> str:
        """
        Saves a report to disk.

        Args:
            results:     The combined results dict from toolkit modules.
            output_path: Destination file path for the report.
            fmt:         Output format — 'json', 'text', 'html', or 'csv'.

        Returns:
            The absolute path to the written report file.

        Raises:
            ValueError: If fmt is not a supported format.
        """
        fmt = fmt.lower().strip()
        if fmt not in ("json", "text", "html", "csv"):
            raise ValueError(f"Unsupported format '{fmt}'. Choose 'json', 'text', 'html', or 'csv'.")

        # Ensure parent directory exists
        parent = os.path.dirname(os.path.abspath(output_path))
        os.makedirs(parent, exist_ok=True)

        if fmt == "json":
            content = self._to_json(results)
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(content)
        elif fmt == "text":
            content = self.summarize(results)
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(content)
        elif fmt == "html":
            self.generate_html(results, output_path)
        elif fmt == "csv":
            self.generate_csv(results, output_path)

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
        lines.append(f"  Developer: {self.DEVELOPER}")
        lines.append("=" * 60)

        # File path
        target_file = results.get("file", "N/A")
        lines.append(f"\nTarget file : {target_file}\n")

        # ---- Risk Score ----
        risk = self.calculate_risk_score(results)
        lines.append(f"--- Risk Score ---")
        lines.append(f"  Total: {risk['total']}/100  Level: {risk['level']}")
        for item in risk.get("breakdown", []):
            lines.append(f"    + {item}")

        # ---- EXIF section ----
        exif = results.get("exif")
        lines.append("\n--- EXIF Metadata ---")
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
                    if isinstance(finding, dict):
                        lines.append(f"    - [{finding.get('confidence','?').upper()}] {finding.get('type','?')}: {finding.get('detail','')}")
                    else:
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
        lines.append(f"  END OF REPORT  |  Developer: {self.DEVELOPER}  |  Educational use only")
        lines.append("=" * 60)

        return "\n".join(lines)

    def generate_html(self, results: dict, output_path: str) -> str:
        """
        Generates a self-contained HTML report with dark theme, inline CSS,
        color-coded risk levels, and sections per module.
        No external dependencies — fully self-contained.

        Args:
            results: The combined results dict.
            output_path: Path to write the HTML file.

        Returns:
            Absolute path to the written HTML file.
        """
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        target_file = results.get("file", "N/A")
        risk = self.calculate_risk_score(results)

        risk_color = {
            "LOW": "#4caf50",
            "MEDIUM": "#ff9800",
            "HIGH": "#f44336",
            "CRITICAL": "#b71c1c",
        }.get(risk["level"], "#9e9e9e")

        def _row(key, val, mono=False):
            style = " style=\"font-family:monospace\"" if mono else ""
            return f"<tr><td class='key'>{_esc(str(key))}</td><td{style}>{_esc(str(val))}</td></tr>"

        def _esc(s):
            return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    .replace('"', "&quot;"))

        def _section(title, content_html):
            return f"""
<div class="section">
  <h2>{_esc(title)}</h2>
  {content_html}
</div>"""

        def _dict_table(d):
            if not d:
                return "<p class='muted'>No data available.</p>"
            rows = "".join(_row(k, v, mono=(k in ("md5", "sha256", "sha1", "sha512")))
                           for k, v in d.items())
            return f"<table><tbody>{rows}</tbody></table>"

        # Build sections
        exif_html = _dict_table(results.get("exif") or {})

        forensics = results.get("forensics") or {}
        forensics_html = _dict_table(forensics)

        crypto = results.get("crypto") or {}
        crypto_rows = ""
        for alg in ("md5", "sha1", "sha256", "sha512"):
            if alg in crypto:
                crypto_rows += _row(alg.upper(), crypto[alg], mono=True)
        sigs = crypto.get("signatures", [])
        sig_items = ""
        if sigs:
            for s in sigs:
                if isinstance(s, dict):
                    conf = s.get("confidence", "?").upper()
                    color = {"HIGH": "#f44336", "MEDIUM": "#ff9800", "LOW": "#4caf50"}.get(conf, "#aaa")
                    sig_items += f"<li><span style='color:{color}'>[{conf}]</span> <b>{_esc(s.get('type','?'))}</b>: {_esc(s.get('detail',''))}</li>"
                else:
                    sig_items += f"<li>{_esc(str(s))}</li>"
        stego = crypto.get("steganography", {})
        stego_html = ""
        if stego:
            stego_score = stego.get("suspicion_score", 0.0)
            stego_color = "#f44336" if stego_score > 0.5 else ("#ff9800" if stego_score > 0.2 else "#4caf50")
            stego_html = f"<p>Steganography score: <span style='color:{stego_color};font-weight:bold'>{stego_score:.2f}</span></p>"
            if stego.get("reasons"):
                stego_html += "<ul>" + "".join(f"<li>{_esc(r)}</li>" for r in stego["reasons"]) + "</ul>"
        crypto_html = (
            f"<table><tbody>{crypto_rows}</tbody></table>"
            + (f"<h3>Encryption Signatures</h3><ul>{sig_items}</ul>" if sig_items else "")
            + stego_html
        ) if (crypto_rows or sig_items or stego_html) else "<p class='muted'>No crypto data.</p>"

        ai = results.get("ai_detection") or {}
        is_ai = ai.get("is_likely_ai", False)
        ai_color = "#f44336" if is_ai else "#4caf50"
        ai_verdict = "YES — Likely AI-generated" if is_ai else "NO — No strong AI indicators"
        meta_ev = (ai.get("metadata_analysis") or {}).get("evidence", [])
        text_an = ai.get("text_analysis") or {}
        ai_html = f"<p><b>AI Verdict:</b> <span style='color:{ai_color}'>{ai_verdict}</span></p>"
        if ai.get("summary"):
            ai_html += f"<p>{_esc(ai['summary'])}</p>"
        if meta_ev:
            ai_html += "<h3>Metadata Evidence</h3><ul>" + "".join(f"<li>{_esc(e)}</li>" for e in meta_ev) + "</ul>"
        if text_an:
            ai_html += (
                f"<p>Text AI score: <b>{text_an.get('score', 0.0):.2f}</b> "
                f"(confidence: {text_an.get('confidence', '?')})</p>"
            )
            inds = text_an.get("indicators", [])
            if inds:
                ai_html += "<ul>" + "".join(f"<li>{_esc(i)}</li>" for i in inds) + "</ul>"

        # Risk score section
        risk_items = "".join(f"<li>{_esc(b)}</li>" for b in risk.get("breakdown", []))
        risk_html = (
            f"<p>Total: <span style='color:{risk_color};font-size:1.5em;font-weight:bold'>"
            f"{risk['total']}/100</span> &nbsp; Level: "
            f"<span style='color:{risk_color};font-weight:bold'>{risk['level']}</span></p>"
            + (f"<ul>{risk_items}</ul>" if risk_items else "")
        )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Metadata Security Toolkit Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: #121212; color: #e0e0e0;
    font-family: 'Segoe UI', Arial, sans-serif; font-size: 14px;
    padding: 20px;
  }}
  header {{
    background: #1e1e2e; border-left: 4px solid #7c3aed;
    padding: 16px 20px; margin-bottom: 20px; border-radius: 4px;
  }}
  header h1 {{ font-size: 1.4em; color: #a78bfa; }}
  header .meta {{ color: #888; font-size: 0.85em; margin-top: 6px; }}
  .section {{
    background: #1e1e2e; border-radius: 6px; padding: 16px 20px;
    margin-bottom: 16px; border-left: 3px solid #444;
  }}
  .section h2 {{ color: #a78bfa; font-size: 1em; margin-bottom: 12px; border-bottom: 1px solid #333; padding-bottom: 6px; }}
  .section h3 {{ color: #888; font-size: 0.9em; margin: 12px 0 6px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  td {{ padding: 4px 8px; border-bottom: 1px solid #2a2a3e; vertical-align: top; }}
  td.key {{ color: #888; width: 200px; font-size: 0.85em; white-space: nowrap; }}
  ul {{ padding-left: 20px; }}
  li {{ padding: 3px 0; }}
  p {{ margin: 4px 0; }}
  .muted {{ color: #555; font-style: italic; }}
  footer {{
    text-align: center; color: #555; font-size: 0.8em;
    margin-top: 30px; padding-top: 12px; border-top: 1px solid #333;
  }}
  .risk-badge {{
    display: inline-block; padding: 4px 12px; border-radius: 4px;
    font-weight: bold; color: #fff; background: {risk_color};
    font-size: 1.1em;
  }}
</style>
</head>
<body>
<header>
  <h1>&#128272; Metadata Security Toolkit — Analysis Report</h1>
  <div class="meta">
    <b>Target:</b> {_esc(target_file)} &nbsp;|&nbsp;
    <b>Generated:</b> {timestamp} &nbsp;|&nbsp;
    <b>Developer:</b> {self.DEVELOPER} &nbsp;|&nbsp;
    <b>Educational use only</b>
  </div>
</header>

{_section("Risk Score", risk_html)}
{_section("EXIF Metadata", exif_html)}
{_section("File Forensics", forensics_html)}
{_section("Crypto / Encryption", crypto_html)}
{_section("AI Detection", ai_html)}

<footer>
  metadata-security-toolkit &nbsp;|&nbsp; Developer: {self.DEVELOPER} &nbsp;|&nbsp; Educational use only
</footer>
</body>
</html>"""

        parent = os.path.dirname(os.path.abspath(output_path))
        os.makedirs(parent, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html)

        return os.path.abspath(output_path)

    def generate_csv(self, results: dict, output_path: str) -> str:
        """
        Generates a flat key=value CSV from the results dict.
        Nested dicts are flattened with dot notation (e.g., forensics.md5).

        Args:
            results: The combined results dict.
            output_path: Path to write the CSV file.

        Returns:
            Absolute path to the written CSV file.
        """
        flat = {}
        self._flatten_dict(results, flat, prefix="")

        parent = os.path.dirname(os.path.abspath(output_path))
        os.makedirs(parent, exist_ok=True)

        with open(output_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["key", "value"])
            for key, value in flat.items():
                writer.writerow([key, str(value)])

        return os.path.abspath(output_path)

    @staticmethod
    def _flatten_dict(d, result: dict, prefix: str):
        """Recursively flatten a nested dict into dot-notation keys."""
        if isinstance(d, dict):
            for k, v in d.items():
                new_key = f"{prefix}.{k}" if prefix else str(k)
                ReportEngine._flatten_dict(v, result, new_key)
        elif isinstance(d, list):
            for i, item in enumerate(d):
                new_key = f"{prefix}[{i}]"
                ReportEngine._flatten_dict(item, result, new_key)
        else:
            result[prefix] = d

    def calculate_risk_score(self, results: dict) -> dict:
        """
        Calculates an overall risk score (0–100) based on analysis findings.

        Scoring:
        - Encryption detected: +30
        - File type mismatch: +25
        - Entropy > 7.5: +20
        - Stego suspicion > 0.5: +25
        - AI score > 0.6: +15
        - No camera EXIF in JPEG: +10
        - Manipulation signs (medium/high): +20
        - Each crypto signature (high confidence): +5 (capped at +15)

        Args:
            results: The combined results dict.

        Returns:
            dict with: total (int), level (str), breakdown (list of strings).
        """
        total = 0
        breakdown = []

        # --- Encryption detected ---
        crypto = results.get("crypto") or {}
        signatures = crypto.get("signatures", [])
        if signatures:
            high_conf_sigs = [
                s for s in signatures
                if isinstance(s, dict) and s.get("confidence") == "high"
            ]
            # Legacy string format
            string_sigs = [s for s in signatures if isinstance(s, str) and s != "No encryption signatures detected."]
            n_sigs = len(high_conf_sigs) + len(string_sigs)
            if n_sigs > 0:
                pts = min(30 + (n_sigs - 1) * 5, 45)
                total += pts
                breakdown.append(f"Encryption signatures detected ({n_sigs}): +{pts}")

        # --- File type mismatch ---
        forensics = results.get("forensics") or {}
        mismatch = forensics.get("mismatch", False)
        if mismatch:
            total += 25
            breakdown.append("File type mismatch detected: +25")

        # --- High entropy ---
        entropy = results.get("entropy")
        if entropy is None:
            # Try to extract from forensics or crypto
            entropy = forensics.get("entropy")
        if entropy is not None and isinstance(entropy, (int, float)) and entropy > 7.5:
            total += 20
            breakdown.append(f"High entropy ({entropy:.2f} > 7.5): +20")
        elif not entropy:
            # Check crypto steganography entropy hint
            stego = crypto.get("steganography") or {}
            if stego.get("suspicion_score", 0) > 0.5:
                pass  # handled below

        # --- Steganography suspicion ---
        stego = crypto.get("steganography") or {}
        stego_score = stego.get("suspicion_score", 0.0)
        if stego_score > 0.5:
            total += 25
            breakdown.append(f"Steganography suspicion score ({stego_score:.2f} > 0.5): +25")
        elif stego_score > 0.2:
            total += 10
            breakdown.append(f"Moderate steganography suspicion ({stego_score:.2f}): +10")

        # --- AI content score ---
        ai = results.get("ai_detection") or {}
        text_analysis = ai.get("text_analysis") or {}
        ai_score = text_analysis.get("score", 0.0)
        meta_analysis = ai.get("metadata_analysis") or {}
        if meta_analysis.get("is_likely_ai") or ai_score > 0.6:
            total += 15
            breakdown.append(f"AI-generated content detected (score={ai_score:.2f}): +15")

        # --- No camera EXIF in JPEG ---
        exif = results.get("exif") or {}
        target_file = results.get("file", "")
        ext = os.path.splitext(target_file)[1].lower()
        if ext in (".jpg", ".jpeg") and not exif.get("Make") and not exif.get("Model"):
            total += 10
            breakdown.append("JPEG missing camera Make/Model EXIF: +10")

        # --- Manipulation signs ---
        manipulation = results.get("manipulation") or {}
        risk_level_manip = manipulation.get("risk_level", "low")
        if risk_level_manip == "high":
            total += 20
            breakdown.append("High-risk manipulation signs detected: +20")
        elif risk_level_manip == "medium":
            total += 10
            breakdown.append("Medium-risk manipulation signs detected: +10")

        total = min(total, 100)

        if total >= 85:
            level = "CRITICAL"
        elif total >= 60:
            level = "HIGH"
        elif total >= 30:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {"total": total, "level": level, "breakdown": breakdown}

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
