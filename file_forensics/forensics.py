# Developer: pendatkill
# Module: file_forensics.forensics
# Description: Performs forensic analysis on files including hashing, MIME detection, and entropy calculation

import os
import hashlib
import mimetypes
import math
import subprocess
import json
import zipfile
from datetime import datetime
from typing import Optional

try:
    import fitz  # PyMuPDF
    FITZ_AVAILABLE = True
except ImportError:
    FITZ_AVAILABLE = False

try:
    from docx import Document as DocxDocument
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False

try:
    import openpyxl
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False


# Magic bytes for common file types
_MAGIC_BYTES = {
    b"%PDF": "PDF",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"\xff\xd8\xff": "JPEG",
    b"PK\x03\x04": "ZIP",
    b"GIF8": "GIF",
    b"\x7fELF": "ELF",
    b"MZ": "PE/EXE",
    b"7z\xbc\xaf\x27\x1c": "7-Zip",
    b"Rar!\x1a\x07": "RAR",
    b"BM": "BMP",
    b"RIFF": "RIFF (WAV/AVI)",
    b"\x1f\x8b": "GZIP",
    b"\xca\xfe\xba\xbe": "Java Class",
    b"\xfe\xed\xfa\xce": "Mach-O 32-bit",
    b"\xfe\xed\xfa\xcf": "Mach-O 64-bit",
    b"OggS": "OGG",
    b"ID3": "MP3",
    b"\xff\xfb": "MP3",
}

_EXTENSION_MAP = {
    ".pdf": "PDF",
    ".png": "PNG",
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".zip": "ZIP",
    ".gif": "GIF",
    ".elf": "ELF",
    ".exe": "PE/EXE",
    ".dll": "PE/EXE",
    ".7z": "7-Zip",
    ".rar": "RAR",
    ".bmp": "BMP",
    ".wav": "RIFF (WAV/AVI)",
    ".avi": "RIFF (WAV/AVI)",
    ".gz": "GZIP",
    ".class": "Java Class",
    ".ogg": "OGG",
    ".mp3": "MP3",
    ".docx": "ZIP",
    ".xlsx": "ZIP",
    ".pptx": "ZIP",
    ".mp4": "MP4",
    ".m4v": "MP4",
    ".mov": "MP4",
}


class FileForensics:
    """Performs forensic analysis on arbitrary files."""

    def analyze(self, filepath: str) -> dict:
        """
        Returns a forensic summary dict for the given file.

        Keys: filename, size, mime_type, created, modified, md5, sha256.

        Args:
            filepath: Path to the target file.

        Returns:
            dict with forensic metadata.
        """
        if not os.path.isfile(filepath):
            return {}

        stat = os.stat(filepath)
        mime_type, _ = mimetypes.guess_type(filepath)

        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)

        return {
            "filename": os.path.basename(filepath),
            "size": stat.st_size,
            "mime_type": mime_type or "application/octet-stream",
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "md5": md5_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest(),
        }

    def get_pdf_metadata(self, filepath: str) -> dict:
        """
        Extracts extended metadata from a PDF file using PyMuPDF (fitz).
        Includes author, creator, producer, dates, page count,
        JavaScript detection, embedded files, and encryption status.

        Returns an empty dict if PyMuPDF is not installed or the file is not a PDF.

        Args:
            filepath: Path to a PDF file.

        Returns:
            dict of PDF metadata fields.
        """
        if not FITZ_AVAILABLE:
            return {}
        if not os.path.isfile(filepath):
            return {}
        try:
            doc = fitz.open(filepath)
            meta = doc.metadata or {}
            result = {}

            # Standard metadata fields
            for field in ("author", "creator", "producer", "creationDate", "modDate", "title", "subject"):
                val = meta.get(field, "")
                if val:
                    result[field] = val

            result["page_count"] = doc.page_count
            result["is_encrypted"] = doc.is_encrypted

            # Check for JavaScript
            has_js = False
            try:
                # Search for JS action in all pages
                for page in doc:
                    text = page.get_text("rawdict")
                    # Check annotation actions
                    for annot in page.annots():
                        info = annot.info
                        if info:
                            action = str(info)
                            if "/JS" in action or "/JavaScript" in action:
                                has_js = True
                                break
                    if has_js:
                        break
                # Also check raw PDF content for JS markers
                if not has_js:
                    raw_content = b""
                    with open(filepath, "rb") as fh:
                        raw_content = fh.read(min(os.path.getsize(filepath), 1024 * 1024))
                    if b"/JS" in raw_content or b"/JavaScript" in raw_content:
                        has_js = True
            except Exception:
                pass

            result["has_javascript"] = has_js

            # Check for embedded files
            has_embedded = False
            embedded_count = 0
            try:
                for i in range(doc.embfile_count()):
                    has_embedded = True
                    embedded_count += 1
            except Exception:
                pass
            result["has_embedded_files"] = has_embedded
            result["embedded_file_count"] = embedded_count

            doc.close()
            return result
        except Exception as exc:
            return {"error": str(exc)}

    def get_office_metadata(self, filepath: str) -> dict:
        """
        Extracts core metadata from .docx or .xlsx Office files.
        Uses python-docx for Word files, openpyxl for Excel files.
        Returns an empty dict if the relevant library is not installed.

        Args:
            filepath: Path to an Office document.

        Returns:
            dict of document metadata, or {} if unavailable.
        """
        if not os.path.isfile(filepath):
            return {}

        ext = os.path.splitext(filepath)[1].lower()

        if ext == ".docx" and DOCX_AVAILABLE:
            try:
                doc = DocxDocument(filepath)
                props = doc.core_properties
                result = {}
                for attr in (
                    "author", "created", "description", "identifier",
                    "keywords", "language", "last_modified_by",
                    "last_printed", "modified", "revision",
                    "subject", "title", "version",
                ):
                    val = getattr(props, attr, None)
                    if val is not None:
                        result[attr] = str(val)
                return result
            except Exception:
                return {}

        if ext == ".xlsx" and OPENPYXL_AVAILABLE:
            try:
                wb = openpyxl.load_workbook(filepath, read_only=True, data_only=True)
                props = wb.properties
                result = {}
                for attr in (
                    "creator", "created", "description", "identifier",
                    "keywords", "language", "lastModifiedBy",
                    "lastPrinted", "modified", "revision",
                    "subject", "title", "version",
                ):
                    val = getattr(props, attr, None)
                    if val is not None:
                        result[attr] = str(val)
                wb.close()
                return result
            except Exception:
                return {}

        return {}

    def compute_entropy(self, filepath: str) -> float:
        """
        Computes the Shannon entropy of the file's bytes.
        A value near 0 indicates low randomness (e.g., all zeros).
        A value near 8 indicates high randomness (encrypted or compressed data).

        Args:
            filepath: Path to the target file.

        Returns:
            Shannon entropy as a float in [0, 8].
        """
        if not os.path.isfile(filepath):
            return 0.0

        with open(filepath, "rb") as fh:
            data = fh.read()

        return self._shannon_entropy(data)

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        """Compute Shannon entropy for a bytes object."""
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        length = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                prob = count / length
                entropy -= prob * math.log2(prob)
        return entropy

    def analyze_strings(self, filepath: str, min_length: int = 6) -> list:
        """
        Extracts printable ASCII strings from a binary file (similar to Unix `strings`).
        Useful for discovering URLs, paths, credentials, and other artifacts.

        Args:
            filepath: Path to the file to scan.
            min_length: Minimum string length to include (default: 6).

        Returns:
            List of up to 200 extracted strings.
        """
        if not os.path.isfile(filepath):
            return []

        results = []
        printable = set(range(0x20, 0x7F))  # space through ~
        printable.add(0x09)  # tab
        printable.add(0x0A)  # newline
        printable.add(0x0D)  # carriage return

        try:
            with open(filepath, "rb") as fh:
                data = fh.read()

            current = []
            for byte in data:
                if byte in printable:
                    current.append(chr(byte))
                else:
                    if len(current) >= min_length:
                        s = "".join(current).strip()
                        if s:
                            results.append(s)
                            if len(results) >= 200:
                                break
                    current = []

            # Flush last string
            if len(current) >= min_length and len(results) < 200:
                s = "".join(current).strip()
                if s:
                    results.append(s)

        except Exception:
            pass

        return results

    def detect_file_type_mismatch(self, filepath: str) -> dict:
        """
        Reads the first 16 bytes of a file and checks magic bytes against the file extension.
        Identifies files disguised with a wrong extension.

        Args:
            filepath: Path to the file to check.

        Returns:
            dict with: extension, detected_type, mismatch (bool), risk ('high'/'low'/'none').
        """
        if not os.path.isfile(filepath):
            return {"extension": "", "detected_type": "unknown", "mismatch": False, "risk": "none"}

        ext = os.path.splitext(filepath)[1].lower()

        try:
            with open(filepath, "rb") as fh:
                header = fh.read(16)
        except Exception:
            return {"extension": ext, "detected_type": "unknown", "mismatch": False, "risk": "none"}

        detected_type = "unknown"

        # Check MP4: ftyp box at offset 4
        if len(header) >= 8 and header[4:8] == b"ftyp":
            detected_type = "MP4"
        else:
            # Check magic bytes in order (longest first for accuracy)
            magic_checks = [
                (b"\x89PNG\r\n\x1a\n", "PNG"),
                (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
                (b"Rar!\x1a\x07", "RAR"),
                (b"GIF8", "GIF"),
                (b"\x7fELF", "ELF"),
                (b"\xff\xd8\xff", "JPEG"),
                (b"PK\x03\x04", "ZIP"),
                (b"%PDF", "PDF"),
                (b"MZ", "PE/EXE"),
                (b"BM", "BMP"),
                (b"RIFF", "RIFF (WAV/AVI)"),
                (b"\x1f\x8b", "GZIP"),
                (b"\xca\xfe\xba\xbe", "Java Class"),
                (b"OggS", "OGG"),
                (b"ID3", "MP3"),
                (b"\xff\xfb", "MP3"),
            ]
            for magic, name in magic_checks:
                if header[:len(magic)] == magic:
                    detected_type = name
                    break

        extension_expected = _EXTENSION_MAP.get(ext, "unknown")

        # Determine mismatch
        mismatch = False
        if detected_type != "unknown" and extension_expected != "unknown":
            # Normalize: ZIP-based formats (docx/xlsx/pptx) are actually ZIP
            if extension_expected == "ZIP" and detected_type == "ZIP":
                mismatch = False
            elif extension_expected != detected_type:
                mismatch = True

        # If extension is unknown but we detected something, not necessarily a mismatch
        if extension_expected == "unknown" and detected_type != "unknown":
            mismatch = False  # Can't confirm mismatch without known extension

        risk = "high" if mismatch else ("low" if detected_type == "unknown" else "none")

        return {
            "extension": ext,
            "detected_type": detected_type,
            "expected_type": extension_expected,
            "mismatch": mismatch,
            "risk": risk,
        }

    def get_video_metadata(self, filepath: str) -> dict:
        """
        Extracts video metadata using ffprobe (if available in PATH).
        Returns duration, codec, resolution, creation_time, and encoder.

        Gracefully degrades if ffprobe is not installed.

        Args:
            filepath: Path to the video file.

        Returns:
            dict with video metadata, or {"ffprobe_available": False} if unavailable.
        """
        if not os.path.isfile(filepath):
            return {"error": "File not found"}

        try:
            result = subprocess.run(
                [
                    "ffprobe", "-v", "quiet",
                    "-print_format", "json",
                    "-show_format",
                    "-show_streams",
                    filepath,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return {"ffprobe_available": True, "error": result.stderr.strip()}

            data = json.loads(result.stdout)
            fmt = data.get("format", {})
            streams = data.get("streams", [])

            # Find video stream
            video_stream = next((s for s in streams if s.get("codec_type") == "video"), None)
            audio_stream = next((s for s in streams if s.get("codec_type") == "audio"), None)

            output = {
                "ffprobe_available": True,
                "duration": fmt.get("duration"),
                "size": fmt.get("size"),
                "bitrate": fmt.get("bit_rate"),
                "format_name": fmt.get("format_name"),
                "encoder": fmt.get("tags", {}).get("encoder") or fmt.get("tags", {}).get("Encoder"),
                "creation_time": fmt.get("tags", {}).get("creation_time"),
            }

            if video_stream:
                output["codec"] = video_stream.get("codec_name")
                output["codec_long_name"] = video_stream.get("codec_long_name")
                output["width"] = video_stream.get("width")
                output["height"] = video_stream.get("height")
                output["resolution"] = (
                    f"{video_stream.get('width')}x{video_stream.get('height')}"
                    if video_stream.get("width") else None
                )
                output["frame_rate"] = video_stream.get("r_frame_rate")
                output["pixel_format"] = video_stream.get("pix_fmt")

            if audio_stream:
                output["audio_codec"] = audio_stream.get("codec_name")
                output["sample_rate"] = audio_stream.get("sample_rate")
                output["channels"] = audio_stream.get("channels")

            return output

        except FileNotFoundError:
            return {"ffprobe_available": False}
        except subprocess.TimeoutExpired:
            return {"ffprobe_available": True, "error": "ffprobe timed out"}
        except json.JSONDecodeError as exc:
            return {"ffprobe_available": True, "error": f"JSON parse error: {exc}"}
        except Exception as exc:
            return {"ffprobe_available": True, "error": str(exc)}

    def find_embedded_files(self, filepath: str) -> list:
        """
        Lists files embedded within container formats.

        - ZIP-based formats (zip, docx, xlsx, pptx): uses stdlib zipfile.
        - PDF: lists embedded attachments using PyMuPDF if available.

        Args:
            filepath: Path to the container file.

        Returns:
            List of dicts with 'name' and 'size' keys.
        """
        if not os.path.isfile(filepath):
            return []

        ext = os.path.splitext(filepath)[1].lower()
        embedded = []

        # ZIP-based formats
        zip_exts = {".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".jar", ".apk"}
        if ext in zip_exts:
            try:
                with zipfile.ZipFile(filepath, "r") as zf:
                    for info in zf.infolist():
                        embedded.append({
                            "name": info.filename,
                            "size": info.file_size,
                            "compressed_size": info.compress_size,
                        })
            except zipfile.BadZipFile:
                pass
            except Exception:
                pass
            return embedded

        # PDF embedded files
        if ext == ".pdf" and FITZ_AVAILABLE:
            try:
                doc = fitz.open(filepath)
                for i in range(doc.embfile_count()):
                    info = doc.embfile_info(i)
                    embedded.append({
                        "name": info.get("filename", f"embedded_{i}"),
                        "size": info.get("size", 0),
                    })
                doc.close()
            except Exception:
                pass
            return embedded

        return embedded
