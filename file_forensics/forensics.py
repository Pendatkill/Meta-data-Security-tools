# Developer: pendatkill
# Module: file_forensics.forensics
# Description: Performs forensic analysis on files including hashing, MIME detection, and entropy calculation

import os
import hashlib
import mimetypes
import math
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
        Extracts metadata from a PDF file using PyMuPDF (fitz).
        Returns an empty dict if PyMuPDF is not installed or the file is not a PDF.

        Args:
            filepath: Path to a PDF file.

        Returns:
            dict of PDF metadata fields, or {} if unavailable.
        """
        if not FITZ_AVAILABLE:
            return {}
        if not os.path.isfile(filepath):
            return {}
        try:
            doc = fitz.open(filepath)
            meta = doc.metadata or {}
            doc.close()
            return {k: v for k, v in meta.items() if v}
        except Exception:
            return {}

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
