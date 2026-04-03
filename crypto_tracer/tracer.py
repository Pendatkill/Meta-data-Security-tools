# Developer: pendatkill
# Module: crypto_tracer.tracer
# Description: Detects cryptographic signatures, measures entropy, and checks steganography hints in files

import os
import hashlib
import math
from typing import Optional

try:
    from PIL import Image
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False


# Magic byte signatures for common encrypted / protected formats
_MAGIC_SIGNATURES = [
    # PGP ASCII armor
    (b"-----BEGIN PGP", "PGP ASCII-armored message"),
    # PGP binary (old-format packet, ctb with bit 7 set and bit 6 clear)
    (bytes([0x85]), "PGP binary packet (0x85 header)"),
    (bytes([0x99]), "PGP binary packet (0x99 header)"),
    # VeraCrypt / TrueCrypt volumes have no reliable magic, but we detect
    # very high entropy on the first 512 bytes as a hint (handled separately)
    # OpenSSL encrypted with salted key derivation
    (b"Salted__", "OpenSSL salted encryption header"),
    # GPG symmetric encrypted data (rfc4880 new-format)
    (bytes([0xC3]), "GPG symmetric-key encrypted session packet"),
    # ZIP with AES encryption: PK\x03\x04 with general-purpose bit 6 set
    # Detected in logic below due to flag-byte check
]

# ZIP local file header magic
_ZIP_MAGIC = b"PK\x03\x04"


class CryptoTracer:
    """Traces cryptographic properties and encryption indicators in files."""

    def hash_file(self, filepath: str) -> dict:
        """
        Computes multiple cryptographic hashes of a file.

        Args:
            filepath: Path to the target file.

        Returns:
            dict with keys 'md5', 'sha1', 'sha256', 'sha512', each a hex string.
        """
        if not os.path.isfile(filepath):
            return {}

        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()

        with open(filepath, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                sha512.update(chunk)

        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
            "sha512": sha512.hexdigest(),
        }

    def detect_encryption_signature(self, filepath: str) -> list:
        """
        Reads the first 512 bytes of a file and checks for known magic bytes
        associated with encrypted or cryptographically protected formats.

        Detects:
        - PGP ASCII armor and binary packets
        - OpenSSL salted encryption
        - ZIP with AES encryption (flag bit 6 set in local file header)
        - GPG symmetric session packets
        - High entropy (>7.5 bits/byte) suggesting encryption/compression

        Args:
            filepath: Path to the file to inspect.

        Returns:
            List of finding strings (empty list if nothing suspicious found).
        """
        if not os.path.isfile(filepath):
            return []

        with open(filepath, "rb") as fh:
            header = fh.read(512)

        if not header:
            return []

        findings = []

        # Check static magic signatures
        for magic, description in _MAGIC_SIGNATURES:
            if header.startswith(magic) or magic in header[:len(magic) + 2]:
                findings.append(description)
                break

        # Check ZIP AES encryption: PK\x03\x04 at offset 0,
        # general-purpose bit flag at bytes 6-7 (little-endian), bit 6 = strong encryption
        if header[:4] == _ZIP_MAGIC and len(header) >= 8:
            gp_flag = int.from_bytes(header[6:8], "little")
            if gp_flag & (1 << 6):
                findings.append("ZIP with AES/strong encryption (general-purpose bit 6 set)")
            elif gp_flag & (1 << 0):
                # bit 0 = standard ZIP encryption (legacy)
                findings.append("ZIP with legacy password encryption (general-purpose bit 0 set)")

        # High-entropy header suggests encryption or compression
        entropy = self.measure_entropy(header)
        if entropy > 7.5:
            findings.append(
                f"High entropy in file header ({entropy:.2f} bits/byte) — "
                "likely encrypted or compressed"
            )

        return findings

    def measure_entropy(self, data: bytes) -> float:
        """
        Computes Shannon entropy of a bytes object.

        High entropy (>7.5) suggests encrypted or compressed data.
        Low entropy (<1.0) suggests highly repetitive or structured data.

        Args:
            data: Raw bytes to analyse.

        Returns:
            Shannon entropy as a float in [0.0, 8.0].
        """
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

    def check_steganography_hints(self, filepath: str) -> dict:
        """
        Heuristically checks for possible steganographic content in PNG or BMP files.

        Checks performed:
        1. File size vs. expected size from image dimensions (ratio anomaly).
        2. LSB randomness: measures entropy of least-significant bits of pixel values.
           Natural images have structured LSBs; steganographic images have near-random LSBs.

        Args:
            filepath: Path to a PNG or BMP image file.

        Returns:
            dict with:
                - 'suspicion_score': float in [0.0, 1.0]
                - 'reasons': list of human-readable reason strings
                - 'supported': bool (False if file type unsupported or Pillow unavailable)
        """
        result = {"suspicion_score": 0.0, "reasons": [], "supported": False}

        if not PILLOW_AVAILABLE:
            result["reasons"].append("Pillow not available; steganography check skipped.")
            return result

        if not os.path.isfile(filepath):
            result["reasons"].append("File not found.")
            return result

        ext = os.path.splitext(filepath)[1].lower()
        if ext not in (".png", ".bmp"):
            result["reasons"].append(
                f"Unsupported format '{ext}'; only PNG and BMP are checked."
            )
            return result

        result["supported"] = True
        score = 0.0
        reasons = []

        try:
            img = Image.open(filepath).convert("RGB")
        except Exception as exc:
            result["reasons"].append(f"Could not open image: {exc}")
            return result

        width, height = img.size
        pixels = list(img.getdata())
        total_pixels = width * height

        # --- Check 1: file size vs. expected uncompressed size ---
        actual_size = os.path.getsize(filepath)
        # Expected uncompressed RGB: width * height * 3 bytes
        expected_raw = total_pixels * 3
        if ext == ".png":
            # PNG compresses well; typical ratio 0.5–0.9 for photos, near 1.0 for artificial images
            # A PNG that is larger than expected_raw / 2 and contains very random data is suspicious
            size_ratio = actual_size / expected_raw if expected_raw > 0 else 0
            if size_ratio > 0.95:
                reasons.append(
                    f"PNG file size ({actual_size} bytes) is unusually large relative to "
                    f"uncompressed size ({expected_raw} bytes); ratio={size_ratio:.2f}"
                )
                score += 0.25
        elif ext == ".bmp":
            # BMP is uncompressed; file should be close to expected_raw + header (~54 bytes)
            expected_bmp = expected_raw + 54
            deviation = abs(actual_size - expected_bmp)
            if deviation > 1024:
                reasons.append(
                    f"BMP file size ({actual_size}) deviates significantly from expected "
                    f"({expected_bmp}); extra bytes may hide data."
                )
                score += 0.3

        # --- Check 2: LSB entropy analysis ---
        # Extract LSBs of R, G, B channels
        lsb_bytes = bytearray()
        sample_limit = min(total_pixels, 50000)  # cap for performance
        for r, g, b in pixels[:sample_limit]:
            lsb_bytes.append(r & 1)
            lsb_bytes.append(g & 1)
            lsb_bytes.append(b & 1)

        # Pack LSBs into actual bytes (8 LSB values per byte)
        packed = bytearray()
        for i in range(0, len(lsb_bytes) - 7, 8):
            val = 0
            for bit in range(8):
                val |= lsb_bytes[i + bit] << bit
            packed.append(val)

        if packed:
            lsb_entropy = self.measure_entropy(bytes(packed))
            if lsb_entropy > 7.2:
                reasons.append(
                    f"LSB entropy is very high ({lsb_entropy:.2f} bits/byte), "
                    "suggesting possible steganographic payload."
                )
                score += 0.5
            elif lsb_entropy > 6.5:
                reasons.append(
                    f"LSB entropy is elevated ({lsb_entropy:.2f} bits/byte); "
                    "slightly suspicious."
                )
                score += 0.2

        result["suspicion_score"] = min(score, 1.0)
        result["reasons"] = reasons
        return result
