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
        - SSH private keys (OpenSSH, RSA PEM)
        - X.509 certificates (PEM)
        - JWT tokens (base64url eyJ prefix)
        - 7-Zip archives
        - RAR archives
        - Encrypted PDFs (contain %PDF and /Encrypt)
        - High entropy (>7.5 bits/byte) with no recognizable header → encrypted blob

        Args:
            filepath: Path to the file to inspect.

        Returns:
            List of dicts: {"type": str, "confidence": str, "detail": str}
        """
        if not os.path.isfile(filepath):
            return []

        with open(filepath, "rb") as fh:
            header = fh.read(512)

        if not header:
            return []

        findings = []
        header_text = header[:200]  # text portion for ASCII checks

        # --- PGP ASCII armor ---
        if header.startswith(b"-----BEGIN PGP"):
            findings.append({
                "type": "PGP ASCII Armor",
                "confidence": "high",
                "detail": f"File starts with PGP ASCII armor header: {header[:30].decode('utf-8', errors='replace')!r}",
            })

        # --- SSH private keys ---
        elif header.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
            findings.append({
                "type": "SSH Private Key (OpenSSH)",
                "confidence": "high",
                "detail": "OpenSSH private key detected — do not share or expose.",
            })
        elif header.startswith(b"-----BEGIN RSA PRIVATE KEY-----"):
            findings.append({
                "type": "SSH/RSA Private Key (PEM)",
                "confidence": "high",
                "detail": "RSA private key in PEM format detected.",
            })
        elif header.startswith(b"-----BEGIN EC PRIVATE KEY-----"):
            findings.append({
                "type": "EC Private Key (PEM)",
                "confidence": "high",
                "detail": "Elliptic Curve private key in PEM format detected.",
            })
        elif header.startswith(b"-----BEGIN DSA PRIVATE KEY-----"):
            findings.append({
                "type": "DSA Private Key (PEM)",
                "confidence": "high",
                "detail": "DSA private key in PEM format detected.",
            })

        # --- X.509 Certificate ---
        elif header.startswith(b"-----BEGIN CERTIFICATE-----"):
            findings.append({
                "type": "X.509 Certificate (PEM)",
                "confidence": "high",
                "detail": "PEM-encoded X.509 certificate.",
            })
        elif header.startswith(b"-----BEGIN CERTIFICATE REQUEST-----"):
            findings.append({
                "type": "X.509 Certificate Signing Request (PEM)",
                "confidence": "high",
                "detail": "PEM-encoded certificate signing request (CSR).",
            })

        # --- OpenSSL Salted ---
        elif header.startswith(b"Salted__"):
            findings.append({
                "type": "OpenSSL Salted Encryption",
                "confidence": "high",
                "detail": "OpenSSL-encrypted file with salt-based key derivation (AES-CBC typical).",
            })

        # --- PGP binary packets ---
        elif header[0:1] in (bytes([0x85]), bytes([0x99])):
            findings.append({
                "type": "PGP Binary Packet",
                "confidence": "medium",
                "detail": f"PGP binary format detected (header byte: 0x{header[0]:02X}).",
            })

        # --- GPG symmetric session packet ---
        elif header[0:1] == bytes([0xC3]):
            findings.append({
                "type": "GPG Symmetric Session Packet",
                "confidence": "medium",
                "detail": "GPG new-format symmetric-key encrypted data packet.",
            })

        # --- JWT ---
        if header.startswith(b"eyJ"):
            findings.append({
                "type": "JWT (JSON Web Token)",
                "confidence": "high",
                "detail": "File starts with 'eyJ' — base64url-encoded JWT header.",
            })

        # --- 7-Zip ---
        if header[:6] == b"7z\xbc\xaf\x27\x1c":
            findings.append({
                "type": "7-Zip Archive",
                "confidence": "high",
                "detail": "7-Zip archive magic bytes detected (may be encrypted).",
            })

        # --- RAR ---
        if header[:7] == b"Rar!\x1a\x07\x00" or header[:7] == b"Rar!\x1a\x07\x01":
            findings.append({
                "type": "RAR Archive",
                "confidence": "high",
                "detail": "RAR archive magic bytes detected (may be password-protected).",
            })

        # --- ZIP with AES/legacy encryption ---
        if header[:4] == _ZIP_MAGIC and len(header) >= 8:
            gp_flag = int.from_bytes(header[6:8], "little")
            if gp_flag & (1 << 6):
                findings.append({
                    "type": "ZIP with AES/Strong Encryption",
                    "confidence": "high",
                    "detail": "ZIP general-purpose bit 6 set — AES or strong encryption active.",
                })
            elif gp_flag & (1 << 0):
                findings.append({
                    "type": "ZIP with Legacy Password Encryption",
                    "confidence": "high",
                    "detail": "ZIP general-purpose bit 0 set — legacy ZipCrypto password encryption.",
                })

        # --- Encrypted PDF ---
        if b"%PDF" in header and b"/Encrypt" in header:
            findings.append({
                "type": "Encrypted PDF",
                "confidence": "high",
                "detail": "PDF header with /Encrypt dictionary — document is password-protected.",
            })
        elif b"%PDF" in header:
            # Also read more of the file to check for /Encrypt
            try:
                with open(filepath, "rb") as fh:
                    chunk = fh.read(8192)
                if b"/Encrypt" in chunk:
                    findings.append({
                        "type": "Encrypted PDF",
                        "confidence": "high",
                        "detail": "PDF contains /Encrypt dictionary — document is password-protected.",
                    })
            except Exception:
                pass

        # --- High entropy with no recognizable header → likely encrypted blob ---
        entropy = self.measure_entropy(header)
        has_recognized_header = any(
            f["confidence"] == "high" for f in findings
            if f.get("type") not in ("JWT (JSON Web Token)",)
        )
        if entropy > 7.5 and not has_recognized_header:
            findings.append({
                "type": "Likely Encrypted or Compressed Blob",
                "confidence": "medium",
                "detail": (
                    f"High entropy ({entropy:.2f} bits/byte) with no recognizable format header. "
                    "This is consistent with encryption, compression, or random data."
                ),
            })
        elif entropy > 7.5:
            # Add entropy note even when other findings exist
            findings.append({
                "type": "High Entropy",
                "confidence": "low",
                "detail": f"File header entropy is {entropy:.2f} bits/byte (high — consistent with encryption/compression).",
            })

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

    def chi_square_test(self, data: bytes) -> dict:
        """
        Performs a chi-square uniformity test on byte frequency distribution.
        A uniform byte distribution (all 256 values equally frequent) indicates
        likely encrypted or truly random data.

        Uses the regularized incomplete gamma function via math.lgamma to approximate
        the p-value for 255 degrees of freedom.

        Args:
            data: Raw bytes to test.

        Returns:
            dict with:
                - 'chi_square': float — chi-square statistic
                - 'is_likely_random': bool — True if distribution is uniform
                - 'interpretation': str — human-readable explanation
        """
        if not data:
            return {
                "chi_square": 0.0,
                "is_likely_random": False,
                "interpretation": "Empty data — no test performed.",
            }

        n = len(data)
        expected = n / 256.0

        # Count byte frequencies
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        # Compute chi-square statistic
        chi2 = sum((count - expected) ** 2 / expected for count in freq if expected > 0)

        # Approximate p-value using regularized upper incomplete gamma function
        # P(chi2, df) where df = 255
        # We use the complementary regularized incomplete gamma: 1 - P(df/2, chi2/2)
        # Approximated via math.lgamma (log-gamma function)
        df = 255
        p_value = self._chi2_p_value(chi2, df)

        # Threshold: p > 0.05 means we cannot reject the null hypothesis of uniformity
        is_likely_random = p_value > 0.05

        if is_likely_random:
            interpretation = (
                f"Chi-square={chi2:.2f}, p={p_value:.4f}: Byte distribution is consistent with "
                "uniform/random data — likely encrypted, compressed, or truly random."
            )
        else:
            interpretation = (
                f"Chi-square={chi2:.2f}, p={p_value:.4f}: Byte distribution is NOT uniform — "
                "data has structure (plaintext, image, etc.)."
            )

        return {
            "chi_square": round(chi2, 4),
            "p_value": round(p_value, 6),
            "is_likely_random": is_likely_random,
            "interpretation": interpretation,
        }

    @staticmethod
    def _chi2_p_value(chi2: float, df: int) -> float:
        """
        Approximate the p-value for a chi-square test using the regularized
        incomplete gamma function. Computed via the log-gamma function from stdlib.

        Returns a float in [0, 1].
        """
        # P-value = 1 - CDF = Q(df/2, chi2/2) = upper regularized incomplete gamma
        # We use a numerical approximation via series expansion
        k = df / 2.0
        x = chi2 / 2.0

        if x <= 0.0:
            return 1.0

        # Log of the lower regularized incomplete gamma P(k, x)
        # Using the series: P(k, x) = e^(-x) * x^k / Gamma(k) * sum(x^n / Gamma(k+n+1))
        # We compute via log-space to avoid overflow

        # Use a simple numerical integration approach (Gauss-Legendre approximation)
        # For practical purposes with chi2 distributions, we use Wilson-Hilferty approximation
        # which is accurate for df >= 30

        # Wilson-Hilferty normal approximation: z = ((x/df)^(1/3) - (1 - 2/(9*df))) / sqrt(2/(9*df))
        if df > 0:
            h = 2.0 / (9.0 * df)
            z = ((chi2 / df) ** (1.0 / 3.0) - (1.0 - h)) / math.sqrt(h)
            # P-value = 1 - Phi(z) where Phi is the standard normal CDF
            p = 1.0 - CryptoTracer._normal_cdf(z)
            return max(0.0, min(1.0, p))
        return 0.5

    @staticmethod
    def _normal_cdf(z: float) -> float:
        """Approximation of the standard normal CDF using math.erf."""
        return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))

    def detect_steganography_lsb(self, filepath: str) -> dict:
        """
        Performs a chi-square attack and LSB entropy analysis on PNG/BMP images
        to detect potential LSB steganography.

        Chi-square attack principle: In natural images, for each pair of values
        (2k, 2k+1), the frequency of 2k is generally NOT equal to 2k+1.
        After LSB embedding, they become approximately equal.

        Args:
            filepath: Path to a PNG or BMP image file.

        Returns:
            dict with:
                - 'suspicion_score': float [0.0, 1.0]
                - 'lsb_entropy': float — entropy of LSB plane
                - 'chi_square': float — chi-square statistic from LSB pair analysis
                - 'verdict': str — human-readable verdict
        """
        result = {
            "suspicion_score": 0.0,
            "lsb_entropy": 0.0,
            "chi_square": 0.0,
            "verdict": "Cannot analyze",
            "supported": False,
        }

        if not PILLOW_AVAILABLE:
            result["verdict"] = "Pillow not available."
            return result

        if not os.path.isfile(filepath):
            result["verdict"] = "File not found."
            return result

        ext = os.path.splitext(filepath)[1].lower()
        if ext not in (".png", ".bmp"):
            result["verdict"] = f"Format '{ext}' not supported (PNG/BMP only)."
            return result

        result["supported"] = True

        try:
            img = Image.open(filepath).convert("RGB")
        except Exception as exc:
            result["verdict"] = f"Cannot open image: {exc}"
            return result

        pixels = list(img.getdata())
        sample_limit = min(len(pixels), 100000)
        sampled = pixels[:sample_limit]

        # Extract all channel values
        all_values = []
        lsb_bits = []
        for r, g, b in sampled:
            all_values.extend([r, g, b])
            lsb_bits.extend([r & 1, g & 1, b & 1])

        # --- Chi-square attack on LSB pairs ---
        # For each value v in [0, 254], count occurrences of v and v+1
        # h(2k) should ≈ h(2k+1) if stego is present
        pair_chi2 = 0.0
        valid_pairs = 0
        freq = [0] * 256
        for v in all_values:
            freq[v] += 1

        for k in range(128):
            n0 = freq[2 * k]
            n1 = freq[2 * k + 1]
            total = n0 + n1
            if total > 0:
                expected = total / 2.0
                pair_chi2 += (n0 - expected) ** 2 / expected + (n1 - expected) ** 2 / expected
                valid_pairs += 1

        result["chi_square"] = round(pair_chi2, 4)

        # --- LSB entropy ---
        # Pack LSB bits into bytes and compute entropy
        packed_lsb = bytearray()
        for i in range(0, len(lsb_bits) - 7, 8):
            val = 0
            for bit in range(8):
                val |= lsb_bits[i + bit] << bit
            packed_lsb.append(val)

        lsb_entropy = self.measure_entropy(bytes(packed_lsb)) if packed_lsb else 0.0
        result["lsb_entropy"] = round(lsb_entropy, 4)

        # --- Suspicion scoring ---
        score = 0.0

        # High LSB entropy → suspicious (natural images have lower LSB entropy)
        if lsb_entropy > 7.5:
            score += 0.5
        elif lsb_entropy > 7.0:
            score += 0.3
        elif lsb_entropy > 6.5:
            score += 0.15

        # Low chi-square on pairs → suspicious (pairs are similar → stego)
        # For 128 pairs, expected chi2 under H0 (no stego) is large
        # Low chi2 means pairs ARE similar → stego present
        if valid_pairs > 0:
            avg_pair_chi2 = pair_chi2 / valid_pairs
            if avg_pair_chi2 < 0.5:
                score += 0.5
            elif avg_pair_chi2 < 1.0:
                score += 0.3
            elif avg_pair_chi2 < 2.0:
                score += 0.1

        score = min(score, 1.0)
        result["suspicion_score"] = round(score, 4)

        if score >= 0.7:
            verdict = "HIGH suspicion of LSB steganography — chi-square pairs are abnormally uniform."
        elif score >= 0.4:
            verdict = "MEDIUM suspicion — some LSB uniformity detected. Further investigation recommended."
        elif score >= 0.2:
            verdict = "LOW suspicion — minor anomalies in LSB distribution."
        else:
            verdict = "No significant LSB steganography indicators detected."

        result["verdict"] = verdict
        return result

    def verify_file_integrity(self, filepath: str, expected_hash: str, algorithm: str = "sha256") -> dict:
        """
        Verifies a file's integrity by comparing its hash against an expected value.

        Args:
            filepath: Path to the file to verify.
            expected_hash: The expected hash hex string.
            algorithm: Hash algorithm to use ('md5', 'sha1', 'sha256', 'sha512').

        Returns:
            dict with: match (bool), expected (str), actual (str), algorithm (str).
        """
        algorithm = algorithm.lower().strip()
        supported = {"md5", "sha1", "sha256", "sha512", "sha224", "sha384"}
        if algorithm not in supported:
            return {
                "match": False,
                "expected": expected_hash,
                "actual": "",
                "algorithm": algorithm,
                "error": f"Unsupported algorithm '{algorithm}'. Supported: {sorted(supported)}",
            }

        if not os.path.isfile(filepath):
            return {
                "match": False,
                "expected": expected_hash,
                "actual": "",
                "algorithm": algorithm,
                "error": "File not found.",
            }

        h = hashlib.new(algorithm)
        try:
            with open(filepath, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            actual = h.hexdigest()
        except Exception as exc:
            return {
                "match": False,
                "expected": expected_hash,
                "actual": "",
                "algorithm": algorithm,
                "error": str(exc),
            }

        return {
            "match": actual.lower() == expected_hash.lower().strip(),
            "expected": expected_hash.lower().strip(),
            "actual": actual,
            "algorithm": algorithm,
        }
