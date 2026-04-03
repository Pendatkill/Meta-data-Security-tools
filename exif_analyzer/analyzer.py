# Developer: pendatkill
# Module: exif_analyzer.analyzer
# Description: Extracts and analyzes EXIF metadata from image files using Pillow

import os
import subprocess
import json
import math
from datetime import datetime
from typing import Optional

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False


class ExifAnalyzer:
    """Analyzes EXIF metadata embedded in image files."""

    def _get_raw_exif(self, filepath: str) -> dict:
        """Internal helper to extract raw EXIF data as a tag-name dict."""
        if not PILLOW_AVAILABLE:
            return {}
        try:
            img = Image.open(filepath)
            raw = img._getexif()
            if raw is None:
                return {}
            return {TAGS.get(tag, str(tag)): value for tag, value in raw.items()}
        except Exception:
            return {}

    def analyze(self, filepath: str) -> dict:
        """
        Returns a dict of all EXIF metadata found in the given image file.
        Falls back gracefully to an empty dict if no EXIF data is present
        or if the file is not an image.

        Args:
            filepath: Path to the image file.

        Returns:
            dict mapping EXIF tag names to their values.
        """
        if not PILLOW_AVAILABLE:
            return {}
        if not os.path.isfile(filepath):
            return {}

        exif_data = self._get_raw_exif(filepath)

        # Convert bytes values to hex strings for JSON-serializability
        clean = {}
        for key, val in exif_data.items():
            if isinstance(val, bytes):
                try:
                    clean[key] = val.decode("utf-8", errors="replace")
                except Exception:
                    clean[key] = val.hex()
            elif isinstance(val, tuple):
                clean[key] = list(val)
            else:
                clean[key] = val
        return clean

    def get_gps(self, filepath: str) -> Optional[dict]:
        """
        Extracts GPS coordinates from EXIF data if present.
        Parses DMS (degrees/minutes/seconds) format and converts to decimal degrees.

        Args:
            filepath: Path to the image file.

        Returns:
            dict with lat, lon, lat_ref, lon_ref, maps_url or None if not found.
        """
        if not PILLOW_AVAILABLE:
            return None
        if not os.path.isfile(filepath):
            return None

        raw_exif = self._get_raw_exif(filepath)
        gps_info_raw = raw_exif.get("GPSInfo")
        if not gps_info_raw:
            return None

        if not isinstance(gps_info_raw, dict):
            return None

        gps_data = {GPSTAGS.get(k, k): v for k, v in gps_info_raw.items()}

        def _ratio_to_float(val):
            """Convert IFDRational or tuple fraction to float."""
            try:
                if hasattr(val, 'numerator') and hasattr(val, 'denominator'):
                    return float(val.numerator) / float(val.denominator)
                if isinstance(val, tuple) and len(val) == 2:
                    return float(val[0]) / float(val[1]) if val[1] != 0 else 0.0
                return float(val)
            except (TypeError, ZeroDivisionError):
                return 0.0

        def _dms_to_decimal(dms, ref: str) -> Optional[float]:
            """Convert degrees/minutes/seconds tuple to decimal degrees."""
            try:
                degrees = _ratio_to_float(dms[0])
                minutes = _ratio_to_float(dms[1])
                seconds = _ratio_to_float(dms[2])
                decimal = degrees + minutes / 60.0 + seconds / 3600.0
                if ref in ("S", "W"):
                    decimal = -decimal
                return round(decimal, 7)
            except (TypeError, IndexError, ZeroDivisionError):
                return None

        lat_ref = gps_data.get("GPSLatitudeRef", "N")
        lon_ref = gps_data.get("GPSLongitudeRef", "E")
        if isinstance(lat_ref, bytes):
            lat_ref = lat_ref.decode("utf-8", errors="replace").strip()
        if isinstance(lon_ref, bytes):
            lon_ref = lon_ref.decode("utf-8", errors="replace").strip()

        lat = _dms_to_decimal(gps_data.get("GPSLatitude"), lat_ref)
        lon = _dms_to_decimal(gps_data.get("GPSLongitude"), lon_ref)

        if lat is None or lon is None:
            return None

        maps_url = f"https://www.google.com/maps?q={lat},{lon}"
        return {
            "lat": lat,
            "lon": lon,
            "lat_ref": lat_ref,
            "lon_ref": lon_ref,
            "maps_url": maps_url,
        }

    def detect_editing_software(self, filepath: str) -> Optional[str]:
        """
        Detects the name of software used to edit/create the image by reading
        the EXIF 'Software' tag.

        Args:
            filepath: Path to the image file.

        Returns:
            Software name string if present, otherwise None.
        """
        if not PILLOW_AVAILABLE:
            return None
        if not os.path.isfile(filepath):
            return None

        exif_data = self.analyze(filepath)
        software = exif_data.get("Software")
        if software and isinstance(software, str):
            return software.strip()
        return None

    def analyze_with_exiftool(self, filepath: str) -> dict:
        """
        Runs exiftool -json on the given file via subprocess.
        Returns the full parsed JSON output from exiftool.

        If exiftool is not in PATH or fails, returns {"exiftool_available": False}.

        Args:
            filepath: Path to the file to analyze.

        Returns:
            dict with exiftool output, or {"exiftool_available": False} if unavailable.
        """
        try:
            result = subprocess.run(
                ["exiftool", "-json", filepath],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return {"exiftool_available": True, "error": result.stderr.strip()}
            data = json.loads(result.stdout)
            if isinstance(data, list) and data:
                output = data[0]
                output["exiftool_available"] = True
                return output
            return {"exiftool_available": True, "data": data}
        except FileNotFoundError:
            return {"exiftool_available": False}
        except subprocess.TimeoutExpired:
            return {"exiftool_available": True, "error": "exiftool timed out"}
        except json.JSONDecodeError as exc:
            return {"exiftool_available": True, "error": f"JSON parse error: {exc}"}
        except Exception as exc:
            return {"exiftool_available": True, "error": str(exc)}

    def extract_thumbnail(self, filepath: str, output_dir: str) -> Optional[str]:
        """
        Extracts the embedded JPEG thumbnail from an image's EXIF data using Pillow.
        Saves it to output_dir and returns the saved path, or None if not found.

        Args:
            filepath: Path to the source image.
            output_dir: Directory to save the extracted thumbnail.

        Returns:
            Absolute path to the saved thumbnail, or None.
        """
        if not PILLOW_AVAILABLE:
            return None
        if not os.path.isfile(filepath):
            return None

        try:
            img = Image.open(filepath)
            # Pillow stores thumbnail data in the EXIF appdata
            exif_data = img.info.get("exif", b"")
            if not exif_data:
                # Try _getexif for some formats
                raw = getattr(img, "_getexif", lambda: None)()
                if raw is None:
                    return None

            # Use piexif if available, otherwise try PIL thumbnail extraction
            try:
                import piexif
                exif_dict = piexif.load(filepath)
                thumbnail_data = exif_dict.get("thumbnail")
                if thumbnail_data and len(thumbnail_data) > 10:
                    os.makedirs(output_dir, exist_ok=True)
                    base = os.path.splitext(os.path.basename(filepath))[0]
                    out_path = os.path.join(output_dir, f"{base}_thumbnail.jpg")
                    with open(out_path, "wb") as fh:
                        fh.write(thumbnail_data)
                    return os.path.abspath(out_path)
            except ImportError:
                pass
            except Exception:
                pass

            # Fallback: try to open as PIL image and create thumbnail
            img_thumb = img.copy()
            img_thumb.thumbnail((128, 128))
            os.makedirs(output_dir, exist_ok=True)
            base = os.path.splitext(os.path.basename(filepath))[0]
            out_path = os.path.join(output_dir, f"{base}_thumbnail.jpg")
            img_thumb.convert("RGB").save(out_path, format="JPEG")
            return os.path.abspath(out_path)

        except Exception:
            return None

    def detect_manipulation_signs(self, filepath: str) -> dict:
        """
        Checks for signs that an image may have been manipulated or tampered with.

        Checks performed:
        - Presence of a Software EXIF field (editing software detected)
        - DateTimeOriginal vs file mtime mismatch (more than 60 seconds difference)
        - EXIF completely stripped from JPEG (suspicious — camera images always have EXIF)

        Args:
            filepath: Path to the image file.

        Returns:
            dict with keys:
                - 'flags': list of warning strings
                - 'risk_level': 'low' | 'medium' | 'high'
                - 'details': human-readable summary
        """
        flags = []

        if not os.path.isfile(filepath):
            return {"flags": ["File not found"], "risk_level": "high", "details": "File not found."}

        ext = os.path.splitext(filepath)[1].lower()
        exif_data = self._get_raw_exif(filepath) if PILLOW_AVAILABLE else {}

        # Flag 1: editing software present
        software = exif_data.get("Software", "")
        if isinstance(software, bytes):
            software = software.decode("utf-8", errors="replace")
        if software and software.strip():
            flags.append(f"Editing software detected in EXIF: '{software.strip()}'")

        # Flag 2: DateTimeOriginal vs file mtime mismatch
        dto = exif_data.get("DateTimeOriginal") or exif_data.get("DateTime")
        if dto and isinstance(dto, str):
            try:
                exif_dt = datetime.strptime(dto.strip(), "%Y:%m:%d %H:%M:%S")
                file_mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                diff_seconds = abs((exif_dt - file_mtime).total_seconds())
                if diff_seconds > 60:
                    flags.append(
                        f"DateTimeOriginal ({dto}) differs from file mtime "
                        f"({file_mtime.strftime('%Y-%m-%d %H:%M:%S')}) "
                        f"by {int(diff_seconds)} seconds — possible re-save or manipulation."
                    )
            except (ValueError, OSError):
                pass

        # Flag 3: JPEG with no EXIF data at all
        if ext in (".jpg", ".jpeg") and not exif_data:
            flags.append(
                "JPEG has no EXIF data — camera-captured images always contain EXIF. "
                "Stripping may indicate metadata scrubbing."
            )

        # Determine risk level
        n = len(flags)
        if n == 0:
            risk_level = "low"
            details = "No manipulation signs detected."
        elif n == 1:
            risk_level = "medium"
            details = "One manipulation indicator found. Manual review recommended."
        else:
            risk_level = "high"
            details = f"{n} manipulation indicators found. High likelihood of post-processing or tampering."

        return {"flags": flags, "risk_level": risk_level, "details": details}

    def get_camera_fingerprint(self, filepath: str) -> dict:
        """
        Extracts camera hardware fingerprint fields from EXIF data.
        Useful for identifying the originating device.

        Args:
            filepath: Path to the image file.

        Returns:
            dict with: make, model, focal_length, iso, exposure_time, flash, orientation.
        """
        exif_data = self._get_raw_exif(filepath) if PILLOW_AVAILABLE else {}

        def _safe(val):
            if val is None:
                return None
            if isinstance(val, bytes):
                return val.decode("utf-8", errors="replace").strip()
            if isinstance(val, tuple) and len(val) == 2:
                # IFD rational as (numerator, denominator)
                try:
                    return f"{val[0]}/{val[1]}"
                except Exception:
                    return str(val)
            return val

        # Flash values mapping
        flash_map = {
            0: "No flash", 1: "Flash fired", 5: "Flash fired, no strobe", 7: "Flash fired, strobe",
            9: "Flash fired, compulsory", 13: "Flash fired, compulsory, no strobe",
            15: "Flash fired, compulsory, strobe", 16: "Flash off", 24: "Flash off",
            25: "Flash fired, auto", 29: "Flash fired, auto, no strobe",
            31: "Flash fired, auto, strobe", 32: "No flash function",
        }
        flash_raw = exif_data.get("Flash")
        flash_str = flash_map.get(flash_raw, str(flash_raw) if flash_raw is not None else None)

        orientation_map = {
            1: "Normal", 2: "Mirrored horizontal", 3: "Rotated 180°",
            4: "Mirrored vertical", 5: "Mirrored horizontal, rotated 270° CW",
            6: "Rotated 90° CW", 7: "Mirrored horizontal, rotated 90° CW",
            8: "Rotated 270° CW",
        }
        orient_raw = exif_data.get("Orientation")
        orient_str = orientation_map.get(orient_raw, str(orient_raw) if orient_raw is not None else None)

        return {
            "make": _safe(exif_data.get("Make")),
            "model": _safe(exif_data.get("Model")),
            "focal_length": _safe(exif_data.get("FocalLength")),
            "iso": exif_data.get("ISOSpeedRatings"),
            "exposure_time": _safe(exif_data.get("ExposureTime")),
            "flash": flash_str,
            "orientation": orient_str,
        }
