# Developer: pendatkill
# Module: exif_analyzer.analyzer
# Description: Extracts and analyzes EXIF metadata from image files using Pillow

import os
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

        Args:
            filepath: Path to the image file.

        Returns:
            dict with 'latitude' and 'longitude' as floats, or None if not found.
        """
        if not PILLOW_AVAILABLE:
            return None
        if not os.path.isfile(filepath):
            return None

        raw_exif = self._get_raw_exif(filepath)
        gps_info_raw = raw_exif.get("GPSInfo")
        if not gps_info_raw:
            return None

        # gps_info_raw may be a dict keyed by integer GPS tag IDs
        if not isinstance(gps_info_raw, dict):
            return None

        gps_data = {GPSTAGS.get(k, k): v for k, v in gps_info_raw.items()}

        def _dms_to_decimal(dms, ref: str) -> Optional[float]:
            """Convert degrees/minutes/seconds tuple to decimal degrees."""
            try:
                degrees = float(dms[0])
                minutes = float(dms[1])
                seconds = float(dms[2])
                decimal = degrees + minutes / 60.0 + seconds / 3600.0
                if ref in ("S", "W"):
                    decimal = -decimal
                return decimal
            except (TypeError, IndexError, ZeroDivisionError):
                return None

        lat = _dms_to_decimal(
            gps_data.get("GPSLatitude"), gps_data.get("GPSLatitudeRef", "N")
        )
        lon = _dms_to_decimal(
            gps_data.get("GPSLongitude"), gps_data.get("GPSLongitudeRef", "E")
        )

        if lat is None or lon is None:
            return None

        return {"latitude": lat, "longitude": lon}

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
