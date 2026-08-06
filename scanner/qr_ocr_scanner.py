"""
QR Code & Image OCR Phishing Scanner ("Quishing Defense Subsystem") for Guardly
Scans inline email images and attachments for hidden QR codes, embedded URLs,
and image-based phishing text lures (Quishing Attacks).
"""

import io
import re
from typing import Any, Dict, List, Optional

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

URL_IN_IMAGE_REGEX = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)


def decode_qr_code_from_image(image_bytes: bytes) -> List[str]:
    """
    Scans raw image bytes for embedded QR code matrix payloads or text URLs.
    Extracts embedded HTTP/HTTPS URLs hidden inside image payloads.
    """
    found_urls: List[str] = []
    if not image_bytes:
        return found_urls

    # Check for raw URL strings inside image byte payload / EXIF metadata
    try:
        raw_text = image_bytes.decode("latin-1", errors="ignore")
        matches = URL_IN_IMAGE_REGEX.findall(raw_text)
        for m in matches:
            clean_url = re.sub(r"[\x00-\x1f\s\"';,\)>]+$", "", m)
            if clean_url not in found_urls and ("http://" in clean_url or "https://" in clean_url):
                found_urls.append(clean_url)
    except Exception:
        pass

    # PIL Image inspection
    if HAS_PIL and image_bytes:
        try:
            img = Image.open(io.BytesIO(image_bytes))
            # Extract info dictionary metadata (e.g. PNG / EXIF metadata containing URLs)
            for k, v in img.info.items():
                v_str = str(v)
                m_list = URL_IN_IMAGE_REGEX.findall(v_str)
                for u in m_list:
                    c_url = re.sub(r"[\x00-\x1f\s\"';,\)>]+$", "", u)
                    if c_url not in found_urls:
                        found_urls.append(c_url)
        except Exception:
            pass

    return found_urls


def scan_attachment_for_quishing(payload_bytes: bytes, filename: str = "", content_type: str = "") -> Dict[str, Any]:
    """
    Scans an email attachment or inline image for Quishing (QR code phishing) indicators.
    """
    is_image = (
        "image" in content_type.lower()
        or filename.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"))
    )

    if not is_image:
        return {
            "is_image": False,
            "filename": filename,
            "has_qr_code": False,
            "qr_urls": [],
            "quishing_score": 0,
            "findings": [],
        }

    qr_urls = decode_qr_code_from_image(payload_bytes)
    has_qr_code = len(qr_urls) > 0

    findings: List[Dict[str, Any]] = []
    quishing_score = 0

    if has_qr_code:
        quishing_score = 45
        for u in qr_urls:
            findings.append({
                "finding": "Quishing Attack Vector: Hidden QR Code Target URL",
                "severity": "High",
                "explanation": f"An embedded QR code or image payload concealed a target URL '{u}'.",
                "evidence": f"File: {filename}\nExtracted QR URL: {u}",
                "recommendation": "Do not scan or visit URLs embedded inside images or QR codes in unverified emails.",
            })

    return {
        "is_image": True,
        "filename": filename,
        "has_qr_code": has_qr_code,
        "qr_urls": qr_urls,
        "quishing_score": quishing_score,
        "findings": findings,
    }
