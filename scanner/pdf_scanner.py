"""
PDF Attachment Intelligence & Security Scanner Module
Extracts plain text and embedded link annotations from PDF attachments for phishing detection.
"""

import io
import re
from typing import Any, Dict, List
import pypdf


def extract_pdf_intel(payload_bytes: bytes, max_text_chars: int = 20000) -> Dict[str, Any]:
    """
    Parses PDF from raw bytes using pypdf.
    Extracts text and URLs from both link annotations (/Annots -> /A -> /URI)
    and text regex scanning.

    Returns:
        dict: {
            "text": str,
            "urls": List[str],
            "page_count": int,
            "error": Optional[str],
        }
    """
    if not payload_bytes or not isinstance(payload_bytes, bytes):
        return {"text": "", "urls": [], "page_count": 0, "error": "Empty or invalid PDF payload."}

    text_parts: List[str] = []
    urls: List[str] = []
    seen_urls = set()

    def add_url(url_str: str):
        if not url_str or not isinstance(url_str, str):
            return
        cleaned = url_str.strip()
        # Clean trailing punctuation from regex matches
        cleaned = re.sub(r"[.,;!?\)\>]+$", "", cleaned)
        if cleaned.startswith("www."):
            cleaned = "http://" + cleaned
        if cleaned and cleaned not in seen_urls:
            seen_urls.add(cleaned)
            urls.append(cleaned)

    try:
        reader = pypdf.PdfReader(io.BytesIO(payload_bytes))
        page_count = len(reader.pages)

        for page in reader.pages:
            # 1. Extract text from page
            try:
                page_text = page.extract_text() or ""
                if page_text:
                    text_parts.append(page_text)
            except Exception:
                page_text = ""

            # 2. Extract Link Annotations (page["/Annots"] -> annot["/A"]["/URI"])
            try:
                annots = page.get("/Annots")
                if annots:
                    for annot in annots:
                        try:
                            obj = annot.get_object()
                            if isinstance(obj, dict) and "/A" in obj:
                                action = obj["/A"]
                                if isinstance(action, dict) and "/URI" in action:
                                    add_url(str(action["/URI"]))
                        except Exception:
                            continue
            except Exception:
                pass

            # 3. Regex scan of extracted page text for http(s):// and www. URLs
            if page_text:
                regex_matches = re.findall(r"(?:https?://|www\.)[^\s<>\"]+", page_text)
                for match in regex_matches:
                    add_url(match)

        full_text = "\n".join(text_parts)[:max_text_chars]

        return {
            "text": full_text,
            "urls": urls,
            "page_count": page_count,
            "error": None,
        }

    except Exception as err:
        return {
            "text": "",
            "urls": [],
            "page_count": 0,
            "error": f"Failed to parse PDF attachment: {err}",
        }
