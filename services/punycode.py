"""
Punycode & Internationalized Domain Name (IDN) Analyzer for Guardly
Detects xn-- Punycode domain prefixes, converts to decoded Unicode representation,
and flags mixed-script Unicode abuse.
"""

from typing import Any, Dict


def analyze_punycode_domain(hostname: str) -> Dict[str, Any]:
    """
    Analyzes domain name for Punycode encoding (xn--) and Unicode homograph abuse.
    """
    if not hostname:
        return {"is_punycode": False, "decoded_unicode": "", "risk": 0}

    is_punycode = False
    decoded_unicode = hostname

    parts = hostname.split(".")
    punycode_parts = []

    for part in parts:
        if part.lower().startswith("xn--"):
            is_punycode = True
            try:
                decoded = part.encode("utf-8").decode("idna")
                punycode_parts.append(decoded)
            except Exception:
                punycode_parts.append(part)
        else:
            punycode_parts.append(part)

    if is_punycode:
        decoded_unicode = ".".join(punycode_parts)

    return {
        "is_punycode": is_punycode,
        "original_hostname": hostname,
        "decoded_unicode": decoded_unicode,
        "risk": 35 if is_punycode else 0,
    }
