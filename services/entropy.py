"""
URL Entropy & Query Parameter Analysis Module for Guardly
Calculates Shannon Entropy (H = -sum p_i log2 p_i), randomness estimation,
character distribution, Base64 decoding, and nested URL detection.
"""

import base64
import math
import re
from typing import Any, Dict, List


def calculate_shannon_entropy(text: str) -> float:
    """
    Calculates Shannon Entropy of a string (in bits per character).
    Higher values indicate random strings, encoded payloads, or DGA domains.
    """
    if not text:
        return 0.0
    prob_dict = {c: text.count(c) / len(text) for c in set(text)}
    return -sum(p * math.log2(p) for p in prob_dict.values())


def analyze_url_entropy_and_params(parsed_url_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyzes Shannon Entropy across hostname, path, and query parameters.
    Extracts Base64 parameters, nested URLs, and obfuscated payloads.
    """
    hostname = parsed_url_data.get("hostname", "")
    path = parsed_url_data.get("path", "")
    query = parsed_url_data.get("query", "")
    full_url = parsed_url_data.get("normalized_url", "")

    url_entropy = calculate_shannon_entropy(full_url)
    host_entropy = calculate_shannon_entropy(hostname)
    path_entropy = calculate_shannon_entropy(path)

    # Detect High Entropy (> 4.8 bits/char is suspicious for hostname; > 5.2 for path/query)
    is_high_entropy = host_entropy > 4.8 or path_entropy > 5.2

    # Query Parameter Obfuscation & Base64 / Nested URL Detection
    base64_found = False
    nested_urls: List[str] = []
    suspicious_params: List[str] = []

    if query:
        # Check for nested URLs in query parameters
        nested_matches = re.findall(r"(https?%3A%2F%2F[^\s&]+|https?://[^\s&]+)", query, re.IGNORECASE)
        for nu in nested_matches:
            if nu not in nested_urls:
                nested_urls.append(nu)

        # Check for Base64 encoded strings in query parameters
        param_parts = query.split("&")
        for p in param_parts:
            if "=" in p:
                key, val = p.split("=", 1)
                if len(val) >= 16 and re.match(r"^[a-zA-Z0-9+/=]+$", val):
                    try:
                        decoded = base64.b64decode(val).decode("utf-8", errors="ignore")
                        if "http://" in decoded or "https://" in decoded or "@" in decoded:
                            base64_found = True
                            suspicious_params.append(f"{key}={val[:12]}... (Base64 payload)")
                    except Exception:
                        pass

    return {
        "url_entropy": round(url_entropy, 2),
        "host_entropy": round(host_entropy, 2),
        "path_entropy": round(path_entropy, 2),
        "is_high_entropy": is_high_entropy,
        "base64_payload_found": base64_found,
        "nested_urls": nested_urls,
        "suspicious_params": suspicious_params,
    }
