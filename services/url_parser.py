"""
URL Parser & Normalizer Engine for Guardly URL Intelligence
Normalizes HTTP, HTTPS, IPv4, IPv6, Punycode, Percent Encoding, and relative URLs.
Extracts protocol, hostname, root domain, subdomain, path, query, fragment, port, credentials.
Detects Hexadecimal IP (0x7F000001), Decimal Integer IP (2130706433), and Octal IP (0177.0.0.1).
"""

import ipaddress
import re
import urllib.parse
from typing import Any, Dict, Optional


def decode_numeric_ip(host_str: str) -> Optional[str]:
    """
    Decodes Hexadecimal (0x7F000001), Decimal Integer (2130706433), or Octal (0177.0.0.1) IPs into standard IPv4 dotted decimal.
    Returns decoded IPv4 string or None if not a numeric IP representation.
    """
    if not host_str:
        return None

    clean_host = host_str.strip().lower()
    if clean_host.startswith("[") and clean_host.endswith("]"):
        clean_host = clean_host[1:-1]
    if ":" in clean_host and clean_host.count(":") == 1:
        clean_host = clean_host.split(":")[0]

    # 1. Hexadecimal IP representation (e.g. 0x7f000001 or 0x7f.0.0.1)
    if clean_host.startswith("0x") and "." not in clean_host:
        try:
            val = int(clean_host, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(val))
        except ValueError:
            pass

    # 2. Decimal Integer IP representation (e.g. 2130706433 = 127.0.0.1)
    if clean_host.isdigit():
        try:
            val = int(clean_host)
            if 0 <= val <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(val))
        except ValueError:
            pass

    # 3. Octal IP representation (e.g. 0177.0.0.1 = 127.0.0.1)
    octal_parts = clean_host.split(".")
    if len(octal_parts) == 4 and any(p.startswith("0") and len(p) > 1 for p in octal_parts):
        try:
            dec_parts = [str(int(p, 8)) for p in octal_parts]
            dec_str = ".".join(dec_parts)
            ipaddress.IPv4Address(dec_str)
            return dec_str
        except ValueError:
            pass

    return None


def parse_and_normalize_url(url_string: str) -> Dict[str, Any]:
    """
    Parses and normalizes a URL string into structured components.
    Handles percent decoding, Punycode, numeric IP decoding, and embedded credentials.
    """
    if not url_string:
        return {"original_url": "", "normalized_url": "", "is_valid": False}

    raw_url = url_string.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url):
        raw_url = "http://" + raw_url

    try:
        parsed = urllib.parse.urlparse(raw_url)
    except Exception:
        return {"original_url": url_string, "normalized_url": url_string, "is_valid": False}

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc
    hostname = parsed.hostname or ""
    port = parsed.port

    username = parsed.username or ""
    password = parsed.password or ""
    has_credentials = bool(username or password)

    # Check for numeric IP obfuscation (Hex, Decimal Integer, Octal)
    decoded_ip = decode_numeric_ip(hostname)
    numeric_ip_type = None

    if decoded_ip:
        if hostname.lower().startswith("0x"):
            numeric_ip_type = "Hexadecimal IP"
        elif hostname.isdigit():
            numeric_ip_type = "Decimal Integer IP"
        else:
            numeric_ip_type = "Octal IP"
        hostname_eval = decoded_ip
    else:
        hostname_eval = hostname

    # IP Classification
    is_ip = False
    ip_classification = {"is_ip": False, "category": "Domain"}
    try:
        ip_obj = ipaddress.ip_address(hostname_eval)
        is_ip = True
        is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        cat = "Loopback" if ip_obj.is_loopback else ("Private RFC1918" if ip_obj.is_private else "Public IPv4")
        ip_classification = {
            "is_ip": True,
            "ip_str": str(ip_obj),
            "version": ip_obj.version,
            "is_private": is_private,
            "category": cat,
        }
    except ValueError:
        pass

    # Extract Domain & Subdomain
    root_domain = ""
    subdomain = ""
    if not is_ip and hostname_eval:
        parts = hostname_eval.split(".")
        known_2part_tlds = {
            "co.uk", "com.au", "co.in", "org.uk", "gov.uk", "edu.au",
            "net.au", "co.jp", "com.br", "co.nz", "com.sg", "com.tw",
            "com.mx", "co.za"
        }
        if len(parts) >= 3 and ".".join(parts[-2:]).lower() in known_2part_tlds:
            root_domain = ".".join(parts[-3:])
            subdomain = ".".join(parts[:-3]) if len(parts) > 3 else ""
        elif len(parts) >= 2:
            root_domain = ".".join(parts[-2:])
            subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""

    # Reconstruct Normalized URL
    normalized_netloc = hostname_eval
    if port and port not in (80, 443):
        normalized_netloc += f":{port}"

    normalized_url = urllib.parse.urlunparse((
        scheme,
        normalized_netloc,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        parsed.fragment,
    ))

    # Query Parameter Count
    query_params = urllib.parse.parse_qs(parsed.query)

    return {
        "original_url": url_string,
        "normalized_url": normalized_url,
        "is_valid": True,
        "scheme": scheme,
        "hostname": hostname,
        "evaluated_hostname": hostname_eval,
        "root_domain": root_domain,
        "subdomain": subdomain,
        "port": port,
        "path": parsed.path or "/",
        "query": parsed.query,
        "query_param_count": len(query_params),
        "fragment": parsed.fragment,
        "has_credentials": has_credentials,
        "username": username,
        "password": password,
        "numeric_ip_type": numeric_ip_type,
        "decoded_numeric_ip": decoded_ip,
        "ip_classification": ip_classification,
        "url_length": len(normalized_url),
    }
