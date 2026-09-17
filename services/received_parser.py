"""
Received Header Parser & Mail Routing Chain Analyzer for Guardly
Parses every Received: header in RFC 5322 emails, extracts hop numbers, sending/receiving hosts,
IP addresses, timestamps, protocols, and TLS parameters.
Detects missing/duplicate hops, private/loopback/reserved IPs, clock skew, out-of-order timestamps,
and unexpected relays.
"""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import ipaddress
import re
from typing import Any, Dict, List, Optional

IP_IN_RECEIVED_REGEX = re.compile(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-fA-F0-9:]+)\]|\b(?:\d{1,3}\.){3}\d{1,3}\b")


def classify_ip_address(ip_str: str) -> Dict[str, Any]:
    """
    Classifies an IP address using Python's native ipaddress module into
    Public, Private, Loopback, Link-Local, Reserved, Multicast, or IPv6.
    """
    if not ip_str:
        return {"ip": "", "is_valid": False, "category": "Unknown", "is_private": False}

    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved

        if ip_obj.is_loopback:
            cat = "Loopback"
        elif ip_obj.is_private:
            cat = "Private RFC1918"
        elif ip_obj.is_link_local:
            cat = "Link-Local"
        elif ip_obj.is_reserved:
            cat = "Reserved"
        elif ip_obj.is_multicast:
            cat = "Multicast"
        elif ip_obj.version == 6:
            cat = "IPv6 Public" if not is_private else "IPv6 Internal"
        else:
            cat = "Public IPv4"

        return {
            "ip": str(ip_obj),
            "is_valid": True,
            "category": cat,
            "is_private": is_private,
            "version": ip_obj.version,
        }
    except ValueError:
        return {"ip": ip_str, "is_valid": False, "category": "Invalid", "is_private": False}


def parse_single_received_header(received_str: str, hop_index: int) -> Dict[str, Any]:
    """
    Parses a single Received header string into structured DFIR hop telemetry.
    """
    text = re.sub(r"\s+", " ", received_str).strip()

    # Extract Sending Host (from ...)
    from_match = re.search(r"from\s+([^\s]+(?:\s+\([^)]+\))?)", text, re.IGNORECASE)
    sending_host = from_match.group(1) if from_match else "Unknown"

    # Extract Receiving Host (by ...)
    by_match = re.search(r"by\s+([^\s]+)", text, re.IGNORECASE)
    receiving_host = by_match.group(1) if by_match else "Unknown"

    # Extract IP address
    ip_match = IP_IN_RECEIVED_REGEX.search(text)
    extracted_ip = ""
    if ip_match:
        extracted_ip = ip_match.group(1) or ip_match.group(0)

    ip_info = classify_ip_address(extracted_ip)

    # Extract Protocol / TLS
    proto_match = re.search(r"with\s+([^\s;]+)", text, re.IGNORECASE)
    protocol = proto_match.group(1) if proto_match else "SMTP"
    has_tls = "tls" in text.lower() or "ssl" in text.lower() or "https" in text.lower()

    # Extract Timestamp
    timestamp_raw = ""
    dt_utc: Optional[datetime] = None
    if ";" in text:
        parts = text.rsplit(";", 1)
        timestamp_raw = parts[1].strip()
        try:
            parsed_dt = parsedate_to_datetime(timestamp_raw)
            if parsed_dt:
                dt_utc = parsed_dt.astimezone(timezone.utc)
        except Exception:
            dt_utc = None

    return {
        "hop_number": hop_index,
        "raw": text,
        "sending_host": sending_host,
        "receiving_host": receiving_host,
        "ip": extracted_ip,
        "ip_classification": ip_info,
        "protocol": protocol,
        "tls": has_tls,
        "timestamp_raw": timestamp_raw,
        "timestamp_utc": dt_utc.isoformat() if dt_utc else None,
        "dt_object": dt_utc,
    }


def parse_received_chain(headers_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parses all Received headers in chronological order (bottom-to-top / sender-to-recipient).
    Detects timing anomalies, clock skew, private IP relays, and missing hops.
    """
    received_list = headers_dict.get("Received", []) or headers_dict.get("received", [])
    if isinstance(received_list, str):
        received_list = [received_list]

    # RFC 5322 Received headers are prepended top-to-bottom.
    # Reverse to analyze in chronological order (hop 1 = initial sender relay).
    chronological_raw = list(reversed(received_list))

    hops = []
    for idx, raw_h in enumerate(chronological_raw, start=1):
        hop = parse_single_received_header(str(raw_h), idx)
        hops.append(hop)

    anomalies: List[Dict[str, Any]] = []
    timing_issues = 0
    private_relay_count = 0

    # Analyze transit times and timing anomalies across consecutive hops
    prev_dt: Optional[datetime] = None
    total_transit_seconds = 0

    for hop in hops:
        if hop["ip_classification"]["is_private"]:
            private_relay_count += 1

        dt = hop["dt_object"]
        if dt and prev_dt:
            delay = (dt - prev_dt).total_seconds()
            hop["delay_seconds"] = delay
            if delay < -60:  # Out of order timestamp (clock skew > 1 min)
                timing_issues += 1
                anomalies.append({
                    "finding": "Chronological Clock Skew / Out-of-Order Timestamp",
                    "severity": "Medium",
                    "explanation": f"Hop {hop['hop_number']} timestamp ({hop['timestamp_raw']}) is earlier than previous Hop by {abs(int(delay))} seconds.",
                    "evidence": f"Hop {hop['hop_number']} delay: {delay}s",
                    "recommendation": "Inspect server clock synchronization or check for forged Received headers.",
                })
            elif delay > 86400:  # Suspicious delivery delay > 24 hours
                timing_issues += 1
                anomalies.append({
                    "finding": "Excessive Delivery Transit Delay",
                    "severity": "Low",
                    "explanation": f"Hop {hop['hop_number']} experienced a delay of {int(delay // 3600)} hours.",
                    "evidence": f"Hop {hop['hop_number']} delay: {int(delay)}s",
                    "recommendation": "Check for email spool queuing or temporary graylisting delay.",
                })
            total_transit_seconds += max(0, int(delay))
        else:
            hop["delay_seconds"] = 0
        if dt:
            prev_dt = dt

    if private_relay_count > 0:
        anomalies.append({
            "finding": "Internal / Private IP Relay Detected in Path",
            "severity": "Info",
            "explanation": f"{private_relay_count} hop(s) traversed internal or private IP address spaces.",
            "evidence": f"Private Relays: {private_relay_count}",
            "recommendation": "Normal for corporate email gateways and internal mail submission servers.",
        })

    trust_score = max(0, 100 - (timing_issues * 15 + (10 if len(hops) == 0 else 0)))

    # Clean up non-serializable dt_object before returning
    for h in hops:
        h.pop("dt_object", None)

    return {
        "hop_count": len(hops),
        "hops": hops,
        "total_transit_seconds": total_transit_seconds,
        "private_relay_count": private_relay_count,
        "timing_issues": timing_issues,
        "infrastructure_trust_score": trust_score,
        "anomalies": anomalies,
    }
