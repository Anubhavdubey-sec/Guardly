"""
PhishGuard Email Delivery Timeline Analysis Module
Parses RFC 822 "Received:" headers to reconstruct mail flow, compute inter-hop delays,
classify IP relays using native ipaddress module, and detect timeline anomalies.
Operates 100% offline with zero external network dependencies.
"""

from dataclasses import dataclass, field
import datetime
import email.utils
import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

from services.public_lookup import get_ip_location


@dataclass
class MailHop:
    hop_number: int
    from_host: Optional[str] = None
    from_ip: Optional[str] = None
    by_host: Optional[str] = None
    by_ip: Optional[str] = None
    protocol: Optional[str] = None
    timestamp_raw: Optional[str] = None
    timestamp_iso: Optional[str] = None
    timestamp_dt: Optional[datetime.datetime] = None
    delay_seconds: Optional[float] = None
    delay_display: str = "Unknown"
    ip_type: str = "Unknown"
    relay_type: str = "Unknown"
    is_internal: bool = False
    auth_info: Optional[str] = None
    location_display: str = "Location Unavailable"
    geo_data: Optional[Dict[str, Any]] = None
    observations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hop_number": self.hop_number,
            "from_host": self.from_host or "Unknown / Direct",
            "from_ip": self.from_ip or "None Recorded",
            "by_host": self.by_host or "Unknown Destination",
            "by_ip": self.by_ip or "None Recorded",
            "protocol": self.protocol or "SMTP / Standard",
            "timestamp_raw": self.timestamp_raw or "Timestamp Missing",
            "timestamp_iso": self.timestamp_iso or "",
            "delay_seconds": self.delay_seconds,
            "delay_display": self.delay_display,
            "ip_type": self.ip_type,
            "relay_type": self.relay_type,
            "is_internal": self.is_internal,
            "auth_info": self.auth_info or "",
            "location_display": self.location_display,
            "geo_data": self.geo_data or {},
            "observations": self.observations,
        }


@dataclass
class DeliverySummary:
    total_hops: int = 0
    internal_hops: int = 0
    external_hops: int = 0
    max_delay_display: str = "0s"
    avg_delay_display: str = "0s"
    first_received_raw: str = "N/A"
    final_delivery_raw: str = "N/A"
    total_delivery_time_display: str = "0s"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_hops": self.total_hops,
            "internal_hops": self.internal_hops,
            "external_hops": self.external_hops,
            "max_delay_display": self.max_delay_display,
            "avg_delay_display": self.avg_delay_display,
            "first_received_raw": self.first_received_raw,
            "final_delivery_raw": self.final_delivery_raw,
            "total_delivery_time_display": self.total_delivery_time_display,
        }


@dataclass
class TimelineAnalysis:
    hops: List[MailHop] = field(default_factory=list)
    summary: DeliverySummary = field(default_factory=DeliverySummary)
    has_timeline: bool = False
    summary_message: str = "No delivery path available."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hops": [hop.to_dict() for hop in self.hops],
            "summary": self.summary.to_dict(),
            "has_timeline": self.has_timeline,
            "summary_message": self.summary_message,
        }


def _classify_ip(ip_str: Optional[str]) -> Tuple[str, bool]:
    """
    Classify IP address using Python's native ipaddress module.
    Returns (ip_type_label, is_internal_boolean).
    """
    if not ip_str:
        return "Unknown", False

    clean_ip = ip_str.strip("[]() ")
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return "Unknown", False

    is_priv = (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )

    if isinstance(ip_obj, ipaddress.IPv6Address):
        return "IPv6", is_priv
    elif ip_obj.is_loopback:
        return "Loopback", True
    elif ip_obj.is_link_local:
        return "Link-Local", True
    elif ip_obj.is_reserved:
        return "Reserved", True
    elif ip_obj.is_private:
        return "Private IP", True
    else:
        return "Public IP", False


def _format_delay_seconds(seconds: float) -> str:
    """Format seconds into human-readable delay string."""
    if seconds < 0:
        return f"{abs(int(seconds))}s (Clock Skew Anomaly)"
    if seconds < 60:
        return f"{int(seconds)}s"
    minutes = int(seconds // 60)
    rem_sec = int(seconds % 60)
    if minutes < 60:
        return f"{minutes}m {rem_sec}s" if rem_sec else f"{minutes}m"
    hours = int(minutes // 60)
    rem_min = minutes % 60
    return f"{hours}h {rem_min}m"


def parse_received_header(header_str: str) -> Optional[MailHop]:
    """
    Parse a single RFC822 Received header string into a MailHop object.
    Never raises exceptions.
    """
    if not header_str or not isinstance(header_str, str):
        return None

    clean_header = " ".join(header_str.split())
    observations: List[str] = []

    # Separate timestamp (semicolon delimited at end of Received header)
    raw_timestamp: Optional[str] = None
    content_part = clean_header

    if ";" in clean_header:
        parts = clean_header.rsplit(";", 1)
        content_part = parts[0].strip()
        raw_timestamp = parts[1].strip()

    # Extract sending host ("from ...")
    from_host: Optional[str] = None
    from_match = re.search(r"\bfrom\s+([^\s()]+)", content_part, re.IGNORECASE)
    if from_match:
        from_host = from_match.group(1).strip()
    else:
        observations.append("Missing sender hostname")

    # Extract receiving host ("by ...")
    by_host: Optional[str] = None
    by_match = re.search(r"\bby\s+([^\s()]+)", content_part, re.IGNORECASE)
    if by_match:
        by_host = by_match.group(1).strip()

    # Extract IP address ([xxx.xxx.xxx.xxx] or IPv6)
    from_ip: Optional[str] = None
    ip_match = re.search(
        r"\[(?:IPv6:)?([a-fA-F0-9:\.]+)\]|\b(?:\d{1,3}\.){3}\d{1,3}\b", content_part
    )
    if ip_match:
        from_ip = ip_match.group(1) or ip_match.group(0)

    # Extract Protocol ("with ...")
    protocol: Optional[str] = None
    proto_match = re.search(r"\bwith\s+([A-Za-z0-9\-_]+)", content_part, re.IGNORECASE)
    if proto_match:
        protocol = proto_match.group(1).upper()

    # Extract Auth / TLS details
    auth_info: Optional[str] = None
    auth_match = re.search(
        r"\b(using\s+TLS[^\s;()]+|tls\s+[^\s;()]+|dkim=[^\s;()]+|spf=[^\s;()]+)",
        content_part,
        re.IGNORECASE,
    )
    if auth_match:
        auth_info = auth_match.group(0)

    # Classify IP
    ip_type, is_internal = _classify_ip(from_ip)

    if is_internal:
        relay_type = "Internal Relay"
        observations.append("Private IP relay")
    elif from_ip:
        relay_type = "External Relay"
    else:
        relay_type = "Unknown Relay"

    if ip_type == "IPv6":
        observations.append("IPv6 relay")

    if not from_host or from_host.lower() in ("unknown", "localhost"):
        observations.append("Unknown hostname")

    # Parse Timestamp
    parsed_dt: Optional[datetime.datetime] = None
    timestamp_iso: Optional[str] = None

    if raw_timestamp:
        try:
            parsed_tuple = email.utils.parsedate_tz(raw_timestamp)
            if parsed_tuple:
                timestamp_sec = email.utils.mktime_tz(parsed_tuple)
                parsed_dt = datetime.datetime.fromtimestamp(
                    timestamp_sec, tz=datetime.timezone.utc
                )
                timestamp_iso = parsed_dt.isoformat()
        except Exception:
            parsed_dt = None
            observations.append("Unparseable timestamp")
    else:
        observations.append("Missing timestamp")

    # Local IP Location Lookup
    loc_display = "Location Unavailable"
    geo_data = None
    if from_ip:
        loc_info = get_ip_location(from_ip)
        if loc_info and isinstance(loc_info, dict):
            geo_data = loc_info
            loc_display = loc_info.get("location_display") or "Location Unavailable"

    return MailHop(
        hop_number=0,  # Will be assigned during chronological sequencing
        from_host=from_host,
        from_ip=from_ip,
        by_host=by_host,
        by_ip=None,
        protocol=protocol,
        timestamp_raw=raw_timestamp,
        timestamp_iso=timestamp_iso,
        timestamp_dt=parsed_dt,
        delay_seconds=None,
        delay_display="Unknown",
        ip_type=ip_type,
        relay_type=relay_type,
        is_internal=is_internal,
        auth_info=auth_info,
        location_display=loc_display,
        geo_data=geo_data,
        observations=observations,
    )


def parse_received_headers(raw_headers: List[str]) -> List[MailHop]:
    """
    Parse a list of Received header strings.
    Never raises exceptions.
    """
    hops: List[MailHop] = []
    if not raw_headers:
        return hops

    for header in raw_headers:
        try:
            hop = parse_received_header(header)
            if hop:
                hops.append(hop)
        except Exception:
            continue

    return hops


def extract_mail_hops(email_message) -> List[MailHop]:
    """
    Extract Received headers from Python email.message.Message and reverse to chronological order.
    RFC 822 Received headers are prepended top-to-bottom (most recent at top).
    Reversing puts Hop 1 as the initial sender relay and Hop N as recipient inbox.
    """
    if not email_message:
        return []

    try:
        raw_received = email_message.get_all("Received", [])
    except Exception:
        raw_received = []

    if not raw_received:
        return []

    parsed_hops = parse_received_headers(raw_received)
    # Reverse to chronological order: Hop 1 = First relay (Internet/Sender) -> Hop N = Recipient Inbox
    chronological_hops = list(reversed(parsed_hops))

    # Assign 1-indexed hop numbers
    for idx, hop in enumerate(chronological_hops, start=1):
        hop.hop_number = idx

    return chronological_hops


def calculate_delivery_delays(hops: List[MailHop]) -> List[MailHop]:
    """
    Compute inter-hop delivery delays and identify timestamp anomalies across hops.
    Never fails.
    """
    if not hops:
        return []

    # Detect Duplicate Relays across consecutive hops
    for i in range(1, len(hops)):
        prev = hops[i - 1]
        curr = hops[i]
        if (
            curr.from_ip
            and prev.from_ip
            and curr.from_ip == prev.from_ip
        ) or (
            curr.from_host
            and prev.from_host
            and curr.from_host == prev.from_host
            and curr.from_host not in ("unknown", "localhost")
        ):
            curr.observations.append("Duplicate relay")

    for i, hop in enumerate(hops):
        if i == 0:
            hop.delay_seconds = 0.0
            hop.delay_display = "0s (Initial Hop)"
            continue

        prev_hop = hops[i - 1]

        if hop.timestamp_dt and prev_hop.timestamp_dt:
            diff = (hop.timestamp_dt - prev_hop.timestamp_dt).total_seconds()
            hop.delay_seconds = diff
            if diff < 0:
                hop.delay_display = _format_delay_seconds(diff)
                if "Timestamp anomaly" not in hop.observations:
                    hop.observations.append("Timestamp anomaly")
                if "Out-of-order timestamps" not in hop.observations:
                    hop.observations.append("Out-of-order timestamps")
            else:
                hop.delay_display = _format_delay_seconds(diff)
        else:
            hop.delay_seconds = None
            hop.delay_display = "Unknown"
            if "Missing timestamp" not in hop.observations:
                hop.observations.append("Missing timestamp")

    return hops


def generate_delivery_summary(hops: List[MailHop]) -> DeliverySummary:
    """
    Generate aggregate metrics for the delivery timeline summary panel.
    """
    if not hops:
        return DeliverySummary()

    total_hops = len(hops)
    internal_hops = sum(1 for h in hops if h.is_internal)
    external_hops = total_hops - internal_hops

    valid_delays = [h.delay_seconds for h in hops[1:] if h.delay_seconds is not None]

    if valid_delays:
        max_del = max(valid_delays)
        avg_del = sum(valid_delays) / len(valid_delays)
        max_display = _format_delay_seconds(max_del)
        avg_display = _format_delay_seconds(avg_del)
    else:
        max_display = "Unknown"
        avg_display = "Unknown"

    first_received = hops[0].timestamp_raw or "Timestamp Unavailable"
    final_delivery = hops[-1].timestamp_raw or "Timestamp Unavailable"

    total_delivery_time_display = "Unknown"
    if (
        hops[0].timestamp_dt
        and hops[-1].timestamp_dt
        and len(hops) > 1
    ):
        tot_diff = (hops[-1].timestamp_dt - hops[0].timestamp_dt).total_seconds()
        total_delivery_time_display = _format_delay_seconds(tot_diff)

    return DeliverySummary(
        total_hops=total_hops,
        internal_hops=internal_hops,
        external_hops=external_hops,
        max_delay_display=max_display,
        avg_delay_display=avg_display,
        first_received_raw=first_received,
        final_delivery_raw=final_delivery,
        total_delivery_time_display=total_delivery_time_display,
    )


def build_delivery_timeline(email_message) -> TimelineAnalysis:
    """
    Top-level orchestrator: extracts, calculates delays, and returns TimelineAnalysis.
    Guaranteed never to crash.
    """
    try:
        hops = extract_mail_hops(email_message)
        if not hops:
            return TimelineAnalysis(
                hops=[],
                summary=DeliverySummary(),
                has_timeline=False,
                summary_message="No delivery path available.",
            )

        hops_with_delays = calculate_delivery_delays(hops)
        summary = generate_delivery_summary(hops_with_delays)

        return TimelineAnalysis(
            hops=hops_with_delays,
            summary=summary,
            has_timeline=True,
            summary_message=f"Reconstructed {len(hops_with_delays)} mail server relay hops.",
        )
    except Exception as err:
        return TimelineAnalysis(
            hops=[],
            summary=DeliverySummary(),
            has_timeline=False,
            summary_message="No delivery path available.",
        )
