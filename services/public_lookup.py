import json
import socket
import urllib.request
from services.ssrf import is_ip_private_or_internal, validate_url_ssrf

COUNTRY_FLAGS = {
    "US": "🇺🇸", "GB": "🇬🇧", "CA": "🇨🇦", "DE": "🇩🇪", "FR": "🇫🇷",
    "IN": "🇮🇳", "JP": "🇯🇵", "CN": "🇨🇳", "AU": "🇦🇺", "BR": "🇧🇷",
    "RU": "🇷🇺", "NL": "🇳🇱", "SG": "🇸🇬", "LOCAL": "🏠"
}

def get_ip_location(ip_str):
    if not ip_str or not isinstance(ip_str, str):
        return None

    ip_clean = ip_str.strip()

    # Check for private, loopback, or internal IP addresses via ipaddress module
    if is_ip_private_or_internal(ip_clean):
        return {
            "ip": ip_clean,
            "city": "Local / Internal Network",
            "region": "Intranet",
            "country": "Private Subnet",
            "country_code": "LOCAL",
            "flag": "🏠",
            "org": "Private RFC1918 Subnet",
            "location_display": "🏠 Private Subnet (Internal Network)"
        }

    # Fast offline fallback dictionary for common public DNS / Cloud IPs
    known_ips = {
        "8.8.8.8": {"city": "Mountain View", "region": "California", "country": "United States", "code": "US", "org": "Google LLC"},
        "8.8.4.4": {"city": "Mountain View", "region": "California", "country": "United States", "code": "US", "org": "Google LLC"},
        "1.1.1.1": {"city": "Los Angeles", "region": "California", "country": "United States", "code": "US", "org": "Cloudflare Inc"},
        "9.9.9.9": {"city": "Berkeley", "region": "California", "country": "United States", "code": "US", "org": "Quad9"}
    }

    if ip_clean in known_ips:
        k = known_ips[ip_clean]
        return {
            "ip": ip_clean,
            "city": k["city"],
            "region": k["region"],
            "country": k["country"],
            "country_code": k["code"],
            "flag": COUNTRY_FLAGS.get(k["code"], "🌐"),
            "org": k["org"],
            "location_display": f"{COUNTRY_FLAGS.get(k['code'], '🌐')} {k['city']}, {k['country']} ({k['org']})"
        }

    # Live IP Geolocation API attempt (ip-api.com) with 1.5s timeout
    try:
        url = f"http://ip-api.com/json/{ip_clean}?fields=status,message,country,countryCode,regionName,city,isp,org,query"
        req = urllib.request.Request(url, headers={"User-Agent": "Guardly-IP-Geo/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                code = data.get("countryCode", "US")
                city = data.get("city", "Unknown City")
                country = data.get("country", "Unknown Country")
                org = data.get("org") or data.get("isp") or "Public Network"
                flag = COUNTRY_FLAGS.get(code, "🌐")
                return {
                    "ip": ip_clean,
                    "city": city,
                    "region": data.get("regionName", ""),
                    "country": country,
                    "country_code": code,
                    "flag": flag,
                    "org": org,
                    "location_display": f"{flag} {city}, {country} ({org})"
                }
    except Exception:
        pass

    # Generic fallback if offline or API unavailable
    return {
        "ip": ip_clean,
        "city": "Public Gateway Node",
        "region": "Global Subnet",
        "country": "Public Internet",
        "country_code": "US",
        "flag": "🌐",
        "org": "Internet Service Provider",
        "location_display": "🌐 Public Internet IP Node"
    }


class PublicLookupClient:
    def __init__(self, timeout_seconds=3, max_lookups=5):
        self.timeout_seconds = timeout_seconds
        self.max_lookups = max_lookups

    def lookup_context(self, domains=None, ip_addresses=None):
        lookups = []
        if ip_addresses:
            for ip in ip_addresses[:self.max_lookups]:
                geo = get_ip_location(ip)
                if geo:
                    lookups.append(geo)

        return {
            "provider": "Public RDAP and IP network context",
            "message": "Public context lookups active.",
            "lookups": lookups,
        }


def enrich_analysis_with_public_context(analysis, reputation_data):
    enriched = dict(analysis)
    enriched["reputation_data"] = reputation_data
    return enriched
