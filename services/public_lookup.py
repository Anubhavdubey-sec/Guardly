"""
Guardly Public & Geolocation Context Integration Module
Delegates all IP classification and location resolving to services.geolocation.GeolocationService,
ensuring a unified, cached, offline-first geolocation pipeline.
"""

from typing import Any, Dict, Optional
from services.geolocation import get_geolocation_service, GeoResult

COUNTRY_FLAGS = {
    "US": "🇺🇸", "GB": "🇬🇧", "CA": "🇨🇦", "DE": "🇩🇪", "FR": "🇫🇷",
    "IN": "🇮🇳", "JP": "🇯🇵", "CN": "🇨🇳", "AU": "🇦🇺", "BR": "🇧🇷",
    "RU": "🇷🇺", "NL": "🇳🇱", "SG": "🇸🇬", "LOCAL": "🏠"
}


def get_ip_location(ip_str: str) -> Optional[Dict[str, Any]]:
    """
    Resolves IP geolocation by invoking GeolocationService.
    Returns a unified dictionary containing all GeoResult fields and UI display helpers.
    Guaranteed never to crash.
    """
    if not ip_str or not isinstance(ip_str, str):
        return None

    clean_ip = ip_str.strip("[]() ")
    geo_service = get_geolocation_service()
    geo_res = geo_service.lookup(clean_ip)

    # Determine flag emoji and display strings
    code = geo_res.country_code if geo_res.country_code not in ("Unknown", "Unavailable") else ("LOCAL" if geo_res.address_type != "public" else "US")
    flag = COUNTRY_FLAGS.get(code, "🏠" if geo_res.address_type != "public" else "🌐")

    if geo_res.address_type != "public":
        city = "Local / Internal Network"
        region = "Intranet"
        country = "Private Subnet"
        org = "Private Subnet"
        location_display = f"🏠 Private Subnet ({geo_res.address_type.title()})"
    else:
        city = geo_res.city if geo_res.city != "Unknown" else "Public Gateway Node"
        region = geo_res.region if geo_res.region != "Unknown" else "Global Subnet"
        country = geo_res.country if geo_res.country != "Unknown" else "Public Internet"
        org = geo_res.organization if geo_res.organization != "Unknown" else "Internet Service Provider"

        if city != "Public Gateway Node" and country != "Public Internet":
            location_display = f"{flag} {city}, {country} ({org})"
        else:
            location_display = f"{flag} Public Internet IP Node ({org})"

    return {
        "ip": clean_ip,
        "ip_version": geo_res.ip_version,
        "address_type": geo_res.address_type,
        "city": city,
        "region": region,
        "country": country,
        "country_code": code,
        "flag": flag,
        "latitude": geo_res.latitude,
        "longitude": geo_res.longitude,
        "timezone": geo_res.timezone,
        "asn": geo_res.asn,
        "organization": org,
        "network": geo_res.network,
        "source": geo_res.source,
        "status": geo_res.status,
        "provider_used": geo_res.provider_used,
        "org": org,
        "location_display": location_display,
        "geo_result": geo_res.to_dict(),
    }


class PublicLookupClient:
    """
    Context lookup client forwarding IP queries to GeolocationService.
    """

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
            "provider": "Guardly Offline-First Geolocation & RDAP Subsystem",
            "message": "Public context lookups active.",
            "lookups": lookups,
        }


def enrich_analysis_with_public_context(analysis, reputation_data):
    enriched = dict(analysis)
    enriched["reputation_data"] = reputation_data
    return enriched
