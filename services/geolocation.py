"""
Guardly Enterprise IP Geolocation & Classification Subsystem
Authoritative Primary Provider: MaxMind GeoLite2 (City + ASN)
Optional Fallback: Online HTTP Provider (Config-gated)

Provides offline-first IP classification, MaxMind GeoLite2 City/ASN lookups,
database metadata health checks, thread-safe LRU/TTL caching, and fail-safe diagnostic logging.
"""

from dataclasses import asdict, dataclass
import datetime
import ipaddress
import json
import logging
import os
import socket
import threading
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Protocol, Tuple

logger = logging.getLogger(__name__)

# Try importing geoip2 database reader
try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False


@dataclass
class GeoResult:
    ip: str
    ip_version: int              # 4 or 6
    address_type: str            # "public" | "private" | "loopback" | "link-local" | "multicast" | "reserved" | "unknown"
    country: str = "Unknown"
    country_code: str = "Unknown"
    region: str = "Unknown"
    city: str = "Unknown"
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: str = "Unknown"
    asn: Optional[int] = None
    organization: str = "Unknown"
    network: str = "Unknown"
    source: str = "none"         # "maxmind" | "online" | "none"
    status: str = "unavailable"  # "ok" | "partial" | "unavailable"
    provider_used: str = "None"  # "MaxMind GeoLite2 (City + ASN)" | "MaxMind City" | "MaxMind ASN" | "Online Fallback (ip-api)" | "None"
    db_build_date: Optional[str] = None  # Build timestamp of MaxMind database

    def to_dict(self) -> Dict[str, Any]:
        """Convert GeoResult dataclass to serializable dictionary."""
        return asdict(self)


def classify_ip(ip_str: str) -> Tuple[str, int]:
    """
    Classify IP address into address_type and ip_version using Python's ipaddress module.
    Address types: 'public', 'private', 'loopback', 'link-local', 'multicast', 'reserved', 'unknown'.
    """
    if not ip_str or not isinstance(ip_str, str):
        return "unknown", 4

    clean_ip = ip_str.strip("[]() ")
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return "unknown", 4

    version = ip_obj.version

    if ip_obj.is_loopback:
        return "loopback", version
    elif ip_obj.is_link_local:
        return "link-local", version
    elif ip_obj.is_multicast:
        return "multicast", version
    elif ip_obj.is_reserved or ip_obj.is_unspecified:
        return "reserved", version
    elif ip_obj.is_private:
        return "private", version
    elif getattr(ip_obj, "is_global", not ip_obj.is_private):
        return "public", version
    else:
        return "unknown", version


class GeoProvider(Protocol):
    """Protocol interface for pluggable IP geolocation providers."""
    is_available: bool

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        ...

    def close(self) -> None:
        ...


class MaxMindCityProvider:
    """
    Authoritative Primary Provider for GeoLite2-City.mmdb.
    Resolves country, country_code, region, city, latitude, longitude, and timezone.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.is_available = False
        self._reader = None
        self._load_warning_logged = False
        self.build_epoch = None
        self.database_type = None
        self._open_reader()

    def _open_reader(self) -> None:
        abs_path = os.path.abspath(self.db_path)
        logger.info(f"[GEOLOCATION INITIALIZATION] MaxMind City Provider loading: '{abs_path}'")

        if not os.path.exists(abs_path):
            if not self._load_warning_logged:
                logger.warning(f"[GEOLOCATION WARNING] MaxMind City Database file missing at '{abs_path}'. MaxMind City lookups disabled.")
                self._load_warning_logged = True
            self.is_available = False
            return

        if not os.access(abs_path, os.R_OK):
            if not self._load_warning_logged:
                logger.warning(f"[GEOLOCATION WARNING] MaxMind City Database unreadable (permission denied) at '{abs_path}'. MaxMind City lookups disabled.")
                self._load_warning_logged = True
            self.is_available = False
            return

        if not GEOIP2_AVAILABLE:
            if not self._load_warning_logged:
                logger.warning("[GEOLOCATION WARNING] geoip2 package is not installed. MaxMindCityProvider disabled.")
                self._load_warning_logged = True
            self.is_available = False
            return

        try:
            self._reader = geoip2.database.Reader(abs_path)
            self.is_available = True

            # Extract MaxMind Database Metadata
            try:
                meta = self._reader.metadata()
                self.build_epoch = getattr(meta, "build_epoch", None)
                self.database_type = getattr(meta, "database_type", "GeoLite2-City")
            except Exception:
                pass

            logger.info(f"[GEOLOCATION SUCCESS] MaxMind City Provider ONLINE (Opened '{abs_path}', Type='{self.database_type}')")
        except Exception as e:
            if not self._load_warning_logged:
                logger.warning(f"[GEOLOCATION ERROR] Failed to open MaxMind City database at '{abs_path}': {e}")
                self._load_warning_logged = True
            self.is_available = False

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        if not self.is_available or not self._reader:
            return None

        try:
            response = self._reader.city(ip)
            city_name = response.city.name or "Unknown"
            country_name = response.country.name or "Unknown"
            country_code = response.country.iso_code or "Unknown"
            region_name = response.subdivisions.most_specific.name if response.subdivisions else "Unknown"
            latitude = response.location.latitude
            longitude = response.location.longitude
            time_zone = response.location.time_zone or "Unknown"

            status = "ok" if (city_name != "Unknown" or country_name != "Unknown") else "partial"

            return {
                "city": city_name,
                "country": country_name,
                "country_code": country_code,
                "region": region_name or "Unknown",
                "latitude": latitude,
                "longitude": longitude,
                "timezone": time_zone,
                "status": status,
                "db_build_date": datetime.datetime.fromtimestamp(self.build_epoch, tz=datetime.timezone.utc).strftime("%Y-%m-%d") if self.build_epoch else None,
            }
        except (geoip2.errors.AddressNotFoundError, ValueError):
            return None
        except Exception as e:
            logger.warning(f"MaxMindCityProvider lookup exception for IP {ip}: {e}")
            return None

    def close(self) -> None:
        if self._reader:
            try:
                self._reader.close()
            except Exception:
                pass
            self._reader = None


class MaxMindASNProvider:
    """
    Authoritative Primary Provider for GeoLite2-ASN.mmdb.
    Resolves ASN, organization, and network CIDR block.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.is_available = False
        self._reader = None
        self._load_warning_logged = False
        self.build_epoch = None
        self.database_type = None
        self._open_reader()

    def _open_reader(self) -> None:
        abs_path = os.path.abspath(self.db_path)
        logger.info(f"[GEOLOCATION INITIALIZATION] MaxMind ASN Provider loading: '{abs_path}'")

        if not os.path.exists(abs_path):
            if not self._load_warning_logged:
                logger.warning(f"[GEOLOCATION WARNING] MaxMind ASN Database file missing at '{abs_path}'. MaxMind ASN lookups disabled.")
                self._load_warning_logged = True
            self.is_available = False
            return

        if not os.access(abs_path, os.R_OK):
            if not self._load_warning_logged:
                logger.warning(f"[GEOLOCATION WARNING] MaxMind ASN Database unreadable (permission denied) at '{abs_path}'. MaxMind ASN lookups disabled.")
                self._load_warning_logged = True
            self.is_available = False
            return

        if not GEOIP2_AVAILABLE:
            if not self._load_warning_logged:
                logger.warning("[GEOLOCATION WARNING] geoip2 package is not installed. MaxMindASNProvider disabled.")
                self._load_warning_logged = True
            self.is_available = False
            return

        try:
            self._reader = geoip2.database.Reader(abs_path)
            self.is_available = True

            try:
                meta = self._reader.metadata()
                self.build_epoch = getattr(meta, "build_epoch", None)
                self.database_type = getattr(meta, "database_type", "GeoLite2-ASN")
            except Exception:
                pass

            logger.info(f"[GEOLOCATION SUCCESS] MaxMind ASN Provider ONLINE (Opened '{abs_path}', Type='{self.database_type}')")
        except Exception as e:
            if not self._load_warning_logged:
                logger.warning(f"[GEOLOCATION ERROR] Failed to open MaxMind ASN database at '{abs_path}': {e}")
                self._load_warning_logged = True
            self.is_available = False

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        if not self.is_available or not self._reader:
            return None

        try:
            response = self._reader.asn(ip)
            asn_number = response.autonomous_system_number
            org_name = response.autonomous_system_organization or "Unknown"
            network_cidr = str(response.network) if response.network else "Unknown"

            return {
                "asn": asn_number,
                "organization": org_name,
                "network": network_cidr,
                "status": "ok" if asn_number is not None else "partial",
                "db_build_date": datetime.datetime.fromtimestamp(self.build_epoch, tz=datetime.timezone.utc).strftime("%Y-%m-%d") if self.build_epoch else None,
            }
        except (geoip2.errors.AddressNotFoundError, ValueError):
            return None
        except Exception as e:
            logger.warning(f"MaxMindASNProvider lookup exception for IP {ip}: {e}")
            return None

    def close(self) -> None:
        if self._reader:
            try:
                self._reader.close()
            except Exception:
                pass
            self._reader = None


class OnlineFallbackProvider:
    """
    Optional HTTP-based online provider (e.g. ip-api.com / ipinfo.io).
    Used ONLY when local MaxMind databases are unavailable or return no match AND fallback.enabled=True.
    """

    def __init__(self, provider_type: str = "ip-api", api_key: str = "", timeout: float = 2.0):
        self.provider_type = provider_type.lower()
        self.api_key = api_key
        self.timeout = timeout
        self.is_available = True

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        if not self.is_available:
            return None

        try:
            if self.provider_type == "ipinfo":
                return self._lookup_ipinfo(ip)
            else:
                return self._lookup_ipapi(ip)
        except Exception as e:
            logger.warning(f"OnlineFallbackProvider ({self.provider_type}) query exception for IP {ip}: {e}")
            return None

    def _lookup_ipapi(self, ip: str) -> Optional[Dict[str, Any]]:
        url = f"http://ip-api.com/json/{urllib.parse.quote(ip)}?fields=status,country,countryCode,regionName,city,lat,lon,timezone,as,org,query"
        req = urllib.request.Request(url, headers={"User-Agent": "Guardly-Geolocation-Fallback/2.4"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                as_info = data.get("as", "")
                asn_val = None
                if as_info and as_info.startswith("AS"):
                    try:
                        asn_val = int(as_info.split()[0][2:])
                    except ValueError:
                        asn_val = None

                return {
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "timezone": data.get("timezone", "Unknown"),
                    "asn": asn_val,
                    "organization": data.get("org", "Unknown"),
                    "network": "Unknown",
                    "status": "ok",
                }
        return None

    def _lookup_ipinfo(self, ip: str) -> Optional[Dict[str, Any]]:
        url = f"https://ipinfo.io/{urllib.parse.quote(ip)}/json"
        if self.api_key:
            url += f"?token={urllib.parse.quote(self.api_key)}"
        req = urllib.request.Request(url, headers={"User-Agent": "Guardly-Geolocation-Fallback/2.4"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            loc = data.get("loc", "")
            lat, lon = None, None
            if loc and "," in loc:
                try:
                    parts = loc.split(",")
                    lat, lon = float(parts[0]), float(parts[1])
                except ValueError:
                    pass

            org_str = data.get("org", "")
            asn_val = None
            if org_str and org_str.startswith("AS"):
                try:
                    asn_val = int(org_str.split()[0][2:])
                except ValueError:
                    pass

            return {
                "country": data.get("country", "Unknown"),
                "country_code": data.get("country", "Unknown"),
                "region": data.get("region", "Unknown"),
                "city": data.get("city", "Unknown"),
                "latitude": lat,
                "longitude": lon,
                "timezone": data.get("timezone", "Unknown"),
                "asn": asn_val,
                "organization": org_str or "Unknown",
                "network": "Unknown",
                "status": "ok",
            }

    def close(self) -> None:
        pass


@dataclass
class CacheEntry:
    result: GeoResult
    expires_at: float


class ThreadSafeGeoCache:
    """Thread-safe LRU/TTL cache for GeoResult items."""

    def __init__(self, max_size: int = 10000, ttl_seconds: int = 3600, negative_ttl_seconds: int = 300):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.negative_ttl_seconds = negative_ttl_seconds
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, ip: str) -> Optional[GeoResult]:
        now = time.time()
        with self._lock:
            entry = self._cache.get(ip)
            if entry is None:
                self.misses += 1
                return None
            if now > entry.expires_at:
                del self._cache[ip]
                self.misses += 1
                return None
            self.hits += 1
            return entry.result

    def put(self, ip: str, result: GeoResult) -> None:
        now = time.time()
        ttl = self.ttl_seconds if result.status in ("ok", "partial") else self.negative_ttl_seconds
        expires_at = now + ttl

        with self._lock:
            if len(self._cache) >= self.max_size and ip not in self._cache:
                first_key = next(iter(self._cache))
                del self._cache[first_key]
            self._cache[ip] = CacheEntry(result=result, expires_at=expires_at)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self.hits = 0
            self.misses = 0

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self.hits,
                "misses": self.misses,
                "ttl_seconds": self.ttl_seconds,
                "negative_ttl_seconds": self.negative_ttl_seconds,
            }


class GeolocationService:
    """
    Orchestrates MaxMind GeoLite2 as Authoritative Primary Provider,
    Online Fallback (config-gated), Thread-Safe Caching, and IP Classification.
    """

    def __init__(
        self,
        city_path: str = "./data/GeoLite2-City.mmdb",
        asn_path: str = "./data/GeoLite2-ASN.mmdb",
        cache_max_size: int = 10000,
        cache_ttl_seconds: int = 3600,
        cache_negative_ttl_seconds: int = 300,
        fallback_enabled: bool = True,
        fallback_provider: str = "ip-api",
        fallback_api_key: str = "",
        fallback_timeout: float = 2.0,
        city_provider: Optional[Any] = None,
        asn_provider: Optional[Any] = None,
        fallback_provider_obj: Optional[Any] = None,
    ):
        self.city_path = city_path
        self.asn_path = asn_path
        self.fallback_enabled = fallback_enabled

        self.city_provider = city_provider or MaxMindCityProvider(city_path)
        self.asn_provider = asn_provider or MaxMindASNProvider(asn_path)

        if fallback_provider_obj:
            self.online_provider = fallback_provider_obj
        elif fallback_enabled and fallback_provider.lower() != "none":
            self.online_provider = OnlineFallbackProvider(
                provider_type=fallback_provider,
                api_key=fallback_api_key,
                timeout=fallback_timeout,
            )
        else:
            self.online_provider = None

        self.cache = ThreadSafeGeoCache(
            max_size=cache_max_size,
            ttl_seconds=cache_ttl_seconds,
            negative_ttl_seconds=cache_negative_ttl_seconds,
        )

        city_avail = getattr(self.city_provider, "is_available", False)
        asn_avail = getattr(self.asn_provider, "is_available", False)
        fallback_avail = self.online_provider is not None and getattr(self.online_provider, "is_available", False)

        logger.info(
            f"[GEOLOCATION REGISTRATION] GeolocationService initialized -> "
            f"Primary: MaxMind GeoLite2 (City={city_avail}, ASN={asn_avail}), "
            f"Fallback: {type(self.online_provider).__name__ if self.online_provider else 'None'} (Enabled={self.fallback_enabled})"
        )

    def lookup(self, ip: str) -> GeoResult:
        """
        Main lookup entrypoint. MaxMind is ALWAYS queried first.
        """
        if not ip or not isinstance(ip, str):
            return GeoResult(
                ip=str(ip or ""),
                ip_version=4,
                address_type="unknown",
                country="Unavailable",
                country_code="Unavailable",
                region="Unavailable",
                city="Unavailable",
                latitude=None,
                longitude=None,
                timezone="Unavailable",
                asn=None,
                organization="Unavailable",
                network="Unavailable",
                source="none",
                status="unavailable",
                provider_used="None",
            )

        clean_ip = ip.strip("[]() ")
        address_type, version = classify_ip(clean_ip)

        # Non-public IPs skip database and online lookups entirely
        if address_type != "public":
            return GeoResult(
                ip=clean_ip,
                ip_version=version,
                address_type=address_type,
                country="Unavailable",
                country_code="Unavailable",
                region="Unavailable",
                city="Unavailable",
                latitude=None,
                longitude=None,
                timezone="Unavailable",
                asn=None,
                organization="Unavailable",
                network="Unavailable",
                source="none",
                status="unavailable",
                provider_used="None (Non-Public IP)",
            )

        # Check Cache
        cached_result = self.cache.get(clean_ip)
        if cached_result is not None:
            return cached_result

        # Execute Provider Lookups safely
        try:
            result = self._resolve_public_ip(clean_ip, version, address_type)
        except Exception as e:
            logger.error(f"[GEOLOCATION EXCEPTION BOUNDARY] Unexpected error in _resolve_public_ip for {clean_ip}: {e}")
            result = GeoResult(
                ip=clean_ip,
                ip_version=version,
                address_type=address_type,
                country="Unknown",
                country_code="Unknown",
                region="Unknown",
                city="Unknown",
                latitude=None,
                longitude=None,
                timezone="Unknown",
                asn=None,
                organization="Unknown",
                network="Unknown",
                source="none",
                status="unavailable",
                provider_used="None (Internal Exception)",
            )

        self.cache.put(clean_ip, result)
        return result

    def _resolve_public_ip(self, clean_ip: str, version: int, address_type: str) -> GeoResult:
        logger.info(f"[GEOLOCATION PIPELINE] 1. Primary Lookup: MaxMind GeoLite2 for '{clean_ip}'...")

        city_res = None
        asn_res = None

        # 1. Primary Provider: MaxMind GeoLite2 ALWAYS queried first
        if self.city_provider and getattr(self.city_provider, "is_available", False):
            city_res = self.city_provider.lookup(clean_ip)

        if self.asn_provider and getattr(self.asn_provider, "is_available", False):
            asn_res = self.asn_provider.lookup(clean_ip)

        has_city = (city_res is not None and (city_res.get("city") != "Unknown" or city_res.get("country") != "Unknown"))
        has_asn = (asn_res is not None and (asn_res.get("asn") is not None or asn_res.get("organization") != "Unknown"))

        # 2. If MaxMind returned valid data -> Return immediately with source="maxmind", DO NOT call online provider
        if has_city or has_asn:
            country = (city_res or {}).get("country", "Unknown")
            country_code = (city_res or {}).get("country_code", "Unknown")
            region = (city_res or {}).get("region", "Unknown")
            city = (city_res or {}).get("city", "Unknown")
            latitude = (city_res or {}).get("latitude")
            longitude = (city_res or {}).get("longitude")
            timezone = (city_res or {}).get("timezone", "Unknown")

            asn = (asn_res or {}).get("asn")
            organization = (asn_res or {}).get("organization", "Unknown")
            network = (asn_res or {}).get("network", "Unknown")
            db_build_date = (city_res or {}).get("db_build_date") or (asn_res or {}).get("db_build_date")

            if has_city and has_asn:
                status = "ok"
                provider_used = "MaxMind GeoLite2 (City + ASN)"
            elif has_city:
                status = "ok"
                provider_used = "MaxMind GeoLite2 City"
            else:
                status = "ok"
                provider_used = "MaxMind GeoLite2 ASN"

            logger.info(f"[GEOLOCATION SUCCESS] MaxMind returned data for '{clean_ip}'. Source=maxmind, Status={status}, Provider={provider_used}")

            return GeoResult(
                ip=clean_ip,
                ip_version=version,
                address_type=address_type,
                country=country,
                country_code=country_code,
                region=region,
                city=city,
                latitude=latitude,
                longitude=longitude,
                timezone=timezone,
                asn=asn,
                organization=organization,
                network=network,
                source="maxmind",
                status=status,
                provider_used=provider_used,
                db_build_date=db_build_date,
            )

        # 3. Only if MaxMind is missing, unreadable, or returned no match -> Try Online Fallback
        logger.info(f"[GEOLOCATION PIPELINE] 2. MaxMind produced no match/unavailable for '{clean_ip}'. Checking Fallback...")

        if self.fallback_enabled and self.online_provider:
            logger.info(f"[GEOLOCATION FALLBACK] Triggering online fallback ({self.online_provider.provider_type}) for '{clean_ip}'...")
            online_res = self.online_provider.lookup(clean_ip)
            if online_res:
                provider_label = f"Online Fallback ({self.online_provider.provider_type})"
                logger.info(f"[GEOLOCATION SUCCESS] Online Fallback resolved '{clean_ip}'. Source=online, Provider={provider_label}")
                return GeoResult(
                    ip=clean_ip,
                    ip_version=version,
                    address_type=address_type,
                    country=online_res.get("country", "Unknown"),
                    country_code=online_res.get("country_code", "Unknown"),
                    region=online_res.get("region", "Unknown"),
                    city=online_res.get("city", "Unknown"),
                    latitude=online_res.get("latitude"),
                    longitude=online_res.get("longitude"),
                    timezone=online_res.get("timezone", "Unknown"),
                    asn=online_res.get("asn"),
                    organization=online_res.get("organization", "Unknown"),
                    network=online_res.get("network", "Unknown"),
                    source="online",
                    status=online_res.get("status", "ok"),
                    provider_used=provider_label,
                )
            else:
                logger.warning(f"[GEOLOCATION LOOKUP FAILURE] Online fallback query failed for '{clean_ip}'.")

        # 4. If all options failed
        logger.warning(f"[GEOLOCATION LOOKUP FAILURE] Lookup for public IP '{clean_ip}' returned STATUS: UNAVAILABLE.")
        return GeoResult(
            ip=clean_ip,
            ip_version=version,
            address_type=address_type,
            country="Unknown",
            country_code="Unknown",
            region="Unknown",
            city="Unknown",
            latitude=None,
            longitude=None,
            timezone="Unknown",
            asn=None,
            organization="Unknown",
            network="Unknown",
            source="none",
            status="unavailable",
            provider_used="None",
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Health check diagnostic report for Geolocation Subsystem.
        """
        city_avail = getattr(self.city_provider, "is_available", False)
        asn_avail = getattr(self.asn_provider, "is_available", False)

        city_epoch = getattr(self.city_provider, "build_epoch", None)
        asn_epoch = getattr(self.asn_provider, "build_epoch", None)

        city_build_date = datetime.datetime.fromtimestamp(city_epoch, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if city_epoch else None
        asn_build_date = datetime.datetime.fromtimestamp(asn_epoch, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if asn_epoch else None

        system_status = "ok" if (city_avail and asn_avail) else ("degraded" if (city_avail or asn_avail or self.fallback_enabled) else "unavailable")

        return {
            "status": system_status,
            "primary_provider": "MaxMind GeoLite2",
            "maxmind_city": {
                "loaded": city_avail,
                "path": os.path.abspath(self.city_path),
                "build_epoch": city_epoch,
                "build_date": city_build_date,
                "database_type": getattr(self.city_provider, "database_type", "GeoLite2-City"),
            },
            "maxmind_asn": {
                "loaded": asn_avail,
                "path": os.path.abspath(self.asn_path),
                "build_epoch": asn_epoch,
                "build_date": asn_build_date,
                "database_type": getattr(self.asn_provider, "database_type", "GeoLite2-ASN"),
            },
            "online_fallback": {
                "enabled": self.fallback_enabled,
                "provider": getattr(self.online_provider, "provider_type", "none") if self.online_provider else "none",
                "available": getattr(self.online_provider, "is_available", False) if self.online_provider else False,
            },
            "cache": self.cache.stats(),
        }

    def clear_cache(self) -> None:
        """Clear cached geolocation results."""
        self.cache.clear()

    def cache_stats(self) -> Dict[str, Any]:
        """Return cache hits, misses, and current size."""
        return self.cache.stats()

    def close(self) -> None:
        """Close provider database handles."""
        if self.city_provider and hasattr(self.city_provider, "close"):
            self.city_provider.close()
        if self.asn_provider and hasattr(self.asn_provider, "close"):
            self.asn_provider.close()
        if self.online_provider and hasattr(self.online_provider, "close"):
            self.online_provider.close()


# Singleton Service Orchestration Instance
_geo_service_instance: Optional[GeolocationService] = None
_geo_service_lock = threading.Lock()


def get_geolocation_service(config_obj: Optional[Any] = None) -> GeolocationService:
    """
    Global getter for the singleton GeolocationService instance.
    Lazy-loads settings from Flask app.config or system Config if not initialized.
    """
    global _geo_service_instance

    if _geo_service_instance is not None:
        return _geo_service_instance

    with _geo_service_lock:
        if _geo_service_instance is not None:
            return _geo_service_instance

        # Extract config values with safe defaults
        city_path = "./data/GeoLite2-City.mmdb"
        asn_path = "./data/GeoLite2-ASN.mmdb"
        cache_max_size = 10000
        cache_ttl = 3600
        cache_neg_ttl = 300
        fallback_enabled = True
        fallback_provider = "ip-api"
        fallback_api_key = ""
        fallback_timeout = 2.0

        if config_obj is not None:
            if hasattr(config_obj, "get"):
                city_path = config_obj.get("GEOLOCATION_CITY_PATH", city_path)
                asn_path = config_obj.get("GEOLOCATION_ASN_PATH", asn_path)
                cache_max_size = config_obj.get("GEOLOCATION_CACHE_MAX_SIZE", cache_max_size)
                cache_ttl = config_obj.get("GEOLOCATION_CACHE_TTL", cache_ttl)
                cache_neg_ttl = config_obj.get("GEOLOCATION_CACHE_NEGATIVE_TTL", cache_neg_ttl)
                fallback_enabled = config_obj.get("GEOLOCATION_FALLBACK_ENABLED", fallback_enabled)
                fallback_provider = config_obj.get("GEOLOCATION_FALLBACK_PROVIDER", fallback_provider)
                fallback_api_key = config_obj.get("GEOLOCATION_FALLBACK_API_KEY", fallback_api_key)
                fallback_timeout = config_obj.get("GEOLOCATION_FALLBACK_TIMEOUT", fallback_timeout)
            else:
                city_path = getattr(config_obj, "GEOLOCATION_CITY_PATH", city_path)
                asn_path = getattr(config_obj, "GEOLOCATION_ASN_PATH", asn_path)
                cache_max_size = getattr(config_obj, "GEOLOCATION_CACHE_MAX_SIZE", cache_max_size)
                cache_ttl = getattr(config_obj, "GEOLOCATION_CACHE_TTL", cache_ttl)
                cache_neg_ttl = getattr(config_obj, "GEOLOCATION_CACHE_NEGATIVE_TTL", cache_neg_ttl)
                fallback_enabled = getattr(config_obj, "GEOLOCATION_FALLBACK_ENABLED", fallback_enabled)
                fallback_provider = getattr(config_obj, "GEOLOCATION_FALLBACK_PROVIDER", fallback_provider)
                fallback_api_key = getattr(config_obj, "GEOLOCATION_FALLBACK_API_KEY", fallback_api_key)
                fallback_timeout = getattr(config_obj, "GEOLOCATION_FALLBACK_TIMEOUT", fallback_timeout)

        _geo_service_instance = GeolocationService(
            city_path=city_path,
            asn_path=asn_path,
            cache_max_size=cache_max_size,
            cache_ttl_seconds=cache_ttl,
            cache_negative_ttl_seconds=cache_neg_ttl,
            fallback_enabled=fallback_enabled,
            fallback_provider=fallback_provider,
            fallback_api_key=fallback_api_key,
            fallback_timeout=fallback_timeout,
        )

        return _geo_service_instance


def reset_geolocation_service() -> None:
    """Reset the singleton instance (used in unit tests)."""
    global _geo_service_instance
    with _geo_service_lock:
        if _geo_service_instance:
            _geo_service_instance.close()
        _geo_service_instance = None
