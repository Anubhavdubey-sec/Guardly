"""
Unit Tests for Guardly Enterprise Geolocation Subsystem
Tests IP classification, MaxMind GeoLite2 City + ASN Primary Provider rules,
Online Fallback priority, Health Check API, ThreadSafeGeoCache, and Exception Boundaries.
No real network calls or real MaxMind files are required.
"""

import time
import unittest
from unittest.mock import MagicMock, patch

from services.geolocation import (
    CacheEntry,
    GeoResult,
    GeolocationService,
    MaxMindASNProvider,
    MaxMindCityProvider,
    OnlineFallbackProvider,
    ThreadSafeGeoCache,
    classify_ip,
    reset_geolocation_service,
)


class TestIPClassification(unittest.TestCase):
    def test_classify_ip_v4(self):
        self.assertEqual(classify_ip("8.8.8.8"), ("public", 4))
        self.assertEqual(classify_ip("1.1.1.1"), ("public", 4))
        self.assertEqual(classify_ip("127.0.0.1"), ("loopback", 4))
        self.assertEqual(classify_ip("192.168.1.100"), ("private", 4))
        self.assertEqual(classify_ip("10.0.0.1"), ("private", 4))
        self.assertEqual(classify_ip("172.16.0.1"), ("private", 4))
        self.assertEqual(classify_ip("169.254.1.1"), ("link-local", 4))
        self.assertEqual(classify_ip("224.0.0.1"), ("multicast", 4))
        self.assertEqual(classify_ip("240.0.0.1"), ("reserved", 4))

    def test_classify_ip_v6(self):
        self.assertEqual(classify_ip("2001:4860:4860::8888"), ("public", 6))
        self.assertEqual(classify_ip("::1"), ("loopback", 6))
        self.assertEqual(classify_ip("fd00::1"), ("private", 6))
        self.assertEqual(classify_ip("fe80::1"), ("link-local", 6))
        self.assertEqual(classify_ip("ff02::1"), ("multicast", 6))

    def test_classify_ip_invalid(self):
        self.assertEqual(classify_ip("invalid_ip"), ("unknown", 4))
        self.assertEqual(classify_ip(""), ("unknown", 4))
        self.assertEqual(classify_ip(None), ("unknown", 4))


class TestThreadSafeGeoCache(unittest.TestCase):
    def test_cache_put_get(self):
        cache = ThreadSafeGeoCache(max_size=10, ttl_seconds=10, negative_ttl_seconds=5)
        res = GeoResult(ip="8.8.8.8", ip_version=4, address_type="public", city="Mountain View", status="ok", source="maxmind")
        cache.put("8.8.8.8", res)

        cached = cache.get("8.8.8.8")
        self.assertIsNotNone(cached)
        self.assertEqual(cached.city, "Mountain View")
        self.assertEqual(cached.source, "maxmind")

        stats = cache.stats()
        self.assertEqual(stats["hits"], 1)
        self.assertEqual(stats["size"], 1)

    def test_cache_ttl_expiration(self):
        cache = ThreadSafeGeoCache(max_size=10, ttl_seconds=1, negative_ttl_seconds=1)
        res = GeoResult(ip="8.8.8.8", ip_version=4, address_type="public", status="ok")
        cache.put("8.8.8.8", res)

        time.sleep(1.1)
        cached = cache.get("8.8.8.8")
        self.assertIsNone(cached)
        self.assertEqual(cache.stats()["misses"], 1)


class TestMaxMindPrimaryProvider(unittest.TestCase):
    def setUp(self):
        reset_geolocation_service()

    def test_maxmind_primary_provider_returns_maxmind_source(self):
        mock_city = MagicMock()
        mock_city.is_available = True
        mock_city.lookup.return_value = {
            "city": "Mountain View",
            "country": "United States",
            "country_code": "US",
            "region": "California",
            "latitude": 37.386,
            "longitude": -122.0838,
            "timezone": "America/Los_Angeles",
            "status": "ok",
            "db_build_date": "2026-08-01",
        }

        mock_asn = MagicMock()
        mock_asn.is_available = True
        mock_asn.lookup.return_value = {
            "asn": 15169,
            "organization": "Google LLC",
            "network": "8.8.8.0/24",
            "status": "ok",
            "db_build_date": "2026-08-01",
        }

        mock_online = MagicMock()
        mock_online.is_available = True

        service = GeolocationService(
            city_provider=mock_city,
            asn_provider=mock_asn,
            fallback_enabled=True,
            fallback_provider_obj=mock_online,
        )

        res = service.lookup("8.8.8.8")

        # Assert MaxMind is source
        self.assertEqual(res.source, "maxmind")
        self.assertEqual(res.status, "ok")
        self.assertEqual(res.city, "Mountain View")
        self.assertEqual(res.country, "United States")
        self.assertEqual(res.asn, 15169)
        self.assertEqual(res.organization, "Google LLC")
        self.assertEqual(res.network, "8.8.8.0/24")

        # Assert online fallback was NEVER called because MaxMind returned data
        mock_online.lookup.assert_not_called()

    def test_online_fallback_triggers_only_when_maxmind_unavailable(self):
        mock_city = MagicMock()
        mock_city.is_available = False
        mock_city.lookup.return_value = None

        mock_asn = MagicMock()
        mock_asn.is_available = False
        mock_asn.lookup.return_value = None

        mock_online = MagicMock()
        mock_online.is_available = True
        mock_online.provider_type = "ip-api"
        mock_online.lookup.return_value = {
            "city": "Chicago",
            "country": "United States",
            "country_code": "US",
            "region": "Illinois",
            "latitude": 41.8781,
            "longitude": -87.6298,
            "timezone": "America/Chicago",
            "asn": 15169,
            "organization": "Google LLC",
            "network": "Unknown",
            "status": "ok",
        }

        service = GeolocationService(
            city_provider=mock_city,
            asn_provider=mock_asn,
            fallback_enabled=True,
            fallback_provider_obj=mock_online,
        )

        res = service.lookup("142.250.190.78")

        # Assert online fallback was invoked because MaxMind was unavailable
        self.assertEqual(res.source, "online")
        self.assertEqual(res.status, "ok")
        self.assertEqual(res.city, "Chicago")
        mock_online.lookup.assert_called_once_with("142.250.190.78")

    def test_non_public_ip_short_circuit(self):
        mock_city = MagicMock()
        mock_asn = MagicMock()
        mock_online = MagicMock()

        service = GeolocationService(
            city_provider=mock_city,
            asn_provider=mock_asn,
            fallback_provider_obj=mock_online,
        )

        res = service.lookup("192.168.1.1")
        self.assertEqual(res.address_type, "private")
        self.assertEqual(res.source, "none")
        self.assertEqual(res.status, "unavailable")

        mock_city.lookup.assert_not_called()
        mock_asn.lookup.assert_not_called()
        mock_online.lookup.assert_not_called()

    def test_geolocation_health_check(self):
        mock_city = MagicMock()
        mock_city.is_available = True
        mock_city.db_path = "./data/GeoLite2-City.mmdb"
        mock_city.build_epoch = 1720000000
        mock_city.database_type = "GeoLite2-City"

        mock_asn = MagicMock()
        mock_asn.is_available = True
        mock_asn.db_path = "./data/GeoLite2-ASN.mmdb"
        mock_asn.build_epoch = 1720000000
        mock_asn.database_type = "GeoLite2-ASN"

        service = GeolocationService(
            city_provider=mock_city,
            asn_provider=mock_asn,
            fallback_enabled=True,
        )

        health = service.health_check()
        self.assertEqual(health["status"], "ok")
        self.assertTrue(health["maxmind_city"]["loaded"])
        self.assertTrue(health["maxmind_asn"]["loaded"])
        self.assertEqual(health["maxmind_city"]["build_epoch"], 1720000000)
        self.assertEqual(health["online_fallback"]["enabled"], True)


if __name__ == "__main__":
    unittest.main()
