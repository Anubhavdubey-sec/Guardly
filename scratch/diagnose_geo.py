import os
import sys
import logging

sys.path.insert(0, os.getcwd())

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

from config import Config
from services.geolocation import (
    GeolocationService,
    MaxMindCityProvider,
    MaxMindASNProvider,
    classify_ip,
    get_geolocation_service,
    reset_geolocation_service,
)
from services.public_lookup import get_ip_location

print("=" * 80)
print("             GUARDLY IP GEOLOCATION SUBSYSTEM COMPLETE DIAGNOSTIC             ")
print("=" * 80)

# Task 1 & 3: Configured and resolved database paths from config.py / .env
city_path = Config.GEOLOCATION_CITY_PATH
asn_path = Config.GEOLOCATION_ASN_PATH
abs_city_path = os.path.abspath(city_path)
abs_asn_path = os.path.abspath(asn_path)

print(f"\n1. CONFIGURATION & RESOLVED PATHS:")
print(f"   - Configured City Path: '{city_path}'")
print(f"   - Resolved Absolute City Path: '{abs_city_path}'")
print(f"   - Configured ASN Path: '{asn_path}'")
print(f"   - Resolved Absolute ASN Path: '{abs_asn_path}'")
print(f"   - GEOLOCATION_FALLBACK_ENABLED: {Config.GEOLOCATION_FALLBACK_ENABLED}")
print(f"   - GEOLOCATION_FALLBACK_PROVIDER: {Config.GEOLOCATION_FALLBACK_PROVIDER}")

# Task 4: Missing or unreadable database files detection
print(f"\n2. DATABASE FILE INTEGRITY CHECK:")
city_exists = os.path.exists(abs_city_path)
city_readable = os.access(abs_city_path, os.R_OK) if city_exists else False
print(f"   - GeoLite2-City.mmdb Exists: {city_exists} | Readable: {city_readable}")

asn_exists = os.path.exists(abs_asn_path)
asn_readable = os.access(abs_asn_path, os.R_OK) if asn_exists else False
print(f"   - GeoLite2-ASN.mmdb Exists: {asn_exists} | Readable: {asn_readable}")

# Task 2, 5 & 6: Provider initialization, registration, and failure logging
print(f"\n3. PROVIDER INITIALIZATION & REGISTRATION TEST:")
reset_geolocation_service()
geo_svc = get_geolocation_service(Config)

print(f"   - City Provider Class: {type(geo_svc.city_provider).__name__}")
print(f"   - City Provider Available: {getattr(geo_svc.city_provider, 'is_available', False)}")
print(f"   - ASN Provider Class: {type(geo_svc.asn_provider).__name__}")
print(f"   - ASN Provider Available: {getattr(geo_svc.asn_provider, 'is_available', False)}")
print(f"   - Online Fallback Provider Class: {type(geo_svc.online_provider).__name__ if geo_svc.online_provider else 'None'}")
print(f"   - Online Fallback Available: {getattr(geo_svc.online_provider, 'is_available', False) if geo_svc.online_provider else False}")

# Task 7, 8, 9, 10, 11: Public IP lookup pipeline test, exact failure logging, provider used, UI field verification
test_ips = ["8.8.8.8", "1.1.1.1", "142.250.190.78"]
print(f"\n4. PUBLIC IP LOOKUP PIPELINE TEST:")

for ip in test_ips:
    print(f"\n>>> TESTING TARGET PUBLIC IP: {ip}")
    cls, ver = classify_ip(ip)
    print(f"    - Classification: {cls} (IPv{ver})")
    
    # Direct service lookup
    geo_res = geo_svc.lookup(ip)
    print(f"    - Provider Used: {geo_res.provider_used}")
    print(f"    - Source: {geo_res.source}")
    print(f"    - Status: {geo_res.status}")
    print(f"    - Country / Code: {geo_res.country} ({geo_res.country_code})")
    print(f"    - City / Region: {geo_res.city}, {geo_res.region}")
    print(f"    - ASN: {geo_res.asn}")
    print(f"    - Organization: {geo_res.organization}")
    print(f"    - Network (CIDR): {geo_res.network}")
    print(f"    - Timezone: {geo_res.timezone}")
    print(f"    - Coordinates (Lat/Lon): ({geo_res.latitude}, {geo_res.longitude})")

    # UI Context dictionary verification via get_ip_location
    ui_dict = get_ip_location(ip)
    safe_display = ui_dict.get('location_display', '').encode('ascii', 'replace').decode('ascii')
    print(f"    - UI Display String: '{safe_display}'")
    print(f"    - UI Dictionary Complete: {all(k in ui_dict for k in ['ip', 'country', 'city', 'asn', 'organization', 'timezone', 'latitude', 'longitude', 'status', 'provider_used'])}")

print("\n" + "=" * 80)
print("                         DIAGNOSTIC TEST COMPLETE                             ")
print("=" * 80)
