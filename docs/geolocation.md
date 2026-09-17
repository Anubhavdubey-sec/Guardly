# 🌍 Guardly IP Geolocation Subsystem (MaxMind GeoLite2 Primary)

Guardly operates as an enterprise email threat analysis platform that performs **all IP geolocation locally by default**, using **MaxMind GeoLite2** as the authoritative primary provider.

---

## 🏛️ Authoritative Primary Provider Rules

1. **MaxMind is ALWAYS the First Provider**:
   - `GeoLite2-City.mmdb`: Authoritative source for Country, Country Code, Region, City, Latitude, Longitude, and Timezone.
   - `GeoLite2-ASN.mmdb`: Authoritative source for Autonomous System Number (ASN), Organization name, and Network CIDR block.

2. **Source & Status Attribution**:
   - When MaxMind returns valid data for an IP, Guardly sets `status="ok"` and `source="maxmind"`.
   - **Online HTTP Fallback is NEVER invoked when MaxMind returns data.**

3. **Fallback Conditions**:
   - Online fallback (`OnlineFallbackProvider`) triggers **ONLY IF** local `.mmdb` files are missing, unreadable, or return no match **AND** `GEOLOCATION_FALLBACK_ENABLED=True`.

---

## 🏥 Subsystem Health Check API & Diagnostics

Guardly exposes a live diagnostic health check endpoint for monitoring subsystem state, database build dates, and cache metrics:

- **API Endpoint**: `GET /api/v1/geolocation/health` or `GET /admin/geolocation/health`

### Sample Health Check Response:

```json
{
  "status": "ok",
  "primary_provider": "MaxMind GeoLite2",
  "maxmind_city": {
    "loaded": true,
    "path": "C:\\Users\\anubh\\Desktop\\Phishing-Email-Detector\\data\\GeoLite2-City.mmdb",
    "build_epoch": 1722500000,
    "build_date": "2026-08-01 12:00:00 UTC",
    "database_type": "GeoLite2-City"
  },
  "maxmind_asn": {
    "loaded": true,
    "path": "C:\\Users\\anubh\\Desktop\\Phishing-Email-Detector\\data\\GeoLite2-ASN.mmdb",
    "build_epoch": 1722500000,
    "build_date": "2026-08-01 12:00:00 UTC",
    "database_type": "GeoLite2-ASN"
  },
  "online_fallback": {
    "enabled": true,
    "provider": "ip-api",
    "available": true
  },
  "cache": {
    "size": 128,
    "max_size": 10000,
    "hits": 450,
    "misses": 128,
    "ttl_seconds": 3600,
    "negative_ttl_seconds": 300
  }
}
```

---

## 📥 MaxMind GeoLite2 Setup & Download Instructions

1. **Register Free Account**: Sign up at [MaxMind GeoLite2 Free Data](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
2. **Generate License Key**: In Account Settings, create a License Key under **My License Key**.
3. **Download Files**: Download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`.
4. **Directory Placement**: Place both `.mmdb` files in `./data/`:

```
Phishing-Email-Detector/
├── data/
│   ├── GeoLite2-City.mmdb
│   └── GeoLite2-ASN.mmdb
├── services/
│   └── geolocation.py
└── config.py
```

---

## 🔄 Automated Updates via `geoipupdate`

Keep MaxMind databases updated automatically twice weekly:

1. Install `geoipupdate`.
2. Configure `GeoIP.conf`:
```ini
AccountID YOUR_ACCOUNT_ID
LicenseKey YOUR_LICENSE_KEY
EditionIDs GeoLite2-City GeoLite2-ASN
DatabaseDirectory ./data
```
3. Schedule `geoipupdate` in cron/timer:
```bash
0 2 * * 3 /usr/bin/geoipupdate
```

---

## 🎨 User Interface Indications

When inspecting IPs in the Threat Intelligence portal or delivery timeline:
- **Authoritative MaxMind Data**: Displays `AUTHORITATIVE: MAXMIND GEOLITE2` badge (`src: maxmind`) with database build date.
- **Online Fallback Data**: Displays `FALLBACK: ONLINE HTTP PROVIDER` badge (`src: online`) along with a warning banner indicating local `.mmdb` files are missing in `./data/`.
