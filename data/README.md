# 📂 Guardly MaxMind GeoLite2 Data Directory

Place your MaxMind GeoLite2 binary database files (`.mmdb`) in this directory for **100% local, offline IP geolocation lookups**:

- `GeoLite2-City.mmdb` (Primary source for Country, City, Region, Coordinates, Timezone)
- `GeoLite2-ASN.mmdb` (Primary source for Autonomous System Number, Organization, Network CIDR)

---

## 📥 Quick Download Instructions

1. **Sign Up**: Register for a free MaxMind account at [MaxMind GeoLite2 Signup](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
2. **Generate License Key**: Create a License Key in your MaxMind Account settings.
3. **Download Database Files**: Download the binary database archives (`.tar.gz`) for GeoLite2 City and GeoLite2 ASN.
4. **Copy `.mmdb` Files Here**:
   - Extract `GeoLite2-City.mmdb` to `Phishing-Email-Detector/data/GeoLite2-City.mmdb`
   - Extract `GeoLite2-ASN.mmdb` to `Phishing-Email-Detector/data/GeoLite2-ASN.mmdb`

Once placed here, Guardly will automatically detect the databases, display the `AUTHORITATIVE: MAXMIND GEOLITE2` badge in the UI, and operate 100% offline with zero external network requests!
