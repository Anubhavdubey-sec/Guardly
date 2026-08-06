"""
Guardly MaxMind GeoLite2 Automated Downloader Script
Usage:
    python scripts/download_geolite2.py YOUR_MAXMIND_LICENSE_KEY
"""

import os
import sys
import tarfile
import urllib.request

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")


def download_and_extract(edition_id: str, license_key: str):
    os.makedirs(DATA_DIR, exist_ok=True)
    url = f"https://download.maxmind.com/app/geoip_download?edition_id={edition_id}&license_key={license_key}&suffix=tar.gz"
    tar_path = os.path.join(DATA_DIR, f"{edition_id}.tar.gz")

    print(f"[*] Downloading {edition_id} database from MaxMind...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Guardly-GeoIP-Downloader/1.0"})
        with urllib.request.urlopen(req) as resp, open(tar_path, "wb") as out_file:
            out_file.write(resp.read())
        print(f"[+] Successfully downloaded {edition_id}.tar.gz ({os.path.getsize(tar_path)} bytes)")

        print(f"[*] Extracting {edition_id}.mmdb into ./data/...")
        with tarfile.open(tar_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith(".mmdb"):
                    member.name = os.path.basename(member.name)
                    tar.extract(member, path=DATA_DIR)
                    print(f"[+] Extracted {member.name} to {os.path.join(DATA_DIR, member.name)}")

        if os.path.exists(tar_path):
            os.remove(tar_path)

    except Exception as e:
        print(f"[-] Error downloading {edition_id}: {e}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/download_geolite2.py YOUR_MAXMIND_LICENSE_KEY")
        print("\nGet a free license key at: https://www.maxmind.com/en/geolite2/signup")
        sys.exit(1)

    license_key = sys.argv[1].strip()
    download_and_extract("GeoLite2-City", license_key)
    download_and_extract("GeoLite2-ASN", license_key)
    print("\n[SUCCESS] MaxMind GeoLite2 databases installed in ./data/")


if __name__ == "__main__":
    main()
