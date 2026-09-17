"""
Guardly 1-Click Free Mirror Downloader (No MaxMind Account Required)
Downloads open-source GeoLite2-City.mmdb and GeoLite2-ASN.mmdb directly into ./data/
"""

import os
import sys
import urllib.request

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")

CITY_MIRROR_URL = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb"
ASN_MIRROR_URL = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-ASN.mmdb"


def download_file(url: str, dest_filename: str):
    os.makedirs(DATA_DIR, exist_ok=True)
    dest_path = os.path.join(DATA_DIR, dest_filename)
    print(f"[*] Downloading {dest_filename} from public mirror...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        with urllib.request.urlopen(req) as resp, open(dest_path, "wb") as out_file:
            out_file.write(resp.read())
        size_mb = round(os.path.getsize(dest_path) / (1024 * 1024), 2)
        print(f"[+] Successfully installed {dest_filename} ({size_mb} MB) at {dest_path}")
    except Exception as e:
        print(f"[-] Error downloading {dest_filename}: {e}")


def main():
    print("=" * 60)
    print("      GUARDLY 1-CLICK FREE GEOLOCATION DATABASE DOWNLOADER      ")
    print("           (No MaxMind Registration / Account Needed)          ")
    print("=" * 60 + "\n")

    download_file(CITY_MIRROR_URL, "GeoLite2-City.mmdb")
    download_file(ASN_MIRROR_URL, "GeoLite2-ASN.mmdb")

    print("\n[SUCCESS] Local MaxMind database files installed in ./data/")


if __name__ == "__main__":
    main()
