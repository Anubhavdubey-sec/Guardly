import base64
import json
import logging
import os
import urllib.parse
import urllib.request
from typing import Any, Dict

from services.threat_intelligence.base_provider import BaseThreatProvider

logger = logging.getLogger("guardly.threat_intel.virustotal")


class VirusTotalProvider(BaseThreatProvider):
    """
    VirusTotal Threat Intelligence Provider.
    Queries the VirusTotal API v3 for IP addresses, domains, URLs, and file hashes.
    """

    VT_BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = None, timeout: int = 5):
        key = api_key or os.environ.get("VIRUSTOTAL_API_KEY", "")
        super().__init__(api_key=key, timeout=timeout)

    @property
    def name(self) -> str:
        return "VirusTotal"

    def analyze(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        result = self._default_result(ioc_value, ioc_type)
        if not self.api_key:
            result["status"] = "unavailable"
            result["verdict"] = "Provider unavailable"
            result["message"] = "VirusTotal API key not configured."
            return result

        val = ioc_value.strip()

        try:
            if ioc_type == "ip":
                endpoint = f"{self.VT_BASE_URL}/ip_addresses/{urllib.parse.quote(val)}"
            elif ioc_type == "domain":
                endpoint = f"{self.VT_BASE_URL}/domains/{urllib.parse.quote(val)}"
            elif ioc_type == "hash":
                endpoint = f"{self.VT_BASE_URL}/files/{urllib.parse.quote(val)}"
            elif ioc_type == "url":
                # VT v3 URL identifier is base64 of the URL without '=' padding
                url_id = base64.urlsafe_b64encode(val.encode("utf-8")).decode("ascii").rstrip("=")
                endpoint = f"{self.VT_BASE_URL}/urls/{url_id}"
            else:
                return result

            data = self._get_request(endpoint)
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            result["malicious"] = malicious
            result["suspicious"] = suspicious
            result["harmless"] = harmless
            result["unknown"] = undetected

            total_engines = malicious + suspicious + harmless + undetected
            if total_engines > 0:
                result["confidence"] = 0.95
                if malicious >= 3:
                    result["verdict"] = "Malicious"
                    result["score"] = min(100, int((malicious / total_engines) * 100) + 50)
                elif malicious > 0 or suspicious >= 2:
                    result["verdict"] = "Suspicious"
                    result["score"] = 50
                else:
                    result["verdict"] = "Clean"
                    result["score"] = 0

                result["message"] = f"VirusTotal detections: {malicious}/{total_engines} engines flagged as malicious"
                categories = attrs.get("categories", {})
                if isinstance(categories, dict):
                    result["categories"] = list(set(categories.values()))[:5]

            return result
        except Exception as exc:
            logger.debug(f"VirusTotal query failed for {val}: {exc}")
            result["message"] = f"VirusTotal query error: {exc}"
            return result

    def _get_request(self, endpoint: str) -> Dict[str, Any]:
        req = urllib.request.Request(
            endpoint,
            headers={
                "x-apikey": self.api_key,
                "Accept": "application/json",
                "User-Agent": "Guardly-Threat-Intelligence/2.4",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return {}
        return {}
