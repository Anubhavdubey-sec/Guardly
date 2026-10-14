import json
import logging
import os
import urllib.parse
import urllib.request
from typing import Any, Dict

from services.threat_intelligence.base_provider import BaseThreatProvider

logger = logging.getLogger("guardly.threat_intel.abuseipdb")


class AbuseIPDBProvider(BaseThreatProvider):
    """
    AbuseIPDB Threat Intelligence Provider.
    Queries the AbuseIPDB API v2 to check IP reputation, abuse confidence score,
    and associated threat categories.
    """

    CHECK_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str = None, timeout: int = 5):
        key = api_key or os.environ.get("ABUSEIPDB_API_KEY", "")
        super().__init__(api_key=key, timeout=timeout)

    @property
    def name(self) -> str:
        return "AbuseIPDB"

    def analyze(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        result = self._default_result(ioc_value, ioc_type)
        if ioc_type != "ip":
            result["verdict"] = "Not Applicable"
            return result

        if not self.api_key:
            result["status"] = "unavailable"
            result["verdict"] = "Provider unavailable"
            result["message"] = "AbuseIPDB API key not configured."
            return result

        ip = ioc_value.strip()

        try:
            params = urllib.parse.urlencode({
                "ipAddress": ip,
                "maxAgeInDays": "90",
                "verbose": "true",
            })
            url = f"{self.CHECK_ENDPOINT}?{params}"
            req = urllib.request.Request(
                url,
                headers={
                    "Key": self.api_key,
                    "Accept": "application/json",
                    "User-Agent": "Guardly-Threat-Intelligence/2.4",
                },
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    payload = json.loads(resp.read().decode("utf-8"))
                    data = payload.get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    reports = data.get("totalReports", 0)
                    usage_type = data.get("usageType", "Unknown")
                    isp = data.get("isp", "Unknown")
                    country = data.get("countryCode", "")

                    result["score"] = score
                    result["confidence"] = 0.95
                    result["raw_data"] = {
                        "usage_type": usage_type,
                        "isp": isp,
                        "country": country,
                        "total_reports": reports,
                    }

                    if score >= 50:
                        result["verdict"] = "Malicious"
                        result["malicious"] = 1
                    elif score >= 20:
                        result["verdict"] = "Suspicious"
                        result["suspicious"] = 1
                    else:
                        result["verdict"] = "Clean"
                        result["harmless"] = 1

                    result["message"] = f"Abuse confidence: {score}% ({reports} reports, ISP: {isp})"

            return result
        except Exception as exc:
            logger.debug(f"AbuseIPDB query error for {ip}: {exc}")
            result["message"] = f"AbuseIPDB query failed: {exc}"
            return result
