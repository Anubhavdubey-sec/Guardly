import json
import logging
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, List

from services.threat_intelligence.base_provider import BaseThreatProvider

logger = logging.getLogger("guardly.threat_intel.alienvault_otx")


class AlienVaultOTXProvider(BaseThreatProvider):
    """
    AlienVault OTX (Open Threat Exchange) Threat Intelligence Provider.
    Queries the OTX DirectConnect API for IP, domain, URL, and file hash indicators.
    Requires a free OTX API key from https://otx.alienvault.com
    """

    OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(self, api_key: str = None, timeout: int = 5):
        key = api_key or os.environ.get("OTX_API_KEY", "")
        super().__init__(api_key=key, timeout=timeout)

    @property
    def name(self) -> str:
        return "AlienVault OTX"

    def analyze(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        result = self._default_result(ioc_value, ioc_type)

        if not self.api_key:
            result["status"] = "unavailable"
            result["verdict"] = "Provider unavailable"
            result["message"] = "OTX API key not configured. Get one free at otx.alienvault.com"
            return result

        val = ioc_value.strip()

        try:
            if ioc_type == "ip":
                sections = ["general", "reputation", "geo", "malware"]
                endpoint = f"{self.OTX_BASE}/IPv4/{urllib.parse.quote(val)}/general"
                rep_endpoint = f"{self.OTX_BASE}/IPv4/{urllib.parse.quote(val)}/reputation"
            elif ioc_type == "domain":
                endpoint = f"{self.OTX_BASE}/domain/{urllib.parse.quote(val)}/general"
                rep_endpoint = None
            elif ioc_type == "url":
                url_encoded = urllib.parse.quote(val, safe="")
                endpoint = f"{self.OTX_BASE}/url/{url_encoded}/general"
                rep_endpoint = None
            elif ioc_type == "hash":
                endpoint = f"{self.OTX_BASE}/file/{urllib.parse.quote(val)}/general"
                rep_endpoint = None
            else:
                result["verdict"] = "Not Applicable"
                result["message"] = f"OTX does not support IOC type: {ioc_type}"
                return result

            # General lookup
            data = self._get_request(endpoint)
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            pulses: List[Dict] = data.get("pulse_info", {}).get("pulses", [])

            # Reputation for IPs
            reputation_score = 0
            if rep_endpoint:
                rep_data = self._get_request(rep_endpoint)
                reputation_score = rep_data.get("reputation", 0) or 0

            # Build category tags from pulse names
            tags: List[str] = []
            for pulse in pulses[:5]:
                tags.extend(pulse.get("tags", []))
                name = pulse.get("name", "")
                if name:
                    tags.append(name)
            tags = list(set(t.lower() for t in tags if t))[:8]

            result["confidence"] = 0.85
            result["raw_data"] = {
                "pulse_count": pulse_count,
                "reputation_score": reputation_score,
                "pulse_names": [p.get("name", "") for p in pulses[:5]],
            }

            if pulse_count >= 3 or reputation_score >= 2:
                result["verdict"] = "Malicious"
                result["malicious"] = 1
                result["score"] = min(100, 50 + pulse_count * 5 + reputation_score * 10)
                result["categories"] = tags
                result["message"] = (
                    f"OTX: Found in {pulse_count} threat intelligence pulse(s)"
                    + (f", reputation score: {reputation_score}" if reputation_score else "")
                )
            elif pulse_count >= 1 or reputation_score >= 1:
                result["verdict"] = "Suspicious"
                result["suspicious"] = 1
                result["score"] = 40
                result["categories"] = tags
                result["message"] = f"OTX: Found in {pulse_count} pulse(s) — low-confidence indicator"
            else:
                result["verdict"] = "Clean"
                result["harmless"] = 1
                result["score"] = 0
                result["message"] = "OTX: No threat pulses found for this indicator"

            return result

        except Exception as exc:
            logger.debug(f"AlienVault OTX query failed for {val}: {exc}")
            result["message"] = f"OTX query failed: {exc}"
            return result

    def _get_request(self, endpoint: str) -> Dict[str, Any]:
        req = urllib.request.Request(
            endpoint,
            headers={
                "X-OTX-API-KEY": self.api_key,
                "Accept": "application/json",
                "User-Agent": "Guardly-Threat-Intelligence/2.4",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
        except Exception:
            pass
        return {}
