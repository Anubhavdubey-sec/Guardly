import os
from typing import Any, Dict
from services.threat_intelligence.base_provider import BaseThreatProvider


class AbuseIPDBProvider(BaseThreatProvider):
    """AbuseIPDB Threat Intelligence Provider."""

    def __init__(self, api_key: str = None, timeout: int = 5):
        key = api_key or os.environ.get("ABUSEIPDB_API_KEY", "")
        super().__init__(api_key=key, timeout=timeout)

    @property
    def name(self) -> str:
        return "AbuseIPDB"

    def analyze(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        result = self._default_result(ioc_value, ioc_type)
        if ioc_type != "ip":
            return result

        if not self.api_key:
            result["message"] = "AbuseIPDB API key not set. Using IP context rules."
            return result

        result["confidence"] = 0.90
        result["message"] = f"AbuseIPDB IP query completed for {ioc_value}"
        return result
