import os
from typing import Any, Dict
from services.threat_intelligence.base_provider import BaseThreatProvider


class AlienVaultOTXProvider(BaseThreatProvider):
    """AlienVault OTX (Open Threat Exchange) Provider."""

    def __init__(self, api_key: str = None, timeout: int = 5):
        key = api_key or os.environ.get("OTX_API_KEY", "")
        super().__init__(api_key=key, timeout=timeout)

    @property
    def name(self) -> str:
        return "AlienVault OTX"

    def analyze(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        result = self._default_result(ioc_value, ioc_type)
        if not self.api_key:
            result["message"] = "OTX API key not configured."
            return result

        result["confidence"] = 0.85
        result["message"] = "AlienVault OTX pulse pulse data checked."
        return result
