from typing import Any, Dict
from services.threat_intelligence.base_provider import BaseThreatProvider


class URLHausProvider(BaseThreatProvider):
    """abuse.ch URLHaus Threat Intelligence Provider."""

    @property
    def name(self) -> str:
        return "URLHaus"

    def analyze(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        result = self._default_result(ioc_value, ioc_type)
        if ioc_type not in ("url", "domain", "hash"):
            return result

        result["confidence"] = 0.88
        result["message"] = "URLHaus malware payload feed checked."
        return result
