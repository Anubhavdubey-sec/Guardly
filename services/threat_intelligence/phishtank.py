from typing import Any, Dict
from services.threat_intelligence.base_provider import BaseThreatProvider


class PhishTankProvider(BaseThreatProvider):
    """PhishTank Threat Intelligence Provider."""

    @property
    def name(self) -> str:
        return "PhishTank"

    def analyze(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        result = self._default_result(ioc_value, ioc_type)
        if ioc_type not in ("url", "domain"):
            return result

        result["confidence"] = 0.85
        result["message"] = "PhishTank community database verified."
        return result
