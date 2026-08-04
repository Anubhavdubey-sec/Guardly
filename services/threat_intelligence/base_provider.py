from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseThreatProvider(ABC):
    """Abstract base class for all threat intelligence providers."""

    def __init__(self, api_key: str = None, timeout: int = 5):
        self.api_key = api_key
        self.timeout = timeout

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the threat provider."""
        pass

    @abstractmethod
    def analyze(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        """Analyze an IOC and return standardized reputation data dictionary.
        
        Returns:
            dict with keys: provider, verdict, score, confidence, malicious, suspicious, harmless, unknown, categories
        """
        pass

    def _default_result(self, ioc_value: str, ioc_type: str, status: str = "Unknown", message: str = "") -> Dict[str, Any]:
        return {
            "provider": self.name,
            "ioc_value": ioc_value,
            "ioc_type": ioc_type,
            "verdict": status,
            "score": 0,
            "confidence": 0.5,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "unknown": 1,
            "categories": [],
            "message": message,
            "raw_data": {},
        }
