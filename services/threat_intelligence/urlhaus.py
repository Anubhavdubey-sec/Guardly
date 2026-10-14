import json
import logging
import urllib.parse
import urllib.request
from typing import Any, Dict

from services.threat_intelligence.base_provider import BaseThreatProvider

logger = logging.getLogger("guardly.threat_intel.urlhaus")


class URLHausProvider(BaseThreatProvider):
    """
    abuse.ch URLhaus Threat Intelligence Provider.
    Queries the official abuse.ch free API to check if URLs, domains/hosts, or hashes
    are actively hosting malware or associated with known phishing campaigns.
    """

    API_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
    API_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"
    API_PAYLOAD_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/payload/"

    @property
    def name(self) -> str:
        return "URLHaus"

    def analyze(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        result = self._default_result(ioc_value, ioc_type)
        if ioc_type not in ("url", "domain", "ip", "hash"):
            return result

        val = ioc_value.strip()

        try:
            if ioc_type == "url":
                data = self._post_query(self.API_URL_ENDPOINT, {"url": val})
                query_status = data.get("query_status", "")
                if query_status == "ok":
                    url_status = data.get("url_status", "unknown")
                    threat = data.get("threat", "malware_download")
                    tags = data.get("tags") or []
                    result["verdict"] = "Malicious"
                    result["malicious"] = 1
                    result["score"] = 95
                    result["confidence"] = 0.98
                    result["categories"] = [threat] + tags
                    result["message"] = f"Listed in URLhaus malware database (Status: {url_status}, Threat: {threat})"
                elif query_status == "no_results":
                    result["verdict"] = "Clean"
                    result["harmless"] = 1
                    result["score"] = 0
                    result["confidence"] = 0.85
                    result["message"] = "No malware records found in URLhaus feed"

            elif ioc_type in ("domain", "ip"):
                data = self._post_query(self.API_HOST_ENDPOINT, {"host": val})
                query_status = data.get("query_status", "")
                if query_status == "ok":
                    url_count = data.get("url_count", 0)
                    result["verdict"] = "Malicious" if url_count > 0 else "Clean"
                    if url_count > 0:
                        result["malicious"] = 1
                        result["score"] = 90
                        result["confidence"] = 0.95
                        result["message"] = f"Host associated with {url_count} active malware distribution URLs in URLhaus"
                    else:
                        result["harmless"] = 1
                        result["score"] = 0
                        result["message"] = "Host clean in URLhaus"
                elif query_status == "no_results":
                    result["verdict"] = "Clean"
                    result["harmless"] = 1
                    result["score"] = 0
                    result["confidence"] = 0.80
                    result["message"] = "Host not listed in URLhaus"

            elif ioc_type == "hash":
                data = self._post_query(self.API_PAYLOAD_ENDPOINT, {"sha256_hash": val})
                query_status = data.get("query_status", "")
                if query_status == "ok":
                    signature = data.get("signature", "malware")
                    result["verdict"] = "Malicious"
                    result["malicious"] = 1
                    result["score"] = 100
                    result["confidence"] = 0.99
                    result["categories"] = [signature]
                    result["message"] = f"Malware payload identified by URLhaus: {signature}"
                elif query_status == "no_results":
                    result["verdict"] = "Clean"
                    result["harmless"] = 1
                    result["score"] = 0
                    result["confidence"] = 0.80
                    result["message"] = "Payload hash clean in URLhaus"

            return result
        except Exception as exc:
            logger.debug(f"URLhaus query error for {val}: {exc}")
            result["verdict"] = "Unknown"
            result["message"] = f"URLhaus API query failed: {exc}"
            return result

    def _post_query(self, endpoint: str, post_data: Dict[str, str]) -> Dict[str, Any]:
        encoded = urllib.parse.urlencode(post_data).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=encoded,
            headers={
                "User-Agent": "Guardly-Threat-Intelligence/2.4",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return {}
        return {}
