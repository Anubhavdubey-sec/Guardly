import hashlib
import json
import logging
import os
import urllib.parse
import urllib.request
from typing import Any, Dict

from services.threat_intelligence.base_provider import BaseThreatProvider

logger = logging.getLogger("guardly.threat_intel.phishtank")


class PhishTankProvider(BaseThreatProvider):
    """
    PhishTank Threat Intelligence Provider.
    Uses the PhishTank free community API to check if a URL is a known phishing site.
    No API key required for basic lookups (anonymous app key optional for higher rate limits).
    """

    API_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"

    def __init__(self, app_key: str = None, timeout: int = 5):
        # PhishTank uses an optional app_key for rate-limit extension, not auth
        key = app_key or os.environ.get("PHISHTANK_APP_KEY", "")
        super().__init__(api_key=key, timeout=timeout)

    @property
    def name(self) -> str:
        return "PhishTank"

    def analyze(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        result = self._default_result(ioc_value, ioc_type)

        if ioc_type not in ("url", "domain"):
            result["verdict"] = "Not Applicable"
            result["message"] = "PhishTank only checks URLs and domains."
            return result

        val = ioc_value.strip()

        # For domains, construct a basic http URL for lookup
        query_url = val if ioc_type == "url" else f"http://{val}/"

        try:
            post_data: Dict[str, str] = {
                "url": query_url,
                "format": "json",
            }
            if self.api_key:
                post_data["app_key"] = self.api_key

            encoded = urllib.parse.urlencode(post_data).encode("utf-8")
            req = urllib.request.Request(
                self.API_ENDPOINT,
                data=encoded,
                headers={
                    "User-Agent": "phishtank/Guardly-2.4",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
            )

            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status != 200:
                    result["message"] = f"PhishTank API returned HTTP {resp.status}"
                    return result

                payload = json.loads(resp.read().decode("utf-8"))

            results_block = payload.get("results", {})
            in_database = results_block.get("in_database", False)

            if not in_database:
                result["verdict"] = "Clean"
                result["harmless"] = 1
                result["score"] = 0
                result["confidence"] = 0.80
                result["message"] = "URL not found in PhishTank phishing database"
                return result

            is_phish = results_block.get("valid", False)
            verified = results_block.get("verified", False)
            phish_detail_url = results_block.get("phish_detail_page", "")

            if is_phish:
                result["verdict"] = "Phishing"
                result["malicious"] = 1
                result["score"] = 100
                result["confidence"] = 0.99 if verified else 0.88
                result["categories"] = ["phishing"]
                label = "verified phishing" if verified else "reported phishing"
                result["message"] = f"PhishTank: URL is a {label} site"
                if phish_detail_url:
                    result["raw_data"] = {"phish_detail_url": phish_detail_url}
            else:
                # In database but marked invalid (false positive, removed)
                result["verdict"] = "Clean"
                result["harmless"] = 1
                result["score"] = 0
                result["confidence"] = 0.75
                result["message"] = "PhishTank: URL was reported but determined not phishing"

            return result

        except urllib.error.HTTPError as exc:
            if exc.code == 509:
                logger.warning("PhishTank rate limit hit (509). Consider adding PHISHTANK_APP_KEY.")
                result["status"] = "rate_limited"
                result["message"] = "PhishTank rate limit exceeded"
            else:
                logger.debug(f"PhishTank HTTP error for {val}: {exc}")
                result["message"] = f"PhishTank API error: HTTP {exc.code}"
        except Exception as exc:
            logger.debug(f"PhishTank query error for {val}: {exc}")
            result["message"] = f"PhishTank query failed: {exc}"

        return result
