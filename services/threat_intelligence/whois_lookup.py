import json
import logging
import urllib.parse
import urllib.request
from typing import Any, Dict
from datetime import datetime, timezone

from services.threat_intelligence.base_provider import BaseThreatProvider

logger = logging.getLogger("guardly.threat_intel.whois")


class WhoisLookupProvider(BaseThreatProvider):
    """
    WHOIS & RDAP (Registration Data Access Protocol) Provider.
    Queries official RDAP endpoints to retrieve structured registration,
    creation dates, expiration, registrar, and registrant status for domains and IPs.
    """

    RDAP_BASE_DOMAIN = "https://rdap.org/domain/"
    RDAP_BASE_IP = "https://rdap.org/ip/"

    @property
    def name(self) -> str:
        return "WHOIS/RDAP"

    def analyze(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        result = self._default_result(ioc_value, ioc_type)
        if ioc_type not in ("domain", "ip", "url"):
            result["verdict"] = "Not Applicable"
            result["message"] = f"WHOIS not applicable for {ioc_type}"
            return result

        target = ioc_value.strip().lower()
        if ioc_type == "url":
            parsed = urllib.parse.urlparse(target if "://" in target else f"http://{target}")
            target = parsed.hostname or target
            ioc_type = "domain"

        try:
            rdap_data = self._query_rdap(target, is_ip=(ioc_type == "ip"))
            if not rdap_data:
                result["verdict"] = "Unknown"
                result["message"] = f"No WHOIS/RDAP records found for {target}"
                return result

            extracted = self._extract_rdap_fields(rdap_data)
            result["raw_data"] = extracted
            result["verdict"] = "Info"
            result["confidence"] = 0.90

            # Calculate domain age risk factor if newly registered (< 30 days)
            age_days = extracted.get("age_days")
            if age_days is not None and age_days < 30:
                result["suspicious"] = 1
                result["verdict"] = "Suspicious"
                result["score"] = 65
                result["message"] = f"Newly registered domain ({age_days} days old)"
            elif age_days is not None and age_days < 90:
                result["suspicious"] = 1
                result["score"] = 35
                result["message"] = f"Young domain ({age_days} days old)"
            else:
                result["harmless"] = 1
                result["score"] = 0
                result["message"] = f"WHOIS data retrieved. Registrar: {extracted.get('registrar', 'Unknown')}"

            return result
        except Exception as exc:
            logger.debug(f"RDAP lookup failed for {target}: {exc}")
            result["verdict"] = "Lookup Error"
            result["message"] = f"WHOIS lookup failed: {exc}"
            return result

    def _query_rdap(self, target: str, is_ip: bool = False) -> Dict[str, Any]:
        endpoint = f"{self.RDAP_BASE_IP if is_ip else self.RDAP_BASE_DOMAIN}{urllib.parse.quote(target)}"
        req = urllib.request.Request(
            endpoint,
            headers={
                "Accept": "application/rdap+json, application/json",
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

    def _extract_rdap_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) if isinstance(e, dict)}
        created_str = events.get("registration") or events.get("transfer")
        expires_str = events.get("expiration")
        updated_str = events.get("last changed")

        age_days = None
        if created_str:
            try:
                created_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                age_days = (now - created_dt).days
            except Exception:
                age_days = None

        # Find registrar entity
        registrar = "Unknown"
        entities = data.get("entities", [])
        for ent in entities:
            roles = ent.get("roles", [])
            if "registrar" in roles:
                vcard = ent.get("vcardArray", [])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    for prop in vcard[1]:
                        if prop and prop[0] == "fn":
                            registrar = prop[3]
                            break

        return {
            "domain_name": data.get("ldhName") or data.get("handle", ""),
            "created_date": created_str,
            "expires_date": expires_str,
            "updated_date": updated_str,
            "age_days": age_days,
            "registrar": registrar,
            "status": data.get("status", []),
        }
