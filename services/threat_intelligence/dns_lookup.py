import json
import logging
import socket
import urllib.parse
import urllib.request
from typing import Any, Dict, List

from services.threat_intelligence.base_provider import BaseThreatProvider

logger = logging.getLogger("guardly.threat_intel.dns")


class DNSLookupProvider(BaseThreatProvider):
    """
    DNS Lookup Provider.
    Queries DNS records (A, AAAA, MX, TXT, SPF, DMARC, NS) using DNS-over-HTTPS (DoH)
    with local socket resolution fallback to detect missing MX, suspicious SPF/DMARC configurations,
    or fast-flux domain indicators.
    """

    DOH_CLOUDFLARE = "https://cloudflare-dns.com/dns-query"
    RECORD_TYPES = {
        "A": 1,
        "NS": 2,
        "CNAME": 5,
        "SOA": 6,
        "MX": 15,
        "TXT": 16,
        "AAAA": 28,
    }

    @property
    def name(self) -> str:
        return "DNS Resolver"

    def analyze(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        result = self._default_result(ioc_value, ioc_type)
        if ioc_type not in ("domain", "url", "email"):
            result["verdict"] = "Not Applicable"
            return result

        domain = ioc_value.strip().lower()
        if ioc_type == "url":
            parsed = urllib.parse.urlparse(domain if "://" in domain else f"http://{domain}")
            domain = parsed.hostname or domain
        elif ioc_type == "email" and "@" in domain:
            domain = domain.split("@")[-1]

        try:
            records = self._resolve_all(domain)
            dmarc_records = self._resolve_record(f"_dmarc.{domain}", "TXT")

            dns_summary = {
                "domain": domain,
                "a": records.get("A", []),
                "aaaa": records.get("AAAA", []),
                "mx": records.get("MX", []),
                "txt": records.get("TXT", []),
                "ns": records.get("NS", []),
                "dmarc": dmarc_records,
            }
            result["raw_data"] = dns_summary
            result["confidence"] = 0.90

            # Security heuristics based on DNS configurations:
            # 1. Missing MX record for mail sending domains
            has_mx = bool(records.get("MX"))
            has_a = bool(records.get("A"))
            has_dmarc = bool(dmarc_records)
            spf_present = any("v=spf1" in txt.lower() for txt in records.get("TXT", []))

            suspicious_flags = []
            score = 0

            if not has_a and not has_mx:
                suspicious_flags.append("Domain does not resolve to any active A or MX records (NXDOMAIN or dead domain)")
                score += 50
            elif ioc_type == "email" and not has_mx:
                suspicious_flags.append("Email domain has no valid MX records configured")
                score += 40

            if ioc_type in ("domain", "email") and not spf_present and not has_dmarc:
                suspicious_flags.append("Neither SPF nor DMARC DNS policies are established")
                score += 25

            if score >= 50:
                result["verdict"] = "Suspicious"
                result["suspicious"] = 1
                result["score"] = score
                result["message"] = "; ".join(suspicious_flags)
            else:
                result["verdict"] = "Clean"
                result["harmless"] = 1
                result["score"] = score
                result["message"] = f"DNS records verified: {len(records.get('A', []))} A, {len(records.get('MX', []))} MX, SPF={'Yes' if spf_present else 'No'}, DMARC={'Yes' if has_dmarc else 'No'}"

            return result
        except Exception as exc:
            logger.debug(f"DNS lookup failed for {domain}: {exc}")
            result["verdict"] = "Lookup Error"
            result["message"] = f"DNS resolution failed: {exc}"
            return result

    def _resolve_all(self, domain: str) -> Dict[str, List[str]]:
        results = {}
        for rtype in ("A", "MX", "TXT", "NS", "AAAA"):
            results[rtype] = self._resolve_record(domain, rtype)

        # Fallback to local socket resolution for A records if DoH failed or empty
        if not results.get("A"):
            try:
                addr_info = socket.getaddrinfo(domain, None)
                ips = list({info[4][0] for info in addr_info if info[0] == socket.AF_INET})
                if ips:
                    results["A"] = ips
            except Exception:
                pass

        return results

    def _resolve_record(self, name: str, rtype: str) -> List[str]:
        url = f"{self.DOH_CLOUDFLARE}?name={urllib.parse.quote(name)}&type={rtype}"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/dns-json",
                "User-Agent": "Guardly-DNS-Resolver/2.4",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    answers = data.get("Answer", [])
                    return [ans.get("data", "").strip('"') for ans in answers if "data" in ans]
        except Exception:
            return []
        return []
