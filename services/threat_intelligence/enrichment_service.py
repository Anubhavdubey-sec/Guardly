import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from services.threat_intelligence.abuseipdb import AbuseIPDBProvider
from services.threat_intelligence.alienvault_otx import AlienVaultOTXProvider
from services.threat_intelligence.dns_lookup import DNSLookupProvider
from services.threat_intelligence.phishtank import PhishTankProvider
from services.threat_intelligence.urlhaus import URLHausProvider
from services.threat_intelligence.virustotal import VirusTotalProvider
from services.threat_intelligence.whois_lookup import WhoisLookupProvider

logger = logging.getLogger("guardly.threat_intel.enrichment")


class ThreatEnrichmentService:
    """
    Threat Intelligence Consensus & Enrichment Engine.
    Aggregates multi-source threat intelligence (VirusTotal, AbuseIPDB, URLHaus,
    PhishTank, AlienVault OTX, WHOIS/RDAP, and DNS Resolution) to provide
    unified consensus verdicts, risk scores, and actionable context.
    """

    CACHE_TTL_HOURS = 12

    def __init__(self, timeout: int = 4):
        self.timeout = timeout
        self.providers = [
            URLHausProvider(timeout=timeout),
            PhishTankProvider(timeout=timeout),
            WhoisLookupProvider(timeout=timeout),
            DNSLookupProvider(timeout=timeout),
            VirusTotalProvider(timeout=timeout),
            AbuseIPDBProvider(timeout=timeout),
            AlienVaultOTXProvider(timeout=timeout),
        ]
        self._memory_cache: Dict[str, Dict[str, Any]] = {}

    def enrich_ioc(self, ioc_value: str, ioc_type: str = "auto") -> Dict[str, Any]:
        """
        Enriches a single Indicator of Compromise (IOC).
        
        Args:
            ioc_value: IP, Domain, URL, or File Hash
            ioc_type: 'ip', 'domain', 'url', 'hash', 'email', or 'auto'
            
        Returns:
            Dictionary with aggregated consensus, provider breakdowns, whois, and dns records.
        """
        ioc_val = ioc_value.strip()
        if not ioc_val:
            return {"verdict": "Invalid", "score": 0, "message": "Empty IOC value"}

        if ioc_type == "auto":
            ioc_type = self._detect_ioc_type(ioc_val)

        cache_key = f"{ioc_type}:{ioc_val.lower()}"

        # 1. Check in-memory / DB cache
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        # 2. Query each active provider
        provider_results = []
        malicious_count = 0
        suspicious_count = 0
        harmless_count = 0
        total_score = 0
        whois_data = {}
        dns_data = {}
        categories = set()

        for provider in self.providers:
            try:
                res = provider.analyze(ioc_val, ioc_type)
                provider_results.append(res)

                if res.get("malicious", 0) > 0 or res.get("verdict") in ("Malicious", "Phishing", "Blacklisted"):
                    malicious_count += 1
                elif res.get("suspicious", 0) > 0 or res.get("verdict") == "Suspicious":
                    suspicious_count += 1
                elif res.get("harmless", 0) > 0 or res.get("verdict") in ("Clean", "Harmless"):
                    harmless_count += 1

                score = res.get("score", 0)
                if score > 0:
                    total_score = max(total_score, score)

                for cat in res.get("categories", []):
                    categories.add(cat)

                # Capture WHOIS and DNS specifics
                if provider.name == "WHOIS/RDAP" and res.get("raw_data"):
                    whois_data = res["raw_data"]
                elif provider.name == "DNS Resolver" and res.get("raw_data"):
                    dns_data = res["raw_data"]

            except Exception as exc:
                logger.debug(f"Provider {provider.name} failed for {ioc_val}: {exc}")

        # 3. Calculate consensus verdict & risk score
        if malicious_count > 0:
            consensus_verdict = "Malicious"
            final_score = max(80, total_score)
        elif suspicious_count > 0 or total_score >= 40:
            consensus_verdict = "Suspicious"
            final_score = max(45, total_score)
        elif harmless_count > 0:
            consensus_verdict = "Clean"
            final_score = total_score
        else:
            consensus_verdict = "Unknown"
            final_score = 0

        response = {
            "ioc_value": ioc_val,
            "ioc_type": ioc_type,
            "consensus_verdict": consensus_verdict,
            "risk_score": final_score,
            "confidence": 0.85 if (malicious_count + suspicious_count + harmless_count) > 0 else 0.40,
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "harmless_count": harmless_count,
            "categories": sorted(list(categories)),
            "whois": whois_data,
            "dns": dns_data,
            "providers": provider_results,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }

        # 4. Save to cache
        self._set_cached(cache_key, response)

        return response

    def enrich_batch(self, iocs: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Batch enriches a list of IOC dicts [{'value': '...', 'type': '...'}]"""
        results = []
        for item in iocs:
            val = item.get("value") or item.get("ioc_value", "")
            itype = item.get("type") or item.get("ioc_type", "auto")
            if val:
                results.append(self.enrich_ioc(val, itype))
        return results

    def _detect_ioc_type(self, value: str) -> str:
        import re
        val = value.strip()
        if re.match(r"^(?:https?://|ftp://)", val, re.IGNORECASE) or "/" in val:
            return "url"
        if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", val):
            return "hash"
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val):
            return "ip"
        if "@" in val:
            return "email"
        return "domain"

    def _get_cached(self, key: str) -> Optional[Dict[str, Any]]:
        # In-memory check
        item = self._memory_cache.get(key)
        if item:
            exp = item.get("_expires_at")
            if exp and datetime.now(timezone.utc) < exp:
                return item.get("data")
            self._memory_cache.pop(key, None)

        # Database IOCCache check if application context available
        try:
            from models.threat_intel import IOCCache
            db_item = IOCCache.query.filter_by(cache_key=key).first()
            if db_item and not db_item.is_expired:
                return json.loads(db_item.data)
        except Exception:
            pass

        return None

    def _set_cached(self, key: str, data: Dict[str, Any]):
        expires_at = datetime.now(timezone.utc) + timedelta(hours=self.CACHE_TTL_HOURS)
        self._memory_cache[key] = {
            "data": data,
            "_expires_at": expires_at,
        }

        # Try to persist in database if in Flask app context
        try:
            from models.threat_intel import IOCCache, db
            existing = IOCCache.query.filter_by(cache_key=key).first()
            if existing:
                existing.data = json.dumps(data)
                existing.expires_at = expires_at
            else:
                new_cache = IOCCache(
                    cache_key=key,
                    data=json.dumps(data),
                    expires_at=expires_at,
                )
                db.session.add(new_cache)
            db.session.commit()
        except Exception:
            pass
