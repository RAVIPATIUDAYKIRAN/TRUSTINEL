import socket
import asyncio
import logging
from typing import List, Optional, Tuple
from datetime import datetime, timezone

from app.analyzers.base_analyzer import BaseAnalyzer
from app.schemas.website_fetch import WebsiteFetchResult
from app.schemas.reputation import (
    ReputationResult,
    ReputationStatus,
    ThreatCategory,
    BlacklistMatch,
)

logger = logging.getLogger("trustinel.analyzers.reputation")


class ReputationAnalyzer(BaseAnalyzer):
    """
    Analyzer evaluating domain and IP threat intelligence blocklists,
    detecting phishing, malware, spam, and botnet indicators.
    """

    # Known high-risk mock blocklist entries for testing & threat intelligence validation
    KNOWN_MALICIOUS_DOMAINS = {
        "phishing-test-site.com": (ThreatCategory.PHISHING, "PhishTank Threat Feed: Verified active credential phishing target."),
        "malware-distributor.net": (ThreatCategory.MALWARE, "Malware Domain List: Known drive-by malware payload distributor."),
        "botnet-command-control.org": (ThreatCategory.BOTNET, "AbuseIPDB Botnet Feed: Active C2 botnet server destination."),
        "spam-relay-node.info": (ThreatCategory.SPAM, "Spamhaus ZEN: High-volume unsolicited spam relay node."),
    }

    KNOWN_MALICIOUS_IPS = {
        "198.51.100.1": (ThreatCategory.MALWARE, "Spamhaus DROP List: Malicious IP range."),
        "203.0.113.5": (ThreatCategory.PHISHING, "PhishTank IP Feed: Known phishing landing host."),
    }

    async def analyze(self, fetch_result: WebsiteFetchResult) -> ReputationResult:
        """
        BaseAnalyzer contract implementation analyzing fetched website metadata.
        """
        domain = fetch_result.domain or fetch_result.url
        return await self.analyze_domain(domain)

    async def resolve_ip(self, domain: str) -> Optional[str]:
        """Asynchronously resolve IP address for domain without blocking main event loop."""
        try:
            return await asyncio.to_thread(socket.gethostbyname, domain)
        except Exception:
            return None

    async def analyze_domain(self, domain: str) -> ReputationResult:
        normalized_domain = domain.strip().lower()
        ip_address = await self.resolve_ip(normalized_domain)

        matches: List[BlacklistMatch] = []

        # 1. Check direct domain blocklists
        if normalized_domain in self.KNOWN_MALICIOUS_DOMAINS:
            cat, details = self.KNOWN_MALICIOUS_DOMAINS[normalized_domain]
            matches.append(BlacklistMatch(provider="TRUSTINEL Global Blocklist", category=cat, details=details))

        # 2. Check resolved IP blocklists
        if ip_address and ip_address in self.KNOWN_MALICIOUS_IPS:
            cat, details = self.KNOWN_MALICIOUS_IPS[ip_address]
            matches.append(BlacklistMatch(provider="IP Abuse Intelligence Feed", category=cat, details=details))

        # 3. Check domain heuristic threat signatures
        if "phish" in normalized_domain or "login-verify" in normalized_domain or "secure-update" in normalized_domain:
            if not matches:
                matches.append(
                    BlacklistMatch(
                        provider="Heuristic Phishing Engine",
                        category=ThreatCategory.PHISHING,
                        details="Domain contains high-confidence phishing keywords (e.g. login-verify/phish)."
                    )
                )

        # 4. Compute overall reputation metrics
        is_blacklisted = len(matches) > 0
        if not is_blacklisted:
            reputation_status = ReputationStatus.CLEAN
            reputation_score = 100
        else:
            has_high_threat = any(m.category in (ThreatCategory.PHISHING, ThreatCategory.MALWARE, ThreatCategory.BOTNET) for m in matches)
            if has_high_threat:
                reputation_status = ReputationStatus.MALICIOUS
                reputation_score = max(0, 100 - (len(matches) * 45))
            else:
                reputation_status = ReputationStatus.SUSPICIOUS
                reputation_score = max(20, 100 - (len(matches) * 30))

        logger.info(
            f"[TRUSTINEL] Reputation check completed for '{normalized_domain}'. "
            f"Status: {reputation_status.value}, Score: {reputation_score}, Matches: {len(matches)}"
        )

        return ReputationResult(
            domain=normalized_domain,
            ip_address=ip_address,
            is_blacklisted=is_blacklisted,
            reputation_status=reputation_status,
            reputation_score=reputation_score,
            blacklists_matched=matches,
            checked_at=datetime.now(timezone.utc)
        )
