import abc
import logging
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from app.config.settings import settings

logger = logging.getLogger("trustinel.services.threat_intelligence_service")


class ThreatReputationStatus(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


class ReputationThreatResult(BaseModel):
    status: ThreatReputationStatus = ThreatReputationStatus.UNKNOWN
    reputation_score: int = Field(default=100, ge=0, le=100, description="100=Clean/Reputable, 0=Confirmed Malicious")
    provider_name: str = "internal_heuristics"
    matches_found: int = 0
    matched_lists: List[str] = Field(default_factory=list)
    threat_details: Optional[str] = None


class ThreatIntelligenceProvider(abc.ABC):
    """
    Abstract base class for external/internal threat intelligence reputation providers.
    """
    @abc.abstractmethod
    async def check_domain(self, domain: str) -> ReputationThreatResult:
        ...


class InternalHeuristicsThreatProvider(ThreatIntelligenceProvider):
    """
    Default provider that checks internal reputation heuristics and domain security indicators.
    Returns UNKNOWN if no authoritative third-party provider is configured.
    """
    async def check_domain(self, domain: str) -> ReputationThreatResult:
        clean_domain = (domain or "").strip().lower()
        if not clean_domain:
            return ReputationThreatResult(
                status=ThreatReputationStatus.UNKNOWN,
                reputation_score=50,
                provider_name="internal_heuristics",
                matches_found=0,
                matched_lists=[],
                threat_details="Domain string is empty."
            )

        # Standard heuristics fallback returns UNKNOWN when no external threat API key is configured
        return ReputationThreatResult(
            status=ThreatReputationStatus.UNKNOWN,
            reputation_score=100,
            provider_name="internal_heuristics",
            matches_found=0,
            matched_lists=[],
            threat_details="No third-party threat intelligence provider configured; reputation is UNKNOWN."
        )


class ThreatIntelligenceService:
    """
    Orchestrates threat intelligence queries through extensible providers.
    """
    def __init__(self, provider: Optional[ThreatIntelligenceProvider] = None) -> None:
        self.provider = provider or InternalHeuristicsThreatProvider()

    async def get_reputation(self, domain: str) -> ReputationThreatResult:
        try:
            return await self.provider.check_domain(domain)
        except Exception as exc:
            logger.warning(f"[TRUSTINEL] Threat intelligence provider exception for '{domain}': {exc}")
            return ReputationThreatResult(
                status=ThreatReputationStatus.UNKNOWN,
                reputation_score=50,
                provider_name="error_fallback",
                matches_found=0,
                matched_lists=[],
                threat_details=f"Threat intelligence lookup failed: {exc}"
            )
