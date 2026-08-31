from enum import Enum
from typing import List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class ReputationStatus(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNRATED = "UNRATED"


class ThreatCategory(str, Enum):
    PHISHING = "PHISHING"
    MALWARE = "MALWARE"
    SPAM = "SPAM"
    BOTNET = "BOTNET"
    CLEAN = "CLEAN"


class BlacklistMatch(BaseModel):
    provider: str = Field(..., description="Name of the reputation feed / blocklist provider")
    category: ThreatCategory = Field(ThreatCategory.MALWARE, description="Classified threat category")
    details: str = Field(..., description="Provider finding details or matching signature")


class ReputationResult(BaseModel):
    domain: str = Field(..., description="Normalized target domain name")
    ip_address: Optional[str] = Field(None, description="Resolved IP address of the domain")
    is_blacklisted: bool = Field(False, description="Flag indicating if domain/IP matches blocklists")
    reputation_status: ReputationStatus = Field(ReputationStatus.CLEAN, description="Overall domain reputation classification")
    reputation_score: int = Field(100, ge=0, le=100, description="Domain reputation score (0 = High Risk, 100 = Clean)")
    blacklists_matched: List[BlacklistMatch] = Field(default_factory=list, description="List of matching security blocklist feeds")
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of reputation check")
