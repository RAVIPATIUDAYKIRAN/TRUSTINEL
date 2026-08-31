from enum import Enum
from typing import List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class ImpersonationConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class PhishingDetectionType(str, Enum):
    TYPOSQUATTING_OMISSION = "TYPOSQUATTING_OMISSION"
    TYPOSQUATTING_INSERTION = "TYPOSQUATTING_INSERTION"
    TYPOSQUATTING_SUBSTITUTION = "TYPOSQUATTING_SUBSTITUTION"
    TYPOSQUATTING_TRANSPOSITION = "TYPOSQUATTING_TRANSPOSITION"
    REPEATED_CHARACTER = "REPEATED_CHARACTER"
    HYPHENATION_TRICK = "HYPHENATION_TRICK"
    HOMOGLYPH_IDN_ABUSE = "HOMOGLYPH_IDN_ABUSE"
    SUBDOMAIN_IMPERSONATION = "SUBDOMAIN_IMPERSONATION"
    BRAND_KEYWORD_INCLUSION = "BRAND_KEYWORD_INCLUSION"


class PhishingImpersonationResult(BaseModel):
    input_domain: str = Field(..., description="Raw input domain string")
    normalized_domain: str = Field(..., description="Normalized domain name")
    is_impersonation_suspected: bool = Field(False, description="Flag indicating if brand impersonation is suspected")
    suspected_brand: Optional[str] = Field(None, description="Name of the targeted legitimate brand")
    matched_legitimate_domain: Optional[str] = Field(None, description="Canonical domain of the targeted brand")
    similarity_score: float = Field(0.0, ge=0.0, le=1.0, description="String similarity score (0.0 to 1.0)")
    confidence_level: ImpersonationConfidence = Field(ImpersonationConfidence.NONE, description="Confidence level of detection")
    detection_types: List[PhishingDetectionType] = Field(default_factory=list, description="Categorized impersonation techniques detected")
    security_findings: List[str] = Field(default_factory=list, description="List of human-readable security warning findings")
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of analysis")
