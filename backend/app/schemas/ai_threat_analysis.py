"""
Schema representing the structured result of AI-assisted threat analysis.
"""
from typing import Any, Dict, List
from pydantic import BaseModel, Field, ConfigDict, field_validator


VALID_EVIDENCE_CATEGORIES = {
    "SSL",
    "WHOIS",
    "SECURITY_HEADERS",
    "REDIRECTS",
    "DETERMINISTIC_TRUST",
    "CONTENT_ANALYSIS",
    "REPUTATION",
}


class AIEvidenceMapping(BaseModel):
    """
    Structured model mapping an AI finding directly to its source evidence category.
    """
    category: str = Field(
        ...,
        description="Evidence category ('SSL', 'WHOIS', 'SECURITY_HEADERS', 'REDIRECTS', 'CONTENT_ANALYSIS', 'REPUTATION', or 'DETERMINISTIC_TRUST')."
    )
    finding: str = Field(
        ...,
        description="Specific finding or indicator tied to this evidence category."
    )
    impact: str = Field(
        ...,
        description="Explanation of how this finding impacts security or trust evaluation."
    )

    @field_validator("category", mode="before")
    @classmethod
    def validate_category(cls, v: Any) -> str:
        upper_v = str(v).strip().upper() if v is not None else ""
        alias_map = {
            "DOMAIN": "WHOIS",
            "WHOIS_DOMAIN": "WHOIS",
            "HEADERS": "SECURITY_HEADERS",
            "HEADER": "SECURITY_HEADERS",
            "TRUST": "DETERMINISTIC_TRUST",
            "DETERMINISTIC": "DETERMINISTIC_TRUST",
            "REDIRECT": "REDIRECTS",
            "CONTENT": "CONTENT_ANALYSIS",
            "CONTENT_SCAM": "CONTENT_ANALYSIS",
            "MULTI_RISK": "DETERMINISTIC_TRUST",
            "MULTI_DIMENSIONAL_RISK": "DETERMINISTIC_TRUST",
        }
        category = alias_map.get(upper_v, upper_v)
        if category not in VALID_EVIDENCE_CATEGORIES:
            raise ValueError(f"Invalid evidence category '{v}'. Must be one of {VALID_EVIDENCE_CATEGORIES}")
        return category

    @field_validator("finding", "impact", mode="before")
    @classmethod
    def trim_text(cls, v: Any) -> str:
        if isinstance(v, str):
            return v.strip()
        return str(v) if v is not None else ""

    model_config = ConfigDict(from_attributes=True)


class AIThreatAnalysisResult(BaseModel):
    """
    Structured model containing the AI-generated (or deterministic fallback)
    threat analysis evaluation based on website security evidence.
    """
    enabled: bool = Field(
        ...,
        description="Whether AI threat analysis was active for this evaluation."
    )
    threat_level: str = Field(
        ...,
        description="Assessed threat level ('LOW', 'MEDIUM', 'HIGH', or 'UNKNOWN')."
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score of the threat assessment ranging from 0.0 to 1.0."
    )
    suspicious_indicators: List[str] = Field(
        default_factory=list,
        description="List of specific suspicious indicators identified during analysis."
    )
    reasoning: str = Field(
        ...,
        description="Structured reasoning explaining the threat assessment."
    )
    recommended_action: str = Field(
        ...,
        description="Recommended action for the user based on the threat assessment."
    )
    evidence_mappings: List[AIEvidenceMapping] = Field(
        default_factory=list,
        description="Traceable evidence mappings connecting AI findings directly to source evidence categories."
    )

    @field_validator("threat_level", mode="before")
    @classmethod
    def validate_threat_level(cls, v: Any) -> str:
        upper_v = str(v).strip().upper() if v is not None else ""
        if upper_v not in {"LOW", "MEDIUM", "HIGH", "UNKNOWN"}:
            raise ValueError(f"Invalid threat_level: {v}. Must be LOW, MEDIUM, HIGH, or UNKNOWN.")
        return upper_v

    @field_validator("reasoning", "recommended_action", mode="before")
    @classmethod
    def trim_strings(cls, v: Any) -> str:
        if isinstance(v, str):
            return v.strip()
        return str(v) if v is not None else ""

    @field_validator("suspicious_indicators", mode="before")
    @classmethod
    def normalize_and_deduplicate_indicators(cls, v: Any) -> List[str]:
        if not isinstance(v, list):
            return []
        seen = set()
        deduped = []
        for item in v:
            if not isinstance(item, str):
                item = str(item)
            cleaned = item.strip()
            if cleaned and cleaned.lower() not in seen:
                seen.add(cleaned.lower())
                deduped.append(cleaned)
        return deduped[:10]

    @field_validator("evidence_mappings", mode="before")
    @classmethod
    def normalize_and_deduplicate_mappings(cls, v: Any) -> List[Any]:
        if not isinstance(v, list):
            return []
        seen = set()
        deduped = []
        for item in v:
            if isinstance(item, dict):
                cat = str(item.get("category", "")).strip().upper()
                find = str(item.get("finding", "")).strip().lower()
                key = (cat, find)
                if cat and find and key not in seen:
                    seen.add(key)
                    deduped.append(item)
            elif isinstance(item, AIEvidenceMapping):
                key = (item.category, item.finding.lower())
                if key not in seen:
                    seen.add(key)
                    deduped.append(item)
        return deduped[:10]

    model_config = ConfigDict(from_attributes=True)


class AIServiceStatusResponse(BaseModel):
    """
    Response model exposing non-sensitive operational health, diagnostic configuration,
    and security audit telemetry for the AI Threat Analysis service.
    """
    enabled: bool = Field(..., description="Whether AI threat analysis is active.")
    provider: str = Field(..., description="Configured AI provider name.")
    model: str = Field(..., description="Configured AI provider model.")
    model_configured: bool = Field(..., description="Whether a model name is configured.")
    api_key_configured: bool = Field(..., description="Whether an API key is configured (strictly boolean, secret string is NEVER exposed).")
    timeout_seconds: float = Field(..., description="Configured provider HTTP timeout in seconds.")
    cache_ttl_seconds: int = Field(..., description="Configured cache TTL in seconds.")
    in_memory_cache_entries: int = Field(..., description="Current count of active in-memory cache entries.")
    security_audit: Dict[str, Any] = Field(
        default_factory=dict,
        description="Non-sensitive policy and status metadata for security compliance audit."
    )

    model_config = ConfigDict(from_attributes=True)
