"""
Schema representing the structured result of AI-assisted threat analysis.
"""
from typing import Any, List
from pydantic import BaseModel, Field, ConfigDict, field_validator


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

    model_config = ConfigDict(from_attributes=True)
