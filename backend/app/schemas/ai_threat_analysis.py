"""
Schema representing the structured result of AI-assisted threat analysis.
"""
from typing import List, Literal
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

    @field_validator("threat_level")
    @classmethod
    def validate_threat_level(cls, v: str) -> str:
        upper_v = v.upper() if isinstance(v, str) else ""
        if upper_v not in {"LOW", "MEDIUM", "HIGH", "UNKNOWN"}:
            raise ValueError(f"Invalid threat_level: {v}. Must be LOW, MEDIUM, HIGH, or UNKNOWN.")
        return upper_v

    model_config = ConfigDict(from_attributes=True)
