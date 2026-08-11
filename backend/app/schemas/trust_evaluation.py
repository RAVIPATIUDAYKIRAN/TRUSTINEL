"""
Schema representing the structured result of the website trust evaluation.
"""
from typing import List
from pydantic import BaseModel, Field, ConfigDict

from app.models.enums import RiskLevel


class TrustEvaluationResult(BaseModel):
    """
    Structured model containing the final trust score, computed risk level,
    overall summary text, and detailed explainable reasons for the scoring decisions.
    """
    trust_score: int = Field(
        ...,
        description="Final website trust score from 0 to 100.",
        ge=0,
        le=100
    )
    risk_level: RiskLevel = Field(
        ...,
        description="Overall risk classification derived from the trust score."
    )
    summary: str = Field(
        ...,
        description="Human-readable explanation of the overall trust evaluation."
    )
    reasons: List[str] = Field(
        default_factory=list,
        description="Human-readable reasons explaining positive and negative scoring factors."
    )

    model_config = ConfigDict(from_attributes=True)
