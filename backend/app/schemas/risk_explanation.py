"""
Schema representing the structured result of AI-powered risk explanation.
"""
from typing import List
from pydantic import BaseModel, Field, ConfigDict


class RiskExplanationResult(BaseModel):
    """
    Structured model containing the AI-generated (or deterministic fallback)
    human-readable explanation of a website's trust evaluation.
    """
    explanation: str = Field(
        ...,
        description="Human-readable explanation of why the website received its trust evaluation."
    )
    key_risks: List[str] = Field(
        default_factory=list,
        description="Important security risks identified during website analysis."
    )
    positive_signals: List[str] = Field(
        default_factory=list,
        description="Positive security indicators identified during website analysis."
    )
    recommendation: str = Field(
        ...,
        description="Concise recommendation for the user based on the existing risk level and evidence."
    )

    model_config = ConfigDict(from_attributes=True)
