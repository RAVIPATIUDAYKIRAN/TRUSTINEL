"""
Schema representing the structured result of HTTP security header analysis.
"""
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


# Canonical list of recommended security headers checked by the analyzer
RECOMMENDED_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


class HeaderAnalysisResult(BaseModel):
    """
    Structured model containing presence flags for recommended HTTP security
    response headers, a composite score, and the list of missing headers.
    """
    strict_transport_security: bool = Field(
        ...,
        description="Indicates whether the Strict-Transport-Security header is present."
    )
    content_security_policy: bool = Field(
        ...,
        description="Indicates whether the Content-Security-Policy header is present."
    )
    x_frame_options: bool = Field(
        ...,
        description="Indicates whether the X-Frame-Options header is present."
    )
    x_content_type_options: bool = Field(
        ...,
        description="Indicates whether the X-Content-Type-Options header is present."
    )
    referrer_policy: bool = Field(
        ...,
        description="Indicates whether the Referrer-Policy header is present."
    )
    permissions_policy: bool = Field(
        ...,
        description="Indicates whether the Permissions-Policy header is present."
    )
    security_headers_score: int = Field(
        ...,
        description="Number of recommended security headers detected.",
        ge=0,
        le=6
    )
    missing_headers: List[str] = Field(
        default_factory=list,
        description="List of recommended security headers that are missing."
    )
    error: Optional[str] = Field(
        None,
        description="Security header analysis error message if analysis fails."
    )

    model_config = ConfigDict(from_attributes=True)
