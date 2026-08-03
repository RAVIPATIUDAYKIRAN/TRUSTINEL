"""
Schema representing the structured result of an SSL certificate analysis.
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class SSLAnalysisResult(BaseModel):
    """
    Structured model containing details about a website's SSL/TLS certificate,
    validity ranges, and cryptographic protocol negotiation metadata.
    """
    issuer: Optional[str] = Field(
        None,
        description="Certificate issuer organization."
    )
    subject: Optional[str] = Field(
        None,
        description="Certificate subject / common name."
    )
    valid_from: Optional[datetime] = Field(
        None,
        description="Certificate validity start date."
    )
    expires_on: Optional[datetime] = Field(
        None,
        description="Certificate expiry date."
    )
    days_remaining: Optional[int] = Field(
        None,
        description="Remaining number of valid certificate days."
    )
    is_valid: bool = Field(
        ...,
        description="Indicates whether the certificate is currently valid."
    )
    tls_version: Optional[str] = Field(
        None,
        description="Negotiated TLS version if available."
    )
    error: Optional[str] = Field(
        None,
        description="SSL analysis error message if retrieval fails."
    )

    model_config = ConfigDict(from_attributes=True)
