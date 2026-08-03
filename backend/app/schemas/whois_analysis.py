"""
Schema representing the structured result of a WHOIS domain analysis.
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class WHOISAnalysisResult(BaseModel):
    """
    Structured model containing registrar details, registration lifecycle dates,
    authoritative name servers, and origin country retrieved via WHOIS queries.
    """
    registrar: Optional[str] = Field(
        None,
        description="Registrar responsible for the domain."
    )
    creation_date: Optional[datetime] = Field(
        None,
        description="Domain registration date."
    )
    expiration_date: Optional[datetime] = Field(
        None,
        description="Domain expiration date."
    )
    updated_date: Optional[datetime] = Field(
        None,
        description="Most recent WHOIS update date."
    )
    domain_age_days: Optional[int] = Field(
        None,
        description="Age of the domain in days."
    )
    country: Optional[str] = Field(
        None,
        description="Registrant country if available."
    )
    name_servers: List[str] = Field(
        default_factory=list,
        description="List of authoritative name servers."
    )
    is_registered: bool = Field(
        ...,
        description="Indicates whether WHOIS information was successfully retrieved."
    )
    error: Optional[str] = Field(
        None,
        description="WHOIS lookup error."
    )

    model_config = ConfigDict(from_attributes=True)
