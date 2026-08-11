"""
Schema representing the structured result of redirect behavior analysis.
"""
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class RedirectAnalysisResult(BaseModel):
    """
    Structured model containing redirect chain metrics, domain comparison
    flags, HTTPS upgrade detection, and overall redirect safety evaluation.
    """
    redirect_count: int = Field(
        ...,
        description="Total number of redirects followed before reaching the final destination."
    )
    redirected: bool = Field(
        ...,
        description="Indicates whether at least one redirect occurred."
    )
    final_url: Optional[str] = Field(
        None,
        description="The final resolved URL after following all redirects."
    )
    same_domain: bool = Field(
        ...,
        description="Indicates whether the original and final URLs belong to the same registered domain."
    )
    https_upgrade: bool = Field(
        ...,
        description="Indicates whether the request was automatically upgraded from HTTP to HTTPS."
    )
    cross_domain_redirect: bool = Field(
        ...,
        description="Indicates whether the redirect chain ended on a different domain."
    )
    is_safe_redirect: bool = Field(
        ...,
        description="Overall redirect safety evaluation."
    )
    error: Optional[str] = Field(
        None,
        description="Redirect analysis error message if analysis fails."
    )

    model_config = ConfigDict(from_attributes=True)
