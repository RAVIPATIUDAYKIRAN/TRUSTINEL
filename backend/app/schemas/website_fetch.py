"""
Schema representing the structured result of a website HTTP fetch operation.
"""
from typing import Optional, Dict
from pydantic import BaseModel, Field, ConfigDict


class WebsiteFetchResult(BaseModel):
    """
    Structured model containing target web page contents, headers, timing metrics,
    and redirection statistics collected by WebsiteFetcher.
    """
    original_url: str = Field(
        ...,
        description="The URL initially requested for fetching."
    )
    final_url: Optional[str] = Field(
        None,
        description="The final resolved URL after all redirects."
    )
    status_code: Optional[int] = Field(
        None,
        description="HTTP status code returned by the target server."
    )
    response_time_ms: Optional[float] = Field(
        None,
        description="Round-trip HTTP response latency in milliseconds."
    )
    response_headers: Dict[str, str] = Field(
        default_factory=dict,
        description="Response headers dictionary returned by target server."
    )
    html_content: str = Field(
        "",
        description="Raw HTML body content returned by target server."
    )
    redirect_count: int = Field(
        0,
        description="The number of HTTP redirects traversed."
    )
    error: Optional[str] = Field(
        None,
        description="Error description text if request execution failed."
    )

    model_config = ConfigDict(from_attributes=True)
