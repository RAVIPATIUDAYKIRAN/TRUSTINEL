import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, HttpUrl, field_validator
from app.models.enums import ScanStatus
from app.schemas.trust_report import TrustReportResponse
from app.core.url_security import URLSecurityValidator


class ScanCreateRequest(BaseModel):
    """
    Schema for initiating a new website trust scan.
    """
    url: HttpUrl = Field(..., description="The full website URL to scan (must start with http:// or https://).")

    @field_validator("url", mode="before")
    @classmethod
    def validate_url_security(cls, v: str) -> str:
        if isinstance(v, HttpUrl):
            v = str(v)
        return URLSecurityValidator.validate_url_syntax(v)

    model_config = {
        "json_schema_extra": {
            "example": {
                "url": "https://example-suspicious-site.com/path?query=1"
            }
        }
    }


class ScanResponse(BaseModel):
    """
    Schema for detailed website scan response, including optional trust report.
    """
    id: uuid.UUID = Field(..., description="Unique identifier of the website scan.")
    url: str = Field(..., description="The parsed target URL.")
    domain: str = Field(..., description="The extracted domain name.")
    status: ScanStatus = Field(..., description="The lifecycle status of the scan.")
    created_at: datetime = Field(..., description="Timestamp when the scan was initiated.")
    updated_at: datetime = Field(..., description="Timestamp when the scan was last updated.")
    trust_report: Optional[TrustReportResponse] = Field(None, description="The generated trust report (if completed).")

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": "e93f8e6c-7f24-4f05-83e3-78b1d9bf5b21",
                "url": "https://example-suspicious-site.com/path?query=1",
                "domain": "example-suspicious-site.com",
                "status": "COMPLETED",
                "created_at": "2026-07-16T18:40:00Z",
                "updated_at": "2026-07-16T18:40:02Z",
                "trust_report": {
                    "id": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
                    "scan_id": "e93f8e6c-7f24-4f05-83e3-78b1d9bf5b21",
                    "trust_score": 85,
                    "risk_level": "LOW",
                    "summary": "Mock Assessment: Domain length and format match expected patterns.",
                    "generated_at": "2026-07-16T18:40:01Z"
                }
            }
        }
    }
