import uuid
from datetime import datetime
from pydantic import BaseModel, Field, conint
from app.models.enums import RiskLevel


class TrustReportResponse(BaseModel):
    """
    Schema for trust evaluation reports.
    """
    id: uuid.UUID = Field(..., description="Unique identifier of the trust report.")
    scan_id: uuid.UUID = Field(..., description="Unique identifier of the parent scan.")
    trust_score: conint(ge=0, le=100) = Field(..., description="Calculated trust score ranging from 0 to 100.")
    risk_level: RiskLevel = Field(..., description="The computed risk level.")
    summary: str = Field(..., description="Summary reasoning for the computed score and risk level.")
    generated_at: datetime = Field(..., description="Timestamp when the report was generated.")

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
                "scan_id": "e93f8e6c-7f24-4f05-83e3-78b1d9bf5b21",
                "trust_score": 85,
                "risk_level": "LOW",
                "summary": "Mock Assessment: Domain length and format match expected patterns.",
                "generated_at": "2026-07-16T18:40:01Z"
            }
        }
    }
