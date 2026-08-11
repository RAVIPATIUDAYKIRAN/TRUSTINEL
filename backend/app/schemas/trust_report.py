import json
import uuid
from datetime import datetime
from typing import Any, List, Optional
from pydantic import BaseModel, Field, conint, model_validator
from app.models.enums import RiskLevel


def _safe_deserialize_list(value: Any) -> List[str]:
    """
    Safely converts a stored value into a list of strings.
    Handles: None, already-deserialized list, valid JSON string, malformed JSON.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass
    return []


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
    explanation: Optional[str] = Field(None, description="Human-readable explanation of the trust evaluation.")
    key_risks: List[str] = Field(default_factory=list, description="Key security risks identified during analysis.")
    positive_signals: List[str] = Field(default_factory=list, description="Positive security indicators identified during analysis.")
    recommendation: Optional[str] = Field(None, description="Concise recommendation for the user.")

    @model_validator(mode='before')
    @classmethod
    def deserialize_json_fields(cls, data: Any) -> Any:
        """
        Deserialize JSON Text columns from the ORM into Python lists.
        Handles None, already-deserialized lists, valid JSON strings, and malformed JSON.
        """
        if isinstance(data, dict):
            data['key_risks'] = _safe_deserialize_list(data.get('key_risks'))
            data['positive_signals'] = _safe_deserialize_list(data.get('positive_signals'))
        elif hasattr(data, '__dict__'):
            # ORM object — read attributes
            key_risks_raw = getattr(data, 'key_risks', None)
            positive_signals_raw = getattr(data, 'positive_signals', None)
            object.__setattr__(data, 'key_risks', _safe_deserialize_list(key_risks_raw))
            object.__setattr__(data, 'positive_signals', _safe_deserialize_list(positive_signals_raw))
        return data

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
                "scan_id": "e93f8e6c-7f24-4f05-83e3-78b1d9bf5b21",
                "trust_score": 85,
                "risk_level": "LOW",
                "summary": "Website shows strong trust indicators based on the available security analysis.",
                "generated_at": "2026-07-16T18:40:01Z",
                "explanation": "Website shows strong trust indicators based on the available security analysis.",
                "key_risks": [],
                "positive_signals": ["SSL certificate is valid: +25"],
                "recommendation": "This website appears trustworthy based on the available evidence."
            }
        }
    }
