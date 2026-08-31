from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class ExportFormat(str, Enum):
    JSON = "json"
    CSV = "csv"


class ThreatIntelligenceExportItem(BaseModel):
    domain: str = Field(..., description="Target domain name")
    normalized_domain: str = Field(..., description="Normalized domain name")
    trust_score: int = Field(..., description="Deterministic trust score 0-100")
    risk_level: str = Field(..., description="Risk level (LOW, MEDIUM, HIGH)")
    reputation_score: Optional[int] = Field(None, description="Reputation score")
    reputation_status: Optional[str] = Field(None, description="Reputation status")
    blacklist_matches: List[str] = Field(default_factory=list, description="Blacklist matches")
    phishing_detected: bool = Field(False, description="Phishing indicator")
    phishing_risk_score: Optional[int] = Field(None, description="Phishing risk score")
    ssl_valid: Optional[bool] = Field(None, description="SSL certificate validity")
    ssl_issuer: Optional[str] = Field(None, description="SSL CA issuer")
    ssl_days_remaining: Optional[int] = Field(None, description="SSL days to expiration")
    security_header_grade: Optional[str] = Field(None, description="Header grade (A+ to F)")
    security_header_score: Optional[int] = Field(None, description="Header score 0-100")
    scanned_at: datetime = Field(..., description="Timestamp of scan")
    scan_id: Optional[str] = Field(None, description="Scan identifier")

    model_config = ConfigDict(from_attributes=True)


class ThreatIntelligenceExportResponse(BaseModel):
    format: ExportFormat = Field(..., description="Export format")
    exported_at: datetime = Field(..., description="Timestamp of export generation")
    total_records: int = Field(..., ge=0, description="Total count of exported records")
    items: List[ThreatIntelligenceExportItem] = Field(default_factory=list, description="Exported threat intelligence items")
