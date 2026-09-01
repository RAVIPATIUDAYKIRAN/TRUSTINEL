from enum import Enum
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class DomainTrend(str, Enum):
    IMPROVING = "IMPROVING"
    DEGRADING = "DEGRADING"
    STABLE = "STABLE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class RiskDistribution(BaseModel):
    low: int = Field(default=0, ge=0, description="Count of LOW risk reports")
    medium: int = Field(default=0, ge=0, description="Count of MEDIUM risk reports")
    high: int = Field(default=0, ge=0, description="Count of HIGH risk reports")


class DomainScanTimelineItem(BaseModel):
    scan_id: str = Field(..., description="Scan UUID")
    trust_score: int = Field(..., ge=0, le=100, description="Technical trust score")
    risk_level: str = Field(..., description="Technical risk level (LOW, MEDIUM, HIGH)")
    overall_risk_score: int = Field(..., ge=0, le=100, description="Aggregated overall scam risk score")
    overall_risk_level: str = Field(..., description="Aggregated overall scam risk level (LOW, MEDIUM, HIGH)")
    summary: str = Field(..., description="Scan summary")
    scanned_at: datetime = Field(..., description="Timestamp of scan")


class DomainAnalyticsResponse(BaseModel):
    domain: str = Field(..., description="Normalized domain name")
    total_scans: int = Field(..., ge=0, description="Total scan count")
    # Primary Metrics: Overall Scam Risk Trajectory
    current_scam_risk: Optional[int] = Field(None, ge=0, le=100, description="Latest overall scam risk score")
    average_scam_risk: float = Field(0.0, ge=0.0, le=100.0, description="Average overall scam risk score across history")
    min_scam_risk: Optional[int] = Field(None, ge=0, le=100, description="Minimum overall scam risk score on record")
    max_scam_risk: Optional[int] = Field(None, ge=0, le=100, description="Maximum overall scam risk score on record")
    scam_risk_delta: Optional[int] = Field(None, description="Difference between current scam risk and previous scan")
    trend: DomainTrend = Field(DomainTrend.INSUFFICIENT_DATA, description="Historical scam risk trajectory trend")
    risk_distribution: RiskDistribution = Field(default_factory=RiskDistribution, description="Scam risk level count breakdown")
    first_scanned_at: Optional[datetime] = Field(None, description="First recorded scan timestamp")
    last_scanned_at: Optional[datetime] = Field(None, description="Latest recorded scan timestamp")
    history_timeline: List[DomainScanTimelineItem] = Field(default_factory=list, description="Chronological scan summaries")
    
    # Secondary Metrics: Technical Security Trajectory
    current_technical_score: Optional[int] = Field(None, ge=0, le=100, description="Latest technical trust score")
    average_technical_score: float = Field(0.0, ge=0.0, le=100.0, description="Average technical trust score")
    
    # Backward compatibility aliases
    @property
    def current_trust_score(self) -> Optional[int]:
        return self.current_scam_risk
    
    @property
    def average_trust_score(self) -> float:
        return self.average_scam_risk
    
    @property
    def min_trust_score(self) -> Optional[int]:
        return self.min_scam_risk

    @property
    def max_trust_score(self) -> Optional[int]:
        return self.max_scam_risk

    @property
    def score_delta(self) -> Optional[int]:
        return self.scam_risk_delta
