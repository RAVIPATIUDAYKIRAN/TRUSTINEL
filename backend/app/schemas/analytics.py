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
    trust_score: int = Field(..., ge=0, le=100, description="Trust score")
    risk_level: str = Field(..., description="Risk level (LOW, MEDIUM, HIGH)")
    summary: str = Field(..., description="Scan summary")
    scanned_at: datetime = Field(..., description="Timestamp of scan")


class DomainAnalyticsResponse(BaseModel):
    domain: str = Field(..., description="Normalized domain name")
    total_scans: int = Field(..., ge=0, description="Total scan count")
    current_trust_score: Optional[int] = Field(None, ge=0, le=100, description="Latest trust score")
    average_trust_score: float = Field(0.0, ge=0.0, le=100.0, description="Average trust score across history")
    min_trust_score: Optional[int] = Field(None, ge=0, le=100, description="Minimum trust score on record")
    max_trust_score: Optional[int] = Field(None, ge=0, le=100, description="Maximum trust score on record")
    score_delta: Optional[int] = Field(None, description="Difference between current score and previous score")
    trend: DomainTrend = Field(DomainTrend.INSUFFICIENT_DATA, description="Historical score trajectory trend")
    risk_distribution: RiskDistribution = Field(default_factory=RiskDistribution, description="Risk level count breakdown")
    first_scanned_at: Optional[datetime] = Field(None, description="First recorded scan timestamp")
    last_scanned_at: Optional[datetime] = Field(None, description="Latest recorded scan timestamp")
    history_timeline: List[DomainScanTimelineItem] = Field(default_factory=list, description="Chronological scan summaries")
