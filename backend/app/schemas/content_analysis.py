from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field
from app.models.enums import RiskLevel


class ContentScamCategory(str, Enum):
    URGENCY = "URGENCY"
    SCARCITY = "SCARCITY"
    EXCESSIVE_DISCOUNT = "EXCESSIVE_DISCOUNT"
    FINANCIAL_CLAIM = "FINANCIAL_CLAIM"
    CREDENTIAL_HARVESTING = "CREDENTIAL_HARVESTING"
    PAYMENT_PRESSURE = "PAYMENT_PRESSURE"
    IMPERSONATION = "IMPERSONATION"
    ECOMMERCE_ANOMALY = "ECOMMERCE_ANOMALY"
    BUSINESS_TRANSPARENCY = "BUSINESS_TRANSPARENCY"


class ContentScamSignal(BaseModel):
    category: ContentScamCategory
    severity: str = Field(description="LOW | MEDIUM | HIGH | CRITICAL")
    evidence: str = Field(description="Exact snippet or structural evidence found on website")
    reason: str = Field(description="Clear explanation of why this finding contributes to risk")


class ExtractedWebsiteEvidence(BaseModel):
    title: Optional[str] = None
    meta_description: Optional[str] = None
    visible_text_sample: str = ""
    headings: List[str] = Field(default_factory=list)
    has_contact_info: bool = False
    has_policy_links: bool = False
    price_claims: List[str] = Field(default_factory=list)
    discount_percentages: List[int] = Field(default_factory=list)
    stock_claims: List[str] = Field(default_factory=list)
    urgency_claims: List[str] = Field(default_factory=list)
    is_sold_out_claimed: bool = False
    has_buy_or_checkout_button: bool = False
    payment_methods_claimed: List[str] = Field(default_factory=list)


class ContentAnalysisResult(BaseModel):
    content_risk_score: int = Field(default=0, ge=0, le=100, description="0=Safe/Clean content, 100=Extreme scam risk")
    content_risk_level: RiskLevel = RiskLevel.LOW
    signals: List[ContentScamSignal] = Field(default_factory=list)
    extracted_evidence: Optional[ExtractedWebsiteEvidence] = None
    summary: str = "Content analysis complete."
