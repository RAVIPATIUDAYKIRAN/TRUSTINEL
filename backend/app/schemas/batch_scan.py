from typing import List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from app.schemas.reputation import ReputationResult
from app.schemas.phishing import PhishingImpersonationResult
from app.schemas.ssl_deep_inspection import SSLDeepInspectionResult
from app.schemas.header_audit import HeaderAuditResult


class BatchScanRequest(BaseModel):
    domains: List[str] = Field(
        ...,
        min_length=1,
        max_length=20,
        description="List of target domain names to analyze (maximum 20 domains per batch)"
    )
    include_reputation: bool = Field(True, description="Include domain reputation analysis")
    include_phishing: bool = Field(True, description="Include phishing & typosquatting analysis")
    include_ssl: bool = Field(True, description="Include SSL deep cryptographic inspection")
    include_headers: bool = Field(True, description="Include HTTP security header audit")
    bypass_cache: bool = Field(False, description="Bypass cached threat intelligence and force fresh analysis")


class DomainBatchItemResult(BaseModel):
    domain: str = Field(..., description="Raw input domain string")
    normalized_domain: str = Field(..., description="Normalized domain name")
    is_success: bool = Field(True, description="Flag indicating successful per-domain evaluation")
    is_cached: bool = Field(False, description="Flag indicating if results were served from cache")
    reputation: Optional[ReputationResult] = Field(None, description="Reputation analysis result")
    phishing: Optional[PhishingImpersonationResult] = Field(None, description="Phishing impersonation result")
    ssl_inspection: Optional[SSLDeepInspectionResult] = Field(None, description="SSL deep inspection result")
    header_audit: Optional[HeaderAuditResult] = Field(None, description="Header audit result")
    error: Optional[str] = Field(None, description="Error details if per-domain analysis failed")
    error_code: Optional[str] = Field(None, description="Error code string (e.g. INVALID_DOMAIN, URL_NOT_ALLOWED)")


class BatchScanResponse(BaseModel):
    total_requested: int = Field(..., ge=0, description="Total count of requested domains in batch")
    successful_count: int = Field(..., ge=0, description="Count of successfully analyzed domains")
    failed_count: int = Field(..., ge=0, description="Count of failed or blocked domains")
    cache_hit_count: int = Field(..., ge=0, description="Count of domains served from cache")
    results: List[DomainBatchItemResult] = Field(default_factory=list, description="Per-domain batch item results")
    processed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Batch processing timestamp")
