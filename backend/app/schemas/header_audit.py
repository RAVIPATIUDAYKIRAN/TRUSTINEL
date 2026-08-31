from enum import Enum
from typing import Dict, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class HeaderAuditGrade(str, Enum):
    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class CSPDirectiveAnalysis(BaseModel):
    directive_name: str = Field(..., description="Directive name (e.g. script-src, default-src)")
    values: List[str] = Field(default_factory=list, description="Parsed directive source values")
    has_unsafe_inline: bool = Field(False, description="Flag indicating presence of 'unsafe-inline'")
    has_unsafe_eval: bool = Field(False, description="Flag indicating presence of 'unsafe-eval'")
    is_wildcard: bool = Field(False, description="Flag indicating presence of wildcard '*'")


class CSPAnalysisResult(BaseModel):
    is_present: bool = Field(False, description="Flag indicating if Content-Security-Policy header is present")
    raw_header: Optional[str] = Field(None, description="Raw CSP header value")
    directives: Dict[str, CSPDirectiveAnalysis] = Field(default_factory=dict, description="Parsed directives map")
    has_default_src: bool = Field(False, description="Indicates presence of default-src directive")
    has_script_src: bool = Field(False, description="Indicates presence of script-src directive")
    has_unsafe_inline: bool = Field(False, description="Indicates presence of 'unsafe-inline' in any directive")
    has_unsafe_eval: bool = Field(False, description="Indicates presence of 'unsafe-eval' in any directive")
    allows_unrestricted_wildcards: bool = Field(False, description="Indicates unrestricted wildcard sources ('*')")


class HSTSAnalysisResult(BaseModel):
    is_present: bool = Field(False, description="Flag indicating if Strict-Transport-Security header is present")
    raw_header: Optional[str] = Field(None, description="Raw HSTS header value")
    max_age: Optional[int] = Field(None, description="Parsed max-age in seconds")
    includes_subdomains: bool = Field(False, description="Indicates presence of includeSubDomains directive")
    preload: bool = Field(False, description="Indicates presence of preload directive")
    is_strong: bool = Field(False, description="Indicates strong HSTS configuration (max-age >= 31536000 seconds)")


class HeaderAuditResult(BaseModel):
    domain: str = Field(..., description="Target domain evaluated")
    audit_grade: HeaderAuditGrade = Field(HeaderAuditGrade.F, description="Composite security header audit grade (A+ to F)")
    composite_score: int = Field(0, ge=0, le=100, description="Header security composite score (0 to 100)")
    hsts: HSTSAnalysisResult = Field(default_factory=HSTSAnalysisResult, description="HSTS header deep analysis")
    csp: CSPAnalysisResult = Field(default_factory=CSPAnalysisResult, description="CSP header deep analysis")
    x_frame_options: Optional[str] = Field(None, description="X-Frame-Options header raw value")
    x_content_type_options: Optional[str] = Field(None, description="X-Content-Type-Options header raw value")
    referrer_policy: Optional[str] = Field(None, description="Referrer-Policy header raw value")
    permissions_policy: Optional[str] = Field(None, description="Permissions-Policy header raw value")
    present_headers: List[str] = Field(default_factory=list, description="Canonical names of detected security headers")
    missing_headers: List[str] = Field(default_factory=list, description="Canonical names of missing recommended security headers")
    security_findings: List[str] = Field(default_factory=list, description="List of human-readable audit finding strings")
    inspected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Audit timestamp")
