import logging
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.analyzers.base_analyzer import BaseAnalyzer
from app.schemas.website_fetch import WebsiteFetchResult
from app.schemas.header_audit import (
    HeaderAuditResult,
    HeaderAuditGrade,
    HSTSAnalysisResult,
    CSPAnalysisResult,
    CSPDirectiveAnalysis,
)
from app.services.website_fetcher import WebsiteFetcher

logger = logging.getLogger("trustinel.analyzers.header_deep_analyzer")

RECOMMENDED_HEADERS = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def parse_hsts(raw_header: Optional[str]) -> HSTSAnalysisResult:
    if not raw_header:
        return HSTSAnalysisResult(is_present=False)

    lower = raw_header.lower()
    max_age: Optional[int] = None
    max_age_match = re.search(r"max-age=(\d+)", lower)
    if max_age_match:
        try:
            max_age = int(max_age_match.group(1))
        except ValueError:
            pass

    includes_subdomains = "includesubdomains" in lower
    preload = "preload" in lower
    is_strong = (max_age is not None and max_age >= 31536000 and includes_subdomains)

    return HSTSAnalysisResult(
        is_present=True,
        raw_header=raw_header,
        max_age=max_age,
        includes_subdomains=includes_subdomains,
        preload=preload,
        is_strong=is_strong
    )


def parse_csp(raw_header: Optional[str]) -> CSPAnalysisResult:
    if not raw_header:
        return CSPAnalysisResult(is_present=False)

    directives_map: Dict[str, CSPDirectiveAnalysis] = {}
    tokens = raw_header.split(";")

    has_unsafe_inline = False
    has_unsafe_eval = False
    allows_wildcard = False

    for token in tokens:
        token = token.strip()
        if not token:
            continue

        parts = token.split()
        dir_name = parts[0].lower()
        dir_values = [p.lower() for p in parts[1:]]

        dir_inline = "'unsafe-inline'" in dir_values or "unsafe-inline" in dir_values
        dir_eval = "'unsafe-eval'" in dir_values or "unsafe-eval" in dir_values
        dir_wildcard = "*" in dir_values

        if dir_inline:
            has_unsafe_inline = True
        if dir_eval:
            has_unsafe_eval = True
        if dir_wildcard:
            allows_wildcard = True

        directives_map[dir_name] = CSPDirectiveAnalysis(
            directive_name=dir_name,
            values=dir_values,
            has_unsafe_inline=dir_inline,
            has_unsafe_eval=dir_eval,
            is_wildcard=dir_wildcard
        )

    return CSPAnalysisResult(
        is_present=True,
        raw_header=raw_header,
        directives=directives_map,
        has_default_src="default-src" in directives_map,
        has_script_src="script-src" in directives_map,
        has_unsafe_inline=has_unsafe_inline,
        has_unsafe_eval=has_unsafe_eval,
        allows_unrestricted_wildcards=allows_wildcard
    )


class HeaderDeepAnalyzer(BaseAnalyzer):
    """
    Analyzer evaluating HTTP security response headers, CSP directives,
    HSTS configurations, header security composite scores, and audit grades.
    """

    async def analyze(self, fetch_result: WebsiteFetchResult) -> HeaderAuditResult:
        domain = fetch_result.domain or fetch_result.original_url
        headers = fetch_result.response_headers or {}
        return self.audit_headers(domain, headers)

    async def audit_domain(self, domain: str) -> HeaderAuditResult:
        fetcher = WebsiteFetcher(timeout_seconds=10.0)
        url = f"https://{domain}" if not domain.startswith(("http://", "https://")) else domain
        fetch_res = await fetcher.fetch(url)
        headers = fetch_res.response_headers or {}
        return self.audit_headers(domain, headers)

    def audit_headers(self, domain: str, headers: Dict[str, str]) -> HeaderAuditResult:
        clean_domain = domain.strip().lower()
        norm_headers = {k.lower(): v for k, v in headers.items()}

        findings: List[str] = []
        present_headers: List[str] = []
        missing_headers: List[str] = []

        # Header presence check
        for lower_key, canonical in RECOMMENDED_HEADERS.items():
            if lower_key in norm_headers:
                present_headers.append(canonical)
            else:
                missing_headers.append(canonical)

        # 1. HSTS Analysis
        raw_hsts = norm_headers.get("strict-transport-security")
        hsts = parse_hsts(raw_hsts)
        if not hsts.is_present:
            findings.append("Missing Strict-Transport-Security (HSTS) header.")
        elif not hsts.is_strong:
            findings.append("Weak HSTS configuration: max-age is under 1 year (31,536,000s) or missing includeSubDomains.")

        # 2. CSP Analysis
        raw_csp = norm_headers.get("content-security-policy")
        csp = parse_csp(raw_csp)
        if not csp.is_present:
            findings.append("Missing Content-Security-Policy (CSP) header.")
        else:
            if csp.has_unsafe_inline:
                findings.append("Weak CSP directive: 'unsafe-inline' enabled in policy (vulnerable to XSS).")
            if csp.has_unsafe_eval:
                findings.append("Weak CSP directive: 'unsafe-eval' enabled in policy.")
            if csp.allows_unrestricted_wildcards:
                findings.append("Weak CSP directive: Unrestricted wildcard '*' allowed in directive sources.")

        # 3. X-Frame-Options
        xfo = norm_headers.get("x-frame-options")
        if not xfo:
            findings.append("Missing X-Frame-Options header (vulnerable to clickjacking).")
        elif xfo.upper() not in ("DENY", "SAMEORIGIN"):
            findings.append(f"Non-standard X-Frame-Options value ('{xfo}').")

        # 4. X-Content-Type-Options
        xcto = norm_headers.get("x-content-type-options")
        if not xcto:
            findings.append("Missing X-Content-Type-Options header (vulnerable to MIME-sniffing).")
        elif xcto.lower() != "nosniff":
            findings.append(f"X-Content-Type-Options is not set to 'nosniff' ('{xcto}').")

        # 5. Referrer-Policy & Permissions-Policy
        rp = norm_headers.get("referrer-policy")
        if not rp:
            findings.append("Missing Referrer-Policy header.")

        pp = norm_headers.get("permissions-policy")
        if not pp:
            findings.append("Missing Permissions-Policy header.")

        # Composite Score Calculation (0 to 100)
        score = 0

        # HSTS Scoring (max 25)
        if hsts.is_present:
            score += 15
            if hsts.is_strong:
                score += 10

        # CSP Scoring (max 35)
        if csp.is_present:
            score += 25
            if not csp.has_unsafe_inline:
                score += 5
            if not csp.has_unsafe_eval:
                score += 5
            if csp.has_unsafe_inline:
                score -= 10
            if csp.has_unsafe_eval:
                score -= 10

        # X-Frame-Options Scoring (max 15)
        if xfo and xfo.upper() in ("DENY", "SAMEORIGIN"):
            score += 15

        # X-Content-Type-Options Scoring (max 10)
        if xcto and xcto.lower() == "nosniff":
            score += 10

        # Referrer Policy (max 8)
        if rp:
            score += 8

        # Permissions Policy (max 7)
        if pp:
            score += 7

        score = max(0, min(100, score))

        # Map to Grade
        if score >= 90:
            grade = HeaderAuditGrade.A_PLUS
        elif score >= 80:
            grade = HeaderAuditGrade.A
        elif score >= 70:
            grade = HeaderAuditGrade.B
        elif score >= 55:
            grade = HeaderAuditGrade.C
        elif score >= 40:
            grade = HeaderAuditGrade.D
        else:
            grade = HeaderAuditGrade.F

        if not findings:
            findings.append("All recommended HTTP security headers are cleanly configured.")

        return HeaderAuditResult(
            domain=clean_domain,
            audit_grade=grade,
            composite_score=score,
            hsts=hsts,
            csp=csp,
            x_frame_options=xfo,
            x_content_type_options=xcto,
            referrer_policy=rp,
            permissions_policy=pp,
            present_headers=present_headers,
            missing_headers=missing_headers,
            security_findings=findings,
            inspected_at=datetime.now(timezone.utc)
        )
