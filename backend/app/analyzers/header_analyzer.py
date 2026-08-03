"""
Module containing the HeaderAnalyzer service implementation for evaluating HTTP security headers.
"""
import logging
from typing import Dict

from app.analyzers.base_analyzer import BaseAnalyzer
from app.schemas.website_fetch import WebsiteFetchResult
from app.schemas.header_analysis import HeaderAnalysisResult

logger = logging.getLogger("trustinel.analyzers.header_analyzer")

# Map of canonical header names to their corresponding result field names
SECURITY_HEADER_MAP: Dict[str, str] = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


class HeaderAnalyzer(BaseAnalyzer):
    """
    Concrete analyzer responsible for inspecting HTTP response headers and
    assessing the presence of recommended security headers.
    """

    async def analyze(self, fetch_result: WebsiteFetchResult) -> HeaderAnalysisResult:
        """
        Evaluates the response headers collected during the website fetch for
        the presence of known security headers and returns a scored result.
        """
        headers = fetch_result.response_headers

        if not headers:
            logger.warning(
                f"No response headers available for URL '{fetch_result.original_url}'"
            )
            return HeaderAnalysisResult(
                strict_transport_security=False,
                content_security_policy=False,
                x_frame_options=False,
                x_content_type_options=False,
                referrer_policy=False,
                permissions_policy=False,
                security_headers_score=0,
                missing_headers=list(SECURITY_HEADER_MAP.values()),
                error="No response headers available for analysis."
            )

        # Normalize all header names to lowercase for case-insensitive matching
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        hsts = "strict-transport-security" in normalized_headers
        csp = "content-security-policy" in normalized_headers
        xfo = "x-frame-options" in normalized_headers
        xcto = "x-content-type-options" in normalized_headers
        rp = "referrer-policy" in normalized_headers
        pp = "permissions-policy" in normalized_headers

        present_flags = [hsts, csp, xfo, xcto, rp, pp]
        score = sum(present_flags)

        # Build list of missing header canonical names
        missing_headers = [
            canonical
            for (lower, canonical), present in zip(SECURITY_HEADER_MAP.items(), present_flags)
            if not present
        ]

        return HeaderAnalysisResult(
            strict_transport_security=hsts,
            content_security_policy=csp,
            x_frame_options=xfo,
            x_content_type_options=xcto,
            referrer_policy=rp,
            permissions_policy=pp,
            security_headers_score=score,
            missing_headers=missing_headers,
            error=None
        )
