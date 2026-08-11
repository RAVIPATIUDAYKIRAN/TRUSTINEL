"""
Module containing the RedirectAnalyzer service implementation for evaluating redirect behavior.
"""
import logging
import urllib.parse
from typing import Optional

from app.analyzers.base_analyzer import BaseAnalyzer
from app.schemas.website_fetch import WebsiteFetchResult
from app.schemas.redirect_analysis import RedirectAnalysisResult

logger = logging.getLogger("trustinel.analyzers.redirect_analyzer")


class RedirectAnalyzer(BaseAnalyzer):
    """
    Concrete analyzer responsible for evaluating HTTP redirect chains,
    detecting cross-domain redirects, HTTPS upgrades, and assessing
    overall redirect safety.
    """

    def _normalize_hostname(self, hostname: Optional[str]) -> str:
        """
        Normalizes a hostname by stripping the 'www.' prefix and lowering case.
        """
        if not hostname:
            return ""
        hostname = hostname.lower().strip()
        if hostname.startswith("www."):
            hostname = hostname[4:]
        return hostname

    def _parse_hostname(self, url: Optional[str]) -> Optional[str]:
        """
        Extracts and returns the hostname from a URL string.
        """
        if not url:
            return None
        try:
            cleaned = url.strip()
            if not cleaned.startswith(("http://", "https://")):
                cleaned = "https://" + cleaned
            parsed = urllib.parse.urlparse(cleaned)
            return parsed.hostname
        except Exception:
            return None

    def _parse_scheme(self, url: Optional[str]) -> Optional[str]:
        """
        Extracts and returns the scheme from a URL string.
        """
        if not url:
            return None
        try:
            cleaned = url.strip()
            if not cleaned.startswith(("http://", "https://")):
                return None
            parsed = urllib.parse.urlparse(cleaned)
            return parsed.scheme.lower() if parsed.scheme else None
        except Exception:
            return None

    async def analyze(self, fetch_result: WebsiteFetchResult) -> RedirectAnalysisResult:
        """
        Evaluates redirect behavior by comparing original and final URLs,
        checking for cross-domain redirections, HTTPS upgrades, and assessing
        overall redirect safety based on configurable rules.
        """
        original_url = fetch_result.original_url
        final_url = fetch_result.final_url
        redirect_count = fetch_result.redirect_count

        # Parse hostnames
        original_host = self._parse_hostname(original_url)
        final_host = self._parse_hostname(final_url)

        if not original_host:
            logger.warning(f"Failed to parse hostname from original URL: '{original_url}'")
            return RedirectAnalysisResult(
                redirect_count=redirect_count,
                redirected=redirect_count > 0,
                final_url=final_url,
                same_domain=False,
                https_upgrade=False,
                cross_domain_redirect=False,
                is_safe_redirect=False,
                error=f"Failed to parse hostname from original URL: {original_url}"
            )

        # Normalize hostnames for comparison
        norm_original = self._normalize_hostname(original_host)
        norm_final = self._normalize_hostname(final_host)

        # Determine redirect flags
        redirected = redirect_count > 0
        same_domain = (norm_original == norm_final) if norm_final else True
        cross_domain_redirect = not same_domain if redirected else False

        # Detect HTTPS upgrade
        original_scheme = self._parse_scheme(original_url)
        final_scheme = self._parse_scheme(final_url)
        https_upgrade = (original_scheme == "http" and final_scheme == "https")

        # Evaluate redirect safety
        is_safe_redirect = (
            redirect_count <= 3
            and final_url is not None
            and not cross_domain_redirect
        )

        return RedirectAnalysisResult(
            redirect_count=redirect_count,
            redirected=redirected,
            final_url=final_url,
            same_domain=same_domain,
            https_upgrade=https_upgrade,
            cross_domain_redirect=cross_domain_redirect,
            is_safe_redirect=is_safe_redirect,
            error=None
        )
