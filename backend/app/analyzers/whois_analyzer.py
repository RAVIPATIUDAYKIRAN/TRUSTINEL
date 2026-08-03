"""
Module containing the WHOISAnalyzer service implementation for domain registration analysis.
"""
import asyncio
import logging
import urllib.parse
from datetime import datetime, timezone
from typing import Optional, List, Any

import whois

from app.analyzers.base_analyzer import BaseAnalyzer
from app.schemas.website_fetch import WebsiteFetchResult
from app.schemas.whois_analysis import WHOISAnalysisResult

logger = logging.getLogger("trustinel.analyzers.whois_analyzer")


class WHOISAnalyzer(BaseAnalyzer):
    """
    Concrete analyzer responsible for fetching and parsing WHOIS registry
    data including registrar details, domain lifecycle timestamps, and
    authoritative name server listings.
    """

    def _extract_hostname(self, url: str) -> str:
        """
        Helper method to extract the hostname from a URL.
        """
        cleaned_url = url.strip()
        if not cleaned_url.startswith(("http://", "https://")):
            cleaned_url = "https://" + cleaned_url
        parsed = urllib.parse.urlparse(cleaned_url)
        hostname = parsed.hostname or parsed.netloc
        if hostname and ":" in hostname:
            hostname = hostname.split(":")[0]
        return hostname or cleaned_url

    def _normalize_date(self, value: Any) -> Optional[datetime]:
        """
        Normalizes a date value that may be a single datetime, a list of
        datetimes, or None into a single timezone-aware UTC datetime.
        """
        if value is None:
            return None
        if isinstance(value, list):
            value = value[0] if value else None
        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        return None

    def _normalize_string(self, value: Any) -> Optional[str]:
        """
        Normalizes a string value that may be a list or None.
        """
        if value is None:
            return None
        if isinstance(value, list):
            return value[0] if value else None
        return str(value) if value else None

    def _normalize_name_servers(self, value: Any) -> List[str]:
        """
        Normalizes name server entries into a clean lowercase list of strings.
        """
        if not value:
            return []
        if isinstance(value, str):
            return [value.lower().strip()]
        if isinstance(value, (list, set)):
            result = []
            for ns in value:
                if ns:
                    result.append(str(ns).lower().strip())
            return sorted(set(result))
        return []

    async def analyze(self, fetch_result: WebsiteFetchResult) -> WHOISAnalysisResult:
        """
        Asynchronously performs a WHOIS lookup on the target domain and
        maps available registry information into a structured result model.
        """
        target_url = fetch_result.final_url or fetch_result.original_url
        hostname = self._extract_hostname(target_url)

        try:
            w = await asyncio.wait_for(
                asyncio.to_thread(whois.whois, hostname),
                timeout=15.0
            )
        except asyncio.TimeoutError:
            logger.warning(f"WHOIS lookup timed out for '{hostname}'")
            return WHOISAnalysisResult(
                is_registered=False,
                error=f"WHOIS lookup timed out for domain: {hostname}"
            )
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for '{hostname}': {e}")
            return WHOISAnalysisResult(
                is_registered=False,
                error=f"WHOIS lookup failed: {str(e)}"
            )

        # Parse fields from the WHOIS result
        registrar = self._normalize_string(getattr(w, "registrar", None))
        creation_date = self._normalize_date(getattr(w, "creation_date", None))
        expiration_date = self._normalize_date(getattr(w, "expiration_date", None))
        updated_date = self._normalize_date(getattr(w, "updated_date", None))
        country = self._normalize_string(getattr(w, "country", None))
        name_servers = self._normalize_name_servers(getattr(w, "name_servers", None))

        # Calculate domain age
        domain_age_days: Optional[int] = None
        if creation_date:
            now_utc = datetime.now(timezone.utc)
            domain_age_days = (now_utc - creation_date).days

        # Determine registration status
        is_registered = bool(registrar or creation_date or name_servers)

        if not is_registered:
            return WHOISAnalysisResult(
                is_registered=False,
                error=f"No WHOIS registration data found for domain: {hostname}"
            )

        return WHOISAnalysisResult(
            registrar=registrar,
            creation_date=creation_date,
            expiration_date=expiration_date,
            updated_date=updated_date,
            domain_age_days=domain_age_days,
            country=country,
            name_servers=name_servers,
            is_registered=True,
            error=None
        )
