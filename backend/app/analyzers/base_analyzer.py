"""
Module containing the abstract base interface for all trust website analyzers.
"""
from abc import ABC, abstractmethod
from typing import Any
from app.schemas.website_fetch import WebsiteFetchResult


class BaseAnalyzer(ABC):
    """
    Abstract Base Class enforcing the standard asynchronous contract for
    analyzing specific characteristics of fetched websites.
    """

    @abstractmethod
    async def analyze(self, fetch_result: WebsiteFetchResult) -> Any:
        """
        Analyze one aspect of a fetched website (e.g. SSL, headers, WHOIS, redirects, etc.)
        based on the provided fetch metadata and HTML content.
        """
        raise NotImplementedError("Concrete analyzers must implement analyze() method.")
