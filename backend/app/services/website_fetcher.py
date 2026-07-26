import logging
import time
from typing import Optional
import httpx

from app.schemas.website_fetch import WebsiteFetchResult

logger = logging.getLogger("trustinel.services.website_fetcher")


class WebsiteFetcher:
    """
    Asynchronous helper service responsible for fetching HTML content and
    metadata (headers, response time, redirects) for target URLs.
    """
    def __init__(self, timeout_seconds: float = 10.0) -> None:
        self.timeout_seconds = timeout_seconds

    async def fetch(self, url: str) -> WebsiteFetchResult:
        """
        Fetches web page content asynchronously, recording redirect steps,
        timing metrics, and capturing response headers/errors cleanly.
        """
        # Configure custom User-Agent to emulate standard secure browser requests
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        }

        start_time = time.perf_counter()

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds,
                follow_redirects=True,
                headers=headers
            ) as client:
                response = await client.get(url)
                elapsed = round((time.perf_counter() - start_time) * 1000, 2)
                
                return WebsiteFetchResult(
                    original_url=url,
                    final_url=str(response.url),
                    status_code=response.status_code,
                    response_time_ms=elapsed,
                    response_headers=dict(response.headers),
                    html_content=response.text,
                    redirect_count=len(response.history),
                    error=None
                )

        except httpx.TimeoutException as e:
            elapsed = round((time.perf_counter() - start_time) * 1000, 2)
            logger.warning(f"Timeout occurred fetching URL '{url}': {e}")
            return WebsiteFetchResult(
                original_url=url,
                response_time_ms=elapsed,
                error="Request timed out."
            )
            
        except httpx.ConnectError as e:
            elapsed = round((time.perf_counter() - start_time) * 1000, 2)
            logger.warning(f"Connection failure fetching URL '{url}': {e}")
            return WebsiteFetchResult(
                original_url=url,
                response_time_ms=elapsed,
                error="Failed to connect to the target host."
            )

        except httpx.HTTPStatusError as e:
            elapsed = round((time.perf_counter() - start_time) * 1000, 2)
            logger.warning(f"HTTP status error fetching URL '{url}': {e}")
            return WebsiteFetchResult(
                original_url=url,
                final_url=str(e.response.url),
                status_code=e.response.status_code,
                response_time_ms=elapsed,
                response_headers=dict(e.response.headers),
                html_content=e.response.text,
                redirect_count=len(e.response.history),
                error=f"HTTP error status: {e.response.status_code}"
            )

        except httpx.RequestError as e:
            # Catches other request errors (SSL errors, dns resolution failures, protocol errors, etc.)
            elapsed = round((time.perf_counter() - start_time) * 1000, 2)
            logger.warning(f"Request error fetching URL '{url}': {e}")
            return WebsiteFetchResult(
                original_url=url,
                response_time_ms=elapsed,
                error=f"Request failed: {str(e)}"
            )

        except Exception as e:
            elapsed = round((time.perf_counter() - start_time) * 1000, 2)
            logger.exception(f"Unexpected error fetching URL '{url}': {e}")
            return WebsiteFetchResult(
                original_url=url,
                response_time_ms=elapsed,
                error=f"Unexpected error: {str(e)}"
            )

