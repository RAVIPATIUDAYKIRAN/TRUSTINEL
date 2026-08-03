"""
Module containing the SSLAnalyzer service implementation for assessing SSL certificates.
"""
import _ssl
import asyncio
import logging
import os
import ssl
import tempfile
import urllib.parse
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from app.analyzers.base_analyzer import BaseAnalyzer
from app.schemas.website_fetch import WebsiteFetchResult
from app.schemas.ssl_analysis import SSLAnalysisResult

logger = logging.getLogger("trustinel.analyzers.ssl_analyzer")


class SSLAnalyzer(BaseAnalyzer):
    """
    Concrete analyzer responsible for establishing secure handshakes,
    inspecting peer certificates, and mapping cryptographic validity metadata.
    """

    def _extract_hostname(self, url: str) -> str:
        """
        Helper method to extract the hostname from a URL.
        """
        cleaned_url = url.strip()
        if not cleaned_url.startswith(("http://", "https://")):
            # Add temporary scheme to allow urlparse to resolve host cleanly
            cleaned_url = "https://" + cleaned_url
        parsed = urllib.parse.urlparse(cleaned_url)
        hostname = parsed.hostname or parsed.netloc
        if hostname and ":" in hostname:
            hostname = hostname.split(":")[0]
        return hostname or cleaned_url

    def _extract_cn(self, rdn_tuple: Any) -> Optional[str]:
        """
        Helper method to extract the commonName value from an RDN tuple.
        """
        if not rdn_tuple:
            return None
        for item in rdn_tuple:
            for key, val in item:
                if key == "commonName":
                    return val
        # Fallback to formatting everything
        parts = []
        for item in rdn_tuple:
            for key, val in item:
                parts.append(f"{key}={val}")
        return ", ".join(parts) if parts else None

    def _extract_issuer_org(self, rdn_tuple: Any) -> Optional[str]:
        """
        Helper method to extract organizationName (falling back to commonName) from an RDN tuple.
        """
        if not rdn_tuple:
            return None
        org = None
        cn = None
        for item in rdn_tuple:
            for key, val in item:
                if key == "organizationName":
                    org = val
                elif key == "commonName":
                    cn = val
        if org and cn:
            return f"{org} ({cn})"
        return org or cn or self._extract_cn(rdn_tuple)

    async def analyze(self, fetch_result: WebsiteFetchResult) -> SSLAnalysisResult:
        """
        Asynchronously connects to the target website to fetch and analyze its SSL certificate.
        """
        target_url = fetch_result.final_url or fetch_result.original_url
        hostname = self._extract_hostname(target_url)

        initial_error: Optional[Exception] = None
        peercert: Optional[Dict[str, Any]] = None
        tls_version: Optional[str] = None

        # 1. Attempt standard secure connection with verification context
        try:
            ssl_context = ssl.create_default_context()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, 443, ssl=ssl_context, server_hostname=hostname),
                timeout=5.0
            )
            ssl_obj = writer.transport.get_extra_info("ssl_object")
            peercert = ssl_obj.getpeercert()
            tls_version = ssl_obj.version()
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            initial_error = e

        # 2. If standard handshake fails, try connecting without validation to read the cert anyway
        if initial_error is not None:
            try:
                ssl_context_none = ssl.create_default_context()
                ssl_context_none.check_hostname = False
                ssl_context_none.verify_mode = ssl.CERT_NONE

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, 443, ssl=ssl_context_none, server_hostname=hostname),
                    timeout=5.0
                )
                ssl_obj = writer.transport.get_extra_info("ssl_object")
                der_cert = ssl_obj.getpeercert(binary_form=True)
                tls_version = ssl_obj.version()
                writer.close()
                await writer.wait_closed()

                if der_cert:
                    pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
                    fd, temp_path = tempfile.mkstemp()
                    try:
                        with open(temp_path, "w") as f:
                            f.write(pem_cert)
                        peercert = _ssl._test_decode_cert(temp_path)
                    finally:
                        os.close(fd)
                        try:
                            os.remove(temp_path)
                        except OSError:
                            pass
            except Exception as fallback_err:
                logger.warning(f"Connection failure to '{hostname}' during fallback fetch: {fallback_err}")
                return SSLAnalysisResult(
                    is_valid=False,
                    error=f"Connection failed: {str(initial_error)}"
                )

        # 3. Parse decoded certificate attributes
        issuer = None
        subject = None
        valid_from = None
        expires_on = None
        days_remaining = None

        if peercert:
            issuer = self._extract_issuer_org(peercert.get("issuer"))
            subject = self._extract_cn(peercert.get("subject"))

            not_before_str = peercert.get("notBefore")
            not_after_str = peercert.get("notAfter")

            if not_before_str:
                try:
                    valid_from_ts = ssl.cert_time_to_seconds(not_before_str)
                    valid_from = datetime.fromtimestamp(valid_from_ts, timezone.utc)
                except Exception:
                    pass

            if not_after_str:
                try:
                    expires_on_ts = ssl.cert_time_to_seconds(not_after_str)
                    expires_on = datetime.fromtimestamp(expires_on_ts, timezone.utc)
                except Exception:
                    pass

            if expires_on:
                now = datetime.now(timezone.utc)
                days_remaining = (expires_on - now).days

        # Determine validity flag
        is_valid = (initial_error is None)
        if is_valid and valid_from and expires_on:
            now = datetime.now(timezone.utc)
            is_valid = (valid_from <= now <= expires_on)

        error_message = str(initial_error) if initial_error else None

        return SSLAnalysisResult(
            issuer=issuer,
            subject=subject,
            valid_from=valid_from,
            expires_on=expires_on,
            days_remaining=days_remaining,
            is_valid=is_valid,
            tls_version=tls_version,
            error=error_message
        )
