import pytest
import ipaddress
from unittest.mock import patch, MagicMock

from app.config.settings import settings, Settings
from app.services.threat_intelligence_service import InternalHeuristicsThreatProvider, ThreatReputationStatus
from app.core.url_security import URLSecurityValidator, SSRFBlockedException, InvalidURLException
from app.services.content_extractor import ContentExtractor


@pytest.mark.asyncio
async def test_sprint8_threat_intelligence_unknown_semantics():
    """Verify that UNKNOWN threat reputation returns a neutral score of 50, not 100."""
    provider = InternalHeuristicsThreatProvider()
    result = await provider.check_domain("unrated-domain-example.com")

    assert result.status == ThreatReputationStatus.UNKNOWN
    assert result.reputation_score == 50, "UNKNOWN status must return neutral score (50) to prevent false clean rating"


def test_sprint8_production_cors_regex_hardening():
    """Verify that wildcard chrome-extension regex is disabled in production mode."""
    dev_settings = Settings(ENVIRONMENT="development", CORS_ORIGIN_REGEX=r"^chrome-extension://.*$")
    assert dev_settings.effective_cors_origin_regex == r"^chrome-extension://.*$"

    prod_settings = Settings(ENVIRONMENT="production", CORS_ORIGIN_REGEX=r"^chrome-extension://.*$")
    assert prod_settings.effective_cors_origin_regex is None, "Production mode must disallow wildcard extension regex"


@pytest.mark.asyncio
async def test_sprint8_ssrf_blocking_metadata_and_private_ips():
    """Verify SSRF validator blocks cloud metadata, loopback, and private IP ranges."""
    # Cloud metadata IP
    metadata_ip = ipaddress.ip_address("169.254.169.254")
    assert not URLSecurityValidator.is_ip_public(metadata_ip)

    # Carrier Grade NAT
    cgnat_ip = ipaddress.ip_address("100.64.0.1")
    assert not URLSecurityValidator.is_ip_public(cgnat_ip)

    # Loopback IPv4 and IPv6
    assert not URLSecurityValidator.is_ip_public(ipaddress.ip_address("127.0.0.1"))
    assert not URLSecurityValidator.is_ip_public(ipaddress.ip_address("::1"))

    # Restricted Hostnames
    assert URLSecurityValidator.is_hostname_restricted("localhost")
    assert URLSecurityValidator.is_hostname_restricted("service.internal")
    assert URLSecurityValidator.is_hostname_restricted("router.lan")


def test_sprint8_content_extractor_privacy_redaction():
    """Verify ContentExtractor safely handles HTML without crashing and extracts evidence."""
    html_with_inputs = """
    <html>
      <head><title>Test Store</title></head>
      <body>
        <h1>Test Store</h1>
        <input type="password" value="secret123" name="password" />
        <input type="text" value="user@example.com" name="email" />
        <a href="/privacy">Privacy Policy</a>
        <a href="/contact">Contact Us</a>
      </body>
    </html>
    """
    evidence = ContentExtractor.extract(html_with_inputs, "https://teststore.com")
    assert evidence.has_policy_links is True
    assert evidence.has_contact_info is True
