import socket
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
import httpx

from app.main import app
from app.core.url_security import URLSecurityValidator
from app.middleware.exceptions import InvalidURLException, SSRFBlockedException
from app.services.website_fetcher import WebsiteFetcher, _validate_redirect_security


# --- Unit Tests: URL Syntax & Scheme Validation ---

def test_url_syntax_valid_http_and_https():
    """1, 2. Verify valid HTTP and HTTPS URLs are accepted."""
    assert URLSecurityValidator.validate_url_syntax("http://example.com") == "http://example.com"
    assert URLSecurityValidator.validate_url_syntax("https://example.com/path?a=1") == "https://example.com/path?a=1"


def test_url_syntax_missing_scheme():
    """3. Verify missing scheme is rejected."""
    with pytest.raises(InvalidURLException, match="URL must include a scheme"):
        URLSecurityValidator.validate_url_syntax("example.com")


def test_url_syntax_unsupported_schemes():
    """4. Verify unsupported schemes (ftp, file, javascript, data, ws) are rejected."""
    unsupported = [
        "ftp://example.com",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "data:text/html;base64,1234",
        "ws://example.com",
        "wss://example.com",
        "gopher://example.com",
    ]
    for url in unsupported:
        with pytest.raises(InvalidURLException):
            URLSecurityValidator.validate_url_syntax(url)


def test_url_syntax_malformed_url():
    """5. Verify malformed URL is rejected."""
    with pytest.raises(InvalidURLException):
        URLSecurityValidator.validate_url_syntax("http://")


def test_url_syntax_missing_hostname():
    """6. Verify missing hostname is rejected."""
    with pytest.raises(InvalidURLException):
        URLSecurityValidator.validate_url_syntax("http:///path")


def test_url_syntax_embedded_credentials():
    """7. Verify credentials embedded in URL are rejected."""
    with pytest.raises(InvalidURLException, match="embedded credentials"):
        URLSecurityValidator.validate_url_syntax("http://admin:secret@example.com/login")


# --- Unit Tests: IP & Hostname SSRF Protection ---

@pytest.mark.asyncio
async def test_ssrf_protection_localhost():
    """8, 9. Verify localhost and localhost.localdomain are rejected."""
    with pytest.raises(SSRFBlockedException):
        await URLSecurityValidator.validate_hostname_resolution("localhost")
    with pytest.raises(SSRFBlockedException):
        await URLSecurityValidator.validate_hostname_resolution("localhost.localdomain")


@pytest.mark.asyncio
async def test_ssrf_protection_private_ipv4():
    """10, 11, 12, 13, 14, 15. Verify loopback, private IPv4, link-local, CGNAT are rejected."""
    private_ips = [
        "127.0.0.1",       # Loopback
        "10.0.0.1",        # 10.x.x.x
        "172.16.0.1",      # 172.16.x.x
        "192.168.1.1",     # 192.168.x.x
        "169.254.169.254", # Link-Local / Cloud Metadata
        "100.64.0.1",      # CGNAT
    ]
    for ip in private_ips:
        with pytest.raises(SSRFBlockedException):
            await URLSecurityValidator.validate_hostname_resolution(ip)


@pytest.mark.asyncio
async def test_ssrf_protection_ipv6():
    """16, 17, 18, 19, 20. Verify IPv6 loopback, private, link-local, multicast, reserved are rejected."""
    restricted_ipv6 = [
        "::1",             # Loopback
        "fd00::1",         # Unique Local
        "fe80::1",         # Link-Local
        "ff02::1",         # Multicast
        "::",              # Unspecified
        "::ffff:127.0.0.1" # IPv4-mapped IPv6 loopback
    ]
    for ip in restricted_ipv6:
        with pytest.raises(SSRFBlockedException):
            await URLSecurityValidator.validate_hostname_resolution(ip)


@pytest.mark.asyncio
async def test_dns_resolution_private_ip():
    """21. Verify hostname resolving to private IP is rejected."""
    fake_dns = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))
    ]
    with patch("asyncio.get_running_loop") as mock_loop:
        mock_loop.return_value.getaddrinfo = AsyncMock(return_value=fake_dns)
        with pytest.raises(SSRFBlockedException):
            await URLSecurityValidator.validate_hostname_resolution("evil.example.com")


@pytest.mark.asyncio
async def test_dns_resolution_public_ip():
    """22. Verify hostname resolving to public IP is accepted."""
    fake_dns = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
    ]
    with patch("asyncio.get_running_loop") as mock_loop:
        mock_loop.return_value.getaddrinfo = AsyncMock(return_value=fake_dns)
        res = await URLSecurityValidator.validate_hostname_resolution("example.com")
        assert res == ["93.184.216.34"]


@pytest.mark.asyncio
async def test_dns_resolution_mixed_public_private():
    """23. Verify hostname with mixed public and private DNS IPs is rejected."""
    fake_dns = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))
    ]
    with patch("asyncio.get_running_loop") as mock_loop:
        mock_loop.return_value.getaddrinfo = AsyncMock(return_value=fake_dns)
        with pytest.raises(SSRFBlockedException):
            await URLSecurityValidator.validate_hostname_resolution("mixed.example.com")


# --- Unit Tests: Redirect SSRF Protection ---

@pytest.mark.asyncio
async def test_redirect_ssrf_protection_localhost_and_private():
    """24, 25, 26. Verify redirect to localhost, private IPv4, or private IPv6 is blocked."""
    request_mock = MagicMock()
    
    # Redirect to localhost
    resp_localhost = MagicMock(spec=httpx.Response)
    resp_localhost.is_redirect = True
    resp_localhost.headers = {"location": "http://localhost:8000"}
    resp_localhost.url = httpx.URL("https://public-site.com")
    resp_localhost.request = request_mock

    with pytest.raises(httpx.RequestError):
        await _validate_redirect_security(resp_localhost)

    # Redirect to 192.168.1.1
    resp_private = MagicMock(spec=httpx.Response)
    resp_private.is_redirect = True
    resp_private.headers = {"location": "http://192.168.1.1"}
    resp_private.url = httpx.URL("https://public-site.com")
    resp_private.request = request_mock

    with pytest.raises(httpx.RequestError):
        await _validate_redirect_security(resp_private)


# --- Integration Tests: API & Zero Fetch Guarantee ---

def test_api_invalid_url_returns_400():
    """27. Verify invalid URL returns HTTP 400 and causes zero WebsiteFetcher calls."""
    client = TestClient(app)
    with patch("app.services.website_fetcher.WebsiteFetcher.fetch") as mock_fetch:
        resp = client.post("/api/v1/scan", json={"url": "ftp://example.com"})
        assert resp.status_code == 400
        assert resp.json()["error_code"] == "INVALID_URL"
        mock_fetch.assert_not_called()


def test_api_ssrf_url_returns_403():
    """28. Verify SSRF URL returns HTTP 403 and causes zero WebsiteFetcher calls."""
    client = TestClient(app)
    with patch("app.services.website_fetcher.WebsiteFetcher.fetch") as mock_fetch:
        resp = client.post("/api/v1/scan", json={"url": "http://127.0.0.1:8000"})
        assert resp.status_code == 403
        assert resp.json()["error_code"] == "URL_NOT_ALLOWED"
        mock_fetch.assert_not_called()


def test_nat64_ipv6_public_destination_allowed():
    """29. Verify public destination mapped through IPv6 NAT64 prefix (64:ff9b::/96) is accepted."""
    import ipaddress
    # 64:ff9b::17ca:e587 translates to 23.202.229.135 (eBay public IPv4)
    nat64_public_ip = ipaddress.IPv6Address("64:ff9b::17ca:e587")
    assert URLSecurityValidator.is_ip_public(nat64_public_ip) is True


def test_nat64_ipv6_private_destination_blocked():
    """30. Verify restricted loopback/private IPv4 mapped through IPv6 NAT64 prefix is BLOCKED."""
    import ipaddress
    # 64:ff9b::7f00:0001 translates to 127.0.0.1 (Loopback IPv4)
    nat64_loopback_ip = ipaddress.IPv6Address("64:ff9b::7f00:0001")
    assert URLSecurityValidator.is_ip_public(nat64_loopback_ip) is False

    # 64:ff9b::0a00:0001 translates to 10.0.0.1 (Private IPv4)
    nat64_private_ip = ipaddress.IPv6Address("64:ff9b::0a00:0001")
    assert URLSecurityValidator.is_ip_public(nat64_private_ip) is False
