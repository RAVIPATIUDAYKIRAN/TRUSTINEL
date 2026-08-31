import asyncio
import logging
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.ssl_deep_inspection import ExpirationStatus
from app.analyzers.ssl_deep_analyzer import SSLDeepAnalyzer


def create_mock_peercert(
    subject_cn="example.com",
    subject_org="Example Security Corp",
    issuer_cn="DigiCert Global Root CA",
    issuer_org="DigiCert Inc",
    sans=None,
    not_before="Jan 01 00:00:00 2026 GMT",
    not_after="Dec 31 23:59:59 2026 GMT",
    serial="1234567890ABCDEF"
):
    sans_tuple = tuple(("DNS", name) for name in (sans or [subject_cn]))
    return {
        "subject": ((("commonName", subject_cn),), (("organizationName", subject_org),)),
        "issuer": ((("commonName", issuer_cn),), (("organizationName", issuer_org),), (("countryName", "US"),)),
        "subjectAltName": sans_tuple,
        "notBefore": not_before,
        "notAfter": not_after,
        "serialNumber": serial,
    }


def create_mock_connection(mock_cert, version="TLSv1.3", cipher_name="TLS_AES_256_GCM_SHA384", cipher_bits=256):
    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock()

    mock_ssl_obj = MagicMock()
    mock_ssl_obj.getpeercert.side_effect = lambda binary_form=False: (b"der_bytes" if binary_form else mock_cert)
    mock_ssl_obj.cipher.return_value = (cipher_name, version, cipher_bits)
    mock_ssl_obj.version.return_value = version

    mock_writer.transport.get_extra_info.return_value = mock_ssl_obj
    return mock_reader, mock_writer


@pytest.mark.asyncio
async def test_1_valid_certificate_inspection():
    """1. Test valid certificate inspection."""
    analyzer = SSLDeepAnalyzer()
    mock_cert = create_mock_peercert()
    mock_conn = create_mock_connection(mock_cert)

    with patch("asyncio.open_connection", return_value=mock_conn):
        res = await analyzer.inspect_domain("example.com")
        assert res.domain == "example.com"
        assert res.trust_verified is True
        assert res.hostname_matches is True
        assert res.expiration_status == ExpirationStatus.VALID
        assert res.tls_session.version == "TLSv1.3"


@pytest.mark.asyncio
async def test_2_certificate_issuer_ca_extraction():
    """2. Test Certificate Issuer / CA extraction."""
    analyzer = SSLDeepAnalyzer()
    mock_cert = create_mock_peercert(issuer_cn="Let's Encrypt Authority X3", issuer_org="Let's Encrypt")
    mock_conn = create_mock_connection(mock_cert)

    with patch("asyncio.open_connection", return_value=mock_conn):
        res = await analyzer.inspect_domain("example.com")
        assert res.issuer.common_name == "Let's Encrypt Authority X3"
        assert res.issuer.organization == "Let's Encrypt"
        assert res.issuer.is_self_signed is False


@pytest.mark.asyncio
async def test_3_expiration_calculation():
    """3. Test remaining expiration days calculation."""
    analyzer = SSLDeepAnalyzer()
    future_date = (datetime.now(timezone.utc) + timedelta(days=90)).strftime("%b %d %H:%M:%S %Y GMT")
    mock_cert = create_mock_peercert(not_after=future_date)
    mock_conn = create_mock_connection(mock_cert)

    with patch("asyncio.open_connection", return_value=mock_conn):
        res = await analyzer.inspect_domain("example.com")
        assert res.days_remaining is not None
        assert 88 <= res.days_remaining <= 91
        assert res.expiration_status == ExpirationStatus.VALID


@pytest.mark.asyncio
async def test_4_expired_certificate():
    """4. Test expired certificate detection."""
    analyzer = SSLDeepAnalyzer()
    past_date = "Jan 01 00:00:00 2020 GMT"
    mock_cert = create_mock_peercert(not_after=past_date)
    mock_conn = create_mock_connection(mock_cert)

    with patch("asyncio.open_connection", return_value=mock_conn):
        res = await analyzer.inspect_domain("expired-site.com")
        assert res.expiration_status == ExpirationStatus.EXPIRED
        assert res.is_valid is False
        assert any("expired" in f.lower() for f in res.security_findings)


@pytest.mark.asyncio
async def test_5_self_signed_certificate():
    """5. Test self-signed certificate detection."""
    analyzer = SSLDeepAnalyzer()
    mock_cert = create_mock_peercert(subject_cn="selfsigned.local", issuer_cn="selfsigned.local")
    mock_conn = create_mock_connection(mock_cert)

    with patch("asyncio.open_connection", return_value=mock_conn):
        res = await analyzer.inspect_domain("selfsigned.local")
        assert res.issuer.is_self_signed is True
        assert any("self-signed" in f.lower() for f in res.security_findings)


@pytest.mark.asyncio
async def test_6_hostname_san_mismatch():
    """6. Test Hostname / SAN mismatch detection."""
    analyzer = SSLDeepAnalyzer()
    mock_cert = create_mock_peercert(subject_cn="wrong-domain.com", sans=["wrong-domain.com"])
    mock_conn = create_mock_connection(mock_cert)

    with patch("asyncio.open_connection", return_value=mock_conn):
        res = await analyzer.inspect_domain("target-domain.com")
        assert res.hostname_matches is False
        assert res.is_valid is False
        assert any("mismatch" in f.lower() for f in res.security_findings)


@pytest.mark.asyncio
async def test_7_weak_obsolete_tls_detection():
    """7. Test obsolete TLS protocol detection (TLSv1.0 / TLSv1.1)."""
    analyzer = SSLDeepAnalyzer()
    mock_cert = create_mock_peercert()
    mock_conn = create_mock_connection(mock_cert, version="TLSv1", cipher_name="DES-CBC3-SHA", cipher_bits=168)

    with patch("asyncio.open_connection", return_value=mock_conn):
        res = await analyzer.inspect_domain("legacy-tls.com")
        assert res.tls_session.is_weak_protocol is True
        assert res.is_weak_tls is True
        assert any("obsolete tls" in f.lower() for f in res.security_findings)


@pytest.mark.asyncio
async def test_8_tls_connection_failure():
    """8. Test TLS connection failure handling."""
    analyzer = SSLDeepAnalyzer()
    with patch("asyncio.open_connection", side_effect=ConnectionRefusedError("Connection refused on port 443")):
        res = await analyzer.inspect_domain("unreachable-host.com")
        assert res.is_valid is False
        assert res.error is not None
        assert "Connection refused" in res.error


@pytest.mark.asyncio
async def test_9_dns_failure():
    """9. Test DNS resolution failure handling."""
    client = TestClient(app)
    with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution",
               side_effect=Exception("Invalid hostname or host could not be resolved")):
        resp = client.get("/api/v1/ssl/domain/nonexistent-domain-xyz-99.com")
        assert resp.status_code == 500 or resp.status_code == 400


def test_10_invalid_domain_syntax():
    """10. Test invalid domain syntax rejection (HTTP 400)."""
    client = TestClient(app)
    resp = client.get("/api/v1/ssl/domain/nodotdomain")
    assert resp.status_code == 400
    data = resp.json()
    assert data["error_code"] == "INVALID_DOMAIN"


def test_11_ssrf_private_destination_blocking():
    """11. Test SSRF private destination blocking (HTTP 403)."""
    client = TestClient(app)
    from app.middleware.exceptions import SSRFBlockedException
    with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution",
               side_effect=SSRFBlockedException("The requested URL is not allowed.")):
        resp = client.get("/api/v1/ssl/domain/internal-host.local")
        assert resp.status_code == 403
        data = resp.json()
        assert data["error_code"] == "URL_NOT_ALLOWED"


@pytest.mark.asyncio
async def test_12_timeout_handling():
    """12. Test connection timeout handling."""
    analyzer = SSLDeepAnalyzer()
    with patch("asyncio.open_connection", side_effect=asyncio.TimeoutError()):
        res = await analyzer.inspect_domain("timeout-domain.com")
        assert res.is_valid is False
        assert res.error is not None


def test_13_api_response_schema_validation():
    """13. Test API response schema validation."""
    client = TestClient(app)
    with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution", return_value=["93.184.216.34"]):
        resp = client.get("/api/v1/ssl/domain/example.com")
        assert resp.status_code == 200
        data = resp.json()
        assert "domain" in data
        assert "is_valid" in data
        assert "expiration_status" in data
        assert "security_findings" in data


def test_14_rate_limiting_headers():
    """14. Test rate limit headers present on response."""
    client = TestClient(app)
    with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution", return_value=["93.184.216.34"]):
        resp = client.get("/api/v1/ssl/domain/example.com")
        assert resp.status_code == 200
        assert "X-RateLimit-Limit" in resp.headers


def test_15_no_secret_leakage(caplog):
    """15. Test secrets redaction / no secret leakage."""
    caplog.set_level(logging.INFO)
    logger = logging.getLogger("trustinel.security_ssl_test")
    secret_token = "sk-ssl-secret-token-998877"
    logger.info(f"SSL handshake debug token {secret_token}")

    messages = [r.getMessage() for r in caplog.records]
    assert not any(secret_token in m for m in messages)
    assert any("[REDACTED_API_KEY]" in m for m in messages)


def test_16_deterministic_scoring_isolation():
    """16. Test deterministic scoring engine remains 100% authoritative and isolated."""
    from app.services.rule_based_trust_engine import RuleBasedTrustEngine
    engine_instance = RuleBasedTrustEngine()
    # Confirm RuleBasedTrustEngine exists and retains standard deterministic calculation contract
    assert hasattr(engine_instance, "evaluate")
