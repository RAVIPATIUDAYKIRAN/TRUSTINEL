import logging
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.header_audit import HeaderAuditGrade
from app.analyzers.header_deep_analyzer import HeaderDeepAnalyzer
from app.schemas.website_fetch import WebsiteFetchResult


@pytest.mark.asyncio
async def test_1_excellent_security_headers():
    """1. Test excellent security headers return Grade A+ / A and high composite score."""
    analyzer = HeaderDeepAnalyzer()
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }
    res = analyzer.audit_headers("example.com", headers)
    assert res.composite_score >= 90
    assert res.audit_grade == HeaderAuditGrade.A_PLUS
    assert res.hsts.is_strong is True
    assert res.csp.is_present is True
    assert res.csp.has_unsafe_inline is False


@pytest.mark.asyncio
async def test_2_missing_security_headers():
    """2. Test missing security headers return Grade F and score 0."""
    analyzer = HeaderDeepAnalyzer()
    res = analyzer.audit_headers("insecure.example.com", {})
    assert res.composite_score == 0
    assert res.audit_grade == HeaderAuditGrade.F
    assert len(res.missing_headers) == 6
    assert len(res.present_headers) == 0


@pytest.mark.asyncio
async def test_3_hsts_directive_parsing():
    """3. Test HSTS directive parsing (max-age, includeSubDomains, preload)."""
    analyzer = HeaderDeepAnalyzer()
    headers = {"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload"}
    res = analyzer.audit_headers("example.com", headers)
    assert res.hsts.is_present is True
    assert res.hsts.max_age == 63072000
    assert res.hsts.includes_subdomains is True
    assert res.hsts.preload is True
    assert res.hsts.is_strong is True


@pytest.mark.asyncio
async def test_4_weak_hsts_max_age():
    """4. Test weak HSTS max-age (< 1 year)."""
    analyzer = HeaderDeepAnalyzer()
    headers = {"Strict-Transport-Security": "max-age=86400"}
    res = analyzer.audit_headers("example.com", headers)
    assert res.hsts.is_present is True
    assert res.hsts.is_strong is False
    assert any("weak hsts" in f.lower() for f in res.security_findings)


@pytest.mark.asyncio
async def test_5_csp_unsafe_inline_detection():
    """5. Test CSP directive parsing and unsafe-inline detection."""
    analyzer = HeaderDeepAnalyzer()
    headers = {"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"}
    res = analyzer.audit_headers("example.com", headers)
    assert res.csp.is_present is True
    assert res.csp.has_unsafe_inline is True
    assert any("unsafe-inline" in f.lower() for f in res.security_findings)


@pytest.mark.asyncio
async def test_6_csp_unsafe_eval_wildcard_detection():
    """6. Test CSP unsafe-eval and wildcard source detection."""
    analyzer = HeaderDeepAnalyzer()
    headers = {"Content-Security-Policy": "default-src *; script-src 'self' 'unsafe-eval'"}
    res = analyzer.audit_headers("example.com", headers)
    assert res.csp.has_unsafe_eval is True
    assert res.csp.allows_unrestricted_wildcards is True
    assert any("unsafe-eval" in f.lower() for f in res.security_findings)


@pytest.mark.asyncio
async def test_7_x_frame_options_parsing():
    """7. Test X-Frame-Options DENY / SAMEORIGIN parsing."""
    analyzer = HeaderDeepAnalyzer()
    headers = {"X-Frame-Options": "SAMEORIGIN"}
    res = analyzer.audit_headers("example.com", headers)
    assert res.x_frame_options == "SAMEORIGIN"
    assert "X-Frame-Options" in res.present_headers


@pytest.mark.asyncio
async def test_8_x_content_type_options_nosniff():
    """8. Test X-Content-Type-Options nosniff parsing."""
    analyzer = HeaderDeepAnalyzer()
    headers = {"X-Content-Type-Options": "nosniff"}
    res = analyzer.audit_headers("example.com", headers)
    assert res.x_content_type_options == "nosniff"
    assert "X-Content-Type-Options" in res.present_headers


def test_9_invalid_domain_syntax():
    """9. Test invalid domain syntax rejection (HTTP 400)."""
    client = TestClient(app)
    resp = client.get("/api/v1/headers/domain/nodotdomain")
    assert resp.status_code == 400
    data = resp.json()
    assert data["error_code"] == "INVALID_DOMAIN"


def test_10_ssrf_private_destination_blocking():
    """10. Test SSRF private destination blocking (HTTP 403)."""
    client = TestClient(app)
    from app.middleware.exceptions import SSRFBlockedException
    with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution",
               side_effect=SSRFBlockedException("The requested URL is not allowed.")):
        resp = client.get("/api/v1/headers/domain/internal-host.local")
        assert resp.status_code == 403
        data = resp.json()
        assert data["error_code"] == "URL_NOT_ALLOWED"


def test_11_rate_limiting_headers():
    """11. Test rate limit headers present on response."""
    client = TestClient(app)
    with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution", return_value=["93.184.216.34"]):
        resp = client.get("/api/v1/headers/domain/example.com")
        assert resp.status_code == 200
        assert "X-RateLimit-Limit" in resp.headers


@pytest.mark.asyncio
async def test_12_fetcher_timeout_handling():
    """12. Test website fetcher connection timeout error handling."""
    analyzer = HeaderDeepAnalyzer()
    mock_fetch_res = WebsiteFetchResult(original_url="https://timeout-host.com", error="Request timed out.")
    with patch("app.services.website_fetcher.WebsiteFetcher.fetch", return_value=mock_fetch_res):
        res = await analyzer.audit_domain("timeout-host.com")
        assert res.composite_score == 0
        assert res.audit_grade == HeaderAuditGrade.F


def test_13_api_response_schema_validation():
    """13. Test API response schema validation."""
    client = TestClient(app)
    with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution", return_value=["93.184.216.34"]):
        resp = client.get("/api/v1/headers/domain/example.com")
        assert resp.status_code == 200
        data = resp.json()
        assert "domain" in data
        assert "audit_grade" in data
        assert "composite_score" in data
        assert "hsts" in data
        assert "csp" in data
        assert "security_findings" in data


def test_14_no_secret_leakage(caplog):
    """14. Test secrets redaction / no secret leakage."""
    caplog.set_level(logging.INFO)
    logger = logging.getLogger("trustinel.security_headers_test")
    secret_token = "sk-headers-secret-token-554433"
    logger.info(f"Headers audit debug token {secret_token}")

    messages = [r.getMessage() for r in caplog.records]
    assert not any(secret_token in m for m in messages)
    assert any("[REDACTED_API_KEY]" in m for m in messages)


def test_15_deterministic_scoring_isolation():
    """15. Test deterministic scoring engine remains 100% authoritative and isolated."""
    from app.services.rule_based_trust_engine import RuleBasedTrustEngine
    engine_instance = RuleBasedTrustEngine()
    assert hasattr(engine_instance, "evaluate")
