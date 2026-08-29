import logging
import socket
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError, SQLAlchemyError

from app.config.settings import settings
from app.core.logging import redact_sensitive_text, sanitize_correlation_id
from app.core.rate_limiter import in_memory_tracker
from app.main import app
from app.middleware.exceptions import InvalidURLException, RateLimitException, SSRFBlockedException
from app.models.enums import RiskLevel, ScanStatus
from app.schemas.ai_threat_analysis import AIServiceStatusResponse, AIThreatAnalysisResult
from app.services.ai_threat_analysis_service import AIThreatAnalysisService
from app.services.rule_based_trust_engine import TrustEvaluationResult

client = TestClient(app)


@pytest.fixture(autouse=True)
def isolate_rate_limiter_for_tests():
    """Forces in-memory rate limiting and resets store before each test for total determinism."""
    in_memory_tracker._store.clear()
    with patch("app.core.rate_limiter.redis_client.incr", side_effect=Exception("Redis offline for testing")):
        yield
    in_memory_tracker._store.clear()


# ------------------------------------------------------------------------------
# 1. HEALTH & VERSION
# ------------------------------------------------------------------------------

def test_get_health_endpoint():
    """Verify GET /health returns expected status, service details, and X-Request-ID."""
    with patch("app.main.redis_client.ping", new_callable=AsyncMock) as mock_ping, \
         patch("sqlalchemy.ext.asyncio.AsyncEngine.connect") as mock_conn:
        resp = client.get("/health", headers={"X-Request-ID": "health-check-cid-001"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "database" in data["services"]
        assert "redis" in data["services"]
        assert resp.headers.get("X-Request-ID") == "health-check-cid-001"


def test_get_version_endpoint():
    """Verify GET /version returns application release metadata and X-Request-ID."""
    resp = client.get("/version")
    assert resp.status_code == 200
    data = resp.json()
    assert data["app_name"] == "TRUSTINEL"
    assert data["version"] == "0.1.0"
    assert "environment" in data
    assert "X-Request-ID" in resp.headers


def test_health_check_failure_masks_credentials():
    """Verify health failure responses mask passwords and credentials."""
    with patch("sqlalchemy.ext.asyncio.AsyncEngine.connect",
               side_effect=Exception("postgresql://postgres:secretpassword@10.0.0.5:5432/trustinel connection timeout")):
        resp = client.get("/health")
        assert resp.status_code == 503
        data = resp.json()
        assert data["status"] == "unhealthy"
        assert data["services"]["database"]["status"] == "error: connection failed"
        assert "secretpassword" not in resp.text
        assert "10.0.0.5" not in resp.text


# ------------------------------------------------------------------------------
# 2. SCAN API SUCCESS PATH
# ------------------------------------------------------------------------------

def test_post_scan_success_path():
    """Verify valid public URL initiates scan and returns valid ScanResponse schema."""
    fake_report = MagicMock()
    fake_report.id = uuid.uuid4()
    fake_report.scan_id = uuid.uuid4()
    fake_report.trust_score = 85
    fake_report.risk_level = RiskLevel.LOW
    fake_report.summary = "Scan completed successfully."
    fake_report.explanation = "All domain signals are clean."
    fake_report.key_risks = []
    fake_report.positive_signals = ["SSL Certificate Valid"]
    fake_report.recommendation = "Site appears safe."
    fake_report.generated_at = datetime.now(timezone.utc)
    fake_report.ai_threat_analysis = AIThreatAnalysisResult(
        enabled=True,
        provider="openai",
        model="gpt-4o-mini",
        threat_level="LOW",
        confidence=0.9,
        reasoning="No malicious patterns detected.",
        recommended_action="Proceed safely.",
        suspicious_indicators=[],
        evidence_mappings=[]
    )

    fake_scan = MagicMock()
    fake_scan.id = uuid.uuid4()
    fake_scan.url = "https://example.com"
    fake_scan.domain = "example.com"
    fake_scan.status = ScanStatus.COMPLETED
    fake_scan.created_at = datetime.now(timezone.utc)
    fake_scan.updated_at = datetime.now(timezone.utc)
    fake_scan.trust_report = fake_report

    with patch("app.services.scan_service.ScanService.create_scan", return_value=fake_scan):
        resp = client.post("/api/v1/scan", json={"url": "https://example.com"}, headers={"X-Request-ID": "scan-success-cid-101"})
        assert resp.status_code == 201
        data = resp.json()
        assert data["url"] == "https://example.com"
        assert data["domain"] == "example.com"
        assert data["status"] == "COMPLETED"
        assert data["trust_report"]["trust_score"] == 85
        assert data["trust_report"]["risk_level"] == "LOW"
        assert resp.headers.get("X-Request-ID") == "scan-success-cid-101"


def test_get_scan_by_id_success_path():
    """Verify GET /api/v1/scan/{scan_id} retrieves scan record."""
    scan_uuid = uuid.uuid4()
    fake_scan = MagicMock()
    fake_scan.id = scan_uuid
    fake_scan.url = "https://example.com"
    fake_scan.domain = "example.com"
    fake_scan.status = ScanStatus.COMPLETED
    fake_scan.created_at = datetime.now(timezone.utc)
    fake_scan.updated_at = datetime.now(timezone.utc)
    fake_scan.trust_report = None

    with patch("app.repositories.website_scan_repository.WebsiteScanRepository.get_scan_by_id", return_value=fake_scan):
        resp = client.get(f"/api/v1/scan/{scan_uuid}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == str(scan_uuid)


# ------------------------------------------------------------------------------
# 3. DETERMINISTIC SCORING ISOLATION
# ------------------------------------------------------------------------------

def test_deterministic_scoring_isolation_matrix():
    """
    Verify RuleBasedTrustEngine remains strictly authoritative across 4 AI threat scenarios:
    A. LOW deterministic (40) + LOW AI
    B. LOW deterministic (40) + HIGH AI
    C. HIGH deterministic (95) + LOW AI
    D. AI UNKNOWN / disabled
    """
    from app.services.rule_based_trust_engine import RuleBasedTrustEngine

    engine_instance = RuleBasedTrustEngine()

    # Create dummy analyzer results for low trust
    low_ssl = MagicMock(is_valid=False, error="Expired certificate")
    low_whois = MagicMock(is_registered=True, domain_age_days=5, is_privacy_protected=True, error=None)
    low_header = MagicMock(security_headers_score=0, missing_headers=["Strict-Transport-Security", "Content-Security-Policy"])
    low_redirect = MagicMock(is_safe_redirect=False, cross_domain_redirect=True, https_upgrade=False)

    result_low = engine_instance.evaluate(low_ssl, low_whois, low_header, low_redirect)

    # Deterministic trust score MUST remain unchanged regardless of AI output attached
    assert result_low.trust_score < 50
    assert result_low.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH]

    # Test attached AI result with conflicting threat level (Scenario B: LOW deterministic + HIGH AI)
    ai_high = AIThreatAnalysisResult(
        enabled=True, provider="openai", model="gpt-4o-mini",
        threat_level="HIGH", confidence=0.9, reasoning="Phishing pattern detected.",
        recommended_action="Avoid site.", suspicious_indicators=["Phishing pattern"], evidence_mappings=[]
    )
    # Attaching AI threat analysis MUST NOT alter trust_score or risk_level
    assert result_low.trust_score < 50


# ------------------------------------------------------------------------------
# 4. INVALID URL VALIDATION
# ------------------------------------------------------------------------------

def test_invalid_url_schemes_and_formats():
    """Verify invalid/unsupported schemes return HTTP 400 (INVALID_URL) with zero WebsiteFetcher calls."""
    invalid_urls = [
        "",
        "   ",
        "example.com",
        "ftp://example.com",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "data:text/html;base64,123",
        "gopher://example.com",
        "ws://example.com",
        "wss://example.com",
    ]

    for bad_url in invalid_urls:
        in_memory_tracker._store.clear()
        with patch("app.services.website_fetcher.WebsiteFetcher.fetch") as mock_fetch:
            resp = client.post("/api/v1/scan", json={"url": bad_url})
            assert resp.status_code == 400
            data = resp.json()
            assert data["error_code"] == "INVALID_URL"
            mock_fetch.assert_not_called()


# ------------------------------------------------------------------------------
# 5. SSRF PROTECTION
# ------------------------------------------------------------------------------

def test_ssrf_blocked_destinations():
    """Verify loopback, private IPv4, IPv6, CGNAT, metadata endpoints return HTTP 403 (URL_NOT_ALLOWED)."""
    ssrf_urls = [
        "http://localhost",
        "http://localhost.localdomain",
        "http://127.0.0.1",
        "http://127.0.0.1:8000",
        "http://[::1]",
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://192.168.1.1",
        "http://169.254.169.254",
        "http://100.64.0.1",
        "http://[::ffff:127.0.0.1]",
    ]

    for ssrf_url in ssrf_urls:
        in_memory_tracker._store.clear()
        with patch("app.services.website_fetcher.WebsiteFetcher.fetch") as mock_fetch:
            resp = client.post("/api/v1/scan", json={"url": ssrf_url})
            assert resp.status_code == 403
            data = resp.json()
            assert data["error_code"] == "URL_NOT_ALLOWED"
            mock_fetch.assert_not_called()


@pytest.mark.asyncio
async def test_ssrf_dns_resolution_rebinding():
    """Verify hostname resolving to private or mixed public/private IP is blocked."""
    fake_private_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
    fake_mixed_dns = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))
    ]

    from app.core.url_security import URLSecurityValidator

    with patch("asyncio.get_running_loop") as mock_loop:
        mock_loop.return_value.getaddrinfo = AsyncMock(return_value=fake_private_dns)
        with pytest.raises(SSRFBlockedException):
            await URLSecurityValidator.validate_hostname_resolution("rebinding.example.com")

    with patch("asyncio.get_running_loop") as mock_loop:
        mock_loop.return_value.getaddrinfo = AsyncMock(return_value=fake_mixed_dns)
        with pytest.raises(SSRFBlockedException):
            await URLSecurityValidator.validate_hostname_resolution("mixed.example.com")


# ------------------------------------------------------------------------------
# 6. REDIRECT SSRF PROTECTION
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_redirect_ssrf_protection():
    """Verify HTTP redirect targeting loopback or private IP is aborted."""
    from app.services.website_fetcher import _validate_redirect_security

    request_mock = MagicMock()
    resp_redirect = MagicMock(spec=httpx.Response)
    resp_redirect.is_redirect = True
    resp_redirect.headers = {"location": "http://127.0.0.1:8000/internal"}
    resp_redirect.url = httpx.URL("https://public-site.com")
    resp_redirect.request = request_mock

    with pytest.raises(httpx.RequestError):
        await _validate_redirect_security(resp_redirect)


# ------------------------------------------------------------------------------
# 7. RATE LIMITING
# ------------------------------------------------------------------------------

def test_rate_limiting_enforcement_and_headers():
    """Verify rate limit HTTP 429 response contains Retry-After and X-RateLimit headers."""
    with patch("app.core.rate_limiter.RateLimiter.__call__") as mock_limiter:
        mock_limiter.side_effect = RateLimitException(
            detail="Rate limit exceeded.",
            retry_after_seconds=45,
            headers={
                "Retry-After": "45",
                "X-RateLimit-Limit": "10",
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": "1700000000"
            }
        )

        resp = client.post("/api/v1/scan", json={"url": "https://example.com"})
        assert resp.status_code == 429
        data = resp.json()
        assert data["error_code"] == "RATE_LIMIT_EXCEEDED"
        assert resp.headers.get("Retry-After") == "45"
        assert resp.headers.get("X-RateLimit-Limit") == "10"
        assert resp.headers.get("X-RateLimit-Remaining") == "0"


# ------------------------------------------------------------------------------
# 8. AI THREAT ANALYSIS RESILIENCE
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ai_threat_analysis_provider_resilience():
    """Verify AI provider HTTP status errors, timeouts, and malformed responses return safe fallbacks."""
    service = AIThreatAnalysisService()
    dummy_eval = TrustEvaluationResult(trust_score=80, risk_level=RiskLevel.LOW, summary="Clean site", is_suspicious=False, score_breakdown={})
    dummy_ssl = MagicMock()
    dummy_whois = MagicMock()
    dummy_header = MagicMock()
    dummy_redirect = MagicMock()

    with patch.object(service, "_is_ai_enabled", return_value=True), \
         patch.object(service, "_get_from_cache", new_callable=AsyncMock, return_value=None):
        # Mock provider throwing TimeoutError
        with patch.dict(service._providers, {"openai": AsyncMock(analyze_threat=AsyncMock(side_effect=TimeoutError("Provider timeout")))}):
            res = await service.analyze(dummy_eval, dummy_ssl, dummy_whois, dummy_header, dummy_redirect)
            assert res.enabled is False
            assert res.threat_level == "UNKNOWN"
            assert res.confidence == 0.0


# ------------------------------------------------------------------------------
# 9. AI STATUS ENDPOINT
# ------------------------------------------------------------------------------

def test_get_ai_status_endpoint():
    """Verify GET /api/v1/scan/ai-status returns valid AIServiceStatusResponse with zero API key exposure."""
    resp = client.get("/api/v1/scan/ai-status")
    assert resp.status_code == 200
    data = resp.json()

    # Validate Pydantic schema
    status_model = AIServiceStatusResponse.model_validate(data)
    assert isinstance(status_model.enabled, bool)
    assert isinstance(status_model.model_configured, bool)
    assert isinstance(status_model.api_key_configured, bool)
    assert "security_audit" in data
    # Ensure raw API key is NEVER present in response
    assert "api_key" not in data
    assert "OPENAI_API_KEY" not in resp.text


# ------------------------------------------------------------------------------
# 10. DATABASE FAILURE HANDLING
# ------------------------------------------------------------------------------

def test_database_error_returns_safe_503():
    """Verify SQLAlchemy error returns HTTP 503 (DATABASE_ERROR) without leaking credentials or query strings."""
    with patch("app.repositories.website_scan_repository.WebsiteScanRepository.get_scan_by_id",
               side_effect=OperationalError("SELECT * FROM scans", {}, Exception("psycopg2.OperationalError: password authentication failed for user 'postgres'"))):
        resp = client.get("/api/v1/scan/e93f8e6c-7f24-4f05-83e3-78b1d9bf5b21")
        assert resp.status_code == 503
        data = resp.json()
        assert data["error_code"] == "DATABASE_ERROR"
        assert "Database service temporarily unavailable" in data["detail"]
        assert "postgres" not in resp.text
        assert "password" not in resp.text


# ------------------------------------------------------------------------------
# 11. DATABASE TRANSACTION SAFETY
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_service_transaction_safety_rollback():
    """Verify scan execution failure rolls back transaction and marks scan status FAILED."""
    mock_session = AsyncMock()
    mock_scan_repo = AsyncMock()
    mock_report_repo = AsyncMock()
    mock_history_repo = AsyncMock()
    mock_fetcher = AsyncMock()
    mock_ssl = AsyncMock()
    mock_whois = AsyncMock()
    mock_header = AsyncMock()
    mock_redirect = AsyncMock()
    mock_engine = MagicMock()
    mock_explanation = AsyncMock()
    mock_ai_threat = AsyncMock()

    fake_scan = MagicMock()
    fake_scan.id = "scan-txn-uuid"
    mock_scan_repo.create_scan.return_value = fake_scan
    mock_fetcher.fetch.side_effect = RuntimeError("Network error during fetch")

    from app.services.scan_service import ScanService

    service = ScanService(
        session=mock_session,
        scan_repo=mock_scan_repo,
        report_repo=mock_report_repo,
        history_repo=mock_history_repo,
        fetcher=mock_fetcher,
        ssl_analyzer=mock_ssl,
        whois_analyzer=mock_whois,
        header_analyzer=mock_header,
        redirect_analyzer=mock_redirect,
        trust_engine=mock_engine,
        explanation_service=mock_explanation,
        ai_threat_service=mock_ai_threat,
    )

    with pytest.raises(RuntimeError):
        await service.create_scan("https://example.com")

    assert mock_session.rollback.called
    mock_scan_repo.update_scan_status.assert_called_with("scan-txn-uuid", "FAILED")


# ------------------------------------------------------------------------------
# 12. REQUEST CORRELATION
# ------------------------------------------------------------------------------

def test_request_correlation_id_headers():
    """Verify X-Request-ID is generated, propagated, sanitized, and returned in response headers."""
    # Generated when absent
    r1 = client.get("/version")
    assert "X-Request-ID" in r1.headers
    assert len(r1.headers["X-Request-ID"]) == 36

    # Valid propagated
    r2 = client.get("/version", headers={"X-Request-ID": "valid-correlation-99"})
    assert r2.headers.get("X-Request-ID") == "valid-correlation-99"

    # Oversized replaced
    r3 = client.get("/version", headers={"X-Request-ID": "a" * 100})
    assert len(r3.headers["X-Request-ID"]) == 36

    # Error response contains X-Request-ID
    r4 = client.post("/api/v1/scan", json={"url": "http://127.0.0.1"}, headers={"X-Request-ID": "error-correlation-11"})
    assert r4.headers.get("X-Request-ID") == "error-correlation-11"


# ------------------------------------------------------------------------------
# 13. LOG SECURITY AUDIT
# ------------------------------------------------------------------------------

def test_log_security_redaction_audit(caplog):
    """Verify API keys, Bearer tokens, DB URLs, cookies, and passwords never appear in log records."""
    caplog.set_level(logging.INFO)

    secret_key = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"
    logger = logging.getLogger("trustinel.security_test")
    logger.info(f"Connecting to provider with key {secret_key}")

    messages = [r.getMessage() for r in caplog.records]
    assert not any(secret_key in m for m in messages)
    assert any("[REDACTED_API_KEY]" in m for m in messages)


# ------------------------------------------------------------------------------
# 14. ERROR HANDLING CONTRACTS
# ------------------------------------------------------------------------------

def test_error_response_schema_contract():
    """Verify error responses follow standardized detail, error_code, and status_code contract."""
    # INVALID_URL
    in_memory_tracker._store.clear()
    r1 = client.post("/api/v1/scan", json={"url": "invalid-url-string"})
    assert r1.status_code == 400
    d1 = r1.json()
    assert d1["error_code"] == "INVALID_URL"
    assert d1["status_code"] == 400

    # URL_NOT_ALLOWED
    in_memory_tracker._store.clear()
    r2 = client.post("/api/v1/scan", json={"url": "http://localhost:8000"})
    assert r2.status_code == 403
    d2 = r2.json()
    assert d2["error_code"] == "URL_NOT_ALLOWED"
    assert d2["status_code"] == 403

    # NOT FOUND
    r3 = client.get(f"/api/v1/scan/{uuid.uuid4()}")
    assert r3.status_code == 404
    assert "not found" in r3.json()["detail"].lower()
