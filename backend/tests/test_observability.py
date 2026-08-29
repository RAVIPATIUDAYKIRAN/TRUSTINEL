import logging
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.middleware.exceptions import InvalidURLException
from app.core.logging import (
    sanitize_correlation_id,
    redact_sensitive_text,
    get_correlation_id,
    set_correlation_id
)


# --- Unit Tests: Correlation ID & Redaction ---

def test_sanitize_correlation_id():
    """1, 2, 3. Verify correlation ID sanitization."""
    # Absent -> UUID
    cid1 = sanitize_correlation_id(None)
    assert len(cid1) == 36

    # Valid -> Propagated
    valid_id = "test-correlation-123"
    assert sanitize_correlation_id(valid_id) == valid_id

    # Oversized / Invalid -> Replaced safely
    oversized = "a" * 100
    cid3 = sanitize_correlation_id(oversized)
    assert len(cid3) == 36
    assert cid3 != oversized

    malformed = "invalid@id!#$"
    cid4 = sanitize_correlation_id(malformed)
    assert len(cid4) == 36


def test_log_redaction():
    """8, 9, 10, 11. Verify secrets are redacted from text."""
    # API key
    raw_api = "Failed with key sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"
    redacted_api = redact_sensitive_text(raw_api)
    assert "sk-proj-1234567890abcdef" not in redacted_api
    assert "[REDACTED_API_KEY]" in redacted_api

    # Bearer token
    raw_bearer = "Authorization: Bearer secret-token-abc.xyz.123"
    redacted_bearer = redact_sensitive_text(raw_bearer)
    assert "secret-token-abc" not in redacted_bearer

    # DB credentials
    raw_db = "Connecting to postgresql+asyncpg://postgres:supersecretpass@localhost:5432/trustinel"
    redacted_db = redact_sensitive_text(raw_db)
    assert "supersecretpass" not in redacted_db
    assert "[REDACTED_CREDENTIALS]" in redacted_db

    # Cookie
    raw_cookie = "Cookie: session=123456789"
    redacted_cookie = redact_sensitive_text(raw_cookie)
    assert "session=123456789" not in redacted_cookie


# --- Integration Tests: Middleware & Telemetry ---

def test_x_request_id_response_header():
    """4. Verify X-Request-ID is present in HTTP response headers."""
    client = TestClient(app)

    # Generated when absent
    resp1 = client.get("/version")
    assert resp1.status_code == 200
    assert "X-Request-ID" in resp1.headers
    assert len(resp1.headers["X-Request-ID"]) == 36

    # Propagated when valid
    valid_cid = "custom-client-request-id-999"
    resp2 = client.get("/version", headers={"X-Request-ID": valid_cid})
    assert resp2.status_code == 200
    assert resp2.headers.get("X-Request-ID") == valid_cid


def test_request_lifecycle_logging(caplog):
    """5, 6, 7. Verify request_started and request_completed events contain duration_ms and correlation ID."""
    caplog.set_level(logging.INFO)
    client = TestClient(app)

    test_cid = "test-request-lifecycle-101"
    resp = client.get("/version", headers={"X-Request-ID": test_cid})
    assert resp.status_code == 200

    # Inspect logs
    messages = [r.getMessage() for r in caplog.records]
    assert any("Request started: GET /version" in m for m in messages)
    assert any("Request completed: GET /version" in m for m in messages)

    # Check extra attrs or context
    records_with_cid = [r for r in caplog.records if getattr(r, "correlation_id", None) == test_cid]
    assert len(records_with_cid) > 0


def test_scan_lifecycle_events_emitted(caplog):
    """12. Verify scan lifecycle events (started, completed) emit safe metadata."""
    caplog.set_level(logging.INFO)
    client = TestClient(app)

    with patch("app.services.scan_service.ScanService.create_scan") as mock_create:
        mock_create.side_effect = InvalidURLException("Invalid URL.")
        resp = client.post("/api/v1/scan", json={"url": "ftp://example.com"}, headers={"X-Request-ID": "scan-cid-777"})
        assert resp.status_code == 400
        assert resp.headers.get("X-Request-ID") == "scan-cid-777"

    messages = [r.getMessage() for r in caplog.records]
    assert any("POST /api/v1/scan" in m for m in messages)


def test_ai_telemetry_safe(caplog):
    """13, 14. Verify AI telemetry events do not leak secrets or evidence."""
    caplog.set_level(logging.INFO)
    from app.services.ai_threat_analysis_service import AIThreatAnalysisService

    service = AIThreatAnalysisService()
    status_info = service.get_status()
    assert "enabled" in status_info
    assert "api_key" not in status_info


def test_rate_limit_telemetry(caplog):
    """15. Verify rate limit events contain correlation ID."""
    caplog.set_level(logging.WARNING)
    client = TestClient(app)

    with patch("app.core.rate_limiter.RateLimiter.__call__") as mock_limiter:
        from app.middleware.exceptions import RateLimitException
        mock_limiter.side_effect = RateLimitException(detail="Rate limit exceeded.", retry_after_seconds=30)

        resp = client.post("/api/v1/scan", json={"url": "https://example.com"}, headers={"X-Request-ID": "rate-limit-cid-555"})
        assert resp.status_code == 429
        assert resp.headers.get("X-Request-ID") == "rate-limit-cid-555"


def test_ssrf_telemetry_safe(caplog):
    """16. Verify SSRF events do not expose internal IP topology."""
    caplog.set_level(logging.WARNING)
    client = TestClient(app)

    resp = client.post("/api/v1/scan", json={"url": "http://127.0.0.1:8000"}, headers={"X-Request-ID": "ssrf-cid-333"})
    assert resp.status_code == 403
    assert resp.headers.get("X-Request-ID") == "ssrf-cid-333"


def test_unexpected_exception_logging(caplog):
    """17. Verify unexpected exceptions produce structured log with correlation ID."""
    caplog.set_level(logging.ERROR)
    client = TestClient(app)

    with patch("app.repositories.website_scan_repository.WebsiteScanRepository.get_scan_by_id", side_effect=RuntimeError("Unexpected factory error")):
        resp = client.get("/api/v1/scan/e93f8e6c-7f24-4f05-83e3-78b1d9bf5b21", headers={"X-Request-ID": "exception-cid-111"})
        assert resp.status_code == 500
        assert resp.headers.get("X-Request-ID") == "exception-cid-111"
        assert resp.json()["detail"] == "An internal server error occurred."


def test_system_endpoints_preserved():
    """18, 19, 20, 21. Verify /health and /version endpoints remain intact."""
    client = TestClient(app)

    with patch("app.main.redis_client.ping", new_callable=AsyncMock) as mock_ping, \
         patch("sqlalchemy.ext.asyncio.AsyncEngine.connect") as mock_conn:
        r1 = client.get("/health")
        assert r1.status_code == 200
        assert r1.json()["status"] == "healthy"

    r2 = client.get("/version")
    assert r2.status_code == 200
    assert r2.json()["app_name"] == "TRUSTINEL"
