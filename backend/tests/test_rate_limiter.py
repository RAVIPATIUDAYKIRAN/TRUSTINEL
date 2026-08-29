import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch

from app.main import app
from app.config.settings import settings
from app.core.rate_limiter import in_memory_tracker


@pytest.fixture(autouse=True)
def reset_rate_limit_state():
    """Clear in-memory rate limit tracker state before each test."""
    in_memory_tracker.clear()
    yield
    in_memory_tracker.clear()


def test_rate_limiting_enforcement_and_headers():
    """Verify rate limit threshold enforcement, headers, and 429 response body."""
    client = TestClient(app)

    # Override limit to 3 requests for fast test execution and patch Redis connection for TestClient loop isolation
    with patch.object(settings, "RATE_LIMIT_AI_STATUS", 3), \
         patch.object(settings, "RATE_LIMIT_ENABLED", True), \
         patch.object(settings, "RATE_LIMIT_WINDOW_SECONDS", 60), \
         patch("app.core.rate_limiter.redis_client.incr", new_callable=AsyncMock, side_effect=Exception("Redis offline")):

        # First 3 requests must succeed (HTTP 200) and carry telemetry headers
        for i in range(3):
            resp = client.get("/api/v1/scan/ai-status")
            assert resp.status_code == 200, f"Request {i+1} failed"
            assert "X-RateLimit-Limit" in resp.headers
            assert "X-RateLimit-Remaining" in resp.headers
            assert "X-RateLimit-Reset" in resp.headers
            assert resp.headers["X-RateLimit-Remaining"] == str(3 - (i + 1))

        # 4th request must be rejected with HTTP 429 Too Many Requests
        resp4 = client.get("/api/v1/scan/ai-status")
        assert resp4.status_code == 429
        assert "Retry-After" in resp4.headers
        assert resp4.headers["X-RateLimit-Remaining"] == "0"

        data = resp4.json()
        assert data["status_code"] == 429
        assert data["error_code"] == "RATE_LIMIT_EXCEEDED"
        assert "Rate limit exceeded" in data["detail"]
        assert "retry_after_seconds" in data
        assert data["retry_after_seconds"] >= 1


def test_rate_limiting_in_memory_fallback():
    """Verify rate limiter gracefully falls back to in-memory tracker when Redis fails."""
    client = TestClient(app)

    # Mock Redis client `incr` to throw a connection error
    with patch.object(settings, "RATE_LIMIT_AI_STATUS", 2), \
         patch.object(settings, "RATE_LIMIT_ENABLED", True), \
         patch("app.core.rate_limiter.redis_client.incr", new_callable=AsyncMock, side_effect=Exception("Redis connection refused")):

        resp1 = client.get("/api/v1/scan/ai-status")
        assert resp1.status_code == 200
        assert resp1.headers["X-RateLimit-Remaining"] == "1"

        resp2 = client.get("/api/v1/scan/ai-status")
        assert resp2.status_code == 200
        assert resp2.headers["X-RateLimit-Remaining"] == "0"

        # 3rd request fails via in-memory fallback
        resp3 = client.get("/api/v1/scan/ai-status")
        assert resp3.status_code == 429
        assert resp3.json()["error_code"] == "RATE_LIMIT_EXCEEDED"


def test_rate_limiting_disabled_bypass():
    """Verify RATE_LIMIT_ENABLED=False bypasses rate limiting limits completely."""
    client = TestClient(app)

    with patch.object(settings, "RATE_LIMIT_AI_STATUS", 2), \
         patch.object(settings, "RATE_LIMIT_ENABLED", False):

        # Execute 4 requests when limit is 2 but rate limiting disabled
        for _ in range(4):
            resp = client.get("/api/v1/scan/ai-status")
            assert resp.status_code == 200
