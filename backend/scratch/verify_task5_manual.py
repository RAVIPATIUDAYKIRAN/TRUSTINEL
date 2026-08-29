from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock
from app.main import app

client = TestClient(app)

print("--- 1. Verification of GET /health ---")
r_health = client.get("/health", headers={"X-Request-ID": "manual-test-health-001"})
print("Status:", r_health.status_code)
print("X-Request-ID Header:", r_health.headers.get("X-Request-ID"))
print("Payload:", r_health.json())

print("\n--- 2. Verification of GET /version ---")
r_version = client.get("/version")
print("Status:", r_version.status_code)
print("X-Request-ID Header:", r_version.headers.get("X-Request-ID"))
print("Payload:", r_version.json())

print("\n--- 3. Verification of SSRF-blocked Request ---")
r_ssrf = client.post("/api/v1/scan", json={"url": "http://127.0.0.1:8000"}, headers={"X-Request-ID": "ssrf-test-cid-888"})
print("Status:", r_ssrf.status_code)
print("X-Request-ID Header:", r_ssrf.headers.get("X-Request-ID"))
print("Payload:", r_ssrf.json())

print("\n--- 4. Verification of Rate-limited Request ---")
with patch("app.core.rate_limiter.RateLimiter.__call__") as mock_limiter:
    from app.middleware.exceptions import RateLimitException
    mock_limiter.side_effect = RateLimitException(detail="Rate limit exceeded.", retry_after_seconds=60)
    r_rate = client.post("/api/v1/scan", json={"url": "https://example.com"}, headers={"X-Request-ID": "rate-test-cid-777"})
    print("Status:", r_rate.status_code)
    print("X-Request-ID Header:", r_rate.headers.get("X-Request-ID"))
    print("Payload:", r_rate.json())

print("\n--- 5. Verification of Simulated DB Failure ---")
with patch("app.repositories.website_scan_repository.WebsiteScanRepository.get_scan_by_id", side_effect=RuntimeError("DB Connection Error")):
    from sqlalchemy.exc import OperationalError
    with patch("app.repositories.website_scan_repository.WebsiteScanRepository.get_scan_by_id", side_effect=OperationalError("SELECT 1", {}, Exception("FATAL: password authentication failed for user 'postgres'"))):
        r_db = client.get("/api/v1/scan/e93f8e6c-7f24-4f05-83e3-78b1d9bf5b21", headers={"X-Request-ID": "db-test-cid-999"})
        print("Status:", r_db.status_code)
        print("X-Request-ID Header:", r_db.headers.get("X-Request-ID"))
        print("Payload:", r_db.json())
        print("Secret disclosure check (postgres/password in body?):", ("postgres" in r_db.text or "password" in r_db.text))

print("\nManual verification complete.")
