import asyncio
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch, MagicMock
from app.main import app

client = TestClient(app)

print("--- 1. Testing GET /health ---")
r_health = client.get("/health")
print("Status:", r_health.status_code)
print("Payload:", r_health.json())

print("\n--- 2. Testing GET /version ---")
r_version = client.get("/version")
print("Status:", r_version.status_code)
print("Payload:", r_version.json())

print("\n--- 3. Testing Simulated Database Failure (SQLAlchemyError) ---")
from sqlalchemy.exc import OperationalError
with patch("app.repositories.website_scan_repository.WebsiteScanRepository.get_scan_by_id",
           side_effect=OperationalError("SELECT 1", {}, Exception("FATAL: password authentication failed for user 'postgres'"))):
    r_err = client.get("/api/v1/scan/e93f8e6c-7f24-4f05-83e3-78b1d9bf5b21")
    print("Status:", r_err.status_code)
    print("Payload:", r_err.json())
    print("Secret disclosure check (postgres/password in body?):", ("postgres" in r_err.text or "password" in r_err.text))

print("\n--- 4. Testing Health Check Secret Masking on DB Failure ---")
with patch("sqlalchemy.ext.asyncio.AsyncEngine.connect", side_effect=Exception("postgresql://postgres:secretpassword@10.0.0.5:5432/trustinel connection timeout")):
    r_h_err = client.get("/health")
    print("Status:", r_h_err.status_code)
    print("Payload:", r_h_err.json())
    print("Secret disclosure check (secretpassword/10.0.0.5 in body?):", ("secretpassword" in r_h_err.text or "10.0.0.5" in r_h_err.text))

print("\nManual verification complete.")
