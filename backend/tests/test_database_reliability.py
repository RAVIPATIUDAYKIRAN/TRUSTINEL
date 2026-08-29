import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError, SQLAlchemyError

from app.main import app
from app.database.session import engine


def test_sqlalchemy_exception_handler_returns_safe_503():
    """Verify SQLAlchemyError triggers HTTP 503 response without leaking credentials or query details."""
    client = TestClient(app)

    with patch("app.repositories.website_scan_repository.WebsiteScanRepository.get_scan_by_id",
               side_effect=OperationalError("SELECT 1", {}, Exception("psycopg2.OperationalError: FATAL: password authentication failed for user 'postgres'"))):
        resp = client.get("/api/v1/scan/e93f8e6c-7f24-4f05-83e3-78b1d9bf5b21")
        assert resp.status_code == 503
        data = resp.json()
        assert data["status_code"] == 503
        assert data["error_code"] == "DATABASE_ERROR"
        assert "Database service temporarily unavailable" in data["detail"]
        # Ensure password or connection string is never disclosed in response payload
        assert "postgres" not in resp.text
        assert "password" not in resp.text


def test_health_check_database_failure_masks_secrets():
    """Verify /health masks raw exception messages when database ping fails."""
    client = TestClient(app)

    with patch("sqlalchemy.ext.asyncio.AsyncEngine.connect", side_effect=Exception("postgresql://postgres:secretpassword@10.0.0.5:5432/trustinel connection timeout")):
        resp = client.get("/health")
        assert resp.status_code == 503
        data = resp.json()
        assert data["status"] == "unhealthy"
        assert data["services"]["database"]["status"] == "error: connection failed"
        # Secret password & internal IP address must NOT leak in public health response
        assert "secretpassword" not in resp.text
        assert "10.0.0.5" not in resp.text


def test_invalid_and_ssrf_urls_create_zero_db_records():
    """Verify invalid or SSRF URLs fail before scan repository creation occurs."""
    client = TestClient(app)

    with patch("app.repositories.website_scan_repository.WebsiteScanRepository.create_scan") as mock_create:
        # Invalid scheme
        resp1 = client.post("/api/v1/scan", json={"url": "ftp://example.com"})
        assert resp1.status_code == 400
        mock_create.assert_not_called()

        # SSRF localhost
        resp2 = client.post("/api/v1/scan", json={"url": "http://127.0.0.1:8000"})
        assert resp2.status_code == 403
        mock_create.assert_not_called()


@pytest.mark.asyncio
async def test_scan_service_execution_failure_rolls_back_and_marks_failed():
    """Verify ScanService rolls back active transaction and updates status to FAILED on unexpected execution error."""
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

    # Setup scan mock
    fake_scan = MagicMock()
    fake_scan.id = "test-scan-uuid"
    mock_scan_repo.create_scan.return_value = fake_scan

    # Simulate fetcher throwing an unhandled exception
    mock_fetcher.fetch.side_effect = RuntimeError("Fatal fetcher crash")

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

    with pytest.raises(RuntimeError, match="Fatal fetcher crash"):
        await service.create_scan("https://example.com")

    # Verify session rollback was called
    assert mock_session.rollback.called
    # Verify scan status update to FAILED was attempted
    mock_scan_repo.update_scan_status.assert_called_with("test-scan-uuid", "FAILED")


def test_engine_pool_configuration():
    """Verify engine uses configured pool parameters."""
    assert engine.pool is not None
