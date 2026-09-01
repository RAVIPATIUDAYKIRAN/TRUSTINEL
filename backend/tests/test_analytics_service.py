import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.analytics import DomainTrend
from app.services.analytics_service import AnalyticsService, normalize_domain_input


def test_normalize_domain_input_variations():
    """Verify domain normalization strips schemes, paths, ports, and whitespace."""
    assert normalize_domain_input("https://example.com/path/to/page") == "example.com"
    assert normalize_domain_input("http://SUB.DOMAIN.ORG:8080/foo") == "sub.domain.org"
    assert normalize_domain_input("   TRUSTINEL.IO   ") == "trustinel.io"


@pytest.mark.asyncio
async def test_analytics_service_calculates_improving_trend():
    """Verify AnalyticsService calculates IMPROVING trend when scam risk decreases (scam risk drops)."""
    mock_scan_repo = AsyncMock()

    now = datetime.now(timezone.utc)

    # Scans ordered descending (index 0 is newest)
    scan_newest = MagicMock()
    scan_newest.id = "scan-uuid-1"
    scan_newest.created_at = now
    scan_newest.trust_report = MagicMock(trust_score=95, risk_level="LOW", overall_risk_score=15, overall_risk_level="LOW", summary="Excellent trust")

    scan_older = MagicMock()
    scan_older.id = "scan-uuid-2"
    scan_older.created_at = now
    scan_older.trust_report = MagicMock(trust_score=70, risk_level="MEDIUM", overall_risk_score=40, overall_risk_level="MEDIUM", summary="Moderate trust")

    mock_scan_repo.list_scans_by_domain.return_value = [scan_newest, scan_older]

    service = AnalyticsService(mock_scan_repo)
    result = await service.get_domain_analytics("example.com")

    assert result is not None
    assert result.domain == "example.com"
    assert result.total_scans == 2
    assert result.current_scam_risk == 15
    assert result.average_scam_risk == 27.5
    assert result.min_scam_risk == 15
    assert result.max_scam_risk == 40
    assert result.scam_risk_delta == -25
    assert result.trend == DomainTrend.IMPROVING
    assert result.risk_distribution.low == 1
    assert result.risk_distribution.medium == 1
    assert result.risk_distribution.high == 0
    assert len(result.history_timeline) == 2


@pytest.mark.asyncio
async def test_analytics_service_calculates_degrading_trend():
    """Verify AnalyticsService calculates DEGRADING trend when scam risk increases."""
    mock_scan_repo = AsyncMock()

    now = datetime.now(timezone.utc)

    scan_newest = MagicMock()
    scan_newest.id = "scan-uuid-1"
    scan_newest.created_at = now
    scan_newest.trust_report = MagicMock(trust_score=40, risk_level="HIGH", overall_risk_score=75, overall_risk_level="HIGH", summary="High risk detected")

    scan_older = MagicMock()
    scan_older.id = "scan-uuid-2"
    scan_older.created_at = now
    scan_older.trust_report = MagicMock(trust_score=85, risk_level="LOW", overall_risk_score=15, overall_risk_level="LOW", summary="Low risk")

    mock_scan_repo.list_scans_by_domain.return_value = [scan_newest, scan_older]

    service = AnalyticsService(mock_scan_repo)
    result = await service.get_domain_analytics("risky-site.com")

    assert result is not None
    assert result.scam_risk_delta == 60
    assert result.trend == DomainTrend.DEGRADING
    assert result.risk_distribution.high == 1
    assert result.risk_distribution.low == 1


@pytest.mark.asyncio
async def test_analytics_service_single_scan_returns_insufficient_data():
    """Verify AnalyticsService returns INSUFFICIENT_DATA trend for single scan history."""
    mock_scan_repo = AsyncMock()

    now = datetime.now(timezone.utc)
    scan = MagicMock()
    scan.id = "scan-uuid-1"
    scan.created_at = now
    scan.trust_report = MagicMock(trust_score=80, risk_level="LOW", summary="Initial scan")

    mock_scan_repo.list_scans_by_domain.return_value = [scan]

    service = AnalyticsService(mock_scan_repo)
    result = await service.get_domain_analytics("new-domain.org")

    assert result is not None
    assert result.total_scans == 1
    assert result.score_delta is None
    assert result.trend == DomainTrend.INSUFFICIENT_DATA


def test_analytics_api_returns_404_for_unknown_domain():
    """Verify GET /api/v1/analytics/domain/{domain} returns 404 DOMAIN_NOT_FOUND when domain has no records."""
    client = TestClient(app)

    resp = client.get("/api/v1/analytics/domain/never-scanned-domain-xyz.com")
    assert resp.status_code == 404
    data = resp.json()
    assert data["error_code"] == "DOMAIN_NOT_FOUND"


def test_analytics_api_returns_400_for_invalid_domain_syntax():
    """Verify GET /api/v1/analytics/domain/{domain} returns 400 INVALID_DOMAIN for invalid syntax."""
    client = TestClient(app)

    resp = client.get("/api/v1/analytics/domain/nodotdomain")
    assert resp.status_code == 400
    data = resp.json()
    assert data["error_code"] == "INVALID_DOMAIN"
