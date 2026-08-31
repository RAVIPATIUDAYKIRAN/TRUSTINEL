import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.reputation import ReputationStatus, ThreatCategory
from app.analyzers.reputation_analyzer import ReputationAnalyzer


@pytest.mark.asyncio
async def test_reputation_analyzer_clean_domain():
    """Verify clean domain returns CLEAN status and 100 reputation score."""
    analyzer = ReputationAnalyzer()
    with patch.object(analyzer, "resolve_ip", return_value="93.184.216.34"):
        result = await analyzer.analyze_domain("example.com")
        assert result.domain == "example.com"
        assert result.ip_address == "93.184.216.34"
        assert not result.is_blacklisted
        assert result.reputation_status == ReputationStatus.CLEAN
        assert result.reputation_score == 100
        assert len(result.blacklists_matched) == 0


@pytest.mark.asyncio
async def test_reputation_analyzer_malicious_domain_match():
    """Verify blacklisted phishing domain returns MALICIOUS status and matched provider details."""
    analyzer = ReputationAnalyzer()
    result = await analyzer.analyze_domain("phishing-test-site.com")
    assert result.is_blacklisted
    assert result.reputation_status == ReputationStatus.MALICIOUS
    assert result.reputation_score < 100
    assert len(result.blacklists_matched) >= 1
    assert result.blacklists_matched[0].category == ThreatCategory.PHISHING


@pytest.mark.asyncio
async def test_reputation_analyzer_heuristic_keyword_match():
    """Verify domain with suspicious phishing keyword triggers heuristic blocklist match."""
    analyzer = ReputationAnalyzer()
    with patch.object(analyzer, "resolve_ip", return_value="1.2.3.4"):
        result = await analyzer.analyze_domain("login-verify-account-update.com")
        assert result.is_blacklisted
        assert result.reputation_status == ReputationStatus.MALICIOUS
        assert any(m.provider == "Heuristic Phishing Engine" for m in result.blacklists_matched)


def test_reputation_api_endpoint_clean_domain():
    """Verify GET /api/v1/reputation/domain/{domain} returns valid ReputationResult schema for clean domain."""
    client = TestClient(app)
    resp = client.get("/api/v1/reputation/domain/example.com")
    assert resp.status_code == 200
    data = resp.json()
    assert data["domain"] == "example.com"
    assert data["reputation_status"] in ("CLEAN", "SUSPICIOUS", "MALICIOUS")
    assert "reputation_score" in data
    assert isinstance(data["blacklists_matched"], list)


def test_reputation_api_endpoint_invalid_domain_syntax():
    """Verify GET /api/v1/reputation/domain/{domain} returns 400 INVALID_DOMAIN for invalid syntax."""
    client = TestClient(app)
    resp = client.get("/api/v1/reputation/domain/invalid-no-dot")
    assert resp.status_code == 400
    data = resp.json()
    assert data["error_code"] == "INVALID_DOMAIN"
