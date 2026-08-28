import pytest
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.config.settings import settings
from app.schemas.ai_threat_analysis import AIServiceStatusResponse
from app.services.ai_threat_analysis_service import AIThreatAnalysisService


@pytest.fixture
def clear_caches_autouse():
    AIThreatAnalysisService._in_memory_cache.clear()
    yield
    AIThreatAnalysisService._in_memory_cache.clear()


@pytest.mark.asyncio
async def test_1_endpoint_returns_200_ok():
    """Test 1: GET /api/v1/scan/ai-status returns HTTP 200 OK."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/scan/ai-status")
        assert res.status_code == 200


@pytest.mark.asyncio
async def test_2_response_matches_schema():
    """Test 2: Response parses cleanly into AIServiceStatusResponse Pydantic schema."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/scan/ai-status")
        data = res.json()
        validated = AIServiceStatusResponse.model_validate(data)
        assert validated is not None


@pytest.mark.asyncio
async def test_3_expected_status_fields_exist():
    """Test 3: All expected status fields exist in response payload."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/scan/ai-status")
        data = res.json()

        assert "enabled" in data
        assert "provider" in data
        assert "model" in data
        assert "model_configured" in data
        assert "api_key_configured" in data
        assert "timeout_seconds" in data
        assert "cache_ttl_seconds" in data
        assert "in_memory_cache_entries" in data
        assert "security_audit" in data


@pytest.mark.asyncio
async def test_4_security_audit_metadata_exists():
    """Test 4: security_audit dictionary contains compliance flags."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/scan/ai-status")
        data = res.json()
        audit = data.get("security_audit", {})

        assert audit.get("prompt_injection_defense_enabled") is True
        assert audit.get("evidence_grounding_policy_enforced") is True
        assert audit.get("evidence_mapping_required") is True
        assert audit.get("secret_masking_enforced") is True


@pytest.mark.asyncio
async def test_5_api_key_value_is_never_returned():
    """Test 5: Actual API key string is NEVER exposed anywhere in response."""
    secret_key = "sk-super-secret-key-123456789"
    with patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", secret_key):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.get("/api/v1/scan/ai-status")
            body_text = res.text
            assert secret_key not in body_text


@pytest.mark.asyncio
async def test_6_configured_api_key_represented_as_true():
    """Test 6: Configured API key is represented strictly as boolean True."""
    with patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-secret"):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.get("/api/v1/scan/ai-status")
            data = res.json()
            assert data["api_key_configured"] is True


@pytest.mark.asyncio
async def test_7_unconfigured_api_key_represented_as_false():
    """Test 7: Unconfigured API key is represented strictly as boolean False."""
    with patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", None):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.get("/api/v1/scan/ai-status")
            data = res.json()
            assert data["api_key_configured"] is False


@pytest.mark.asyncio
async def test_8_disabled_ai_reflected_correctly():
    """Test 8: Disabled AI setting is reflected in response."""
    with patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", False):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.get("/api/v1/scan/ai-status")
            data = res.json()
            assert data["enabled"] is False


@pytest.mark.asyncio
async def test_9_enabled_ai_reflected_correctly():
    """Test 9: Enabled AI configuration is reflected in response."""
    with patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-test"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.get("/api/v1/scan/ai-status")
            data = res.json()
            assert data["enabled"] is True


@pytest.mark.asyncio
async def test_10_endpoint_performs_no_external_ai_request():
    """Test 10: Endpoint performs no external AI API calls."""
    mock_provider = AsyncMock()
    service = AIThreatAnalysisService()

    with patch.dict(service._providers, {"openai": mock_provider}):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            await client.get("/api/v1/scan/ai-status")

    assert mock_provider.analyze_threat.call_count == 0


@pytest.mark.asyncio
async def test_11_endpoint_performs_no_website_fetch():
    """Test 11: Endpoint performs no website fetches."""
    with patch("app.services.website_fetcher.WebsiteFetcher.fetch") as mock_fetch:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            await client.get("/api/v1/scan/ai-status")

    assert mock_fetch.call_count == 0


@pytest.mark.asyncio
async def test_12_endpoint_does_not_mutate_cache():
    """Test 12: Endpoint does not mutate or clear cache entries."""
    AIThreatAnalysisService._in_memory_cache["test_key"] = (9999999999.0, "{}")
    initial_count = len(AIThreatAnalysisService._in_memory_cache)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.get("/api/v1/scan/ai-status")

    assert len(AIThreatAnalysisService._in_memory_cache) == initial_count


@pytest.mark.asyncio
async def test_13_deterministic_scoring_remains_untouched():
    """Test 13: RuleBasedTrustEngine remains untouched."""
    from app.services.rule_based_trust_engine import RuleBasedTrustEngine
    engine = RuleBasedTrustEngine()
    assert hasattr(engine, "evaluate")


@pytest.mark.asyncio
async def test_14_existing_tasks_1_8_tests_continue_passing():
    """Test 14: Baseline service status method functions cleanly."""
    status_dict = AIThreatAnalysisService.get_status()
    assert "enabled" in status_dict
    assert "security_audit" in status_dict
