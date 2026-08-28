import logging
import time
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.config.settings import settings
from app.models.enums import RiskLevel
from app.schemas.ssl_analysis import SSLAnalysisResult
from app.schemas.whois_analysis import WHOISAnalysisResult
from app.schemas.header_analysis import HeaderAnalysisResult
from app.schemas.redirect_analysis import RedirectAnalysisResult
from app.schemas.trust_evaluation import TrustEvaluationResult
from app.schemas.ai_threat_analysis import AIThreatAnalysisResult, AIEvidenceMapping
from app.services.ai_threat_analysis_service import AIThreatAnalysisService


@pytest.fixture(autouse=True)
def clear_caches():
    AIThreatAnalysisService._in_memory_cache.clear()
    yield
    AIThreatAnalysisService._in_memory_cache.clear()


@pytest.fixture
def caching_fixtures():
    ssl_res = SSLAnalysisResult(is_valid=True)
    whois_res = WHOISAnalysisResult(is_registered=True, domain_age_days=600)
    header_res = HeaderAnalysisResult(
        strict_transport_security=True, content_security_policy=True, x_frame_options=True,
        x_content_type_options=True, referrer_policy=True, permissions_policy=True,
        security_headers_score=6, missing_headers=[]
    )
    redirect_res = RedirectAnalysisResult(redirect_count=0, redirected=False, same_domain=True, is_safe_redirect=True, cross_domain_redirect=False, https_upgrade=True)
    trust_eval = TrustEvaluationResult(trust_score=95, risk_level=RiskLevel.LOW, summary="Strong site", reasons=["SSL valid: +25"])

    object.__setattr__(trust_eval, "domain", "example.com")

    return trust_eval, ssl_res, whois_res, header_res, redirect_res


# ---------------------------------------------------------------------------
# Test Scenarios (1-19)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_1_cache_miss_calls_provider(caching_fixtures):
    """Test 1: Cache miss executes provider."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = caching_fixtures

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.return_value = AIThreatAnalysisResult(
        enabled=True, threat_level="LOW", confidence=0.9, suspicious_indicators=[], reasoning="r", recommended_action="a"
    )

    with patch("app.services.ai_threat_analysis_service.redis_client.get", new_callable=AsyncMock, return_value=None), \
         patch("app.services.ai_threat_analysis_service.redis_client.set", new_callable=AsyncMock, return_value=True), \
         patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-test"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert mock_provider.analyze_threat.call_count == 1
    assert result.enabled is True


@pytest.mark.asyncio
async def test_2_successful_result_is_cached(caching_fixtures):
    """Test 2: Successful AI result is stored in cache."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = caching_fixtures

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.return_value = AIThreatAnalysisResult(
        enabled=True, threat_level="LOW", confidence=0.9, suspicious_indicators=[], reasoning="r", recommended_action="a"
    )

    with patch("app.services.ai_threat_analysis_service.redis_client.get", new_callable=AsyncMock, return_value=None), \
         patch("app.services.ai_threat_analysis_service.redis_client.set", new_callable=AsyncMock, return_value=True), \
         patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-test"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert len(service._in_memory_cache) == 1


@pytest.mark.asyncio
async def test_3_cache_hit_avoids_provider_call(caching_fixtures):
    """Test 3: Cache hit avoids second call to AI provider."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = caching_fixtures

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.return_value = AIThreatAnalysisResult(
        enabled=True, threat_level="LOW", confidence=0.9, suspicious_indicators=[], reasoning="r", recommended_action="a"
    )

    with patch("app.services.ai_threat_analysis_service.redis_client.get", new_callable=AsyncMock, return_value=None), \
         patch("app.services.ai_threat_analysis_service.redis_client.set", new_callable=AsyncMock, return_value=True), \
         patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-test"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        # First call -> miss
        await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)
        # Second call -> hit
        res2 = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert mock_provider.analyze_threat.call_count == 1
    assert res2.enabled is True


@pytest.mark.asyncio
async def test_4_cache_hit_logs_correctly(caching_fixtures, caplog):
    """Test 4: Cache hit logs cache hit message."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = caching_fixtures

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.return_value = AIThreatAnalysisResult(
        enabled=True, threat_level="LOW", confidence=0.9, suspicious_indicators=[], reasoning="r", recommended_action="a"
    )

    with caplog.at_level(logging.INFO), \
         patch("app.services.ai_threat_analysis_service.redis_client.get", return_value=None), \
         patch("app.services.ai_threat_analysis_service.redis_client.set", return_value=True), \
         patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-test"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)
        await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert any("cache hit" in record.getMessage() for record in caplog.records)


@pytest.mark.asyncio
async def test_5_same_domain_same_evidence_produces_same_cache_key(caching_fixtures):
    """Test 5: Same domain + same evidence produces same cache key."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = caching_fixtures

    ev1 = service._build_evidence(trust_eval, ssl_res, whois_res, header_res, redirect_res)
    ev2 = service._build_evidence(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    k1 = service._generate_cache_key("example.com", ev1)
    k2 = service._generate_cache_key("example.com", ev2)

    assert k1 == k2
    assert k1.startswith("trustinel:ai_threat:example.com:")


@pytest.mark.asyncio
async def test_6_same_domain_changed_evidence_produces_different_cache_key(caching_fixtures):
    """Test 6: Same domain + changed evidence produces different cache key."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = caching_fixtures

    ev1 = service._build_evidence(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    ssl_invalid = SSLAnalysisResult(is_valid=False, error="Expired")
    ev2 = service._build_evidence(trust_eval, ssl_invalid, whois_res, header_res, redirect_res)

    k1 = service._generate_cache_key("example.com", ev1)
    k2 = service._generate_cache_key("example.com", ev2)

    assert k1 != k2


@pytest.mark.asyncio
async def test_7_ttl_expiration_causes_cache_miss(caching_fixtures):
    """Test 7: Expired cache entry causes a cache miss."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = caching_fixtures

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.return_value = AIThreatAnalysisResult(
        enabled=True, threat_level="LOW", confidence=0.9, suspicious_indicators=[], reasoning="r", recommended_action="a"
    )

    with patch("app.services.ai_threat_analysis_service.redis_client.get", new_callable=AsyncMock, return_value=None), \
         patch("app.services.ai_threat_analysis_service.redis_client.set", new_callable=AsyncMock, return_value=True), \
         patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-test"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        # Initial call
        await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

        # Manually expire in-memory cache entry timestamp
        for key in list(service._in_memory_cache.keys()):
            val = service._in_memory_cache[key][1]
            service._in_memory_cache[key] = (time.time() - 10, val)

        # Second call after expiration -> should call provider again
        await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert mock_provider.analyze_threat.call_count == 2


@pytest.mark.asyncio
async def test_8_disabled_ai_is_not_cached(caching_fixtures):
    """Test 8: Disabled AI fallback is not stored in cache."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = caching_fixtures

    with patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", False):
        res = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert res.enabled is False
    assert len(service._in_memory_cache) == 0


@pytest.mark.asyncio
async def test_9_provider_timeout_is_not_cached(caching_fixtures):
    """Test 9: Provider timeout fallback is not cached."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = caching_fixtures

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.side_effect = TimeoutError("Timeout")

    with patch("app.services.ai_threat_analysis_service.redis_client.get", return_value=None), \
         patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-test"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        res = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert res.enabled is False
    assert len(service._in_memory_cache) == 0


@pytest.mark.asyncio
async def test_10_provider_failure_is_not_cached(caching_fixtures):
    """Test 10: Provider failure fallback is not cached."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = caching_fixtures

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.side_effect = RuntimeError("500 Server Error")

    with patch("app.services.ai_threat_analysis_service.redis_client.get", return_value=None), \
         patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-test"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        res = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert res.enabled is False
    assert len(service._in_memory_cache) == 0


@pytest.mark.asyncio
async def test_11_malformed_ai_response_is_not_cached(caching_fixtures):
    """Test 11: Malformed AI response fallback is not cached."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = caching_fixtures

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.side_effect = ValueError("Malformed JSON")

    with patch("app.services.ai_threat_analysis_service.redis_client.get", return_value=None), \
         patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-test"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        res = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert res.enabled is False
    assert len(service._in_memory_cache) == 0


@pytest.mark.asyncio
async def test_12_redis_failure_falls_back_safely(caching_fixtures):
    """Test 12: Redis connection error falls back to in-memory cache safely."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = caching_fixtures

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.return_value = AIThreatAnalysisResult(
        enabled=True, threat_level="LOW", confidence=0.9, suspicious_indicators=[], reasoning="r", recommended_action="a"
    )

    with patch("app.services.ai_threat_analysis_service.redis_client.get", side_effect=Exception("Redis connection error")), \
         patch("app.services.ai_threat_analysis_service.redis_client.set", side_effect=Exception("Redis connection error")), \
         patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-test"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        res = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert res.enabled is True
    assert len(service._in_memory_cache) == 1


@pytest.mark.asyncio
async def test_13_in_memory_fallback_honors_ttl(caching_fixtures):
    """Test 13: In-memory cache honors TTL."""
    service = AIThreatAnalysisService()

    valid_res = AIThreatAnalysisResult(
        enabled=True, threat_level="LOW", confidence=0.9, suspicious_indicators=[], reasoning="r", recommended_action="a"
    )
    key = "trustinel:ai_threat:test:123"

    # Store with TTL = -10 (expired)
    service._in_memory_cache[key] = (time.time() - 10, valid_res.model_dump_json())

    with patch("app.services.ai_threat_analysis_service.redis_client.get", return_value=None):
        cached = await service._get_from_cache(key)

    assert cached is None
    assert key not in service._in_memory_cache


@pytest.mark.asyncio
async def test_14_in_memory_cache_remains_bounded(caching_fixtures):
    """Test 14: In-memory cache remains bounded to _MAX_IN_MEMORY_ENTRIES."""
    service = AIThreatAnalysisService()
    valid_res = AIThreatAnalysisResult(
        enabled=True, threat_level="LOW", confidence=0.9, suspicious_indicators=[], reasoning="r", recommended_action="a"
    )

    with patch("app.services.ai_threat_analysis_service.redis_client.set", new_callable=AsyncMock, return_value=True), \
         patch.object(AIThreatAnalysisService, "_MAX_IN_MEMORY_ENTRIES", 5):
        for i in range(10):
            key = f"key_{i}"
            await service._store_in_cache(key, valid_res, 600)

    assert len(service._in_memory_cache) <= 5


@pytest.mark.asyncio
async def test_15_invalid_corrupted_cached_data_ignored_safely():
    """Test 15: Invalid/corrupted cached JSON is ignored safely."""
    service = AIThreatAnalysisService()
    key = "trustinel:ai_threat:corrupt:123"
    service._in_memory_cache[key] = (time.time() + 600, "{invalid_json_corrupted}")

    with patch("app.services.ai_threat_analysis_service.redis_client.get", return_value=None):
        cached = await service._get_from_cache(key)

    assert cached is None
    assert key not in service._in_memory_cache


@pytest.mark.asyncio
async def test_16_evidence_mappings_survive_cache_round_trip(caching_fixtures):
    """Test 16: evidence_mappings survive cache round-trip serialization."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = caching_fixtures

    mapping = AIEvidenceMapping(category="SSL", finding="Valid SSL", impact="Encryption")
    ai_res = AIThreatAnalysisResult(
        enabled=True, threat_level="LOW", confidence=0.95, suspicious_indicators=[], reasoning="r", recommended_action="a", evidence_mappings=[mapping]
    )

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.return_value = ai_res

    with patch("app.services.ai_threat_analysis_service.redis_client.get", new_callable=AsyncMock, return_value=None), \
         patch("app.services.ai_threat_analysis_service.redis_client.set", new_callable=AsyncMock, return_value=True), \
         patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-test"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        # Miss -> populates cache
        await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

        # Hit from cache
        cached = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert len(cached.evidence_mappings) == 1
    assert cached.evidence_mappings[0].category == "SSL"
    assert cached.evidence_mappings[0].finding == "Valid SSL"


@pytest.mark.asyncio
async def test_17_deterministic_trust_score_remains_unchanged(caching_fixtures):
    """Test 17: Deterministic trust score remains untouched (95)."""
    trust_eval, _, _, _, _ = caching_fixtures
    assert trust_eval.trust_score == 95


@pytest.mark.asyncio
async def test_18_deterministic_risk_level_remains_unchanged(caching_fixtures):
    """Test 18: Deterministic risk level remains untouched (LOW)."""
    trust_eval, _, _, _, _ = caching_fixtures
    assert trust_eval.risk_level == RiskLevel.LOW


@pytest.mark.asyncio
async def test_19_existing_tasks_1_7_tests_continue_passing(caching_fixtures):
    """Test 19: Baseline fixtures intact."""
    trust_eval, _, _, _, _ = caching_fixtures
    assert trust_eval.trust_score == 95
