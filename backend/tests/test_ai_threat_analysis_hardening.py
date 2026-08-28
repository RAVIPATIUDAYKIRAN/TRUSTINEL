import logging
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx

from app.config.settings import settings
from app.models.enums import RiskLevel
from app.schemas.ssl_analysis import SSLAnalysisResult
from app.schemas.whois_analysis import WHOISAnalysisResult
from app.schemas.header_analysis import HeaderAnalysisResult
from app.schemas.redirect_analysis import RedirectAnalysisResult
from app.schemas.trust_evaluation import TrustEvaluationResult
from app.schemas.ai_threat_analysis import AIThreatAnalysisResult
from app.services.ai_threat_analysis_service import (
    AIThreatAnalysisService,
    OpenAIThreatProvider,
)


@pytest.fixture
def sample_evidence_fixtures():
    ssl_res = SSLAnalysisResult(is_valid=True, error=None)
    whois_res = WHOISAnalysisResult(is_registered=True, domain_age_days=500, error=None)
    header_res = HeaderAnalysisResult(
        strict_transport_security=True,
        content_security_policy=True,
        x_frame_options=True,
        x_content_type_options=True,
        referrer_policy=True,
        permissions_policy=True,
        security_headers_score=6,
        missing_headers=[],
    )
    redirect_res = RedirectAnalysisResult(
        redirect_count=0,
        redirected=False,
        same_domain=True,
        is_safe_redirect=True,
        cross_domain_redirect=False,
        https_upgrade=True,
    )
    trust_eval = TrustEvaluationResult(
        trust_score=95,
        risk_level=RiskLevel.LOW,
        summary="Strong trust indicators.",
        reasons=["SSL valid: +25"],
    )
    return trust_eval, ssl_res, whois_res, header_res, redirect_res


# ---------------------------------------------------------------------------
# Test Scenarios (1-19)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_1_ai_disabled_configuration(sample_evidence_fixtures):
    """Test 1: AI disabled configuration -> returns safe fallback."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = sample_evidence_fixtures

    with patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", False):
        result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is False
    assert result.threat_level == "UNKNOWN"


@pytest.mark.asyncio
async def test_2_ai_enabled_valid_configuration(sample_evidence_fixtures):
    """Test 2: AI enabled with valid configuration -> calls provider and succeeds."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = sample_evidence_fixtures

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.return_value = AIThreatAnalysisResult(
        enabled=True,
        threat_level="LOW",
        confidence=0.9,
        suspicious_indicators=[],
        reasoning="Good evidence.",
        recommended_action="Proceed.",
    )

    with patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-secret-key-12345"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is True
    assert result.threat_level == "LOW"


@pytest.mark.asyncio
async def test_3_missing_api_key(sample_evidence_fixtures):
    """Test 3: Missing API key -> safe fallback without crash."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = sample_evidence_fixtures

    with patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", None), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is False


@pytest.mark.asyncio
async def test_4_missing_model(sample_evidence_fixtures):
    """Test 4: Missing model -> safe fallback without crash."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = sample_evidence_fixtures

    with patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-secret-key"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", ""):
        result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is False


@pytest.mark.asyncio
async def test_5_unsupported_provider(sample_evidence_fixtures):
    """Test 5: Unsupported provider -> safe fallback without crash."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = sample_evidence_fixtures

    with patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-secret-key"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_PROVIDER", "unsupported_llm"):
        result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is False


@pytest.mark.asyncio
async def test_6_invalid_timeout_clamped():
    """Test 6: Invalid/out-of-bounds timeout is clamped to safe default (10.0s)."""
    with patch.object(settings, "AI_THREAT_ANALYSIS_TIMEOUT_SECONDS", 0.05):
        timeout = AIThreatAnalysisService._get_validated_timeout()
        assert timeout == 10.0

    with patch.object(settings, "AI_THREAT_ANALYSIS_TIMEOUT_SECONDS", 120.0):
        timeout = AIThreatAnalysisService._get_validated_timeout()
        assert timeout == 10.0


@pytest.mark.asyncio
async def test_7_provider_timeout_handling(sample_evidence_fixtures):
    """Test 7: Provider timeout -> safe fallback."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = sample_evidence_fixtures

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.side_effect = TimeoutError("Timeout exceeded")

    with patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-secret-key"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is False


@pytest.mark.asyncio
async def test_8_http_401_unauthorized(sample_evidence_fixtures):
    """Test 8: HTTP 401 Unauthorized from provider -> safe fallback."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = sample_evidence_fixtures

    provider = OpenAIThreatProvider()
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError("401 Unauthorized", request=MagicMock(), response=mock_response)
        mock_post.return_value = mock_response

        with patch.dict(service._providers, {"openai": provider}), \
             patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
             patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-invalid-key"), \
             patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
            result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is False


@pytest.mark.asyncio
async def test_9_http_403_forbidden(sample_evidence_fixtures):
    """Test 9: HTTP 403 Forbidden from provider -> safe fallback."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = sample_evidence_fixtures

    provider = OpenAIThreatProvider()
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError("403 Forbidden", request=MagicMock(), response=mock_response)
        mock_post.return_value = mock_response

        with patch.dict(service._providers, {"openai": provider}), \
             patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
             patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-secret-key"), \
             patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
            result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is False


@pytest.mark.asyncio
async def test_10_http_429_rate_limit(sample_evidence_fixtures):
    """Test 10: HTTP 429 Rate Limit from provider -> safe fallback."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = sample_evidence_fixtures

    provider = OpenAIThreatProvider()
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError("429 Too Many Requests", request=MagicMock(), response=mock_response)
        mock_post.return_value = mock_response

        with patch.dict(service._providers, {"openai": provider}), \
             patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
             patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-secret-key"), \
             patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
            result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is False


@pytest.mark.asyncio
async def test_11_http_500_server_error(sample_evidence_fixtures):
    """Test 11: HTTP 500 Internal Server Error from provider -> safe fallback."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = sample_evidence_fixtures

    provider = OpenAIThreatProvider()
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError("500 Internal Server Error", request=MagicMock(), response=mock_response)
        mock_post.return_value = mock_response

        with patch.dict(service._providers, {"openai": provider}), \
             patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
             patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-secret-key"), \
             patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
            result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is False


@pytest.mark.asyncio
async def test_12_connection_failure(sample_evidence_fixtures):
    """Test 12: Network connection failure (httpx.RequestError) -> safe fallback."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = sample_evidence_fixtures

    provider = OpenAIThreatProvider()
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_post.side_effect = httpx.ConnectError("Could not connect to host")

        with patch.dict(service._providers, {"openai": provider}), \
             patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
             patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-secret-key"), \
             patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
            result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is False


@pytest.mark.asyncio
async def test_13_malformed_provider_response(sample_evidence_fixtures):
    """Test 13: Malformed provider response JSON -> safe fallback."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = sample_evidence_fixtures

    provider = OpenAIThreatProvider()
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"choices": [{"message": {"content": "Not JSON text"}}]}
        mock_post.return_value = mock_response

        with patch.dict(service._providers, {"openai": provider}), \
             patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
             patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-secret-key"), \
             patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
            result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is False


@pytest.mark.asyncio
async def test_14_api_key_never_in_logs(sample_evidence_fixtures, caplog):
    """Test 14: Secret API key string NEVER appears in log records."""
    secret_key = "sk-SUPER-SECRET-KEY-99999"
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = sample_evidence_fixtures

    with caplog.at_level(logging.DEBUG), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", secret_key), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    for record in caplog.records:
        assert secret_key not in record.getMessage()


@pytest.mark.asyncio
async def test_15_api_key_never_in_api_response_or_status():
    """Test 15: Secret API key string NEVER appears in get_status or AIThreatAnalysisResult."""
    secret_key = "sk-SUPER-SECRET-KEY-99999"
    with patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", secret_key), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        status = AIThreatAnalysisService.get_status()

    assert status["api_key_configured"] is True
    assert "api_key" not in status
    assert secret_key not in str(status)

    res = AIThreatAnalysisResult(
        enabled=True,
        threat_level="LOW",
        confidence=0.9,
        suspicious_indicators=[],
        reasoning="Clean",
        recommended_action="Proceed",
    )
    assert secret_key not in str(res.model_dump())


@pytest.mark.asyncio
async def test_16_deterministic_trust_score_unchanged(sample_evidence_fixtures):
    """Test 16: Deterministic trust score remains untouched (95)."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = sample_evidence_fixtures

    with patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", False):
        await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert trust_eval.trust_score == 95


@pytest.mark.asyncio
async def test_17_deterministic_risk_level_unchanged(sample_evidence_fixtures):
    """Test 17: Deterministic risk level remains untouched (LOW)."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = sample_evidence_fixtures

    with patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", False):
        await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert trust_eval.risk_level == RiskLevel.LOW


@pytest.mark.asyncio
async def test_18_post_scan_succeeds_when_ai_fails(sample_evidence_fixtures):
    """Test 18: Scan analysis returns a valid AIThreatAnalysisResult fallback even when AI provider fails."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = sample_evidence_fixtures

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.side_effect = RuntimeError("Catastrophic AI Provider Crash")

    with patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-secret"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result is not None
    assert result.enabled is False
    assert result.threat_level == "UNKNOWN"
