import pytest
from unittest.mock import AsyncMock, patch, MagicMock

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
from app.services.rule_based_trust_engine import RuleBasedTrustEngine


@pytest.fixture
def dummy_evidence():
    ssl_result = SSLAnalysisResult(is_valid=True, error=None)
    whois_result = WHOISAnalysisResult(is_registered=True, domain_age_days=500, error=None)
    header_result = HeaderAnalysisResult(
        strict_transport_security=True,
        content_security_policy=True,
        x_frame_options=True,
        x_content_type_options=True,
        referrer_policy=True,
        permissions_policy=True,
        security_headers_score=6,
        missing_headers=[],
    )
    redirect_result = RedirectAnalysisResult(
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
        summary="Website shows strong trust indicators.",
        reasons=["SSL certificate is valid: +25", "Domain is older than one year: +15"],
    )
    return trust_eval, ssl_result, whois_result, header_result, redirect_result


@pytest.mark.asyncio
async def test_ai_disabled_returns_fallback(dummy_evidence):
    """Test 1: When AI_THREAT_ANALYSIS_ENABLED is False, returns deterministic fallback without API call."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = dummy_evidence

    with patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", False):
        result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is False
    assert result.threat_level == "UNKNOWN"
    assert result.confidence == 0.0
    assert "disabled" in result.reasoning.lower()
    assert isinstance(result.suspicious_indicators, list)


@pytest.mark.asyncio
async def test_deterministic_fallback_structure(dummy_evidence):
    """Test 2: Deterministic fallback structure has valid non-null default fields."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = dummy_evidence

    with patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", False):
        result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert isinstance(result, AIThreatAnalysisResult)
    assert result.enabled is False
    assert result.threat_level == "UNKNOWN"
    assert result.confidence == 0.0
    assert result.reasoning != ""
    assert result.recommended_action != ""


@pytest.mark.asyncio
async def test_valid_ai_response_handling(dummy_evidence):
    """Test 3: Valid AI provider response returns parsed AIThreatAnalysisResult with enabled=True."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = dummy_evidence

    mock_ai_output = AIThreatAnalysisResult(
        enabled=True,
        threat_level="LOW",
        confidence=0.92,
        suspicious_indicators=[],
        reasoning="Valid SSL certificate and clean headers indicate low threat.",
        recommended_action="Proceed normally.",
    )

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.return_value = mock_ai_output

    with patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-test-key"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is True
    assert result.threat_level == "LOW"
    assert result.confidence == 0.92
    assert result.reasoning == "Valid SSL certificate and clean headers indicate low threat."


@pytest.mark.asyncio
async def test_malformed_ai_json_response_handling(dummy_evidence):
    """Test 4: Provider throwing JSONDecodeError safely triggers fallback."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = dummy_evidence

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.side_effect = ValueError("Invalid JSON from AI provider")

    with patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-test-key"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is False
    assert result.threat_level == "UNKNOWN"
    assert result.confidence == 0.0


@pytest.mark.asyncio
async def test_missing_ai_fields_handling(dummy_evidence):
    """Test 5: Missing required fields from AI response triggers safe fallback."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = dummy_evidence

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.side_effect = KeyError("missing reasoning")

    with patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-test-key"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is False
    assert result.threat_level == "UNKNOWN"


@pytest.mark.asyncio
async def test_invalid_threat_level_handling(dummy_evidence):
    """Test 6: Invalid threat level (e.g. 'CRITICAL') triggers safe fallback."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = dummy_evidence

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.side_effect = ValueError("Invalid threat_level: CRITICAL")

    with patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-test-key"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is False
    assert result.threat_level == "UNKNOWN"


@pytest.mark.asyncio
async def test_invalid_confidence_handling(dummy_evidence):
    """Test 7: Out-of-bounds confidence score (e.g. 5.0) triggers safe fallback."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = dummy_evidence

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.side_effect = ValueError("confidence must be <= 1.0")

    with patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-test-key"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is False
    assert result.threat_level == "UNKNOWN"


@pytest.mark.asyncio
async def test_provider_timeout_handling(dummy_evidence):
    """Test 8: Timeout during AI call is caught and returns fallback."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = dummy_evidence

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.side_effect = TimeoutError("Request timed out")

    with patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-test-key"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is False
    assert result.threat_level == "UNKNOWN"


@pytest.mark.asyncio
async def test_provider_exception_handling(dummy_evidence):
    """Test 9: Generic exception during provider invocation returns fallback."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = dummy_evidence

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.side_effect = Exception("API Connection Error")

    with patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-test-key"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert result.enabled is False
    assert result.threat_level == "UNKNOWN"


@pytest.mark.asyncio
async def test_ai_failure_does_not_fail_scan(dummy_evidence):
    """Test 10: AI service exception does not propagate to caller, scan continues smoothly."""
    service = AIThreatAnalysisService()
    trust_eval, ssl_res, whois_res, header_res, redirect_res = dummy_evidence

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.side_effect = RuntimeError("Fatal AI SDK Crash")

    with patch.dict(service._providers, {"openai": mock_provider}), \
         patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", True), \
         patch.object(settings, "AI_THREAT_ANALYSIS_API_KEY", "sk-test-key"), \
         patch.object(settings, "AI_THREAT_ANALYSIS_MODEL", "gpt-4o"):
        # Execution must complete successfully without throwing
        result = await service.analyze(trust_eval, ssl_res, whois_res, header_res, redirect_res)

    assert isinstance(result, AIThreatAnalysisResult)
    assert result.enabled is False


def test_rule_based_trust_engine_remains_unchanged(dummy_evidence):
    """Test 11: Existing RuleBasedTrustEngine logic and score output remain completely untouched."""
    _, ssl_res, whois_res, header_res, redirect_res = dummy_evidence
    engine = RuleBasedTrustEngine()

    trust_eval = engine.evaluate(
        ssl_result=ssl_res,
        whois_result=whois_res,
        header_result=header_res,
        redirect_result=redirect_res,
    )

    assert trust_eval.trust_score == 100
    assert trust_eval.risk_level == RiskLevel.LOW
