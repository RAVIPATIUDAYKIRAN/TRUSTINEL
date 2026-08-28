import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from uuid import uuid4

from app.config.settings import settings
from app.models.enums import RiskLevel, ScanStatus
from app.schemas.website_fetch import WebsiteFetchResult
from app.schemas.ssl_analysis import SSLAnalysisResult
from app.schemas.whois_analysis import WHOISAnalysisResult
from app.schemas.header_analysis import HeaderAnalysisResult
from app.schemas.redirect_analysis import RedirectAnalysisResult
from app.schemas.trust_evaluation import TrustEvaluationResult
from app.schemas.ai_threat_analysis import AIThreatAnalysisResult
from app.services.scan_service import ScanService
from app.services.ai_threat_analysis_service import AIThreatAnalysisService


@pytest.fixture
def mock_dependencies():
    session = AsyncMock()
    scan_repo = AsyncMock()
    report_repo = AsyncMock()
    history_repo = AsyncMock()

    # Mock WebsiteScan ORM object
    fake_scan_id = uuid4()
    fake_scan = MagicMock()
    fake_scan.id = fake_scan_id
    fake_scan.url = "https://example.com"
    fake_scan.domain = "example.com"
    fake_scan.status = ScanStatus.COMPLETED

    fake_report = MagicMock()
    fake_report.id = uuid4()
    fake_report.scan_id = fake_scan_id
    fake_report.trust_score = 90
    fake_report.risk_level = RiskLevel.LOW
    fake_report.summary = "Strong trust indicators."
    fake_report.explanation = "SSL valid and domain old."
    fake_report.key_risks = []
    fake_report.positive_signals = ["SSL certificate is valid: +25"]
    fake_report.recommendation = "Standard browsing."
    fake_report.ai_threat_analysis = None

    fake_scan.trust_report = fake_report

    scan_repo.create_scan.return_value = fake_scan
    scan_repo.get_scan_by_id.return_value = fake_scan

    fetcher = AsyncMock()
    fetcher.fetch.return_value = WebsiteFetchResult(
        original_url="https://example.com", final_url="https://example.com", status_code=200
    )

    ssl_analyzer = AsyncMock()
    ssl_analyzer.analyze.return_value = SSLAnalysisResult(is_valid=True)

    whois_analyzer = AsyncMock()
    whois_analyzer.analyze.return_value = WHOISAnalysisResult(is_registered=True, domain_age_days=600)

    header_analyzer = AsyncMock()
    header_analyzer.analyze.return_value = HeaderAnalysisResult(
        strict_transport_security=True,
        content_security_policy=True,
        x_frame_options=True,
        x_content_type_options=True,
        referrer_policy=True,
        permissions_policy=True,
        security_headers_score=6,
        missing_headers=[],
    )

    redirect_analyzer = AsyncMock()
    redirect_analyzer.analyze.return_value = RedirectAnalysisResult(
        redirect_count=0,
        redirected=False,
        same_domain=True,
        is_safe_redirect=True,
        cross_domain_redirect=False,
        https_upgrade=True,
    )

    trust_engine = MagicMock()
    trust_engine.evaluate.return_value = TrustEvaluationResult(
        trust_score=90,
        risk_level=RiskLevel.LOW,
        summary="Strong trust indicators.",
        reasons=["SSL certificate is valid: +25"],
    )

    explanation_service = AsyncMock()
    explanation_service.explain.return_value = MagicMock(
        explanation="SSL valid and domain old.",
        key_risks=[],
        positive_signals=["SSL certificate is valid: +25"],
        recommendation="Standard browsing.",
    )

    return {
        "session": session,
        "scan_repo": scan_repo,
        "report_repo": report_repo,
        "history_repo": history_repo,
        "fetcher": fetcher,
        "ssl_analyzer": ssl_analyzer,
        "whois_analyzer": whois_analyzer,
        "header_analyzer": header_analyzer,
        "redirect_analyzer": redirect_analyzer,
        "trust_engine": trust_engine,
        "explanation_service": explanation_service,
    }


@pytest.mark.asyncio
async def test_scan_service_ai_disabled(mock_dependencies):
    """Test 1 & 11: AI disabled -> scan succeeds, AI threat analysis is fallback, no external call."""
    ai_threat_service = AIThreatAnalysisService()
    service = ScanService(**mock_dependencies, ai_threat_service=ai_threat_service)

    with patch.object(settings, "AI_THREAT_ANALYSIS_ENABLED", False):
        scan = await service.create_scan("https://example.com")

    assert scan is not None
    assert scan.trust_report is not None
    assert hasattr(scan.trust_report, "ai_threat_analysis")
    ai_result = scan.trust_report.ai_threat_analysis
    assert ai_result.enabled is False
    assert ai_result.threat_level == "UNKNOWN"


@pytest.mark.asyncio
async def test_scan_service_ai_enabled_success(mock_dependencies):
    """Test 2: AI enabled + valid result -> AI threat analysis attached to scan result."""
    mock_ai_service = AsyncMock()
    mock_ai_service.analyze.return_value = AIThreatAnalysisResult(
        enabled=True,
        threat_level="LOW",
        confidence=0.95,
        suspicious_indicators=[],
        reasoning="Clean indicators.",
        recommended_action="Proceed.",
    )

    service = ScanService(**mock_dependencies, ai_threat_service=mock_ai_service)
    scan = await service.create_scan("https://example.com")

    assert scan.trust_report.ai_threat_analysis.enabled is True
    assert scan.trust_report.ai_threat_analysis.threat_level == "LOW"
    assert scan.trust_report.ai_threat_analysis.confidence == 0.95


@pytest.mark.asyncio
async def test_scan_service_ai_timeout_fallback(mock_dependencies):
    """Test 3: AI timeout -> scan still succeeds with safe fallback."""
    mock_ai_service = AsyncMock()
    mock_ai_service.analyze.side_effect = TimeoutError("AI request timeout")

    service = ScanService(**mock_dependencies, ai_threat_service=mock_ai_service)
    scan = await service.create_scan("https://example.com")

    assert scan is not None
    assert scan.trust_report.ai_threat_analysis.enabled is False
    assert scan.trust_report.ai_threat_analysis.threat_level == "UNKNOWN"


@pytest.mark.asyncio
async def test_scan_service_ai_exception_fallback(mock_dependencies):
    """Test 4: AI provider exception -> scan still succeeds with safe fallback."""
    mock_ai_service = AsyncMock()
    mock_ai_service.analyze.side_effect = Exception("AI Provider Error")

    service = ScanService(**mock_dependencies, ai_threat_service=mock_ai_service)
    scan = await service.create_scan("https://example.com")

    assert scan is not None
    assert scan.trust_report.ai_threat_analysis.enabled is False


@pytest.mark.asyncio
async def test_scan_service_ai_malformed_response(mock_dependencies):
    """Test 5: Malformed AI response -> scan succeeds with safe fallback."""
    mock_ai_service = AsyncMock()
    mock_ai_service.analyze.side_effect = ValueError("Malformed AI JSON")

    service = ScanService(**mock_dependencies, ai_threat_service=mock_ai_service)
    scan = await service.create_scan("https://example.com")

    assert scan is not None
    assert scan.trust_report.ai_threat_analysis.enabled is False


@pytest.mark.asyncio
async def test_ai_does_not_modify_deterministic_trust_score(mock_dependencies):
    """Test 6: AI threat result does NOT modify deterministic trust_score (remains 90)."""
    mock_ai_service = AsyncMock()
    mock_ai_service.analyze.return_value = AIThreatAnalysisResult(
        enabled=True,
        threat_level="HIGH",
        confidence=0.99,
        suspicious_indicators=["Mock threat"],
        reasoning="AI claims high threat",
        recommended_action="Block",
    )

    service = ScanService(**mock_dependencies, ai_threat_service=mock_ai_service)
    scan = await service.create_scan("https://example.com")

    assert scan.trust_report.trust_score == 90
    assert scan.trust_report.ai_threat_analysis.threat_level == "HIGH"


@pytest.mark.asyncio
async def test_ai_does_not_modify_deterministic_risk_level(mock_dependencies):
    """Test 7: AI threat result does NOT overwrite deterministic risk_level (remains LOW)."""
    mock_ai_service = AsyncMock()
    mock_ai_service.analyze.return_value = AIThreatAnalysisResult(
        enabled=True,
        threat_level="HIGH",
        confidence=0.99,
        suspicious_indicators=["Mock threat"],
        reasoning="AI claims high threat",
        recommended_action="Block",
    )

    service = ScanService(**mock_dependencies, ai_threat_service=mock_ai_service)
    scan = await service.create_scan("https://example.com")

    assert scan.trust_report.risk_level == RiskLevel.LOW
    assert scan.trust_report.ai_threat_analysis.threat_level == "HIGH"


@pytest.mark.asyncio
async def test_existing_response_fields_remain_unchanged(mock_dependencies):
    """Test 8: Existing response fields remain completely unchanged."""
    mock_ai_service = AsyncMock()
    mock_ai_service.analyze.return_value = AIThreatAnalysisResult(
        enabled=True,
        threat_level="MEDIUM",
        confidence=0.80,
        suspicious_indicators=[],
        reasoning="Reasoning",
        recommended_action="Action",
    )

    service = ScanService(**mock_dependencies, ai_threat_service=mock_ai_service)
    scan = await service.create_scan("https://example.com")

    assert scan.trust_report.summary == "Strong trust indicators."
    assert scan.trust_report.explanation == "SSL valid and domain old."
    assert scan.trust_report.positive_signals == ["SSL certificate is valid: +25"]
    assert scan.trust_report.recommendation == "Standard browsing."


@pytest.mark.asyncio
async def test_ai_receives_existing_evidence(mock_dependencies):
    """Test 9 & 10: AI receives existing analyzer evidence; fetcher called exactly ONCE."""
    mock_ai_service = AsyncMock()
    mock_ai_service.analyze.return_value = AIThreatAnalysisResult(
        enabled=True,
        threat_level="LOW",
        confidence=0.9,
        suspicious_indicators=[],
        reasoning="Clean",
        recommended_action="Proceed",
    )

    service = ScanService(**mock_dependencies, ai_threat_service=mock_ai_service)
    await service.create_scan("https://example.com")

    # Verify WebsiteFetcher was called exactly once
    assert mock_dependencies["fetcher"].fetch.call_count == 1

    # Verify AIThreatAnalysisService.analyze was called with existing analyzer results
    assert mock_ai_service.analyze.call_count == 1
    call_kwargs = mock_ai_service.analyze.call_args.kwargs
    assert "trust_evaluation" in call_kwargs
    assert "ssl_result" in call_kwargs
    assert "whois_result" in call_kwargs
    assert "header_result" in call_kwargs
    assert "redirect_result" in call_kwargs
