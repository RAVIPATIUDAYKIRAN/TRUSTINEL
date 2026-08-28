import pytest
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from app.models.enums import RiskLevel, ScanStatus
from app.schemas.website_fetch import WebsiteFetchResult
from app.schemas.ssl_analysis import SSLAnalysisResult
from app.schemas.whois_analysis import WHOISAnalysisResult
from app.schemas.header_analysis import HeaderAnalysisResult
from app.schemas.redirect_analysis import RedirectAnalysisResult
from app.schemas.trust_evaluation import TrustEvaluationResult
from app.schemas.risk_explanation import RiskExplanationResult
from app.schemas.ai_threat_analysis import AIThreatAnalysisResult
from app.services.scan_service import ScanService


@pytest.fixture
def synergy_mock_dependencies():
    session = AsyncMock()
    scan_repo = AsyncMock()
    report_repo = AsyncMock()
    history_repo = AsyncMock()

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
    }


@pytest.mark.asyncio
async def test_both_services_execute_successfully(synergy_mock_dependencies):
    """Test 1: Both explanation service and AI threat service execute successfully."""
    explanation_service = AsyncMock()
    explanation_service.explain.return_value = RiskExplanationResult(
        explanation="AI explanation text.",
        key_risks=[],
        positive_signals=["Valid SSL"],
        recommendation="Standard browsing.",
    )

    ai_threat_service = AsyncMock()
    ai_threat_service.analyze.return_value = AIThreatAnalysisResult(
        enabled=True,
        threat_level="LOW",
        confidence=0.95,
        suspicious_indicators=[],
        reasoning="Clean indicators.",
        recommended_action="Proceed.",
    )

    service = ScanService(
        **synergy_mock_dependencies,
        explanation_service=explanation_service,
        ai_threat_service=ai_threat_service,
    )
    scan = await service.create_scan("https://example.com")

    assert scan is not None
    assert scan.trust_report.ai_threat_analysis.enabled is True
    assert scan.trust_report.ai_threat_analysis.threat_level == "LOW"


@pytest.mark.asyncio
async def test_explanation_succeeds_threat_analysis_fails(synergy_mock_dependencies):
    """Test 2: Risk explanation succeeds while AI threat analysis fails -> scan completes cleanly."""
    explanation_service = AsyncMock()
    explanation_service.explain.return_value = RiskExplanationResult(
        explanation="AI explanation text.",
        key_risks=[],
        positive_signals=["Valid SSL"],
        recommendation="Standard browsing.",
    )

    ai_threat_service = AsyncMock()
    ai_threat_service.analyze.side_effect = RuntimeError("AI Threat Analysis Error")

    service = ScanService(
        **synergy_mock_dependencies,
        explanation_service=explanation_service,
        ai_threat_service=ai_threat_service,
    )
    scan = await service.create_scan("https://example.com")

    assert scan is not None
    assert scan.trust_report is not None
    assert scan.trust_report.ai_threat_analysis.enabled is False
    assert scan.trust_report.ai_threat_analysis.threat_level == "UNKNOWN"


@pytest.mark.asyncio
async def test_threat_analysis_succeeds_explanation_fails(synergy_mock_dependencies):
    """Test 3: AI threat analysis succeeds while risk explanation fails -> scan completes cleanly."""
    explanation_service = AsyncMock()
    explanation_service.explain.side_effect = RuntimeError("AI Explanation Error")

    ai_threat_service = AsyncMock()
    ai_threat_service.analyze.return_value = AIThreatAnalysisResult(
        enabled=True,
        threat_level="LOW",
        confidence=0.9,
        suspicious_indicators=[],
        reasoning="Reasoning",
        recommended_action="Action",
    )

    service = ScanService(
        **synergy_mock_dependencies,
        explanation_service=explanation_service,
        ai_threat_service=ai_threat_service,
    )
    scan = await service.create_scan("https://example.com")

    assert scan is not None
    assert scan.trust_report.ai_threat_analysis.enabled is True


@pytest.mark.asyncio
async def test_both_services_fail_without_failing_scan(synergy_mock_dependencies):
    """Test 4: Both services fail -> scan completes cleanly with deterministic fallbacks."""
    explanation_service = AsyncMock()
    explanation_service.explain.side_effect = RuntimeError("Explanation service crash")

    ai_threat_service = AsyncMock()
    ai_threat_service.analyze.side_effect = RuntimeError("AI threat service crash")

    service = ScanService(
        **synergy_mock_dependencies,
        explanation_service=explanation_service,
        ai_threat_service=ai_threat_service,
    )
    scan = await service.create_scan("https://example.com")

    assert scan is not None
    assert scan.trust_report is not None
    assert scan.trust_report.ai_threat_analysis.enabled is False


@pytest.mark.asyncio
async def test_both_services_receive_consistent_evidence(synergy_mock_dependencies):
    """Test 5: Both services receive identical analyzer evidence objects."""
    explanation_service = AsyncMock()
    ai_threat_service = AsyncMock()

    service = ScanService(
        **synergy_mock_dependencies,
        explanation_service=explanation_service,
        ai_threat_service=ai_threat_service,
    )
    await service.create_scan("https://example.com")

    exp_kwargs = explanation_service.explain.call_args.kwargs
    ai_kwargs = ai_threat_service.analyze.call_args.kwargs

    assert exp_kwargs["ssl_result"] is ai_kwargs["ssl_result"]
    assert exp_kwargs["whois_result"] is ai_kwargs["whois_result"]
    assert exp_kwargs["header_result"] is ai_kwargs["header_result"]
    assert exp_kwargs["redirect_result"] is ai_kwargs["redirect_result"]
    assert exp_kwargs["trust_evaluation"] is ai_kwargs["trust_evaluation"]


@pytest.mark.asyncio
async def test_deterministic_trust_score_remains_unchanged(synergy_mock_dependencies):
    """Test 6: Deterministic trust score remains untouched (90)."""
    explanation_service = AsyncMock()
    ai_threat_service = AsyncMock()

    service = ScanService(
        **synergy_mock_dependencies,
        explanation_service=explanation_service,
        ai_threat_service=ai_threat_service,
    )
    scan = await service.create_scan("https://example.com")

    assert scan.trust_report.trust_score == 90


@pytest.mark.asyncio
async def test_deterministic_risk_level_remains_unchanged(synergy_mock_dependencies):
    """Test 7: Deterministic risk level remains untouched (LOW)."""
    explanation_service = AsyncMock()
    ai_threat_service = AsyncMock()

    service = ScanService(
        **synergy_mock_dependencies,
        explanation_service=explanation_service,
        ai_threat_service=ai_threat_service,
    )
    scan = await service.create_scan("https://example.com")

    assert scan.trust_report.risk_level == RiskLevel.LOW


@pytest.mark.asyncio
async def test_no_duplicate_website_fetch_occurs(synergy_mock_dependencies):
    """Test 8: WebsiteFetcher.fetch is called exactly ONCE during scan workflow."""
    explanation_service = AsyncMock()
    ai_threat_service = AsyncMock()

    service = ScanService(
        **synergy_mock_dependencies,
        explanation_service=explanation_service,
        ai_threat_service=ai_threat_service,
    )
    await service.create_scan("https://example.com")

    assert synergy_mock_dependencies["fetcher"].fetch.call_count == 1


@pytest.mark.asyncio
async def test_existing_api_response_fields_remain_intact(synergy_mock_dependencies):
    """Test 9: All API response fields remain present and valid."""
    explanation_service = AsyncMock()
    explanation_service.explain.return_value = RiskExplanationResult(
        explanation="Exp", key_risks=[], positive_signals=[], recommendation="Rec"
    )
    ai_threat_service = AsyncMock()
    ai_threat_service.analyze.return_value = AIThreatAnalysisResult(
        enabled=True, threat_level="LOW", confidence=0.9, suspicious_indicators=[], reasoning="r", recommended_action="a"
    )

    service = ScanService(
        **synergy_mock_dependencies,
        explanation_service=explanation_service,
        ai_threat_service=ai_threat_service,
    )
    scan = await service.create_scan("https://example.com")

    report = scan.trust_report
    assert hasattr(report, "trust_score")
    assert hasattr(report, "risk_level")
    assert hasattr(report, "summary")
    assert hasattr(report, "explanation")
    assert hasattr(report, "key_risks")
    assert hasattr(report, "positive_signals")
    assert hasattr(report, "recommendation")
    assert hasattr(report, "ai_threat_analysis")
