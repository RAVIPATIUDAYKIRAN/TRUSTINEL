import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from app.services.content_extractor import ContentExtractor
from app.services.ai_threat_analysis_service import AIThreatAnalysisService
from app.services.scan_service import ScanService
from app.schemas.ai_threat_analysis import AIThreatAnalysisResult
from app.schemas.trust_evaluation import TrustEvaluationResult
from app.schemas.ssl_analysis import SSLAnalysisResult
from app.schemas.whois_analysis import WHOISAnalysisResult
from app.schemas.header_analysis import HeaderAnalysisResult
from app.schemas.redirect_analysis import RedirectAnalysisResult
from app.models.enums import RiskLevel, ScanStatus

TRENDAYOFFERR_DOM_HTML = """<!DOCTYPE html>
<html>
<head><title>Lycra Men's Track Pants - trendayofferr.store</title></head>
<body>
    <h1>Lycra Men's Track Pants</h1>
    <div>
        <span>Rs. 499.00</span>
        <span>Rs. 2,999.00</span>
        <span>88% OFF - Special Discount</span>
    </div>
    <p>Hurry! Flash Sale Ends in 05:22. Limited Stock Left!</p>
    <button>Buy Now</button>
</body>
</html>"""

def test_content_extractor_rendered_dom():
    evidence = ContentExtractor.extract(TRENDAYOFFERR_DOM_HTML, 'https://trendayofferr.store')
    assert 88 in evidence.discount_percentages
    assert any('HURRY' in u or 'SALE ENDS' in u for u in evidence.urgency_claims)
    assert len(evidence.stock_claims) > 0
    assert evidence.has_buy_or_checkout_button is True

@pytest.mark.asyncio
async def test_ai_threat_service_cache_domain_identity():
    AIThreatAnalysisService._in_memory_cache.clear()
    service = AIThreatAnalysisService()
    service._is_ai_enabled = lambda: True

    mock_provider = AsyncMock()
    mock_provider.analyze_threat.return_value = AIThreatAnalysisResult(
        enabled=True, threat_level='LOW', confidence=0.9, suspicious_indicators=[], reasoning='Clean', recommended_action='Proceed', evidence_mappings=[]
    )
    service._providers = {'openai': mock_provider}

    trust_eval = TrustEvaluationResult(trust_score=90, risk_level=RiskLevel.LOW, summary='Clean', reasons=[])
    ssl_res = SSLAnalysisResult(is_valid=True)
    whois_res = WHOISAnalysisResult(is_registered=True, domain_age_days=500)
    header_res = HeaderAnalysisResult(strict_transport_security=True, content_security_policy=True, x_frame_options=True, x_content_type_options=True, referrer_policy=True, permissions_policy=True, security_headers_score=6)
    redirect_res = RedirectAnalysisResult(redirect_count=0, redirected=False, same_domain=True, is_safe_redirect=True, cross_domain_redirect=False, https_upgrade=True)

    result = await service.analyze(
        trust_evaluation=trust_eval,
        ssl_result=ssl_res,
        whois_result=whois_res,
        header_result=header_res,
        redirect_result=redirect_res,
        domain='trendayofferr.store'
    )
    assert result is not None
    cache_keys = list(service._in_memory_cache.keys())
    assert len(cache_keys) > 0
    assert any('trendayofferr.store' in k for k in cache_keys)
    assert all('unknown' not in k for k in cache_keys)

@pytest.mark.asyncio
async def test_scan_service_end_to_end_dom_integration():
    session = AsyncMock()
    scan_repo = AsyncMock()
    report_repo = AsyncMock()
    history_repo = AsyncMock()

    fake_scan = MagicMock()
    fake_scan.id = '12345678-1234-5678-1234-567812345678'
    fake_scan.url = 'https://trendayofferr.store/products/lycra'
    fake_scan.domain = 'trendayofferr.store'
    fake_scan.status = ScanStatus.COMPLETED

    scan_repo.create_scan.return_value = fake_scan
    scan_repo.get_scan_by_id.return_value = fake_scan

    fetcher = AsyncMock()
    fetcher.fetch.return_value = MagicMock(
        original_url='https://trendayofferr.store', final_url='https://trendayofferr.store', status_code=200, html_content='<html><body>Skeleton</body></html>', response_time_ms=100
    )
    ssl_analyzer = AsyncMock()
    ssl_analyzer.analyze.return_value = SSLAnalysisResult(is_valid=True)
    whois_analyzer = AsyncMock()
    whois_analyzer.analyze.return_value = WHOISAnalysisResult(is_registered=False)
    header_analyzer = AsyncMock()
    header_analyzer.analyze.return_value = HeaderAnalysisResult(strict_transport_security=True, content_security_policy=True, x_frame_options=True, x_content_type_options=True, referrer_policy=True, permissions_policy=True, security_headers_score=6)
    redirect_analyzer = AsyncMock()
    redirect_analyzer.analyze.return_value = RedirectAnalysisResult(redirect_count=0, redirected=False, same_domain=True, is_safe_redirect=True, cross_domain_redirect=False, https_upgrade=True)

    service = ScanService(
        session=session,
        scan_repo=scan_repo,
        report_repo=report_repo,
        history_repo=history_repo,
        fetcher=fetcher,
        ssl_analyzer=ssl_analyzer,
        whois_analyzer=whois_analyzer,
        header_analyzer=header_analyzer,
        redirect_analyzer=redirect_analyzer,
    )

    scan = await service.create_scan('https://trendayofferr.store/products/lycra', page_html=TRENDAYOFFERR_DOM_HTML)
    assert report_repo.create_report.called
    kwargs = report_repo.create_report.call_args.kwargs
    assert kwargs['content_risk_score'] >= 65
    assert kwargs['overall_risk_score'] >= 35
