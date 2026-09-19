import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.content_extractor import ContentExtractor
from app.services.ai_threat_analysis_service import AIThreatAnalysisService
from app.services.scan_service import ScanService
from app.services.rule_based_trust_engine import RuleBasedTrustEngine
from app.schemas.ai_threat_analysis import AIThreatAnalysisResult
from app.schemas.trust_evaluation import TrustEvaluationResult
from app.schemas.ssl_analysis import SSLAnalysisResult
from app.schemas.whois_analysis import WHOISAnalysisResult
from app.schemas.header_analysis import HeaderAnalysisResult
from app.schemas.redirect_analysis import RedirectAnalysisResult
from app.models.enums import RiskLevel, ScanStatus

SYNTHETIC_SCAM_DOM_HTML = """<!DOCTYPE html>
<html>
<head><title>Exclusive Mega Store - Special Promotion</title></head>
<body>
    <h1>Special Deal Item</h1>
    <div>
        <span class="mrp">Original: Rs. 2,999.00</span>
        <span class="sale">Special: Rs. 499.00</span>
        <span class="badge">88% OFF - Special Discount</span>
    </div>
    <p>Hurry! Sale Ends Today. Limited Stock Left! Only 2 remaining!</p>
    <button>Buy Now</button>
</body>
</html>"""

LEGITIMATE_SALE_DOM_HTML = """<!DOCTYPE html>
<html>
<head><title>Acme Electronics Official Store</title></head>
<body>
    <h1>Acme Wireless Headphones</h1>
    <div>Price: $80 (Save 20%)</div>
    <p>Welcome to Acme Electronics. For customer support email support@acmeelectronics.com or call 1-800-555-0199.</p>
    <a href="/privacy">Privacy Policy</a>
    <a href="/terms">Terms of Service</a>
    <button>Add to Cart</button>
</body>
</html>"""

# Test A — Rendered DOM detection
def test_rendered_dom_detection():
    evidence = ContentExtractor.extract(SYNTHETIC_SCAM_DOM_HTML, 'https://example.com')
    assert 88 in evidence.discount_percentages
    assert any('HURRY' in u or 'ENDS TODAY' in u for u in evidence.urgency_claims)
    assert len(evidence.stock_claims) > 0
    assert evidence.has_buy_or_checkout_button is True

# Test B — Discount formats (50% OFF, 50 % OFF, Save 50%, ₹2,999 → ₹499, was $99 now $49)
def test_discount_format_variations():
    html_a = "<div>50% OFF - Summer Sale</div>"
    ev_a = ContentExtractor.extract(html_a, "https://example.com")
    assert 50 in ev_a.discount_percentages

    html_b = "<div>Save 50% on all items</div>"
    ev_b = ContentExtractor.extract(html_b, "https://example.com")
    assert 50 in ev_b.discount_percentages

    html_c = "<div>was $99 now $49</div>"
    ev_c = ContentExtractor.extract(html_c, "https://example.com")
    assert len(ev_c.discount_percentages) > 0

    html_d = "<div>Original: Rs. 2999, Special: Rs. 499</div>"
    ev_d = ContentExtractor.extract(html_d, "https://example.com")
    assert 83 in ev_d.discount_percentages

# Test C — Urgency phrases
def test_urgency_phrases_extraction():
    html = "<div>Hurry! Offer ends today. Last chance!</div>"
    ev = ContentExtractor.extract(html, "https://example.com")
    assert len(ev.urgency_claims) >= 2

# Test D — Scarcity phrases
def test_scarcity_phrases_extraction():
    html = "<div>Only 2 left in stock! Low stock warning.</div>"
    ev = ContentExtractor.extract(html, "https://example.com")
    assert len(ev.stock_claims) >= 1

# Test E — Legitimate sale page (should NOT be high risk)
def test_legitimate_sale_page_isolation():
    ev = ContentExtractor.extract(LEGITIMATE_SALE_DOM_HTML, "https://example.com")
    assert ev.has_contact_info is True
    assert ev.has_policy_links is True
    assert max(ev.discount_percentages, default=0) <= 20

# Test F — Multiple independent signals
def test_multiple_independent_signals():
    ev = ContentExtractor.extract(SYNTHETIC_SCAM_DOM_HTML, "https://example.com")
    assert len(ev.discount_percentages) > 0
    assert len(ev.urgency_claims) > 0
    assert len(ev.stock_claims) > 0

# Test G — Empty HTML handling
def test_empty_html_handling():
    ev = ContentExtractor.extract("<html><body></body></html>", "https://example.com")
    assert ev.discount_percentages == []

# Test H — Oversized HTML handling
def test_oversized_html_handling():
    big_html = "<html><body>" + ("<p>Text</p>" * 100000) + "</body></html>"
    ev = ContentExtractor.extract(big_html[:500000], "https://example.com")
    assert ev is not None

# Test I — Sensitive data protection (redaction simulation)
def test_sensitive_data_redaction():
    html = "<html><body><form><input type='password' value='secret123'></form></body></html>"
    ev = ContentExtractor.extract(html, "https://example.com")
    assert "secret123" not in ev.visible_text_sample

# Test J — Cache freshness behavior & domain identity
@pytest.mark.asyncio
async def test_ai_threat_service_cache_domain_identity():
    service = AIThreatAnalysisService()
    service._is_ai_enabled = lambda: True

    trust_eval = TrustEvaluationResult(trust_score=90, risk_level=RiskLevel.LOW, summary='Clean', reasons=[])
    ssl_res = SSLAnalysisResult(is_valid=True)
    whois_res = WHOISAnalysisResult(is_registered=True, domain_age_days=500)
    header_res = HeaderAnalysisResult(strict_transport_security=True, content_security_policy=True, x_frame_options=True, x_content_type_options=True, referrer_policy=True, permissions_policy=True, security_headers_score=6)
    redirect_res = RedirectAnalysisResult(redirect_count=0, redirected=False, same_domain=True, is_safe_redirect=True, cross_domain_redirect=False, https_upgrade=True)

    evidence = service._build_evidence(trust_eval, ssl_res, whois_res, header_res, redirect_res)
    cache_key = service._generate_cache_key('example.com', evidence)
    assert 'example.com' in cache_key
    assert 'unknown' not in cache_key

# Test K — Explicit fresh scan bypassing cache
@pytest.mark.asyncio
@patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution", new_callable=AsyncMock)
async def test_scan_service_end_to_end_dom_integration(mock_dns):
    mock_dns.return_value = ["93.184.216.34"]
    session = AsyncMock()
    scan_repo = AsyncMock()
    report_repo = AsyncMock()
    history_repo = AsyncMock()

    fake_scan = MagicMock()
    fake_scan.id = '12345678-1234-5678-1234-567812345678'
    fake_scan.url = 'https://example.com/item'
    fake_scan.domain = 'example.com'
    fake_scan.status = ScanStatus.COMPLETED

    scan_repo.create_scan.return_value = fake_scan
    scan_repo.get_scan_by_id.return_value = fake_scan

    fetcher = AsyncMock()
    fetcher.fetch.return_value = MagicMock(
        original_url='https://example.com', final_url='https://example.com', status_code=200, html_content='<html><body>Skeleton</body></html>', response_time_ms=100
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

    scan = await service.create_scan('https://example.com/item', page_html=SYNTHETIC_SCAM_DOM_HTML)
    assert report_repo.create_report.called
    kwargs = report_repo.create_report.call_args.kwargs
    assert kwargs['content_risk_score'] >= 65
    assert kwargs['overall_risk_score'] >= 35

# Test N — Deterministic scoring isolation
def test_rule_based_trust_engine_isolation():
    engine = RuleBasedTrustEngine()
    ssl_res = SSLAnalysisResult(is_valid=True)
    whois_res = WHOISAnalysisResult(is_registered=True, domain_age_days=500)
    header_res = HeaderAnalysisResult(strict_transport_security=True, content_security_policy=True, x_frame_options=True, x_content_type_options=True, referrer_policy=True, permissions_policy=True, security_headers_score=6)
    redirect_res = RedirectAnalysisResult(redirect_count=0, redirected=False, same_domain=True, is_safe_redirect=True, cross_domain_redirect=False, https_upgrade=True)

    eval_res = engine.evaluate(ssl_res, whois_res, header_res, redirect_res)
    assert eval_res.trust_score == 100
    assert eval_res.risk_level == RiskLevel.LOW
