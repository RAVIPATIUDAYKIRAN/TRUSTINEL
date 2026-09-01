# TRUSTINEL — Website Content Intelligence & Multi-Dimensional Risk Test Suite
# Tests content scam analysis, e-commerce anomalies, multi-risk aggregation, false positives, and AI fallbacks.

import pytest
from app.models.enums import RiskLevel
from app.schemas.ssl_analysis import SSLAnalysisResult
from app.schemas.whois_analysis import WHOISAnalysisResult
from app.schemas.header_analysis import HeaderAnalysisResult
from app.schemas.redirect_analysis import RedirectAnalysisResult
from app.schemas.content_analysis import ExtractedWebsiteEvidence, ContentScamCategory
from app.services.rule_based_trust_engine import RuleBasedTrustEngine
from app.services.content_extractor import ContentExtractor
from app.analyzers.content_analyzer import ContentAnalyzer
from app.services.threat_intelligence_service import ThreatIntelligenceService, ThreatReputationStatus, ReputationThreatResult
from app.services.risk_aggregation_engine import RiskAggregationEngine
from app.services.ai_threat_analysis_service import AIThreatAnalysisService


def test_1_technical_trust_scoring_immutability():
    """1. Verify RuleBasedTrustEngine outputs remain 100% untouched and deterministic."""
    ssl_res = SSLAnalysisResult(is_valid=True, issuer="GlobalSign", days_remaining=120, is_self_signed=False)
    whois_res = WHOISAnalysisResult(is_registered=True, domain_age_days=500, registrar="MarkMonitor Inc.")
    header_res = HeaderAnalysisResult(
        strict_transport_security=True,
        content_security_policy=True,
        x_frame_options=True,
        x_content_type_options=True,
        referrer_policy=True,
        permissions_policy=True,
        security_headers_score=5
    )
    redirect_res = RedirectAnalysisResult(
        redirected=False,
        same_domain=True,
        https_upgrade=True,
        cross_domain_redirect=False,
        is_safe_redirect=True,
        redirect_count=0,
        contains_suspicious_redirect=False
    )

    engine = RuleBasedTrustEngine()
    result = engine.evaluate(ssl_res, whois_res, header_res, redirect_res)

    assert result.trust_score == 100
    assert result.risk_level == RiskLevel.LOW


def test_2_content_scam_indicators_urgency_scarcity_discounts():
    """2. Verify content analyzer detects urgency, scarcity, and extreme discount signals."""
    html_sample = """
    <html>
      <head><title>Mega Store - Limited Offer</title></head>
      <body>
        <h1>80% OFF - HURRY LIMITED TIME OFFER!</h1>
        <p>Act now! Offer ends today. Only 2 left in stock.</p>
        <span class="price">Rs. 999 instead of Rs. 4999</span>
      </body>
    </html>
    """
    evidence = ContentExtractor.extract(html_sample)
    analyzer = ContentAnalyzer()
    res = analyzer.analyze(evidence)

    assert res.content_risk_score >= 35
    categories = {s.category for s in res.signals}
    assert ContentScamCategory.URGENCY in categories
    assert ContentScamCategory.SCARCITY in categories
    assert ContentScamCategory.EXCESSIVE_DISCOUNT in categories


def test_3_ecommerce_anomaly_sold_out_buy_now_contradiction():
    """3. Verify contradictory product state (Sold out + Buy Now active) triggers ECOMMERCE_ANOMALY signal."""
    html_sample = """
    <html>
      <body>
        <h2>Lycra Track Pants</h2>
        <span class="stock-status">Sold Out</span>
        <button class="btn">Buy Now</button>
        <button className="checkout">Cash on Delivery</button>
      </body>
    </html>
    """
    evidence = ContentExtractor.extract(html_sample)
    assert evidence.is_sold_out_claimed is True
    assert evidence.has_buy_or_checkout_button is True

    analyzer = ContentAnalyzer()
    res = analyzer.analyze(evidence)

    categories = {s.category for s in res.signals}
    assert ContentScamCategory.ECOMMERCE_ANOMALY in categories
    anomaly_signal = next(s for s in res.signals if s.category == ContentScamCategory.ECOMMERCE_ANOMALY)
    assert anomaly_signal.severity == "HIGH"


def test_4_false_positive_validation_legitimate_store():
    """4. Verify legitimate store with 50% discount & contact info is NOT over-penalized as HIGH risk."""
    html_sample = """
    <html>
      <head><title>Official Brand Store</title></head>
      <body>
        <h1>Summer Clearance - 50% OFF</h1>
        <p>Contact us at support@brandstore.com or call +1-800-555-0199</p>
        <a href="/privacy">Privacy Policy</a>
        <a href="/terms">Terms of Service</a>
        <a href="/returns">Return Policy</a>
      </body>
    </html>
    """
    evidence = ContentExtractor.extract(html_sample)
    assert evidence.has_contact_info is True
    assert evidence.has_policy_links is True

    analyzer = ContentAnalyzer()
    res = analyzer.analyze(evidence)

    # Normal 50% discount on legitimate site must not trigger HIGH content risk
    assert res.content_risk_level != RiskLevel.HIGH
    assert res.content_risk_score < 50


def test_5_high_risk_scam_combination_trendayofferr():
    """5. Verify new domain (9 days) + extreme discount + urgency + scarcity + e-commerce anomaly produces OVERALL HIGH RISK."""
    html_scam = """
    <html>
      <head><title>Track Pants Offer</title></head>
      <body>
        <h1>85% OFF - HOT LIMITED OFFER!</h1>
        <p>Act now! Ends today! Low stock - Only 3 units left.</p>
        <div>Status: Sold Out</div>
        <button>Buy Now - Cash on Delivery</button>
      </body>
    </html>
    """
    evidence = ContentExtractor.extract(html_scam)
    content_analyzer = ContentAnalyzer()
    content_res = content_analyzer.analyze(evidence)

    ssl_res = SSLAnalysisResult(is_valid=True, issuer="Cloudflare", days_remaining=85, is_self_signed=False)
    whois_res = WHOISAnalysisResult(is_registered=True, domain_age_days=9, registrar="Namesilo")
    header_res = HeaderAnalysisResult(
        strict_transport_security=True,
        content_security_policy=True,
        x_frame_options=True,
        x_content_type_options=True,
        referrer_policy=True,
        permissions_policy=True,
        security_headers_score=5
    )
    redirect_res = RedirectAnalysisResult(
        redirected=False,
        same_domain=True,
        https_upgrade=True,
        cross_domain_redirect=False,
        is_safe_redirect=True,
        redirect_count=0,
        contains_suspicious_redirect=False
    )

    trust_engine = RuleBasedTrustEngine()
    trust_eval = trust_engine.evaluate(ssl_res, whois_res, header_res, redirect_res)
    # Technical Trust score is ~90 (Technical Security)
    assert trust_eval.trust_score >= 80

    reputation_res = ReputationThreatResult(
        status=ThreatReputationStatus.UNKNOWN,
        reputation_score=100,
        provider_name="internal_heuristics"
    )

    aggregator = RiskAggregationEngine()
    multi_risk = aggregator.aggregate(trust_eval, content_res, whois_res, reputation_res)

    # Multi-dimensional decision correctly identifies Scam Risk = HIGH and score >= 75
    assert multi_risk.technical_trust_score >= 80  # Technical security preserved separately!
    assert multi_risk.overall_risk_level == RiskLevel.HIGH
    assert multi_risk.overall_risk_score >= 75


def test_6_ai_threat_analysis_diagnostic_fallback():
    """6. Verify AI Threat Analysis returns diagnostic fallback state without crashing when AI is unconfigured."""
    ssl_res = SSLAnalysisResult(is_valid=True)
    whois_res = WHOISAnalysisResult(is_registered=True, domain_age_days=100)
    header_res = HeaderAnalysisResult(
        strict_transport_security=True,
        content_security_policy=False,
        x_frame_options=True,
        x_content_type_options=True,
        referrer_policy=False,
        permissions_policy=False,
        security_headers_score=3
    )
    redirect_res = RedirectAnalysisResult(
        redirected=False,
        same_domain=True,
        https_upgrade=True,
        cross_domain_redirect=False,
        is_safe_redirect=True,
        redirect_count=0,
        contains_suspicious_redirect=False
    )
    trust_engine = RuleBasedTrustEngine()
    trust_eval = trust_engine.evaluate(ssl_res, whois_res, header_res, redirect_res)

    fallback = AIThreatAnalysisService._get_fallback(trust_eval, "AI provider API key unconfigured.")
    assert fallback.enabled is False
    assert fallback.threat_level == "UNKNOWN"
    assert "unconfigured" in fallback.reasoning


@pytest.mark.asyncio
async def test_7_reputation_threat_intelligence_unknown_isolation():
    """7. Verify UNKNOWN threat intelligence does not crash or inject fake malicious reports."""
    service = ThreatIntelligenceService()
    rep = await service.get_reputation("example.com")

    assert rep.status == ThreatReputationStatus.UNKNOWN
    assert rep.matches_found == 0
    assert rep.matched_lists == []


def test_8_footer_contact_and_policy_links_detection():
    """8. Verify contact info and policy links located inside <footer> elements are correctly extracted."""
    html_with_footer = """
    <html>
      <head><title>Legitimate E-Commerce</title></head>
      <body>
        <h1>Store Products</h1>
        <footer>
          <p>Contact Us: support@legitstore.com | Phone: +1-800-555-0199</p>
          <a href="/privacy">Privacy Policy</a>
          <a href="/terms">Terms of Service</a>
          <a href="/returns">Refund & Return Policy</a>
        </footer>
      </body>
    </html>
    """
    evidence = ContentExtractor.extract(html_with_footer)
    assert evidence.has_contact_info is True
    assert evidence.has_policy_links is True

    analyzer = ContentAnalyzer()
    res = analyzer.analyze(evidence)
    categories = {s.category for s in res.signals}
    assert ContentScamCategory.BUSINESS_TRANSPARENCY not in categories
    assert res.content_risk_score == 0


def test_9_old_domain_credential_harvesting_phishing_override():
    """9. Verify Credential Harvesting on an OLD domain (500 days) forces Overall Risk >= 75 and HIGH level."""
    html_phish = """
    <html>
      <body>
        <h1>Security Alert: Account Verification Required</h1>
        <p>Your account will be suspended! Enter your OTP and bank account password immediately to verify!</p>
      </body>
    </html>
    """
    evidence = ContentExtractor.extract(html_phish)
    c_analyzer = ContentAnalyzer()
    c_res = c_analyzer.analyze(evidence)

    # 500-day old domain with valid SSL
    ssl_res = SSLAnalysisResult(is_valid=True)
    whois_res = WHOISAnalysisResult(is_registered=True, domain_age_days=500)
    header_res = HeaderAnalysisResult(strict_transport_security=True, content_security_policy=True, x_frame_options=True, x_content_type_options=True, referrer_policy=True, permissions_policy=True, security_headers_score=6)
    redirect_res = RedirectAnalysisResult(is_safe_redirect=True, redirected=False, same_domain=True, https_upgrade=True, cross_domain_redirect=False, redirect_count=0, contains_suspicious_redirect=False)

    trust_engine = RuleBasedTrustEngine()
    trust_eval = trust_engine.evaluate(ssl_res, whois_res, header_res, redirect_res)
    rep_res = ReputationThreatResult(status=ThreatReputationStatus.UNKNOWN, reputation_score=100)

    aggregator = RiskAggregationEngine()
    multi_risk = aggregator.aggregate(trust_eval, c_res, whois_res, rep_res)

    assert multi_risk.technical_trust_score == 100
    assert multi_risk.overall_risk_score >= 75
    assert multi_risk.overall_risk_level == RiskLevel.HIGH


def test_10_old_domain_financial_scam_override():
    """10. Verify Financial Scam on an OLD domain (400 days) forces Overall Risk >= 75 and HIGH level."""
    html_fin_scam = """
    <html>
      <body>
        <h1>Crypto High Yield Investment</h1>
        <p>Earn Rs. 500000 per month guaranteed returns! Double your money risk-free investment!</p>
      </body>
    </html>
    """
    evidence = ContentExtractor.extract(html_fin_scam)
    c_analyzer = ContentAnalyzer()
    c_res = c_analyzer.analyze(evidence)

    # 400-day old domain with valid SSL
    ssl_res = SSLAnalysisResult(is_valid=True)
    whois_res = WHOISAnalysisResult(is_registered=True, domain_age_days=400)
    header_res = HeaderAnalysisResult(strict_transport_security=True, content_security_policy=True, x_frame_options=True, x_content_type_options=True, referrer_policy=True, permissions_policy=True, security_headers_score=6)
    redirect_res = RedirectAnalysisResult(is_safe_redirect=True, redirected=False, same_domain=True, https_upgrade=True, cross_domain_redirect=False, redirect_count=0, contains_suspicious_redirect=False)

    trust_engine = RuleBasedTrustEngine()
    trust_eval = trust_engine.evaluate(ssl_res, whois_res, header_res, redirect_res)
    rep_res = ReputationThreatResult(status=ThreatReputationStatus.UNKNOWN, reputation_score=100)

    aggregator = RiskAggregationEngine()
    multi_risk = aggregator.aggregate(trust_eval, c_res, whois_res, rep_res)

    assert multi_risk.technical_trust_score == 100
    assert multi_risk.overall_risk_score >= 75
    assert multi_risk.overall_risk_level == RiskLevel.HIGH
