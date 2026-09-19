import pytest
from app.services.risk_aggregation_engine import RiskAggregationEngine
from app.schemas.trust_evaluation import TrustEvaluationResult
from app.schemas.content_analysis import ContentAnalysisResult, ContentScamSignal, ContentScamCategory
from app.schemas.whois_analysis import WHOISAnalysisResult
from app.services.threat_intelligence_service import ReputationThreatResult, ThreatReputationStatus
from app.models.enums import RiskLevel

def test_good_ssl_does_not_cancel_strong_scam_evidence():
    """Property 1: Good SSL (90) must NOT cancel strong content scam evidence (65)."""
    engine = RiskAggregationEngine()
    
    trust_eval = TrustEvaluationResult(trust_score=90, risk_level=RiskLevel.LOW, summary="Clean SSL", reasons=[])
    content_res = ContentAnalysisResult(
        content_risk_score=65,
        signals=[
            ContentScamSignal(category=ContentScamCategory.EXCESSIVE_DISCOUNT, severity="HIGH", reason="88% OFF", evidence="88% OFF"),
            ContentScamSignal(category=ContentScamCategory.URGENCY, severity="MEDIUM", reason="Hurry", evidence="HURRY")
        ],
        summary="High content risk"
    )
    whois_res = WHOISAnalysisResult(is_registered=True, domain_age_days=None) # WHOIS timeout
    rep_res = ReputationThreatResult(status=ThreatReputationStatus.UNKNOWN, threat_score=0.0)
    
    result = engine.aggregate(trust_eval, content_res, whois_res, rep_res)
    assert result.overall_risk_score >= 65
    assert result.overall_risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH)

def test_legitimate_sale_page_remains_low_risk():
    """Property 4: Legitimate 20% sale page must NOT become HIGH risk."""
    engine = RiskAggregationEngine()
    
    trust_eval = TrustEvaluationResult(trust_score=95, risk_level=RiskLevel.LOW, summary="Clean SSL", reasons=[])
    content_res = ContentAnalysisResult(content_risk_score=15, signals=[], summary="Clean content")
    whois_res = WHOISAnalysisResult(is_registered=True, domain_age_days=500)
    rep_res = ReputationThreatResult(status=ThreatReputationStatus.CLEAN, threat_score=0.0)
    
    result = engine.aggregate(trust_eval, content_res, whois_res, rep_res)
    assert result.overall_risk_score <= 25
    assert result.overall_risk_level == RiskLevel.LOW

def test_malicious_reputation_forces_high_scam_risk():
    """Property 6: Confirmed malicious reputation forces high risk."""
    engine = RiskAggregationEngine()
    
    trust_eval = TrustEvaluationResult(trust_score=90, risk_level=RiskLevel.LOW, summary="Clean SSL", reasons=[])
    content_res = ContentAnalysisResult(content_risk_score=0, signals=[], summary="Clean content")
    whois_res = WHOISAnalysisResult(is_registered=True, domain_age_days=100)
    rep_res = ReputationThreatResult(status=ThreatReputationStatus.MALICIOUS, threat_score=100.0)
    
    result = engine.aggregate(trust_eval, content_res, whois_res, rep_res)
    assert result.overall_risk_score >= 90
    assert result.overall_risk_level == RiskLevel.HIGH
