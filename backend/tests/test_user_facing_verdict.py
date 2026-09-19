import pytest
from app.models.enums import RiskLevel, UserFacingVerdict
from app.services.risk_aggregation_engine import RiskAggregationEngine
from app.services.threat_intelligence_service import ThreatReputationStatus
from app.schemas.content_analysis import ContentScamSignal, ContentScamCategory


def test_determine_user_facing_verdict_high_confidence_scam_blacklisted():
    engine = RiskAggregationEngine()
    verdict, action = engine.determine_user_facing_verdict(
        final_overall_risk=95,
        reputation_status=ThreatReputationStatus.MALICIOUS,
        has_critical_scam_signal=False,
        content_signals=[],
        domain_age_days=10,
        is_whois_registered=True,
        tech_trust_score=90
    )
    assert verdict == UserFacingVerdict.HIGH_CONFIDENCE_SCAM
    assert "Do not purchase" in action


def test_determine_user_facing_verdict_high_confidence_scam_credential_harvesting():
    engine = RiskAggregationEngine()
    verdict, action = engine.determine_user_facing_verdict(
        final_overall_risk=80,
        reputation_status=ThreatReputationStatus.CLEAN,
        has_critical_scam_signal=True,
        content_signals=[],
        domain_age_days=365,
        is_whois_registered=True,
        tech_trust_score=95
    )
    assert verdict == UserFacingVerdict.HIGH_CONFIDENCE_SCAM
    assert "sensitive information" in action


def test_determine_user_facing_verdict_likely_scam():
    engine = RiskAggregationEngine()
    sig = ContentScamSignal(
        category=ContentScamCategory.EXCESSIVE_DISCOUNT,
        severity="HIGH",
        reason="Aggressive discount and fake countdown timers",
        evidence="90% OFF"
    )
    verdict, action = engine.determine_user_facing_verdict(
        final_overall_risk=65,
        reputation_status=ThreatReputationStatus.UNKNOWN,
        has_critical_scam_signal=False,
        content_signals=[sig],
        domain_age_days=15,  # NEW_DOMAIN + CONTENT_SCAM = 2 categories
        is_whois_registered=True,
        tech_trust_score=85
    )
    assert verdict == UserFacingVerdict.LIKELY_SCAM
    assert "Avoid purchasing" in action


def test_determine_user_facing_verdict_suspicious():
    engine = RiskAggregationEngine()
    sig = ContentScamSignal(
        category=ContentScamCategory.BUSINESS_TRANSPARENCY,
        severity="MEDIUM",
        reason="Missing verified business address",
        evidence="No contact page"
    )
    verdict, action = engine.determine_user_facing_verdict(
        final_overall_risk=40,
        reputation_status=ThreatReputationStatus.UNKNOWN,
        has_critical_scam_signal=False,
        content_signals=[sig],
        domain_age_days=200,
        is_whois_registered=True,
        tech_trust_score=90
    )
    assert verdict == UserFacingVerdict.SUSPICIOUS
    assert "Be cautious" in action


def test_determine_user_facing_verdict_probably_legitimate():
    engine = RiskAggregationEngine()
    verdict, action = engine.determine_user_facing_verdict(
        final_overall_risk=15,
        reputation_status=ThreatReputationStatus.CLEAN,
        has_critical_scam_signal=False,
        content_signals=[],
        domain_age_days=45,  # Minor uncertainty: domain age between 30 and 90 days
        is_whois_registered=True,
        tech_trust_score=95
    )
    assert verdict == UserFacingVerdict.PROBABLY_LEGITIMATE
    assert "Proceed, but verify" in action


def test_determine_user_facing_verdict_legitimate():
    engine = RiskAggregationEngine()
    verdict, action = engine.determine_user_facing_verdict(
        final_overall_risk=10,
        reputation_status=ThreatReputationStatus.CLEAN,
        has_critical_scam_signal=False,
        content_signals=[],
        domain_age_days=500,
        is_whois_registered=True,
        tech_trust_score=98
    )
    assert verdict == UserFacingVerdict.LEGITIMATE
    assert "Proceed normally" in action


def test_determine_user_facing_verdict_unknown():
    engine = RiskAggregationEngine()
    verdict, action = engine.determine_user_facing_verdict(
        final_overall_risk=0,
        reputation_status=ThreatReputationStatus.UNKNOWN,
        has_critical_scam_signal=False,
        content_signals=[],
        domain_age_days=None,
        is_whois_registered=False,
        tech_trust_score=0,
        scan_failed=True
    )
    assert verdict == UserFacingVerdict.UNKNOWN
    assert "could not verify" in action
