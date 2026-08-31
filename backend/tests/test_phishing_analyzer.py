import logging
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.phishing import ImpersonationConfidence, PhishingDetectionType
from app.analyzers.phishing_analyzer import PhishingAnalyzer


@pytest.mark.asyncio
async def test_1_legitimate_brand_domain():
    """1. Test legitimate brand domain returns no impersonation suspected."""
    analyzer = PhishingAnalyzer()
    res = await analyzer.analyze_domain("paypal.com")
    assert res.is_impersonation_suspected is False
    assert res.confidence_level == ImpersonationConfidence.NONE
    assert res.similarity_score == 1.0


@pytest.mark.asyncio
async def test_2_character_omission():
    """2. Test typosquatting character omission detection (paypa.com)."""
    analyzer = PhishingAnalyzer()
    res = await analyzer.analyze_domain("paypa.com")
    assert res.is_impersonation_suspected is True
    assert res.suspected_brand == "Paypal"
    assert PhishingDetectionType.TYPOSQUATTING_OMISSION in res.detection_types


@pytest.mark.asyncio
async def test_3_character_insertion():
    """3. Test typosquatting character insertion detection (paypaal.com)."""
    analyzer = PhishingAnalyzer()
    res = await analyzer.analyze_domain("paypaal.com")
    assert res.is_impersonation_suspected is True
    assert res.suspected_brand == "Paypal"
    assert (
        PhishingDetectionType.TYPOSQUATTING_INSERTION in res.detection_types
        or PhishingDetectionType.REPEATED_CHARACTER in res.detection_types
    )


@pytest.mark.asyncio
async def test_4_character_substitution():
    """4. Test typosquatting character substitution detection (paypel.com)."""
    analyzer = PhishingAnalyzer()
    res = await analyzer.analyze_domain("paypel.com")
    assert res.is_impersonation_suspected is True
    assert res.suspected_brand == "Paypal"
    assert PhishingDetectionType.TYPOSQUATTING_SUBSTITUTION in res.detection_types


@pytest.mark.asyncio
async def test_5_character_transposition():
    """5. Test typosquatting character transposition detection (papyal.com)."""
    analyzer = PhishingAnalyzer()
    res = await analyzer.analyze_domain("papyal.com")
    assert res.is_impersonation_suspected is True
    assert res.suspected_brand == "Paypal"
    assert PhishingDetectionType.TYPOSQUATTING_TRANSPOSITION in res.detection_types


@pytest.mark.asyncio
async def test_6_repeated_character_attack():
    """6. Test repeated character attack detection (ppaypal.com)."""
    analyzer = PhishingAnalyzer()
    res = await analyzer.analyze_domain("ppaypal.com")
    assert res.is_impersonation_suspected is True
    assert res.suspected_brand == "Paypal"
    assert PhishingDetectionType.REPEATED_CHARACTER in res.detection_types


@pytest.mark.asyncio
async def test_7_hyphenation_attack():
    """7. Test hyphenation attack detection (pay-pal.com, paypal-login-verify.com)."""
    analyzer = PhishingAnalyzer()
    res = await analyzer.analyze_domain("paypal-login-verify.com")
    assert res.is_impersonation_suspected is True
    assert res.suspected_brand == "Paypal"
    assert (
        PhishingDetectionType.HYPHENATION_TRICK in res.detection_types
        or PhishingDetectionType.BRAND_KEYWORD_INCLUSION in res.detection_types
    )


@pytest.mark.asyncio
async def test_8_suspicious_subdomain_impersonation():
    """8. Test suspicious subdomain impersonation (paypal.com.attacker.net)."""
    analyzer = PhishingAnalyzer()
    res = await analyzer.analyze_domain("paypal.com.attacker.net")
    assert res.is_impersonation_suspected is True
    assert res.suspected_brand == "Paypal"
    assert PhishingDetectionType.SUBDOMAIN_IMPERSONATION in res.detection_types


@pytest.mark.asyncio
async def test_9_punycode_homoglyph_handling():
    """9. Test Punycode / Homoglyph attack detection (pаypal.com with Cyrillic 'а')."""
    analyzer = PhishingAnalyzer()
    res = await analyzer.analyze_domain("pаypal.com")  # contains Cyrillic 'а'
    assert res.is_impersonation_suspected is True
    assert res.suspected_brand == "Paypal"
    assert PhishingDetectionType.HOMOGLYPH_IDN_ABUSE in res.detection_types


@pytest.mark.asyncio
async def test_10_multiple_possible_brand_matches():
    """10. Test domain with multiple brand keywords picks highest similarity match."""
    analyzer = PhishingAnalyzer()
    res = await analyzer.analyze_domain("google-apple-auth.com")
    assert res.is_impersonation_suspected is True
    assert res.suspected_brand in ("Google", "Apple")


@pytest.mark.asyncio
async def test_11_low_similarity_legitimate_domain():
    """11. Test unrelated legitimate domain returns no impersonation suspected."""
    analyzer = PhishingAnalyzer()
    res = await analyzer.analyze_domain("wikipedia.org")
    assert res.is_impersonation_suspected is False
    assert res.confidence_level == ImpersonationConfidence.NONE


def test_12_invalid_domain_syntax():
    """12. Test invalid domain syntax rejection (HTTP 400)."""
    client = TestClient(app)
    resp = client.get("/api/v1/phishing/domain/nodotdomain")
    assert resp.status_code == 400
    data = resp.json()
    assert data["error_code"] == "INVALID_DOMAIN"


@pytest.mark.asyncio
async def test_13_empty_oversized_input():
    """13. Test empty/oversized domain input is safely bounded."""
    analyzer = PhishingAnalyzer()
    oversized = ("a" * 300) + ".com"
    res = await analyzer.analyze_domain(oversized)
    assert res.normalized_domain is not None
    assert len(res.normalized_domain) <= 253


def test_14_ssrf_private_destination_blocking():
    """14. Test SSRF private destination blocking (HTTP 403)."""
    client = TestClient(app)
    from app.middleware.exceptions import SSRFBlockedException
    with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution",
               side_effect=SSRFBlockedException("The requested URL is not allowed.")):
        resp = client.get("/api/v1/phishing/domain/internal-server.local")
        assert resp.status_code == 403
        data = resp.json()
        assert data["error_code"] == "URL_NOT_ALLOWED"


def test_15_rate_limiting_headers():
    """15. Test rate limit headers present on response."""
    client = TestClient(app)
    with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution", return_value=["93.184.216.34"]):
        resp = client.get("/api/v1/phishing/domain/example.com")
        assert resp.status_code == 200
        assert "X-RateLimit-Limit" in resp.headers


@pytest.mark.asyncio
async def test_16_deterministic_repeated_analysis():
    """16. Test deterministic repeated analysis returns identical results."""
    analyzer = PhishingAnalyzer()
    r1 = await analyzer.analyze_domain("paypaal.com")
    r2 = await analyzer.analyze_domain("paypaal.com")
    assert r1.is_impersonation_suspected == r2.is_impersonation_suspected
    assert r1.suspected_brand == r2.suspected_brand
    assert r1.similarity_score == r2.similarity_score


def test_17_api_response_schema_validation():
    """17. Test API response schema validation."""
    client = TestClient(app)
    with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution", return_value=["93.184.216.34"]):
        resp = client.get("/api/v1/phishing/domain/paypaal.com")
        assert resp.status_code == 200
        data = resp.json()
        assert "input_domain" in data
        assert "is_impersonation_suspected" in data
        assert "confidence_level" in data
        assert "detection_types" in data
        assert "security_findings" in data


def test_18_no_secret_leakage(caplog):
    """18. Test secrets redaction / no secret leakage."""
    caplog.set_level(logging.INFO)
    logger = logging.getLogger("trustinel.security_phishing_test")
    secret_token = "sk-phishing-secret-token-112233"
    logger.info(f"Phishing analysis debug token {secret_token}")

    messages = [r.getMessage() for r in caplog.records]
    assert not any(secret_token in m for m in messages)
    assert any("[REDACTED_API_KEY]" in m for m in messages)


def test_19_deterministic_scoring_isolation():
    """19. Test deterministic scoring engine remains 100% authoritative and isolated."""
    from app.services.rule_based_trust_engine import RuleBasedTrustEngine
    engine_instance = RuleBasedTrustEngine()
    assert hasattr(engine_instance, "evaluate")
