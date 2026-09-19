"""
Regression tests for e-commerce link extraction and policy/contact detection:
- Tests extraction of policy links located past link index 50 in HTML (up to 300 links)
- Tests recognition of "Privacy Notice", "Conditions of Use", "Help", "Customer Service"
- Verifies legitimate footer structures do not generate false missing policy/contact risk signals
"""
import pytest
from app.services.content_extractor import ContentExtractor
from app.analyzers.content_analyzer import ContentAnalyzer
from app.schemas.content_analysis import ContentScamCategory


def test_content_extractor_parses_footer_links_past_index_50():
    """Verify link scanning parses footer links located past link index 50 in HTML"""
    # Create HTML with 80 top-nav links followed by footer policy links
    nav_links = "".join([f'<a href="/cat/{i}">Category {i}</a>' for i in range(1, 80)])
    footer_html = """
    <footer>
      <a href="/help">Help</a>
      <a href="/privacy-notice">Privacy Notice</a>
      <a href="/conditions-of-use">Conditions of Use</a>
      <a href="/customer-service">Customer Service</a>
    </footer>
    """
    html = f"<html><body><nav>{nav_links}</nav>{footer_html}</body></html>"

    evidence = ContentExtractor.extract(html=html, url="https://store.example.com/")
    assert evidence.has_policy_links is True
    assert evidence.has_contact_info is True


def test_content_extractor_recognizes_real_world_ecommerce_terms():
    """Verify recognition of Privacy Notice, Conditions of Use, Customer Service, Help Center"""
    html = """
    <html><body>
      <div class="footer">
        <a href="/privacy">Privacy Notice</a>
        <a href="/terms">Conditions of Use</a>
        <a href="/support">Customer Service</a>
      </div>
    </body></html>
    """
    evidence = ContentExtractor.extract(html=html, url="https://store.example.com/")
    assert evidence.has_policy_links is True
    assert evidence.has_contact_info is True

    analyzer = ContentAnalyzer()
    res = analyzer.analyze(evidence)
    # Legitimate store content should not have business transparency penalties
    transparency_signals = [s for s in res.signals if s.category == ContentScamCategory.BUSINESS_TRANSPARENCY]
    assert len(transparency_signals) == 0


def test_ecommerce_page_with_deep_footer_has_no_false_transparency_penalties():
    """Verify large e-commerce page structure produces clean transparency evaluation"""
    # 100 top navigation links
    top_nav = "".join([f'<a href="/item-{i}">Item {i}</a>' for i in range(100)])
    body_content = "<h1>Welcome to Official Store</h1><p>Browse our catalog of items.</p>"
    footer = """
    <div id="navFooter">
      <a href="/gp/help/customer/display.html">Conditions of Use</a>
      <a href="/gp/help/customer/privacy.html">Privacy Notice</a>
      <a href="/help">Customer Service</a>
      <a href="/contact">Contact Us</a>
    </div>
    """
    html = f"<html><body>{top_nav}{body_content}{footer}</body></html>"

    evidence = ContentExtractor.extract(html=html, url="https://official-store.com/")
    assert evidence.has_policy_links is True
    assert evidence.has_contact_info is True

    analyzer = ContentAnalyzer()
    res = analyzer.analyze(evidence)
    transparency_signals = [s for s in res.signals if s.category == ContentScamCategory.BUSINESS_TRANSPARENCY]
    assert len(transparency_signals) == 0
