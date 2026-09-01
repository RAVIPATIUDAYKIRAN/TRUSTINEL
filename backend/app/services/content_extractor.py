import re
import logging
from typing import List, Optional
from bs4 import BeautifulSoup

from app.schemas.content_analysis import ExtractedWebsiteEvidence

logger = logging.getLogger("trustinel.services.content_extractor")

MAX_HTML_BYTES = 500_000  # 500 KB MAX
MAX_TEXT_CHARS = 20_000   # 20 KB MAX


class ContentExtractor:
    """
    Safely extracts structured, bounded evidence from raw HTML content.
    Treats all extracted text as UNTRUSTED DATA.
    """

    @staticmethod
    def extract(html: Optional[str], url: Optional[str] = None) -> ExtractedWebsiteEvidence:
        if not html or not isinstance(html, str):
            return ExtractedWebsiteEvidence()

        # Enforce max HTML size
        truncated_html = html[:MAX_HTML_BYTES]

        try:
            soup = BeautifulSoup(truncated_html, "html.parser")
        except Exception as exc:
            logger.warning(f"[TRUSTINEL] HTML parsing error: {exc}")
            return ExtractedWebsiteEvidence()

        # Remove script, style, noscript, svg, iframe elements
        for element in soup(["script", "style", "noscript", "svg", "iframe"]):
            element.decompose()

        # Title
        title = soup.title.string.strip() if soup.title and soup.title.string else None
        if title:
            title = title[:200]

        # Meta description
        meta_desc: Optional[str] = None
        meta_tag = soup.find("meta", attrs={"name": re.compile(r"description", re.I)}) or soup.find("meta", attrs={"property": "og:description"})
        if meta_tag and meta_tag.get("content"):
            meta_desc = str(meta_tag.get("content")).strip()[:300]

        # Headings
        headings: List[str] = []
        for h in soup.find_all(["h1", "h2", "h3"], limit=10):
            txt = h.get_text(strip=True)
            if txt:
                headings.append(txt[:100])

        # Visible text sample
        visible_text = soup.get_text(separator=" ", strip=True)[:MAX_TEXT_CHARS]
        lower_text = visible_text.lower()

        # Contact info detection
        has_contact_info = bool(
            re.search(r"[\w\.-]+@[\w\.-]+\.\w+", visible_text) or  # Email
            re.search(r"(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}", visible_text) or # Phone
            any(term in lower_text for term in ["contact us", "get in touch", "support@", "customer care", "store address", "registered office"])
        )

        # Policy pages detection (check <a> links or text)
        policy_keywords = ["privacy policy", "terms of service", "terms & conditions", "return policy", "refund policy", "shipping policy", "about us"]
        link_texts = [a.get_text(strip=True).lower() for a in soup.find_all("a", limit=50) if a.get_text()]
        combined_links_text = " ".join(link_texts)
        policy_matches = sum(1 for kw in policy_keywords if kw in combined_links_text or kw in lower_text)
        has_policy_links = policy_matches >= 2

        # Discounts detection (e.g. 50% OFF, 80% off, save 75%, 80 percent off, Rs. 999 instead of Rs. 4999)
        discount_matches = re.findall(r"(?:save\s*)?(\d{1,2})\s*(?:%|percent)\s*(?:off|discount|save)?", lower_text)
        discount_percentages = [int(d) for d in discount_matches if 10 <= int(d) <= 99][:5]

        # Price claims (e.g., ₹999, $49.99, Rs. 1499)
        price_matches = re.findall(r"(?:₹|\$|rs\.?|inr)\s*[\d,]+(?:\.\d{2})?", lower_text)
        price_claims = [p.strip() for p in price_matches[:5]]

        # Stock claims (e.g. "only 2 left", "low stock", "almost sold out", "5 units left", "sold out")
        stock_patterns = [
            r"only \d+ left", r"only \d+ remaining", r"low stock", r"almost sold out",
            r"\d+ units left", r"limited stock", r"in stock", r"sold out"
        ]
        stock_claims = []
        for pat in stock_patterns:
            for m in re.finditer(pat, lower_text):
                stock_claims.append(m.group(0))
        stock_claims = list(set(stock_claims))[:5]

        is_sold_out_claimed = any("sold out" in s or "out of stock" in s for s in stock_claims) or "sold out" in lower_text

        # Buy / Checkout button detection
        buttons_text = " ".join([
            btn.get_text(strip=True).lower()
            for btn in soup.find_all(["button", "a", "input"], limit=50)
            if btn.get_text() or (btn.get("value") and isinstance(btn.get("value"), str))
        ])
        has_buy_or_checkout_button = any(term in buttons_text for term in ["buy now", "add to cart", "checkout", "place order", "cash on delivery", "cod", "pay now", "proceed to pay"])

        # Urgency claims
        urgency_patterns = [
            r"limited time", r"offer ends", r"ends today", r"act now", r"hurry",
            r"last chance", r"sale ends", r"don't miss out", r"limited offer", r"hot offer"
        ]
        urgency_claims = []
        for pat in urgency_patterns:
            if re.search(pat, lower_text):
                urgency_claims.append(pat.upper())

        # Payment methods claimed
        payment_methods = []
        for pm in ["cash on delivery", "cod", "upi", "paytm", "gpay", "credit card", "debit card", "paypal", "crypto", "bitcoin"]:
            if pm in lower_text:
                payment_methods.append(pm.upper())

        return ExtractedWebsiteEvidence(
            title=title,
            meta_description=meta_desc,
            visible_text_sample=visible_text,
            headings=headings,
            has_contact_info=has_contact_info,
            has_policy_links=has_policy_links,
            price_claims=price_claims,
            discount_percentages=discount_percentages,
            stock_claims=stock_claims,
            urgency_claims=urgency_claims,
            is_sold_out_claimed=is_sold_out_claimed,
            has_buy_or_checkout_button=has_buy_or_checkout_button,
            payment_methods_claimed=payment_methods,
        )
