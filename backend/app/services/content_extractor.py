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
            any(term in lower_text for term in ["contact us", "get in touch", "support@", "customer care", "store address", "registered office", "customer service", "help center", "help & contact", "contact center", "help"])
        )

        # Policy pages detection (check <a> links or text)
        policy_keywords = [
            "privacy policy", "privacy notice", "terms of service", "terms & conditions", "conditions of use",
            "terms of use", "user agreement", "return policy", "refund policy", "shipping policy", "about us",
            "help", "customer service", "consumer health data privacy"
        ]
        link_texts = [a.get_text(strip=True).lower() for a in soup.find_all("a", limit=300) if a.get_text()]
        combined_links_text = " ".join(link_texts)
        policy_matches = sum(1 for kw in policy_keywords if kw in combined_links_text or kw in lower_text)
        has_policy_links = policy_matches >= 1

        # Discounts detection (e.g. 50% OFF, 80% off, save 75%, 80 percent off, Rs. 2999 -> Rs. 499, was $99 now $49)
        discount_matches = re.findall(r"(?:save\s*)?(\d{1,2})\s*(?:%|percent)\s*(?:off|discount|save)?", lower_text)
        discount_percentages = [int(d) for d in discount_matches if 10 <= int(d) <= 99]

        # Comparative price pairs (was $99 now $49, ₹2,999 → ₹499, Original: Rs. 2999, Special: Rs. 499)
        price_pair_matches = re.findall(
            r"(?:was|original|mrp|list price|regular price)?[:\s]*(?:₹|\$|rs\.?|inr)?\s*([\d,]+(?:\.\d{2})?)[^0-9₹\$rs]*?(?:now|special|sale price|reduced|→|->|instead of)?[:\s]*(?:₹|\$|rs\.?|inr)\s*([\d,]+(?:\.\d{2})?)",
            lower_text
        )
        for orig_str, sale_str in price_pair_matches:
            if not orig_str or not sale_str:
                continue
            try:
                orig_p = float(orig_str.replace(",", ""))
                sale_p = float(sale_str.replace(",", ""))
                if orig_p > sale_p > 0 and orig_p <= 100000:
                    implied_pct = int(round(((orig_p - sale_p) / orig_p) * 100))
                    if 10 <= implied_pct <= 99:
                        discount_percentages.append(implied_pct)
            except ValueError:
                pass

        discount_percentages = list(dict.fromkeys(discount_percentages))[:5]

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

        # Addition 1: Form action & cross-domain sensitive form submission inspection
        form_action_targets: List[str] = []
        has_cross_domain_sensitive_form = False

        from urllib.parse import urlparse, urljoin
        page_domain = ""
        if url:
            try:
                page_domain = urlparse(url).netloc.lower().split(":")[0].lstrip("www.")
            except Exception:
                page_domain = ""

        forms = soup.find_all("form", limit=20)
        for form_el in forms:
            action = form_el.get("action")
            if not action or not isinstance(action, str):
                continue
            action = action.strip()
            if not action or action.startswith("javascript:") or action == "#":
                continue

            target_url = urljoin(url or "", action) if url else action
            try:
                target_domain = urlparse(target_url).netloc.lower().split(":")[0].lstrip("www.")
            except Exception:
                target_domain = ""

            if target_domain:
                form_action_targets.append(target_url[:200])

            # Check if this form contains sensitive inputs or login/payment controls
            form_inputs = form_el.find_all(["input", "textarea", "select"])
            has_sensitive_input = False
            for inp in form_inputs:
                inp_type = (inp.get("type") or "").lower()
                inp_name = (inp.get("name") or "").lower()
                inp_id = (inp.get("id") or "").lower()
                if (
                    inp_type in ("password", "email") or
                    any(k in inp_name or k in inp_id for k in ("password", "pass", "card", "cvv", "cc", "credit", "token", "secret", "ssn", "account", "login", "auth"))
                ):
                    has_sensitive_input = True
                    break

            # Check if target domain is a known standard identity/payment gateway (OAuth/SSO/Stripe/PayPal)
            LEGITIMATE_GATEWAYS = (
                "paypal.com", "stripe.com", "google.com", "microsoft.com", "microsoftonline.com",
                "apple.com", "amazon.com", "auth0.com", "okta.com", "facebook.com", "github.com"
            )
            is_legitimate_gateway = any(target_domain.endswith(gw) for gw in LEGITIMATE_GATEWAYS)

            if page_domain and target_domain and page_domain != target_domain and not is_legitimate_gateway:
                if has_sensitive_input or has_buy_or_checkout_button:
                    has_cross_domain_sensitive_form = True

        form_action_targets = list(dict.fromkeys(form_action_targets))[:10]

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
            form_action_targets=form_action_targets,
            has_cross_domain_sensitive_form=has_cross_domain_sensitive_form,
        )
