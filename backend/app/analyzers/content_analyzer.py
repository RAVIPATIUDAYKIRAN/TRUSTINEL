import re
import logging
from typing import List, Optional
from app.models.enums import RiskLevel
from app.schemas.content_analysis import (
    ContentAnalysisResult,
    ContentScamCategory,
    ContentScamSignal,
    ExtractedWebsiteEvidence,
)

logger = logging.getLogger("trustinel.analyzers.content_analyzer")


class ContentAnalyzer:
    """
    Deterministic Content Scam Analyzer that evaluates extracted website evidence
    for deceptive patterns, urgency/scarcity manipulation, e-commerce anomalies,
    phishing claims, and business transparency indicators.
    """

    def analyze(self, evidence: ExtractedWebsiteEvidence) -> ContentAnalysisResult:
        signals: List[ContentScamSignal] = []
        raw_score = 0.0

        if not evidence or not evidence.visible_text_sample:
            return ContentAnalysisResult(
                content_risk_score=0,
                content_risk_level=RiskLevel.LOW,
                signals=[],
                extracted_evidence=evidence,
                summary="Insufficient website text available for content analysis."
            )

        lower_text = evidence.visible_text_sample.lower()

        # ----------------------------------------------------------------------
        # 1. URGENCY SIGNAL
        # ----------------------------------------------------------------------
        if evidence.urgency_claims:
            count = len(evidence.urgency_claims)
            sev = "HIGH" if count >= 3 else "MEDIUM"
            pts = 20.0 if count >= 3 else 10.0
            raw_score += pts
            signals.append(ContentScamSignal(
                category=ContentScamCategory.URGENCY,
                severity=sev,
                evidence=", ".join(evidence.urgency_claims[:3]),
                reason=f"Website uses High-Pressure Sales Urgency language ({count} indicator(s) found)."
            ))

        # ----------------------------------------------------------------------
        # 2. SCARCITY SIGNAL
        # ----------------------------------------------------------------------
        if evidence.stock_claims:
            scarcity_terms = [s for s in evidence.stock_claims if "sold out" not in s.lower()]
            if scarcity_terms:
                raw_score += 15.0
                signals.append(ContentScamSignal(
                    category=ContentScamCategory.SCARCITY,
                    severity="MEDIUM",
                    evidence=", ".join(scarcity_terms[:3]),
                    reason="Website employs Scarcity / Artificial Low-Stock Claims to induce rapid purchase."
                ))

        # ----------------------------------------------------------------------
        # 3. EXCESSIVE DISCOUNTS SIGNAL
        # ----------------------------------------------------------------------
        high_discounts = [d for d in evidence.discount_percentages if d >= 70]
        extreme_discounts = [d for d in evidence.discount_percentages if d >= 85]
        if extreme_discounts:
            raw_score += 25.0
            signals.append(ContentScamSignal(
                category=ContentScamCategory.EXCESSIVE_DISCOUNT,
                severity="HIGH",
                evidence=f"{max(extreme_discounts)}% OFF",
                reason=f"Extreme discount claimed ({max(extreme_discounts)}% OFF) often associated with deceptive storefronts."
            ))
        elif high_discounts:
            raw_score += 12.0
            signals.append(ContentScamSignal(
                category=ContentScamCategory.EXCESSIVE_DISCOUNT,
                severity="MEDIUM",
                evidence=f"{max(high_discounts)}% OFF",
                reason=f"Unusual high discount claimed ({max(high_discounts)}% OFF)."
            ))

        # ----------------------------------------------------------------------
        # 4. E-COMMERCE ANOMALY SIGNAL (e.g. Sold Out + Active Checkout/Buy Button)
        # ----------------------------------------------------------------------
        if evidence.is_sold_out_claimed and evidence.has_buy_or_checkout_button:
            raw_score += 35.0
            signals.append(ContentScamSignal(
                category=ContentScamCategory.ECOMMERCE_ANOMALY,
                severity="HIGH",
                evidence="Product marked 'Sold Out' while Buy Now/Checkout remains active",
                reason="Contradictory product availability state: item claims to be sold out yet purchase/checkout mechanism remains functional."
            ))

        # ----------------------------------------------------------------------
        # 5. GUARANTEED FINANCIAL CLAIMS
        # ----------------------------------------------------------------------
        fin_claims = []
        if re.search(r"earn\s+(?:₹|\$|rs\.?|inr)?\s*[\d,]+\s*(?:per|/|\s+a\s+)(?:month|day|week)", lower_text):
            fin_claims.append("Guaranteed monthly earnings claim")
        if any(phrase in lower_text for phrase in ["double your money", "risk-free investment", "guaranteed profit", "guaranteed returns", "100% profit"]):
            fin_claims.append("High guaranteed investment return claim")

        if fin_claims:
            raw_score += 40.0
            signals.append(ContentScamSignal(
                category=ContentScamCategory.FINANCIAL_CLAIM,
                severity="CRITICAL",
                evidence=", ".join(fin_claims),
                reason="Unrealistic guaranteed financial earnings or investment return claims detected."
            ))

        # ----------------------------------------------------------------------
        # 6. PHISHING & CREDENTIAL HARVESTING
        # ----------------------------------------------------------------------
        phish_triggers = []
        if re.search(r"account\s+(?:will be|has been)\s+(?:suspended|blocked|locked|terminated)", lower_text):
            phish_triggers.append("Account suspension threat")
        if re.search(r"enter\s+(?:your\s+)?(?:otp|one time password|bank account|cvv|pin|social security)", lower_text):
            phish_triggers.append("Sensitive OTP/PIN/Bank details solicitation")

        if phish_triggers:
            raw_score += 45.0
            signals.append(ContentScamSignal(
                category=ContentScamCategory.CREDENTIAL_HARVESTING,
                severity="CRITICAL",
                evidence=", ".join(phish_triggers),
                reason="High-risk credential or financial verification pressure detected."
            ))

        # ----------------------------------------------------------------------
        # 7. BUSINESS TRANSPARENCY
        # ----------------------------------------------------------------------
        if not evidence.has_contact_info and not evidence.has_policy_links:
            raw_score += 15.0
            signals.append(ContentScamSignal(
                category=ContentScamCategory.BUSINESS_TRANSPARENCY,
                severity="MEDIUM",
                evidence="No contact information or policy pages found",
                reason="Lack of verified business contact details (email/phone/address) and terms/privacy/return policies."
            ))

        # Clamp final content risk score (0 = Safe, 100 = Extreme Risk)
        final_risk_score = max(0, min(100, int(round(raw_score))))

        if final_risk_score >= 70:
            level = RiskLevel.HIGH
            summary = f"Content analysis identified strong scam indicators ({len(signals)} risk signal(s))."
        elif final_risk_score >= 35:
            level = RiskLevel.MEDIUM
            summary = f"Content analysis identified moderate risk indicators ({len(signals)} risk signal(s))."
        else:
            level = RiskLevel.LOW
            summary = "Content analysis identified no significant deceptive or high-risk content indicators."

        return ContentAnalysisResult(
            content_risk_score=final_risk_score,
            content_risk_level=level,
            signals=signals,
            extracted_evidence=evidence,
            summary=summary,
        )
