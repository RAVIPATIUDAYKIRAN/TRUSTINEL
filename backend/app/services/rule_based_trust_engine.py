"""
Service implementation of the RuleBasedTrustEngine that computes website trust scores.
"""
import logging
from typing import List

from app.models.enums import RiskLevel
from app.schemas.ssl_analysis import SSLAnalysisResult
from app.schemas.whois_analysis import WHOISAnalysisResult
from app.schemas.header_analysis import HeaderAnalysisResult
from app.schemas.redirect_analysis import RedirectAnalysisResult
from app.schemas.trust_evaluation import TrustEvaluationResult

logger = logging.getLogger("trustinel.services.rule_based_trust_engine")


class RuleBasedTrustEngine:
    """
    Evaluates website analyzer results and computes a final trust score and risk level
    using a deterministic, explainable, and transparent rules system.
    """

    def evaluate(
        self,
        ssl_result: SSLAnalysisResult,
        whois_result: WHOISAnalysisResult,
        header_result: HeaderAnalysisResult,
        redirect_result: RedirectAnalysisResult
    ) -> TrustEvaluationResult:
        """
        Main evaluation entrypoint that combines individual indicator analyzer results.
        """
        score = 50
        reasons: List[str] = []

        # 1. SSL Rules & Reasons
        if ssl_result.is_valid:
            score += 25
            reasons.append("SSL certificate is valid: +25")
        else:
            error_str = (ssl_result.error or "").lower()
            cert_terms = [
                "expired",
                "verify failed",
                "self-signed",
                "self signed",
                "hostname mismatch",
                "not yet valid",
                "certificate"
            ]
            is_cert_fail = any(term in error_str for term in cert_terms) if ssl_result.error else False

            if is_cert_fail:
                score -= 35
                reasons.append("SSL certificate is invalid: -35")
            else:
                score -= 10
                reasons.append("SSL analysis returned an error and validity could not be established: -10")

        # 2. WHOIS Rules & Reasons
        if whois_result.is_registered:
            age = whois_result.domain_age_days
            if age is not None and age >= 365:
                score += 15
                reasons.append("Domain is older than one year: +15")
            else:
                score += 5
                reasons.append("Domain is registered but less than one year old: +5")
        else:
            if whois_result.error is not None:
                score -= 10
                reasons.append("WHOIS analysis failed and registration status could not be established: -10")
            else:
                score -= 20
                reasons.append("Domain is not registered: -20")

        # 3. Security Headers Rules & Reasons
        # Score calculation: 5 points for each present header
        score += header_result.security_headers_score * 5

        # Explanatory reasons for missing headers in exact fixed order
        header_order = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]
        missing_set = {h.lower() for h in header_result.missing_headers}
        for h in header_order:
            if h.lower() in missing_set:
                reasons.append(f"{h} header is missing: -5")

        # 4. Redirect Rules & Reasons
        if redirect_result.is_safe_redirect:
            score += 5
            reasons.append("Redirect chain is considered safe: +5")
        else:
            score -= 15
            reasons.append("Redirect chain is considered unsafe: -15")

        if redirect_result.cross_domain_redirect:
            score -= 10
            reasons.append("Cross-domain redirect detected: -10")

        # 5. HTTPS Upgrade Rules & Reasons
        if redirect_result.https_upgrade:
            score += 5
            reasons.append("HTTP to HTTPS upgrade detected: +5")

        # 6. Clamp final score
        final_score = max(0, min(100, score))

        # 7. Risk Classification
        if final_score >= 80:
            risk_level = RiskLevel.LOW
            summary = "Website shows strong trust indicators based on the available security analysis."
        elif final_score >= 50:
            risk_level = RiskLevel.MEDIUM
            summary = "Website shows mixed trust indicators and should be reviewed carefully."
        else:
            risk_level = RiskLevel.HIGH
            summary = "Website shows elevated risk indicators based on the available security analysis."

        return TrustEvaluationResult(
            trust_score=final_score,
            risk_level=risk_level,
            summary=summary,
            reasons=reasons
        )
