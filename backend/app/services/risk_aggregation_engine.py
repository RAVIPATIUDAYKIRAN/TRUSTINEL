import logging
from typing import List, Optional
from pydantic import BaseModel, Field

from app.models.enums import RiskLevel, UserFacingVerdict
from app.schemas.trust_evaluation import TrustEvaluationResult
from app.schemas.content_analysis import ContentAnalysisResult, ContentScamCategory
from app.schemas.whois_analysis import WHOISAnalysisResult
from app.services.threat_intelligence_service import ReputationThreatResult, ThreatReputationStatus

logger = logging.getLogger("trustinel.services.risk_aggregation_engine")


class MultiDimensionalRiskResult(BaseModel):
    technical_trust_score: int = Field(description="Deterministic technical security score (0=Insecure, 100=Secure)")
    content_risk_score: int = Field(description="Deterministic content scam risk score (0=Clean, 100=Scam Risk)")
    reputation_risk_score: int = Field(description="Deterministic reputation risk score (0=Clean, 100=Malicious)")
    behavioral_risk_score: int = Field(description="Deterministic domain age & e-commerce anomaly risk score (0=Clean, 100=High Risk)")
    
    overall_risk_score: int = Field(description="Final aggregated scam risk score (0=Safe, 100=Critical Scam Risk)")
    overall_risk_level: RiskLevel = Field(description="Final overall risk level: LOW | MEDIUM | HIGH")
    
    user_facing_verdict: UserFacingVerdict = Field(default=UserFacingVerdict.UNKNOWN, description="User-facing verdict classification")
    recommended_user_action: str = Field(default="", description="Clear, non-technical recommendation for users")

    risk_factors: List[str] = Field(default_factory=list, description="Human-readable evidence findings explaining overall risk")
    summary: str = ""


class RiskAggregationEngine:
    """
    Combines Technical Security, Content Intelligence, Domain Age/Behavioral Anomalies,
    and Reputation Threat Intelligence into a multi-dimensional risk decision.
    """

    def aggregate(
        self,
        trust_evaluation: TrustEvaluationResult,
        content_result: ContentAnalysisResult,
        whois_result: WHOISAnalysisResult,
        reputation_result: ReputationThreatResult,
    ) -> MultiDimensionalRiskResult:
        factors: List[str] = []

        # 1. Technical Trust (Preserved from RuleBasedTrustEngine)
        tech_trust_score = trust_evaluation.trust_score
        tech_insecurity_score = max(0, 100 - tech_trust_score)

        # 2. Content Risk
        content_risk = content_result.content_risk_score
        for sig in content_result.signals:
            factors.append(f"Content Risk ({sig.severity}): {sig.reason} [Evidence: {sig.evidence}]")

        # 3. Behavioral & Domain Age Risk
        behavioral_risk = 0.0
        domain_age = whois_result.domain_age_days

        if whois_result.is_registered:
            if domain_age is not None:
                if domain_age < 30:
                    behavioral_risk += 45.0
                    factors.append(f"Behavioral Risk (HIGH): Very new domain ({domain_age} day(s) old).")
                elif domain_age < 90:
                    behavioral_risk += 25.0
                    factors.append(f"Behavioral Risk (MEDIUM): Recently created domain ({domain_age} day(s) old).")
        else:
            behavioral_risk += 30.0
            factors.append("Behavioral Risk (MEDIUM): Domain registration status is unknown or unregistered.")

        # Behavioral multiplier: New Domain + Content Scam Indicators = Compound High Scam Risk
        is_very_new_domain = domain_age is not None and domain_age < 30
        if is_very_new_domain and content_risk >= 30:
            behavioral_risk = min(100.0, behavioral_risk + 35.0)
            factors.append("Behavioral Risk (CRITICAL): High-risk combination detected — Very new domain operating with aggressive promotional scam indicators.")

        # 4. Reputation Risk
        rep_risk = 0.0
        if reputation_result.status == ThreatReputationStatus.MALICIOUS:
            rep_risk = 100.0
            factors.append("Reputation Threat (CRITICAL): Domain listed on threat intelligence blacklists.")
        elif reputation_result.status == ThreatReputationStatus.SUSPICIOUS:
            rep_risk = 60.0
            factors.append("Reputation Threat (HIGH): Domain flagged as suspicious by reputation sources.")
        elif reputation_result.status == ThreatReputationStatus.UNKNOWN:
            rep_risk = 0.0  # Unknown does NOT mean safe, but does not add arbitrary risk penalty

        # 5. Non-Diluting Multi-Dimensional Risk Aggregation
        # Good technical security (SSL/headers) must NOT cancel strong content fraud/scam evidence.
        # Unavailable WHOIS or Reputation data must NOT act as 0 (safe) to dilute verified scam indicators.
        
        # Base scam risk is driven by content risk and behavioral indicators
        base_scam_risk = content_risk
        
        # Behavioral additions
        if behavioral_risk > 0:
            base_scam_risk = max(base_scam_risk, int(round((content_risk * 0.6) + (behavioral_risk * 0.4))))
            if is_very_new_domain and content_risk >= 30:
                base_scam_risk = min(100, base_scam_risk + 25)

        # Reputation additions
        if rep_risk > 0:
            base_scam_risk = max(base_scam_risk, int(round(rep_risk)))

        # Technical insecurity contribution (only increases risk if technical security is poor)
        if tech_insecurity_score >= 40:
            base_scam_risk = min(100, base_scam_risk + int(tech_insecurity_score * 0.2))

        final_overall_risk = int(round(max(0.0, min(100.0, float(base_scam_risk)))))

        # 6. Override Rules & Safety Constraints
        has_critical_scam_signal = any(
            (sig.category in (ContentScamCategory.CREDENTIAL_HARVESTING, ContentScamCategory.FINANCIAL_CLAIM) and sig.severity == "CRITICAL")
            for sig in (content_result.signals or [])
        )
        if has_critical_scam_signal:
            final_overall_risk = max(75, final_overall_risk)

        if is_very_new_domain and content_risk >= 35:
            final_overall_risk = max(75, final_overall_risk)

        if reputation_result.status == ThreatReputationStatus.MALICIOUS:
            final_overall_risk = max(90, final_overall_risk)

        # 7. Final Risk Classification
        if final_overall_risk >= 70:
            overall_level = RiskLevel.HIGH
            summary = "HIGH SCAM RISK DETECTED: Multiple deceptive content, domain age, or reputation risk indicators present."
        elif final_overall_risk >= 35:
            overall_level = RiskLevel.MEDIUM
            summary = "MEDIUM RISK: Website presents mixed security or content indicators requiring user caution."
        else:
            overall_level = RiskLevel.LOW
            summary = "LOW RISK: Website shows clean technical security and no significant scam content indicators."

        # 8. Deterministic User-Facing Verdict Classification Layer
        user_verdict, user_action = self.determine_user_facing_verdict(
            final_overall_risk=final_overall_risk,
            reputation_status=reputation_result.status,
            has_critical_scam_signal=has_critical_scam_signal,
            content_signals=content_result.signals or [],
            domain_age_days=domain_age,
            is_whois_registered=whois_result.is_registered,
            tech_trust_score=tech_trust_score,
            scan_failed=False
        )

        return MultiDimensionalRiskResult(
            technical_trust_score=tech_trust_score,
            content_risk_score=content_risk,
            reputation_risk_score=int(round(rep_risk)),
            behavioral_risk_score=int(round(behavioral_risk)),
            overall_risk_score=final_overall_risk,
            overall_risk_level=overall_level,
            user_facing_verdict=user_verdict,
            recommended_user_action=user_action,
            risk_factors=factors,
            summary=summary,
        )

    def determine_user_facing_verdict(
        self,
        final_overall_risk: int,
        reputation_status: ThreatReputationStatus,
        has_critical_scam_signal: bool,
        content_signals: list,
        domain_age_days: Optional[int],
        is_whois_registered: bool,
        tech_trust_score: int,
        scan_failed: bool = False
    ) -> tuple[UserFacingVerdict, str]:
        """
        Determines the separate user-facing verdict classification strictly based on
        deterministic evidence thresholds. Keeps numeric score separate.
        """
        if scan_failed:
            return (
                UserFacingVerdict.UNKNOWN,
                "TRUSTINEL could not verify enough information. Proceed only after independent verification."
            )

        # 1. HIGH_CONFIDENCE_SCAM
        # Requires confirmed threat intelligence, or critical credential harvesting / financial phishing signal.
        # Extreme discount, urgency, scarcity, domain age alone CANNOT produce this.
        is_confirmed_malicious = reputation_status == ThreatReputationStatus.MALICIOUS
        if is_confirmed_malicious or has_critical_scam_signal:
            return (
                UserFacingVerdict.HIGH_CONFIDENCE_SCAM,
                "Do not purchase, sign in, or provide sensitive information."
            )

        # Count independent warning categories
        warning_categories = set()
        if len(content_signals) > 0:
            warning_categories.add("CONTENT_SCAM")
        if domain_age_days is not None and domain_age_days < 30:
            warning_categories.add("VERY_NEW_DOMAIN")
        if not is_whois_registered:
            warning_categories.add("WHOIS_UNAVAILABLE")
        if reputation_status == ThreatReputationStatus.SUSPICIOUS:
            warning_categories.add("SUSPICIOUS_REPUTATION")
        if tech_trust_score < 60:
            warning_categories.add("POOR_TECHNICAL_SECURITY")

        # 2. LIKELY_SCAM
        # Overall risk >= 60 with >= 2 independent categories, or overall risk >= 70
        if final_overall_risk >= 70 or (final_overall_risk >= 60 and len(warning_categories) >= 2):
            return (
                UserFacingVerdict.LIKELY_SCAM,
                "Avoid purchasing or entering sensitive information."
            )

        # 3. SUSPICIOUS
        # Overall risk >= 35 or 1 significant warning category
        if final_overall_risk >= 35 or len(warning_categories) >= 1:
            return (
                UserFacingVerdict.SUSPICIOUS,
                "Be cautious. Verify the business before providing payment or personal information."
            )

        # Check minor uncertainties for PROBABLY_LEGITIMATE vs LEGITIMATE
        has_minor_uncertainty = (
            (domain_age_days is not None and 30 <= domain_age_days <= 90) or
            (not is_whois_registered) or
            (tech_trust_score < 80)
        )

        # 4. PROBABLY_LEGITIMATE
        if final_overall_risk < 35 and has_minor_uncertainty:
            return (
                UserFacingVerdict.PROBABLY_LEGITIMATE,
                "Proceed, but verify important details before paying."
            )

        # 5. LEGITIMATE
        if final_overall_risk < 20:
            return (
                UserFacingVerdict.LEGITIMATE,
                "Proceed normally, while still using normal online safety practices."
            )

        # Fallback to PROBABLY_LEGITIMATE if low risk but > 20
        return (
            UserFacingVerdict.PROBABLY_LEGITIMATE,
            "Proceed, but verify important details before paying."
        )

