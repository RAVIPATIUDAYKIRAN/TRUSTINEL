import logging
from typing import List, Optional
from pydantic import BaseModel, Field

from app.models.enums import RiskLevel
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

        # 5. Weighted Aggregation Formula
        # Content (45%) + Behavioral/Domain Age (30%) + Technical Insecurity (15%) + Reputation (10%)
        weighted_score = (
            (content_risk * 0.45) +
            (behavioral_risk * 0.30) +
            (tech_insecurity_score * 0.15) +
            (rep_risk * 0.10)
        )

        final_overall_risk = int(round(max(0.0, min(100.0, weighted_score))))

        # 6. Override Rules & Safety Constraints
        has_critical_scam_signal = any(
            (sig.category in (ContentScamCategory.CREDENTIAL_HARVESTING, ContentScamCategory.FINANCIAL_CLAIM) and sig.severity == "CRITICAL")
            for sig in (content_result.signals or [])
        )
        if has_critical_scam_signal:
            # Critical Phishing/Credential harvesting or Financial scam signals force at least HIGH scam risk regardless of domain age or SSL!
            final_overall_risk = max(75, final_overall_risk)

        if is_very_new_domain and content_risk >= 35:
            # Domain < 30 days old + aggressive urgency/scarcity/anomalies must be at least HIGH overall scam risk!
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

        return MultiDimensionalRiskResult(
            technical_trust_score=tech_trust_score,
            content_risk_score=content_risk,
            reputation_risk_score=int(round(rep_risk)),
            behavioral_risk_score=int(round(behavioral_risk)),
            overall_risk_score=final_overall_risk,
            overall_risk_level=overall_level,
            risk_factors=factors,
            summary=summary,
        )
