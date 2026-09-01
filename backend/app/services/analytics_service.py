import logging
from enum import Enum
from typing import Optional, List
from urllib.parse import urlparse
from app.repositories.website_scan_repository import WebsiteScanRepository
from app.schemas.analytics import (
    DomainAnalyticsResponse,
    DomainTrend,
    RiskDistribution,
    DomainScanTimelineItem,
)

logger = logging.getLogger("trustinel.analytics")


def normalize_domain_input(input_str: str) -> str:
    """Normalize input domain string by stripping protocols and path segments."""
    cleaned = input_str.strip().lower()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"http://{cleaned}"
    try:
        parsed = urlparse(cleaned)
        domain = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
        return domain.strip().lower()
    except Exception:
        return input_str.strip().lower()


class AnalyticsService:
    """
    Business service calculating domain-level historical trust analytics,
    score trajectories, risk distributions, and timeline reports.
    """
    def __init__(self, scan_repo: WebsiteScanRepository) -> None:
        self.scan_repo = scan_repo

    async def get_domain_analytics(self, raw_domain: str) -> Optional[DomainAnalyticsResponse]:
        domain = normalize_domain_input(raw_domain)
        if not domain:
            return None

        scans = await self.scan_repo.list_scans_by_domain(domain, limit=100)
        if not scans:
            logger.info(f"No scan records found for domain: {domain}")
            return None

        # Filter scans that have associated trust reports
        scans_with_reports = [s for s in scans if s.trust_report is not None]
        if not scans_with_reports:
            logger.info(f"No completed trust reports found for domain: {domain}")
            return None

        total_scans = len(scans_with_reports)
        latest_scan = scans_with_reports[0]
        oldest_scan = scans_with_reports[-1]

        # Primary Trajectory: Overall Scam Risk
        scam_risk_scores: List[int] = []
        scam_risk_levels: List[str] = []
        tech_scores: List[int] = []

        for s in scans_with_reports:
            report = s.trust_report
            ov_score = getattr(report, "overall_risk_score", None)
            if ov_score is not None and isinstance(ov_score, int):
                scam_score = ov_score
            else:
                raw_tech = getattr(report, "trust_score", 50)
                scam_score = max(0, min(100, 100 - raw_tech)) if isinstance(raw_tech, int) else 50

            ov_lvl = getattr(report, "overall_risk_level", None)
            if ov_lvl is not None and isinstance(ov_lvl, (str, Enum)):
                lvl_val = getattr(ov_lvl, "value", str(ov_lvl))
            else:
                raw_lvl = getattr(report, "risk_level", "LOW")
                lvl_val = getattr(raw_lvl, "value", str(raw_lvl))

            raw_tech_score = getattr(report, "trust_score", 50)
            scam_risk_scores.append(scam_score)
            scam_risk_levels.append(str(lvl_val).upper())
            tech_scores.append(raw_tech_score if isinstance(raw_tech_score, int) else 50)

        current_scam_risk = scam_risk_scores[0] if scam_risk_scores else None
        avg_scam_risk = round(sum(scam_risk_scores) / len(scam_risk_scores), 2) if scam_risk_scores else 0.0
        min_scam_risk = min(scam_risk_scores) if scam_risk_scores else None
        max_scam_risk = max(scam_risk_scores) if scam_risk_scores else None

        current_tech_score = tech_scores[0] if tech_scores else None
        avg_tech_score = round(sum(tech_scores) / len(tech_scores), 2) if tech_scores else 0.0

        # Scam Risk Delta and Trajectory Trend calculation
        # Note: For scam risk, LOWER score is safer, HIGHER score is riskier.
        # If scam risk DECREASES over time (scores[0] < scores[1]), trajectory is IMPROVING!
        # If scam risk INCREASES over time (scores[0] > scores[1]), trajectory is DEGRADING!
        scam_risk_delta: Optional[int] = None
        trend = DomainTrend.INSUFFICIENT_DATA

        if len(scam_risk_scores) >= 2:
            scam_risk_delta = scam_risk_scores[0] - scam_risk_scores[1]
            if scam_risk_delta < -3:
                trend = DomainTrend.IMPROVING
            elif scam_risk_delta > 3:
                trend = DomainTrend.DEGRADING
            else:
                trend = DomainTrend.STABLE

        # Risk distribution breakdown (based on Overall Scam Risk Level)
        low_count = sum(1 for lvl in scam_risk_levels if "LOW" in lvl)
        med_count = sum(1 for lvl in scam_risk_levels if "MEDIUM" in lvl)
        high_count = sum(1 for lvl in scam_risk_levels if "HIGH" in lvl)

        risk_dist = RiskDistribution(
            low=low_count,
            medium=med_count,
            high=high_count
        )

        # History Timeline list
        timeline = []
        for i, s in enumerate(scans_with_reports):
            rep = s.trust_report
            timeline.append(
                DomainScanTimelineItem(
                    scan_id=str(s.id),
                    trust_score=rep.trust_score,
                    risk_level=getattr(rep.risk_level, "value", str(rep.risk_level)),
                    overall_risk_score=scam_risk_scores[i],
                    overall_risk_level=scam_risk_levels[i],
                    summary=rep.summary,
                    scanned_at=s.created_at
                )
            )

        return DomainAnalyticsResponse(
            domain=domain,
            total_scans=total_scans,
            current_scam_risk=current_scam_risk,
            average_scam_risk=avg_scam_risk,
            min_scam_risk=min_scam_risk,
            max_scam_risk=max_scam_risk,
            scam_risk_delta=scam_risk_delta,
            trend=trend,
            risk_distribution=risk_dist,
            first_scanned_at=oldest_scan.created_at,
            last_scanned_at=latest_scan.created_at,
            history_timeline=timeline,
            current_technical_score=current_tech_score,
            average_technical_score=avg_tech_score,
        )
