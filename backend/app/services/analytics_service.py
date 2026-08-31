import logging
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

        scores = [s.trust_report.trust_score for s in scans_with_reports]
        current_score = scores[0] if scores else None
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        min_score = min(scores) if scores else None
        max_score = max(scores) if scores else None

        # Score delta and trajectory calculation
        score_delta: Optional[int] = None
        trend = DomainTrend.INSUFFICIENT_DATA

        if len(scores) >= 2:
            score_delta = scores[0] - scores[1]
            if score_delta > 3:
                trend = DomainTrend.IMPROVING
            elif score_delta < -3:
                trend = DomainTrend.DEGRADING
            else:
                trend = DomainTrend.STABLE

        # Risk distribution breakdown
        low_count = sum(1 for s in scans_with_reports if s.trust_report.risk_level == "LOW")
        med_count = sum(1 for s in scans_with_reports if s.trust_report.risk_level == "MEDIUM")
        high_count = sum(1 for s in scans_with_reports if s.trust_report.risk_level == "HIGH")

        risk_dist = RiskDistribution(
            low=low_count,
            medium=med_count,
            high=high_count
        )

        # Timeline list
        timeline = [
            DomainScanTimelineItem(
                scan_id=str(s.id),
                trust_score=s.trust_report.trust_score,
                risk_level=s.trust_report.risk_level,
                summary=s.trust_report.summary,
                scanned_at=s.created_at
            )
            for s in scans_with_reports
        ]

        return DomainAnalyticsResponse(
            domain=domain,
            total_scans=total_scans,
            current_trust_score=current_score,
            average_trust_score=avg_score,
            min_trust_score=min_score,
            max_trust_score=max_score,
            score_delta=score_delta,
            trend=trend,
            risk_distribution=risk_dist,
            first_scanned_at=oldest_scan.created_at,
            last_scanned_at=latest_scan.created_at,
            history_timeline=timeline
        )
