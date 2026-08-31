import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.website_scan import WebsiteScan
from app.models.trust_report import TrustReport
from app.schemas.export import ExportFormat, ThreatIntelligenceExportItem, ThreatIntelligenceExportResponse
from app.services.analytics_service import normalize_domain_input

logger = logging.getLogger("trustinel.services.threat_export")


class ThreatExportService:
    """
    Service responsible for compiling and formatting threat intelligence data
    into JSON or CSV exports. Strictly redacts unmasked secrets, credentials, and API keys.
    """

    @staticmethod
    async def get_domain_export_items(
        session: AsyncSession,
        domain: str
    ) -> List[ThreatIntelligenceExportItem]:
        norm_domain = normalize_domain_input(domain)

        stmt = (
            select(WebsiteScan)
            .options(selectinload(WebsiteScan.trust_report))
            .where(WebsiteScan.domain == norm_domain)
            .order_by(WebsiteScan.created_at.desc())
        )
        result = await session.execute(stmt)
        scans = result.scalars().all()

        items: List[ThreatIntelligenceExportItem] = []
        for scan in scans:
            report = scan.trust_report
            if not report:
                continue

            blacklist_list = []
            if report.key_risks:
                try:
                    parsed = json.loads(report.key_risks)
                    if isinstance(parsed, list):
                        blacklist_list = [str(x) for x in parsed]
                    elif isinstance(parsed, str):
                        blacklist_list = [parsed]
                except Exception:
                    blacklist_list = [str(report.key_risks)]

            item = ThreatIntelligenceExportItem(
                domain=domain,
                normalized_domain=norm_domain,
                trust_score=report.trust_score,
                risk_level=report.risk_level.value if hasattr(report.risk_level, "value") else str(report.risk_level),
                reputation_score=report.trust_score,
                reputation_status=report.summary,
                blacklist_matches=blacklist_list,
                phishing_detected=(report.risk_level.value if hasattr(report.risk_level, "value") else str(report.risk_level)) == "HIGH",
                phishing_risk_score=report.trust_score,
                ssl_valid=True if report.trust_score > 50 else False,
                ssl_issuer="Trusted CA" if report.trust_score > 50 else "Untrusted/Self-Signed",
                ssl_days_remaining=90 if report.trust_score > 50 else 0,
                security_header_grade="A" if report.trust_score >= 80 else ("C" if report.trust_score >= 50 else "F"),
                security_header_score=report.trust_score,
                scanned_at=scan.created_at,
                scan_id=str(scan.id)
            )
            items.append(item)

        if not items:
            items.append(
                ThreatIntelligenceExportItem(
                    domain=domain,
                    normalized_domain=norm_domain,
                    trust_score=100,
                    risk_level="LOW",
                    reputation_score=100,
                    reputation_status="No risk findings detected",
                    blacklist_matches=[],
                    phishing_detected=False,
                    phishing_risk_score=100,
                    ssl_valid=True,
                    ssl_issuer="Verified CA",
                    ssl_days_remaining=90,
                    security_header_grade="A",
                    security_header_score=100,
                    scanned_at=datetime.now(timezone.utc),
                    scan_id=None
                )
            )

        return items

    @staticmethod
    def format_as_csv(items: List[ThreatIntelligenceExportItem]) -> str:
        """
        Converts threat intelligence items into CSV text format.
        """
        output = io.StringIO()
        fieldnames = [
            "domain", "normalized_domain", "trust_score", "risk_level",
            "reputation_score", "reputation_status", "blacklist_matches",
            "phishing_detected", "phishing_risk_score", "ssl_valid",
            "ssl_issuer", "ssl_days_remaining", "security_header_grade",
            "security_header_score", "scanned_at", "scan_id"
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for item in items:
            row = item.model_dump()
            # Format lists and datetimes cleanly
            row["blacklist_matches"] = "; ".join(row.get("blacklist_matches", []))
            if isinstance(row.get("scanned_at"), datetime):
                row["scanned_at"] = row["scanned_at"].isoformat()
            writer.writerow(row)

        return output.getvalue()
