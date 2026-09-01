import json
import uuid
from typing import Optional, List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.trust_report import TrustReport
from app.models.enums import RiskLevel
from app.repositories.base import BaseRepository


class TrustReportRepository(BaseRepository):
    """
    Repository class handling all database operations for TrustReport entity.
    """
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session)

    async def create_report(
        self,
        scan_id: uuid.UUID,
        trust_score: int,
        risk_level: RiskLevel,
        summary: str,
        explanation: Optional[str] = None,
        key_risks: Optional[List[str]] = None,
        positive_signals: Optional[List[str]] = None,
        recommendation: Optional[str] = None,
        technical_trust_score: Optional[int] = None,
        content_risk_score: Optional[int] = None,
        reputation_risk_score: Optional[int] = None,
        behavioral_risk_score: Optional[int] = None,
        overall_risk_score: Optional[int] = None,
        overall_risk_level: Optional[RiskLevel] = None,
        risk_factors: Optional[List[str]] = None
    ) -> TrustReport:
        """
        Create and persist a new TrustReport linked to a scan.
        Serializes key_risks, positive_signals, and risk_factors as JSON strings.
        """
        report = TrustReport(
            scan_id=scan_id,
            trust_score=trust_score,
            risk_level=risk_level,
            summary=summary,
            explanation=explanation,
            key_risks=json.dumps(key_risks) if key_risks is not None else None,
            positive_signals=json.dumps(positive_signals) if positive_signals is not None else None,
            recommendation=recommendation,
            technical_trust_score=technical_trust_score,
            content_risk_score=content_risk_score,
            reputation_risk_score=reputation_risk_score,
            behavioral_risk_score=behavioral_risk_score,
            overall_risk_score=overall_risk_score,
            overall_risk_level=overall_risk_level,
            risk_factors=json.dumps(risk_factors) if risk_factors is not None else None
        )
        self.add(report)
        await self.flush()
        return report

    async def get_report_by_scan_id(self, scan_id: uuid.UUID) -> Optional[TrustReport]:
        """
        Retrieve a TrustReport record associated with a given WebsiteScan UUID.
        """
        stmt = select(TrustReport).where(TrustReport.scan_id == scan_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def update_report(
        self,
        report_id: uuid.UUID,
        trust_score: int,
        risk_level: RiskLevel,
        summary: str
    ) -> Optional[TrustReport]:
        """
        Update evaluation properties of a TrustReport.
        """
        report = await self.get_by_id(TrustReport, report_id)
        if report:
            report.trust_score = trust_score
            report.risk_level = risk_level
            report.summary = summary
            await self.flush()
        return report

    async def delete_report(self, report_id: uuid.UUID) -> bool:
        """
        Delete a TrustReport record by its UUID. Returns True if deleted, False otherwise.
        """
        report = await self.get_by_id(TrustReport, report_id)
        if report:
            await self.delete(report)
            await self.flush()
            return True
        return False
