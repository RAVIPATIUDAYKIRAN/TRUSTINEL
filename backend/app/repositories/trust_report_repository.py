import uuid
from typing import Optional
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
        summary: str
    ) -> TrustReport:
        """
        Create and persist a new TrustReport linked to a scan.
        """
        report = TrustReport(
            scan_id=scan_id,
            trust_score=trust_score,
            risk_level=risk_level,
            summary=summary
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
