import uuid
from typing import Sequence
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan_history import ScanHistory
from app.repositories.base import BaseRepository


class ScanHistoryRepository(BaseRepository):
    """
    Repository class handling all database operations for ScanHistory entity.
    """
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session)

    async def create_history(self, scan_id: uuid.UUID, action: str, status: str) -> ScanHistory:
        """
        Create and persist a new ScanHistory transition log.
        """
        history = ScanHistory(
            scan_id=scan_id,
            action=action,
            status=status
        )
        self.add(history)
        await self.flush()
        return history

    async def get_history_by_scan(self, scan_id: uuid.UUID) -> Sequence[ScanHistory]:
        """
        Retrieve all history milestones recorded for a given scan UUID.
        """
        stmt = (
            select(ScanHistory)
            .where(ScanHistory.scan_id == scan_id)
            .order_by(desc(ScanHistory.created_at))
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def list_recent_history(self, limit: int = 50) -> Sequence[ScanHistory]:
        """
        List overall recent history events across all scans, ordered by latest.
        """
        stmt = (
            select(ScanHistory)
            .order_by(desc(ScanHistory.created_at))
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
