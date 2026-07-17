import uuid
from typing import Optional, Sequence
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.website_scan import WebsiteScan
from app.models.enums import ScanStatus
from app.repositories.base import BaseRepository


class WebsiteScanRepository(BaseRepository):
    """
    Repository class handling all database operations for WebsiteScan entity.
    """
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session)

    async def create_scan(self, url: str, domain: str, status: ScanStatus = ScanStatus.PENDING) -> WebsiteScan:
        """
        Create and persist a new WebsiteScan record.
        """
        scan = WebsiteScan(
            url=url,
            domain=domain,
            status=status
        )
        self.add(scan)
        await self.flush()
        return scan

    async def get_scan_by_id(self, scan_id: uuid.UUID) -> Optional[WebsiteScan]:
        """
        Retrieve a WebsiteScan by its UUID, eager loading the linked TrustReport.
        """
        stmt = (
            select(WebsiteScan)
            .where(WebsiteScan.id == scan_id)
            .options(selectinload(WebsiteScan.trust_report))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_scan_by_url(self, url: str) -> Optional[WebsiteScan]:
        """
        Retrieve a WebsiteScan by its exact URL string.
        """
        stmt = (
            select(WebsiteScan)
            .where(WebsiteScan.url == url)
            .options(selectinload(WebsiteScan.trust_report))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def update_scan_status(self, scan_id: uuid.UUID, status: ScanStatus) -> Optional[WebsiteScan]:
        """
        Update the lifecycle status of a scan.
        """
        scan = await self.get_by_id(WebsiteScan, scan_id)
        if scan:
            scan.status = status
            await self.flush()
        return scan

    async def update_scan_domain(self, scan_id: uuid.UUID, domain: str) -> Optional[WebsiteScan]:
        """
        Update the extracted domain of a scan.
        """
        scan = await self.get_by_id(WebsiteScan, scan_id)
        if scan:
            scan.domain = domain
            await self.flush()
        return scan

    async def list_recent_scans(self, limit: int = 20) -> Sequence[WebsiteScan]:
        """
        List most recently created scans, ordered descending by creation date.
        """
        stmt = (
            select(WebsiteScan)
            .order_by(desc(WebsiteScan.created_at))
            .limit(limit)
            .options(selectinload(WebsiteScan.trust_report))
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def delete_scan(self, scan_id: uuid.UUID) -> bool:
        """
        Delete a WebsiteScan record by its UUID. Returns True if deleted, False otherwise.
        """
        scan = await self.get_by_id(WebsiteScan, scan_id)
        if scan:
            await self.delete(scan)
            await self.flush()
            return True
        return False
