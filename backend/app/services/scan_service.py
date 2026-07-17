import uuid
from typing import Optional
from urllib.parse import urlparse
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.website_scan import WebsiteScan
from app.models.enums import ScanStatus
from app.repositories.website_scan_repository import WebsiteScanRepository
from app.repositories.trust_report_repository import TrustReportRepository
from app.repositories.scan_history_repository import ScanHistoryRepository
from app.services.mock_trust_report_generator import MockTrustReportGenerator


class ScanService:
    """
    Service class responsible for orchestrating the complete website scan workflow
    and managing database transaction lifecycles.
    """
    def __init__(
        self,
        session: AsyncSession,
        scan_repo: WebsiteScanRepository,
        report_repo: TrustReportRepository,
        history_repo: ScanHistoryRepository,
        generator: MockTrustReportGenerator
    ) -> None:
        self.session = session
        self.scan_repo = scan_repo
        self.report_repo = report_repo
        self.history_repo = history_repo
        self.generator = generator

    async def create_scan(self, url: str) -> WebsiteScan:
        """
        Orchestrates the transactional sequence of creating a scan,
        generating a mock report, logging history, and completing the scan.
        """
        # 1. Normalize the URL
        normalized_url = url.strip()

        # 2. Extract the domain
        parsed_url = urlparse(normalized_url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        if not domain:
            domain = normalized_url

        try:
            # 3. Create a WebsiteScan record with status=PENDING
            scan = await self.scan_repo.create_scan(
                url=normalized_url,
                domain=domain,
                status=ScanStatus.PENDING
            )

            # 4. Generate mock trust report data
            report_data = self.generator.generate(normalized_url)

            # 5. Store the TrustReport linked to the scan
            await self.report_repo.create_report(
                scan_id=scan.id,
                trust_score=report_data["trust_score"],
                risk_level=report_data["risk_level"],
                summary=report_data["summary"]
            )

            # 6. Create ScanHistory entry recording the scan creation
            await self.history_repo.create_history(
                scan_id=scan.id,
                action="SCAN_INITIATED",
                status="SUCCESS"
            )

            # 7. Update WebsiteScan status to COMPLETED
            await self.scan_repo.update_scan_status(
                scan_id=scan.id,
                status=ScanStatus.COMPLETED
            )

            # 8. Commit the transaction once
            await self.session.commit()

            # 9. Refresh the WebsiteScan instance to reload relationships
            await self.session.refresh(scan)
            return scan

        except Exception:
            # Rollback transaction on unexpected failures and propagate the error
            await self.session.rollback()
            raise

    async def get_scan(self, scan_id: uuid.UUID) -> Optional[WebsiteScan]:
        """
        Retrieve a scan details together with its trust report.
        """
        return await self.scan_repo.get_scan_by_id(scan_id)
