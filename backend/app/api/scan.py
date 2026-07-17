from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.scan import ScanCreateRequest, ScanResponse
from app.repositories.website_scan_repository import WebsiteScanRepository
from app.repositories.trust_report_repository import TrustReportRepository
from app.repositories.scan_history_repository import ScanHistoryRepository
from app.services.mock_trust_report_generator import MockTrustReportGenerator
from app.services.scan_service import ScanService

router = APIRouter(prefix="/api/v1", tags=["Scan"])


@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Initiate website trust scan",
    description="Initiates a new website scan, generates a mock trust report, and logs the transactions."
)
async def create_scan(
    request: ScanCreateRequest,
    db: AsyncSession = Depends(get_db)
) -> ScanResponse:
    """
    HTTP POST route to coordinate scan initiation.
    """
    # Instantiate repositories
    scan_repo = WebsiteScanRepository(db)
    report_repo = TrustReportRepository(db)
    history_repo = ScanHistoryRepository(db)
    
    # Instantiate mock generator
    generator = MockTrustReportGenerator()
    
    # Instantiate scan service
    service = ScanService(
        session=db,
        scan_repo=scan_repo,
        report_repo=report_repo,
        history_repo=history_repo,
        generator=generator
    )
    
    # Delegate orchestration execution to ScanService
    return await service.create_scan(url=str(request.url))
