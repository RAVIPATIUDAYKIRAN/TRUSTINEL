from fastapi import APIRouter, Depends, status, HTTPException
import uuid
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.scan import ScanCreateRequest, ScanResponse
from app.schemas.ai_threat_analysis import AIServiceStatusResponse
from app.repositories.website_scan_repository import WebsiteScanRepository
from app.repositories.trust_report_repository import TrustReportRepository
from app.repositories.scan_history_repository import ScanHistoryRepository
from app.services.website_fetcher import WebsiteFetcher
from app.analyzers.ssl_analyzer import SSLAnalyzer
from app.analyzers.whois_analyzer import WHOISAnalyzer
from app.analyzers.header_analyzer import HeaderAnalyzer
from app.analyzers.redirect_analyzer import RedirectAnalyzer
from app.services.rule_based_trust_engine import RuleBasedTrustEngine
from app.services.risk_explanation_service import RiskExplanationService
from app.services.ai_threat_analysis_service import AIThreatAnalysisService
from app.services.scan_service import ScanService

router = APIRouter(prefix="/api/v1", tags=["Scan"])


@router.get(
    "/scan/ai-status",
    response_model=AIServiceStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve AI Threat Analysis service status and security audit telemetry",
    description=(
        "Returns non-sensitive operational health, diagnostic configuration, cache metrics, "
        "and security audit compliance telemetry for the AI Threat Analysis service. "
        "Read-only; performs no external AI API calls or database writes."
    )
)
async def get_ai_status() -> AIServiceStatusResponse:
    """
    HTTP GET route to retrieve safe operational telemetry and security audit status.
    Performs NO external LLM requests, website fetches, or database mutations.
    """
    status_data = AIThreatAnalysisService.get_status()
    return AIServiceStatusResponse.model_validate(status_data)


@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Initiate website trust scan",
    description="Initiates a new website scan, runs real security analyzers, and generates a trust report."
)
async def create_scan(
    request: ScanCreateRequest,
    db: AsyncSession = Depends(get_db)
) -> ScanResponse:
    """
    HTTP POST route to coordinate scan initiation using the real intelligence pipeline.
    """
    # Instantiate repositories
    scan_repo = WebsiteScanRepository(db)
    report_repo = TrustReportRepository(db)
    history_repo = ScanHistoryRepository(db)

    # Instantiate intelligence components
    fetcher = WebsiteFetcher()
    ssl_analyzer = SSLAnalyzer()
    whois_analyzer = WHOISAnalyzer()
    header_analyzer = HeaderAnalyzer()
    redirect_analyzer = RedirectAnalyzer()
    trust_engine = RuleBasedTrustEngine()
    explanation_service = RiskExplanationService()
    ai_threat_service = AIThreatAnalysisService()

    # Instantiate scan service
    service = ScanService(
        session=db,
        scan_repo=scan_repo,
        report_repo=report_repo,
        history_repo=history_repo,
        fetcher=fetcher,
        ssl_analyzer=ssl_analyzer,
        whois_analyzer=whois_analyzer,
        header_analyzer=header_analyzer,
        redirect_analyzer=redirect_analyzer,
        trust_engine=trust_engine,
        explanation_service=explanation_service,
        ai_threat_service=ai_threat_service,
    )

    # Delegate orchestration execution to ScanService
    return await service.create_scan(url=str(request.url))


@router.get(
    "/scan/{scan_id}",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve scan details",
    description="Retrieves the details and generated trust report of a scan by its unique scan ID."
)
async def get_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
) -> ScanResponse:
    """
    HTTP GET route to retrieve scan details by UUID.
    Only reads persisted data — does NOT execute analyzers or regenerate scores.
    """
    # Instantiate repositories
    scan_repo = WebsiteScanRepository(db)
    report_repo = TrustReportRepository(db)
    history_repo = ScanHistoryRepository(db)

    # Instantiate intelligence components (needed for ScanService constructor,
    # but get_scan does NOT invoke them)
    fetcher = WebsiteFetcher()
    ssl_analyzer = SSLAnalyzer()
    whois_analyzer = WHOISAnalyzer()
    header_analyzer = HeaderAnalyzer()
    redirect_analyzer = RedirectAnalyzer()
    trust_engine = RuleBasedTrustEngine()
    explanation_service = RiskExplanationService()

    # Instantiate scan service
    service = ScanService(
        session=db,
        scan_repo=scan_repo,
        report_repo=report_repo,
        history_repo=history_repo,
        fetcher=fetcher,
        ssl_analyzer=ssl_analyzer,
        whois_analyzer=whois_analyzer,
        header_analyzer=header_analyzer,
        redirect_analyzer=redirect_analyzer,
        trust_engine=trust_engine,
        explanation_service=explanation_service,
    )

    # Delegate query execution to ScanService
    scan = await service.get_scan(scan_id=scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {scan_id} not found"
        )
    return scan
