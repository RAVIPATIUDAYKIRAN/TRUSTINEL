import logging
from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.settings import settings
from app.core.rate_limiter import RateLimiter
from app.database.session import get_db_session
from app.middleware.exceptions import APIException
from app.repositories.website_scan_repository import WebsiteScanRepository
from app.schemas.analytics import DomainAnalyticsResponse
from app.services.analytics_service import AnalyticsService, normalize_domain_input

logger = logging.getLogger("trustinel.api.analytics")

router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get(
    "/domain/{domain}",
    response_model=DomainAnalyticsResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter("get_analytics", lambda: settings.RATE_LIMIT_GET_SCAN))],
    summary="Get domain trust history and trend analytics",
    description="Calculates historical trust score trajectories, score deltas, risk distribution, and scan timeline for a given domain."
)
async def get_domain_analytics(
    domain: str,
    session: AsyncSession = Depends(get_db_session)
):
    normalized_domain = normalize_domain_input(domain)
    if not normalized_domain or "." not in normalized_domain:
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid domain syntax provided: '{domain}'",
            error_code="INVALID_DOMAIN"
        )

    scan_repo = WebsiteScanRepository(session)
    service = AnalyticsService(scan_repo)

    analytics = await service.get_domain_analytics(normalized_domain)
    if not analytics:
        raise APIException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No scan history found for domain '{normalized_domain}'",
            error_code="DOMAIN_NOT_FOUND"
        )

    return analytics
