import logging
from fastapi import APIRouter, Depends, Request, status

from app.config.settings import settings
from app.core.rate_limiter import RateLimiter
from app.middleware.exceptions import APIException
from app.schemas.batch_scan import BatchScanRequest, BatchScanResponse
from app.services.batch_scan_service import BatchScanService
from app.services.threat_cache_service import ThreatCacheService
from app.services.analytics_service import normalize_domain_input

logger = logging.getLogger("trustinel.api.batch")

router = APIRouter(prefix="/batch", tags=["Batch Scan & Threat Cache"])


@router.post(
    "/scan",
    response_model=BatchScanResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter("post_batch_scan", lambda: settings.RATE_LIMIT_POST_SCAN))],
    summary="Execute bulk domain threat scan with result caching",
    description="Processes up to 20 domains concurrently with per-domain SSRF validation, threat intelligence caching, and partial success error handling."
)
async def execute_bulk_scan(request_payload: BatchScanRequest):
    if len(request_payload.domains) > 20:
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch request exceeds maximum limit of 20 domains per request.",
            error_code="INVALID_BATCH_SIZE"
        )

    service = BatchScanService()
    return await service.execute_batch(request_payload)


@router.delete(
    "/cache/domain/{domain}",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter("post_batch_scan", lambda: settings.RATE_LIMIT_POST_SCAN))],
    summary="Invalidate threat intelligence cache for a domain",
    description="Clears all cached threat intelligence entries (reputation, phishing, SSL, headers) for a given domain."
)
async def invalidate_domain_threat_cache(domain: str):
    normalized = normalize_domain_input(domain)
    if not normalized or "." not in normalized:
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid domain syntax provided: '{domain}'",
            error_code="INVALID_DOMAIN"
        )

    cache_service = ThreatCacheService()
    count = await cache_service.invalidate_domain_cache(normalized)
    return {"message": f"Successfully invalidated cache entries for domain '{normalized}'", "entries_cleared": count}
