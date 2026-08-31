import logging
from fastapi import APIRouter, Depends, Request, status

from app.config.settings import settings
from app.core.rate_limiter import RateLimiter
from app.middleware.exceptions import APIException
from app.schemas.reputation import ReputationResult
from app.analyzers.reputation_analyzer import ReputationAnalyzer
from app.services.analytics_service import normalize_domain_input

logger = logging.getLogger("trustinel.api.reputation")

router = APIRouter(prefix="/reputation", tags=["Reputation"])


@router.get(
    "/domain/{domain}",
    response_model=ReputationResult,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter("get_reputation", lambda: settings.RATE_LIMIT_GET_SCAN))],
    summary="Get domain threat intelligence reputation",
    description="Evaluates domain and IP reputation against global threat feeds, phishing blocklists, and malware databases."
)
async def get_domain_reputation(domain: str):
    normalized_domain = normalize_domain_input(domain)
    if not normalized_domain or "." not in normalized_domain:
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid domain syntax provided: '{domain}'",
            error_code="INVALID_DOMAIN"
        )

    analyzer = ReputationAnalyzer()
    result = await analyzer.analyze_domain(normalized_domain)
    return result
