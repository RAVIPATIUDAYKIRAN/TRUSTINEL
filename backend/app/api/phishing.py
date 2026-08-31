import logging
from fastapi import APIRouter, Depends, Request, status

from app.config.settings import settings
from app.core.rate_limiter import RateLimiter
from app.core.url_security import URLSecurityValidator
from app.middleware.exceptions import APIException
from app.schemas.phishing import PhishingImpersonationResult
from app.analyzers.phishing_analyzer import PhishingAnalyzer
from app.services.analytics_service import normalize_domain_input

logger = logging.getLogger("trustinel.api.phishing")

router = APIRouter(prefix="/phishing", tags=["Phishing & Brand Protection"])


@router.get(
    "/domain/{domain}",
    response_model=PhishingImpersonationResult,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter("get_phishing_analysis", lambda: settings.RATE_LIMIT_GET_SCAN))],
    summary="Get domain phishing & typosquatting brand impersonation analysis",
    description="Evaluates domain typosquatting, character manipulations (omission, insertion, substitution, transposition), homoglyphs/IDN abuse, subdomain brand impersonation, and deceptive keyword tricks."
)
async def get_domain_phishing_analysis(domain: str):
    normalized_domain = normalize_domain_input(domain)
    if not normalized_domain or "." not in normalized_domain:
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid domain syntax provided: '{domain}'",
            error_code="INVALID_DOMAIN"
        )

    # SSRF DNS protection check to prevent private/loopback/metadata/CGNAT destination access
    await URLSecurityValidator.validate_hostname_resolution(normalized_domain)

    analyzer = PhishingAnalyzer()
    result = await analyzer.analyze_domain(normalized_domain)
    return result
