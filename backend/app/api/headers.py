import logging
from fastapi import APIRouter, Depends, Request, status

from app.config.settings import settings
from app.core.rate_limiter import RateLimiter
from app.core.url_security import URLSecurityValidator
from app.middleware.exceptions import APIException
from app.schemas.header_audit import HeaderAuditResult
from app.analyzers.header_deep_analyzer import HeaderDeepAnalyzer
from app.services.analytics_service import normalize_domain_input

logger = logging.getLogger("trustinel.api.headers")

router = APIRouter(prefix="/headers", tags=["Header & CSP Audit"])


@router.get(
    "/domain/{domain}",
    response_model=HeaderAuditResult,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter("get_header_audit", lambda: settings.RATE_LIMIT_GET_SCAN))],
    summary="Get domain Content Security Policy & HTTP security header audit",
    description="Performs in-depth security header auditing, Content-Security-Policy (CSP) directive analysis, Strict-Transport-Security (HSTS) parameter validation, header security scoring, and audit grading."
)
async def get_domain_header_audit(domain: str):
    normalized_domain = normalize_domain_input(domain)
    if not normalized_domain or "." not in normalized_domain:
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid domain syntax provided: '{domain}'",
            error_code="INVALID_DOMAIN"
        )

    # SSRF DNS protection check
    await URLSecurityValidator.validate_hostname_resolution(normalized_domain)

    analyzer = HeaderDeepAnalyzer()
    result = await analyzer.audit_domain(normalized_domain)
    return result
