import logging
from fastapi import APIRouter, Depends, Request, status

from app.config.settings import settings
from app.core.rate_limiter import RateLimiter
from app.core.url_security import URLSecurityValidator
from app.middleware.exceptions import APIException
from app.schemas.ssl_deep_inspection import SSLDeepInspectionResult
from app.analyzers.ssl_deep_analyzer import SSLDeepAnalyzer
from app.services.analytics_service import normalize_domain_input

logger = logging.getLogger("trustinel.api.ssl")

router = APIRouter(prefix="/ssl", tags=["SSL Inspection"])


@router.get(
    "/domain/{domain}",
    response_model=SSLDeepInspectionResult,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter("get_ssl_inspection", lambda: settings.RATE_LIMIT_GET_SCAN))],
    summary="Get domain Certificate Authority & SSL cryptographic deep inspection",
    description="Performs deep cryptographic verification of SSL/TLS certificates, Subject Alternative Names (SAN), issuer trust chains, public key strengths, cipher suites, expiration metrics, and obsolete TLS protocol detection."
)
async def get_domain_ssl_inspection(domain: str):
    normalized_domain = normalize_domain_input(domain)
    if not normalized_domain or "." not in normalized_domain:
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid domain syntax provided: '{domain}'",
            error_code="INVALID_DOMAIN"
        )

    # Perform SSRF DNS protection check
    # This validates DNS resolution and blocks private/loopback/metadata/CGNAT destinations
    resolved_ips = await URLSecurityValidator.validate_hostname_resolution(normalized_domain)
    target_ip = resolved_ips[0] if resolved_ips else None

    analyzer = SSLDeepAnalyzer()
    result = await analyzer.inspect_domain(normalized_domain, ip_address=target_ip)
    return result
