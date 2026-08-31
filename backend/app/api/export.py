import logging
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.settings import settings
from app.core.rate_limiter import RateLimiter
from app.database.session import get_db_session
from app.middleware.exceptions import APIException
from app.schemas.export import ExportFormat, ThreatIntelligenceExportResponse
from app.services.threat_export_service import ThreatExportService

logger = logging.getLogger("trustinel.api.export")

router = APIRouter(prefix="/export", tags=["Threat Intelligence Export"])


@router.get(
    "/domain/{domain}",
    summary="Export domain threat intelligence",
    description="Exports threat intelligence data for a domain in JSON or CSV format. Sensitive credentials, secret tokens, and API key hashes are strictly redacted.",
    dependencies=[Depends(RateLimiter("export_domain", lambda: settings.RATE_LIMIT_GET_SCAN))]
)
async def export_domain_threat_intelligence(
    domain: str,
    format: ExportFormat = Query(ExportFormat.JSON, description="Export format: json or csv"),
    session: AsyncSession = Depends(get_db_session)
):
    if not domain or "." not in domain:
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid domain syntax: '{domain}'. Domain must contain a valid TLD.",
            error_code="INVALID_DOMAIN"
        )

    items = await ThreatExportService.get_domain_export_items(session, domain)

    if format == ExportFormat.CSV:
        csv_data = ThreatExportService.format_as_csv(items)
        filename = f"trustinel_export_{domain.replace('.', '_')}.csv"
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )

    return ThreatIntelligenceExportResponse(
        format=format,
        exported_at=items[0].scanned_at if items else datetime.now(timezone.utc),
        total_records=len(items),
        items=items
    )
