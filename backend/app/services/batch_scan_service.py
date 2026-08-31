import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Optional

from app.core.url_security import URLSecurityValidator
from app.middleware.exceptions import InvalidURLException, SSRFBlockedException
from app.services.analytics_service import normalize_domain_input
from app.schemas.batch_scan import (
    BatchScanRequest,
    BatchScanResponse,
    DomainBatchItemResult,
)
from app.schemas.reputation import ReputationResult
from app.schemas.phishing import PhishingImpersonationResult
from app.schemas.ssl_deep_inspection import SSLDeepInspectionResult
from app.schemas.header_audit import HeaderAuditResult

from app.analyzers.reputation_analyzer import ReputationAnalyzer
from app.analyzers.phishing_analyzer import PhishingAnalyzer
from app.analyzers.ssl_deep_analyzer import SSLDeepAnalyzer
from app.analyzers.header_deep_analyzer import HeaderDeepAnalyzer
from app.services.threat_cache_service import ThreatCacheService

logger = logging.getLogger("trustinel.services.batch_scan")


class BatchScanService:
    """
    Service executing concurrent, bounded bulk domain threat scans with per-domain SSRF validation,
    threat intelligence caching, and partial success error handling.
    """

    def __init__(self, cache_service: Optional[ThreatCacheService] = None) -> None:
        self.cache_service = cache_service or ThreatCacheService()

    async def _process_single_domain(
        self,
        raw_domain: str,
        request: BatchScanRequest
    ) -> DomainBatchItemResult:
        normalized = normalize_domain_input(raw_domain)

        # 1. Syntax Check
        if not normalized or "." not in normalized:
            return DomainBatchItemResult(
                domain=raw_domain,
                normalized_domain=normalized or raw_domain,
                is_success=False,
                is_cached=False,
                error=f"Invalid domain syntax provided: '{raw_domain}'",
                error_code="INVALID_DOMAIN"
            )

        # 2. SSRF Protection Check
        try:
            resolved_ips = await URLSecurityValidator.validate_hostname_resolution(normalized)
            target_ip = resolved_ips[0] if resolved_ips else None
        except SSRFBlockedException as exc:
            logger.warning(f"[TRUSTINEL Batch SSRF Blocked] Domain '{normalized}': {exc}")
            return DomainBatchItemResult(
                domain=raw_domain,
                normalized_domain=normalized,
                is_success=False,
                is_cached=False,
                error="The requested URL is not allowed.",
                error_code="URL_NOT_ALLOWED"
            )
        except InvalidURLException as exc:
            logger.warning(f"[TRUSTINEL Batch Invalid Domain] Domain '{normalized}': {exc}")
            return DomainBatchItemResult(
                domain=raw_domain,
                normalized_domain=normalized,
                is_success=False,
                is_cached=False,
                error=f"Invalid hostname or host could not be resolved: '{normalized}'",
                error_code="INVALID_DOMAIN"
            )
        except Exception as exc:
            logger.warning(f"[TRUSTINEL Batch Resolution Error] Domain '{normalized}': {exc}")
            return DomainBatchItemResult(
                domain=raw_domain,
                normalized_domain=normalized,
                is_success=False,
                is_cached=False,
                error=f"Failed to resolve host '{normalized}'",
                error_code="DNS_FAILURE"
            )

        # 3. Threat Cache Check & Analyzer Execution
        rep_res: Optional[ReputationResult] = None
        phish_res: Optional[PhishingImpersonationResult] = None
        ssl_res: Optional[SSLDeepInspectionResult] = None
        header_res: Optional[HeaderAuditResult] = None

        cache_hits = 0
        requested_module_count = sum([
            request.include_reputation,
            request.include_phishing,
            request.include_ssl,
            request.include_headers
        ])

        # Reputation Module
        if request.include_reputation:
            cached_rep = None if request.bypass_cache else await self.cache_service.get_module_result("reputation", normalized)
            if cached_rep:
                try:
                    rep_res = ReputationResult.model_validate(cached_rep)
                    cache_hits += 1
                except Exception:
                    cached_rep = None

            if rep_res is None:
                rep_analyzer = ReputationAnalyzer()
                rep_res = await rep_analyzer.analyze_domain(normalized)
                await self.cache_service.set_module_result("reputation", normalized, rep_res.model_dump())

        # Phishing Module
        if request.include_phishing:
            cached_phish = None if request.bypass_cache else await self.cache_service.get_module_result("phishing", normalized)
            if cached_phish:
                try:
                    phish_res = PhishingImpersonationResult.model_validate(cached_phish)
                    cache_hits += 1
                except Exception:
                    cached_phish = None

            if phish_res is None:
                phish_analyzer = PhishingAnalyzer()
                phish_res = await phish_analyzer.analyze_domain(normalized)
                await self.cache_service.set_module_result("phishing", normalized, phish_res.model_dump())

        # SSL Deep Inspection Module
        if request.include_ssl:
            cached_ssl = None if request.bypass_cache else await self.cache_service.get_module_result("ssl", normalized)
            if cached_ssl:
                try:
                    ssl_res = SSLDeepInspectionResult.model_validate(cached_ssl)
                    cache_hits += 1
                except Exception:
                    cached_ssl = None

            if ssl_res is None:
                ssl_analyzer = SSLDeepAnalyzer()
                ssl_res = await ssl_analyzer.inspect_domain(normalized, ip_address=target_ip)
                await self.cache_service.set_module_result("ssl", normalized, ssl_res.model_dump())

        # Header Audit Module
        if request.include_headers:
            cached_headers = None if request.bypass_cache else await self.cache_service.get_module_result("headers", normalized)
            if cached_headers:
                try:
                    header_res = HeaderAuditResult.model_validate(cached_headers)
                    cache_hits += 1
                except Exception:
                    cached_headers = None

            if header_res is None:
                header_analyzer = HeaderDeepAnalyzer()
                header_res = await header_analyzer.audit_domain(normalized)
                await self.cache_service.set_module_result("headers", normalized, header_res.model_dump())

        is_fully_cached = (cache_hits == requested_module_count and requested_module_count > 0)

        return DomainBatchItemResult(
            domain=raw_domain,
            normalized_domain=normalized,
            is_success=True,
            is_cached=is_fully_cached,
            reputation=rep_res,
            phishing=phish_res,
            ssl_inspection=ssl_res,
            header_audit=header_res
        )

    async def execute_batch(self, request: BatchScanRequest) -> BatchScanResponse:
        # Bounded concurrency: asyncio.gather bounded strictly to max 20 requested domains
        tasks = [self._process_single_domain(domain, request) for domain in request.domains[:20]]
        results: List[DomainBatchItemResult] = await asyncio.gather(*tasks)

        successful_count = sum(1 for r in results if r.is_success)
        failed_count = sum(1 for r in results if not r.is_success)
        cache_hit_count = sum(1 for r in results if r.is_cached)

        return BatchScanResponse(
            total_requested=len(results),
            successful_count=successful_count,
            failed_count=failed_count,
            cache_hit_count=cache_hit_count,
            results=results,
            processed_at=datetime.now(timezone.utc)
        )
