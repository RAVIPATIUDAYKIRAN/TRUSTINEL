import uuid
import logging
import asyncio
from typing import Optional
from urllib.parse import urlparse
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.website_scan import WebsiteScan
from app.models.enums import ScanStatus
from app.repositories.website_scan_repository import WebsiteScanRepository
from app.repositories.trust_report_repository import TrustReportRepository
from app.repositories.scan_history_repository import ScanHistoryRepository
from app.services.website_fetcher import WebsiteFetcher
from app.analyzers.ssl_analyzer import SSLAnalyzer
from app.analyzers.whois_analyzer import WHOISAnalyzer
from app.analyzers.header_analyzer import HeaderAnalyzer
from app.analyzers.redirect_analyzer import RedirectAnalyzer
from app.analyzers.content_analyzer import ContentAnalyzer
from app.services.content_extractor import ContentExtractor
from app.services.threat_intelligence_service import ThreatIntelligenceService
from app.services.risk_aggregation_engine import RiskAggregationEngine
from app.services.rule_based_trust_engine import RuleBasedTrustEngine
from app.services.risk_explanation_service import RiskExplanationService
from app.services.ai_threat_analysis_service import AIThreatAnalysisService
from app.core.url_security import URLSecurityValidator

logger = logging.getLogger("trustinel.services.scan_service")


class ScanService:
    """
    Service class responsible for orchestrating the complete website scan workflow
    using real intelligence analyzers, content scam analysis, threat intelligence,
    multi-dimensional risk aggregation, AI threat analysis, and managing database
    transaction lifecycles.
    """
    def __init__(
        self,
        session: AsyncSession,
        scan_repo: WebsiteScanRepository,
        report_repo: TrustReportRepository,
        history_repo: ScanHistoryRepository,
        fetcher: Optional[WebsiteFetcher] = None,
        ssl_analyzer: Optional[SSLAnalyzer] = None,
        whois_analyzer: Optional[WHOISAnalyzer] = None,
        header_analyzer: Optional[HeaderAnalyzer] = None,
        redirect_analyzer: Optional[RedirectAnalyzer] = None,
        trust_engine: Optional[RuleBasedTrustEngine] = None,
        explanation_service: Optional[RiskExplanationService] = None,
        ai_threat_service: Optional[AIThreatAnalysisService] = None,
        content_analyzer: Optional[ContentAnalyzer] = None,
        threat_intel_service: Optional[ThreatIntelligenceService] = None,
        risk_aggregator: Optional[RiskAggregationEngine] = None,
    ) -> None:
        self.session = session
        self.scan_repo = scan_repo
        self.report_repo = report_repo
        self.history_repo = history_repo
        self.fetcher = fetcher or WebsiteFetcher()
        self.ssl_analyzer = ssl_analyzer or SSLAnalyzer()
        self.whois_analyzer = whois_analyzer or WHOISAnalyzer()
        self.header_analyzer = header_analyzer or HeaderAnalyzer()
        self.redirect_analyzer = redirect_analyzer or RedirectAnalyzer()
        self.trust_engine = trust_engine or RuleBasedTrustEngine()
        self.explanation_service = explanation_service or RiskExplanationService()
        self.ai_threat_service = ai_threat_service or AIThreatAnalysisService()
        self.content_analyzer = content_analyzer or ContentAnalyzer()
        self.threat_intel_service = threat_intel_service or ThreatIntelligenceService()
        self.risk_aggregator = risk_aggregator or RiskAggregationEngine()

    async def create_scan(self, url: str, page_html: Optional[str] = None) -> WebsiteScan:
        """
        Orchestrates the transactional sequence of creating a scan,
        running technical & content analyzers, computing multi-dimensional
        scam risk, generating an explanation, running AI threat analysis,
        persisting results, and completing the scan.
        """
        # 1. Normalize the URL and validate syntax FIRST (zero DB records created for invalid URLs)
        normalized_url = URLSecurityValidator.validate_url_syntax(url)

        # 2. Extract and validate domain / DNS SSRF security BEFORE database transaction
        parsed_url = urlparse(normalized_url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        if not domain:
            domain = normalized_url
        await URLSecurityValidator.validate_hostname_resolution(domain)

        logger.info(f"Scan started for domain: {domain}", extra={"event": "scan_started", "domain": domain})

        scan: Optional[WebsiteScan] = None

        try:
            # 3. Create a WebsiteScan record with status=PENDING
            scan = await self.scan_repo.create_scan(
                url=normalized_url,
                domain=domain,
                status=ScanStatus.PENDING
            )

            # 4. Record SCAN_INITIATED history
            await self.history_repo.create_history(
                scan_id=scan.id,
                action="SCAN_INITIATED",
                status="SUCCESS"
            )

            # 5. Fetch the website
            logger.info(f"Scan fetch started for domain: {domain}", extra={"event": "scan_fetch_started", "domain": domain})
            fetch_result = await self.fetcher.fetch(normalized_url)
            logger.info(
                f"Scan fetch completed for domain: {domain}",
                extra={
                    "event": "scan_fetch_completed",
                    "domain": domain,
                    "status_code": fetch_result.status_code,
                    "duration_ms": fetch_result.response_time_ms
                }
            )

            # 6. Run technical analyzers & threat intelligence concurrently — structured errors, never crash
            ssl_result, whois_result, header_result, redirect_result, reputation_result = await asyncio.gather(
                self.ssl_analyzer.analyze(fetch_result),
                self.whois_analyzer.analyze(fetch_result),
                self.header_analyzer.analyze(fetch_result),
                self.redirect_analyzer.analyze(fetch_result),
                self.threat_intel_service.get_reputation(domain)
            )

            # 6.5 Safely extract and analyze website content scam indicators
            # Use client-rendered DOM HTML if provided by Chrome extension; fall back to server fetch
            html_to_analyze = page_html if (page_html and isinstance(page_html, str) and page_html.strip()) else fetch_result.html_content
            extracted_evidence = ContentExtractor.extract(html_to_analyze, normalized_url)
            content_result = self.content_analyzer.analyze(extracted_evidence)

            # 7. Compute deterministic technical trust evaluation (RuleBasedTrustEngine preserved untouched)
            trust_evaluation = self.trust_engine.evaluate(
                ssl_result=ssl_result,
                whois_result=whois_result,
                header_result=header_result,
                redirect_result=redirect_result
            )

            # 7.5 Compute Multi-Dimensional Scam Risk
            multi_risk = self.risk_aggregator.aggregate(
                trust_evaluation=trust_evaluation,
                content_result=content_result,
                whois_result=whois_result,
                reputation_result=reputation_result
            )

            # 8. Generate risk explanation (deterministic fallback if AI disabled or error)
            try:
                risk_explanation = await self.explanation_service.explain(
                    trust_evaluation=trust_evaluation,
                    ssl_result=ssl_result,
                    whois_result=whois_result,
                    header_result=header_result,
                    redirect_result=redirect_result
                )
            except Exception as exc:
                logger.warning(f"[TRUSTINEL] Risk explanation service exception: {exc}. Using fallback.")
                risk_explanation = RiskExplanationService._get_fallback_explanation(trust_evaluation)

            # 8.5 Run AI threat analysis (uses structured evidence payload)
            try:
                ai_threat = await self.ai_threat_service.analyze(
                    trust_evaluation=trust_evaluation,
                    ssl_result=ssl_result,
                    whois_result=whois_result,
                    header_result=header_result,
                    redirect_result=redirect_result,
                    content_result=content_result,
                    reputation_result=reputation_result,
                    multi_risk=multi_risk,
                    domain=domain
                )
            except Exception as exc:
                logger.warning(f"AI threat analysis service exception: {exc}. Using fallback.")
                ai_threat = AIThreatAnalysisService._get_fallback(
                    trust_evaluation,
                    reason_text=f"AI provider request failed: {exc}"
                )

            logger.info(
                f"[TRUSTINEL] Multi-Dimensional Analysis complete for {domain}. "
                f"TechScore={trust_evaluation.trust_score}, ContentRisk={content_result.content_risk_score}, "
                f"OverallScamRisk={multi_risk.overall_risk_score} ({multi_risk.overall_risk_level.value})"
            )

            # Combine key risks with structured content risk factors
            combined_key_risks = list(set((risk_explanation.key_risks or []) + multi_risk.risk_factors))

            # 9. Persist TrustReport with deterministic scores + explanation + multi-dimensional risk scores
            report = await self.report_repo.create_report(
                scan_id=scan.id,
                trust_score=trust_evaluation.trust_score,
                risk_level=trust_evaluation.risk_level,
                summary=multi_risk.summary,
                explanation=risk_explanation.explanation,
                key_risks=combined_key_risks,
                positive_signals=risk_explanation.positive_signals,
                recommendation=risk_explanation.recommendation,
                technical_trust_score=multi_risk.technical_trust_score,
                content_risk_score=multi_risk.content_risk_score,
                reputation_risk_score=multi_risk.reputation_risk_score,
                behavioral_risk_score=multi_risk.behavioral_risk_score,
                overall_risk_score=multi_risk.overall_risk_score,
                overall_risk_level=multi_risk.overall_risk_level,
                risk_factors=multi_risk.risk_factors
            )
            if isinstance(getattr(report, "trust_score", None), int):
                scan.trust_report = report

            # 10. Record SCAN_COMPLETED history
            await self.history_repo.create_history(
                scan_id=scan.id,
                action="SCAN_COMPLETED",
                status="SUCCESS"
            )

            # 11. Update WebsiteScan status to COMPLETED
            await self.scan_repo.update_scan_status(
                scan_id=scan.id,
                status=ScanStatus.COMPLETED
            )

            # 12. Commit the single transaction once
            await self.session.commit()

            # 13. Fetch refreshed scan with eager-loaded trust_report (or fallback to scan for unit tests)
            refreshed_scan = await self.scan_repo.get_scan_by_id(scan.id)
            final_scan = refreshed_scan if refreshed_scan is not None else scan

            if final_scan and final_scan.trust_report:
                object.__setattr__(final_scan.trust_report, "ai_threat_analysis", ai_threat)

            logger.info(
                f"Scan completed for domain: {domain}",
                extra={
                    "event": "scan_completed",
                    "scan_id": str(scan.id),
                    "domain": domain,
                    "trust_score": trust_evaluation.trust_score,
                    "risk_level": trust_evaluation.risk_level,
                    "ai_enabled": ai_threat.enabled
                }
            )

            return final_scan

        except Exception as exc:
            logger.error(
                f"Scan failed for domain: {domain}",
                extra={
                    "event": "scan_failed",
                    "scan_id": str(scan.id) if scan else None,
                    "domain": domain,
                    "error_class": exc.__class__.__name__
                }
            )
            # Rollback transaction on unexpected failures
            await self.session.rollback()
            # Attempt to record FAILED status for scan if record was created
            if scan is not None and hasattr(scan, "id"):
                try:
                    await self.scan_repo.update_scan_status(scan.id, ScanStatus.FAILED)
                    await self.session.commit()
                except Exception as status_exc:
                    logger.warning(f"[TRUSTINEL] Could not persist FAILED status for scan {scan.id}: {status_exc}")
                    await self.session.rollback()
            raise

    async def get_scan(self, scan_id: uuid.UUID) -> Optional[WebsiteScan]:
        """
        Retrieve scan details together with its trust report.
        Does NOT execute any analyzers or regenerate the trust score.
        """
        return await self.scan_repo.get_scan_by_id(scan_id)
