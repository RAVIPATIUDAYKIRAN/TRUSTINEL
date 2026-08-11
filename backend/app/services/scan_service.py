import uuid
import logging
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
from app.services.rule_based_trust_engine import RuleBasedTrustEngine
from app.services.risk_explanation_service import RiskExplanationService

logger = logging.getLogger("trustinel.services.scan_service")


class ScanService:
    """
    Service class responsible for orchestrating the complete website scan workflow
    using real intelligence analyzers and managing database transaction lifecycles.
    """
    def __init__(
        self,
        session: AsyncSession,
        scan_repo: WebsiteScanRepository,
        report_repo: TrustReportRepository,
        history_repo: ScanHistoryRepository,
        fetcher: WebsiteFetcher,
        ssl_analyzer: SSLAnalyzer,
        whois_analyzer: WHOISAnalyzer,
        header_analyzer: HeaderAnalyzer,
        redirect_analyzer: RedirectAnalyzer,
        trust_engine: RuleBasedTrustEngine,
        explanation_service: RiskExplanationService,
    ) -> None:
        self.session = session
        self.scan_repo = scan_repo
        self.report_repo = report_repo
        self.history_repo = history_repo
        self.fetcher = fetcher
        self.ssl_analyzer = ssl_analyzer
        self.whois_analyzer = whois_analyzer
        self.header_analyzer = header_analyzer
        self.redirect_analyzer = redirect_analyzer
        self.trust_engine = trust_engine
        self.explanation_service = explanation_service

    async def create_scan(self, url: str) -> WebsiteScan:
        """
        Orchestrates the transactional sequence of creating a scan,
        running real analyzers, computing a trust score, generating
        an explanation, persisting results, and completing the scan.
        """
        # 1. Normalize the URL
        normalized_url = url.strip()

        # 2. Extract the domain
        parsed_url = urlparse(normalized_url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        if not domain:
            domain = normalized_url

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
            fetch_result = await self.fetcher.fetch(normalized_url)

            # 6. Run all analyzers independently — structured errors, never crash
            ssl_result = await self.ssl_analyzer.analyze(fetch_result)
            whois_result = await self.whois_analyzer.analyze(fetch_result)
            header_result = await self.header_analyzer.analyze(fetch_result)
            redirect_result = await self.redirect_analyzer.analyze(fetch_result)

            # 7. Compute deterministic trust evaluation
            trust_evaluation = self.trust_engine.evaluate(
                ssl_result=ssl_result,
                whois_result=whois_result,
                header_result=header_result,
                redirect_result=redirect_result
            )

            # 8. Generate risk explanation (deterministic fallback if AI disabled)
            risk_explanation = await self.explanation_service.explain(
                trust_evaluation=trust_evaluation,
                ssl_result=ssl_result,
                whois_result=whois_result,
                header_result=header_result,
                redirect_result=redirect_result
            )

            # 9. Persist TrustReport with deterministic score + explanation
            await self.report_repo.create_report(
                scan_id=scan.id,
                trust_score=trust_evaluation.trust_score,
                risk_level=trust_evaluation.risk_level,
                summary=trust_evaluation.summary,
                explanation=risk_explanation.explanation,
                key_risks=risk_explanation.key_risks,
                positive_signals=risk_explanation.positive_signals,
                recommendation=risk_explanation.recommendation
            )

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

            # 12. Commit the transaction once
            await self.session.commit()

            # 13. Load scan with eager-loaded trust_report
            refreshed_scan = await self.scan_repo.get_scan_by_id(scan.id)
            return refreshed_scan

        except Exception:
            # Rollback transaction on unexpected failures and propagate the error
            await self.session.rollback()
            raise

    async def get_scan(self, scan_id: uuid.UUID) -> Optional[WebsiteScan]:
        """
        Retrieve scan details together with its trust report.
        Does NOT execute any analyzers or regenerate the trust score.
        """
        return await self.scan_repo.get_scan_by_id(scan_id)
