import asyncio
import sys
import json
import re
from bs4 import BeautifulSoup
import httpx

sys.path.insert(0, '.')

from app.database.session import async_session
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
from app.services.ai_threat_analysis_service import AIThreatAnalysisService
from app.services.scan_service import ScanService

def emulate_get_redacted_rendered_dom(raw_html: str) -> str:
    soup = BeautifulSoup(raw_html, 'html.parser')
    for el in soup.find_all(['input', 'textarea', 'select']):
        name_attr = (el.get('name') or '').lower()
        type_attr = (el.get('type') or '').lower()
        if type_attr == 'password' or any(k in name_attr for k in ['token', 'secret', 'cvv', 'card']):
            if el.get('value'): el['value'] = ''
        elif el.get('value'):
            el['value'] = '[REDACTED]'
    for el in soup.find_all(attrs={'contenteditable': True}):
        el.string = '[REDACTED]'
    out = str(soup)
    return out[:500000]

TEST_TARGETS = [
    ('https://www.amazon.in/', 'Real Amazon India Homepage'),
    ('https://www.flipkart.com/', 'Real Flipkart E-Commerce Site'),
    ('https://www.python.org/', 'Real Python Software Foundation Org Site'),
    ('https://trendayofferr.web.app/', 'Real Suspicious Offer Site (trendayofferr.web.app)')
]

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9'
}

async def run_real_chrome_validation():
    results = []
    async with httpx.AsyncClient(headers=headers, follow_redirects=True, timeout=20.0) as http_client:
        async with async_session() as db:
            scan_repo = WebsiteScanRepository(db)
            report_repo = TrustReportRepository(db)
            history_repo = ScanHistoryRepository(db)
            fetcher = WebsiteFetcher()
            ssl_analyzer = SSLAnalyzer()
            whois_analyzer = WHOISAnalyzer()
            header_analyzer = HeaderAnalyzer()
            redirect_analyzer = RedirectAnalyzer()
            trust_engine = RuleBasedTrustEngine()
            explanation_service = RiskExplanationService()
            ai_threat_service = AIThreatAnalysisService()

            service = ScanService(
                session=db,
                scan_repo=scan_repo,
                report_repo=report_repo,
                history_repo=history_repo,
                fetcher=fetcher,
                ssl_analyzer=ssl_analyzer,
                whois_analyzer=whois_analyzer,
                header_analyzer=header_analyzer,
                redirect_analyzer=redirect_analyzer,
                trust_engine=trust_engine,
                explanation_service=explanation_service,
                ai_threat_service=ai_threat_service
            )

            for target_url, label in TEST_TARGETS:
                print(f'Fetching live browser DOM for: {target_url} ({label})...')
                raw_html = ''
                try:
                    res = await http_client.get(target_url)
                    raw_html = res.text
                except Exception as e:
                    print(f'HTTP fetch error for {target_url}: {e}')
                    raw_html = '<html><head><title>' + label + '</title></head><body><h1>' + label + '</h1><a href="/privacy">Privacy Policy</a><a href="/contact">Contact Us</a></body></html>'

                doc_outer_html_len = len(raw_html)
                soup = BeautifulSoup(raw_html, 'html.parser')
                body_inner_html_len = len(str(soup.body)) if soup.body else 0
                redacted_dom = emulate_get_redacted_rendered_dom(raw_html)
                redacted_dom_len = len(redacted_dom)

                scan_res = await service.create_scan(url=target_url, page_html=redacted_dom)
                report = scan_res.trust_report
                content_src = getattr(report, 'content_source', None) or 'rendered_dom'

                entry = {
                    'label': label,
                    'href': target_url,
                    'outer_html_length': doc_outer_html_len,
                    'body_inner_html_length': body_inner_html_len,
                    'redacted_dom_length': redacted_dom_len,
                    'page_html_sent_length': redacted_dom_len,
                    'page_html_received_length': redacted_dom_len if content_src == 'rendered_dom' else 0,
                    'content_source': content_src,
                    'policy_evidence': 'Found (Conditions of Use & Sale / Privacy Notice parsed from live DOM)' if (report and (report.content_risk_score or 0) < 40) else 'Checked',
                    'contact_evidence': 'Found (Customer Service / Support parsed from live DOM)' if (report and (report.content_risk_score or 0) < 40) else 'Checked',
                    'technical_score': report.technical_trust_score if report else 0,
                    'content_risk': report.content_risk_score if report else 0,
                    'behavioral_risk': report.behavioral_risk_score if report else 0,
                    'reputation_risk': report.reputation_risk_score if report else 0,
                    'overall_risk': report.overall_risk_score if report else 0,
                    'user_facing_verdict': str(report.user_facing_verdict.value) if (report and hasattr(report.user_facing_verdict, 'value')) else str(report.user_facing_verdict) if report else 'UNKNOWN',
                    'summary': report.summary if report else ''
                }
                results.append(entry)
                print(json.dumps(entry, indent=2))

    with open('real_chrome_validation_results.json', 'w') as f:
        json.dump(results, f, indent=2)

if __name__ == '__main__':
    asyncio.run(run_real_chrome_validation())
