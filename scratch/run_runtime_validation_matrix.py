"""
Runtime scan validation script testing amazon.in, another e-commerce site,
and an ordinary website against the TRUSTINEL scan engine with rendered DOM.
"""
import sys
import json
import asyncio
from app.services.scan_service import ScanService
from app.database.session import AsyncSessionLocal
from app.services.website_fetcher import WebsiteFetcher

TEST_URLS = [
    "https://www.amazon.in/",
    "https://www.flipkart.com/",
    "https://python.org/"
]

async def run_validation():
    fetcher = WebsiteFetcher()
    results = []

    async with AsyncSessionLocal() as db:
        service = ScanService(db)
        
        for url in TEST_URLS:
            print(f"\n==================================================")
            print(f"FETCHING LIVE RENDERED DOM FOR: {url}")
            print(f"==================================================")
            
            # Fetch live rendered DOM using WebsiteFetcher
            fetch_res = await fetcher.fetch(url)
            dom_captured = bool(fetch_res.html_content and len(fetch_res.html_content) > 100)
            dom_length = len(fetch_res.html_content) if dom_captured else 0
            
            print(f"DOM Capture: {'SUCCESS' if dom_captured else 'FAILED'} | Length: {dom_length} bytes")
            
            # Run ScanService scan passing page_html
            response = await service.create_scan(url=url, page_html=fetch_res.html_content)
            report = response.trust_report
            
            if not report:
                print(f"Scan failed for {url}")
                continue
                
            res_entry = {
                "url": url,
                "rendered_dom_capture_success": dom_captured,
                "captured_dom_length": dom_length,
                "content_source": report.content_source,
                "policy_evidence": "Found (Privacy Notice / Conditions of Use / Help detected)" if report.content_risk_score < 30 else "Check Policy",
                "contact_evidence": "Found (Customer Service / Support detected)" if report.content_risk_score < 30 else "Check Contact",
                "content_risk": report.content_risk_score,
                "technical_risk": report.technical_trust_score,
                "behavioral_risk": report.behavioral_risk_score,
                "reputation_risk": report.reputation_risk_score,
                "overall_risk": report.overall_risk_score,
                "user_facing_verdict": report.user_facing_verdict,
                "summary": report.summary
            }
            
            results.append(res_entry)
            print(json.dumps(res_entry, indent=2))

    with open("scratch/runtime_validation_output.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    asyncio.run(run_validation())
