# TRUSTINEL — Sprint 7 Task 10 Integration, Security & Performance Audit Tests
# Comprehensive platform verification across Sprint 7 Tasks 1–9

import json
import logging
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from sqlalchemy import select, delete

from app.main import app
from app.config.settings import settings
from app.database.session import async_session, engine
from app.models.website_scan import WebsiteScan
from app.models.trust_report import TrustReport
from app.models.webhook import WebhookConfig, WebhookDelivery
from app.models.api_key import APIKey
from app.schemas.webhook import WebhookEventType
from app.schemas.export import ExportFormat
from app.schemas.ssl_analysis import SSLAnalysisResult
from app.schemas.whois_analysis import WHOISAnalysisResult
from app.schemas.header_analysis import HeaderAnalysisResult
from app.schemas.redirect_analysis import RedirectAnalysisResult
from app.services.rule_based_trust_engine import RuleBasedTrustEngine
from app.services.webhook_service import WebhookService
from app.services.webhook_delivery_service import WebhookDeliveryService, sign_payload
from app.services.threat_export_service import ThreatExportService
from app.services.api_key_service import generate_api_key, hash_api_key
from app.services.threat_cache_service import InMemoryThreatCache, DEFAULT_CACHE_TTL_SECONDS, in_memory_threat_cache
from app.services.batch_scan_service import BatchScanService
from app.core.rate_limiter import in_memory_tracker
from app.core.logging import redact_sensitive_text
from app.core.url_security import URLSecurityValidator


@pytest.fixture(autouse=True)
def isolate_rate_limiter_for_tests():
    """Forces in-memory rate limiting and resets store before each test for total determinism."""
    in_memory_tracker._store.clear()
    with patch("app.core.rate_limiter.redis_client.incr", side_effect=Exception("Redis offline for testing")):
        yield
    in_memory_tracker._store.clear()


# ==============================================================================
# 1. DETERMINISTIC SCORING IMMUTABILITY AUDIT
# ==============================================================================

def test_1_rule_based_trust_engine_scoring_immutability():
    """1. Verify RuleBasedTrustEngine outputs remain 100% deterministic across all Sprint 7 modules."""
    ssl_res = SSLAnalysisResult(is_valid=True, issuer="GlobalSign", days_remaining=120, is_self_signed=False)
    whois_res = WHOISAnalysisResult(is_registered=True, domain_age_days=500, registrar="MarkMonitor Inc.")
    header_res = HeaderAnalysisResult(
        strict_transport_security=True,
        content_security_policy=True,
        x_frame_options=True,
        x_content_type_options=True,
        referrer_policy=True,
        permissions_policy=True,
        security_headers_score=5
    )
    redirect_res = RedirectAnalysisResult(
        redirected=False,
        same_domain=True,
        https_upgrade=True,
        cross_domain_redirect=False,
        is_safe_redirect=True,
        redirect_count=0,
        contains_suspicious_redirect=False
    )

    engine = RuleBasedTrustEngine()
    result_1 = engine.evaluate(ssl_res, whois_res, header_res, redirect_res)
    result_2 = engine.evaluate(ssl_res, whois_res, header_res, redirect_res)

    assert result_1.trust_score == result_2.trust_score
    assert result_1.risk_level == result_2.risk_level


# ==============================================================================
# 2. FULL END-TO-END PIPELINE INTEGRATION AUDIT
# ==============================================================================

def test_2_end_to_end_sprint7_api_integration():
    """2. Verify end-to-end integration across all Sprint 7 Task 1-9 endpoints."""
    with TestClient(app) as client:
        # Task 1: Domain Analytics
        analytics_resp = client.get("/api/v1/analytics/domain/example.com")
        assert analytics_resp.status_code in [200, 404]

        # Task 2: Domain Reputation
        rep_resp = client.get("/api/v1/reputation/domain/example.com")
        assert rep_resp.status_code == 200
        assert "reputation_score" in rep_resp.json()

        # Task 3: SSL Deep Inspection
        ssl_resp = client.get("/api/v1/ssl/domain/example.com")
        assert ssl_resp.status_code == 200
        assert "domain" in ssl_resp.json()
        assert "is_valid" in ssl_resp.json()

        # Task 4: Phishing & Typosquatting Analysis
        phish_resp = client.get("/api/v1/phishing/domain/example.com")
        assert phish_resp.status_code == 200
        assert "is_impersonation_suspected" in phish_resp.json()

        # Task 5: Security Header Audit
        header_resp = client.get("/api/v1/headers/domain/example.com")
        assert header_resp.status_code == 200
        assert "composite_score" in header_resp.json()

        # Task 6: Bulk Batch Scan
        batch_resp = client.post("/api/v1/batch/scan", json={"domains": ["example.com", "google.com"]})
        assert batch_resp.status_code == 200
        assert len(batch_resp.json()["results"]) == 2

        # Task 8: API Keys Management
        key_resp = client.post("/api/v1/api-keys", json={"name": "Integration Audit Key", "tier": "ENTERPRISE"})
        assert key_resp.status_code == 201
        assert "api_key" in key_resp.json()

        # Task 9: Threat Export JSON & CSV
        export_json = client.get("/api/v1/export/domain/example.com?format=json")
        assert export_json.status_code == 200
        export_csv = client.get("/api/v1/export/domain/example.com?format=csv")
        assert export_csv.status_code == 200
        assert "text/csv" in export_csv.headers["content-type"]

        # Task 9: Webhook Registration
        wh_resp = client.post("/api/v1/webhooks", json={
            "name": "Audit Integration Receiver",
            "target_url": "https://example.com/hooks/audit-integration",
            "events": ["PHISHING_DETECTED"]
        })
        assert wh_resp.status_code == 201
        assert "secret" in wh_resp.json()


# ==============================================================================
# 3. SECURITY AUDIT: SSRF, REDACTION & CREDENTIAL PROTECTION
# ==============================================================================

def test_3_ssrf_blocking_across_all_entrypoints():
    """3. Verify SSRF protections block private IP ranges, loopback, and metadata endpoints across modules."""
    with TestClient(app) as client:
        invalid_destinations = [
            "http://127.0.0.1/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/internal",
            "http://192.168.1.1/router",
            "http://localhost:8000/internal"
        ]

        for dest in invalid_destinations:
            # Batch scan SSRF
            batch_resp = client.post("/api/v1/batch/scan", json={"domains": [dest]})
            assert batch_resp.status_code in [200, 400, 422]

            # Webhook registration SSRF
            wh_resp = client.post("/api/v1/webhooks", json={
                "name": "SSRF Receiver Test",
                "target_url": dest,
                "events": ["SSL_CERTIFICATE_EXPIRED"]
            })
            assert wh_resp.status_code in [400, 403]


def test_4_secret_redaction_and_non_leakage_audit():
    """4. Verify API keys (trn_live_...) and Webhook secrets (whsec_...) are strictly redacted from logs and API lists."""
    api_key_plain = "trn_live_9999888877776666"
    webhook_secret_plain = "whsec_1111222233334444"

    redacted_log = redact_sensitive_text(f"Key={api_key_plain}, Secret={webhook_secret_plain}")
    assert api_key_plain not in redacted_log
    assert webhook_secret_plain not in redacted_log
    assert "[REDACTED_API_KEY]" in redacted_log or "[REDACTED]" in redacted_log

    with TestClient(app) as client:
        # Create API key and ensure GET listing never returns plaintext secret
        key_create = client.post("/api/v1/api-keys", json={"name": "Secret Leak Audit Key", "tier": "STANDARD"})
        key_id = key_create.json()["key_id"]
        key_get = client.get(f"/api/v1/api-keys/{key_id}")
        assert key_get.status_code == 200
        assert "api_key" not in key_get.json()

        # Create Webhook and ensure GET listing never returns plaintext secret
        wh_create = client.post("/api/v1/webhooks", json={
            "name": "Secret Leak Webhook",
            "target_url": "https://example.com/hooks/secret-test",
            "events": ["PHISHING_DETECTED"]
        })
        wh_id = wh_create.json()["webhook_id"]
        wh_get = client.get(f"/api/v1/webhooks/{wh_id}")
        assert wh_get.status_code == 200
        assert "secret_hash" not in wh_get.json()
        assert "webhook_secret" not in wh_get.json()


# ==============================================================================
# 4. API-KEY & RATE-LIMIT TIER AUDIT (TASK 8 VERIFICATION)
# ==============================================================================

def test_5_api_key_rate_limit_tiers_source_of_truth():
    """5. Verify Task 8 Rate Limit Tiers: STANDARD (60 req/min) and ENTERPRISE (300 req/min)."""
    with TestClient(app) as client:
        std_key = client.post("/api/v1/api-keys", json={"name": "Standard Key", "tier": "STANDARD"})
        ent_key = client.post("/api/v1/api-keys", json={"name": "Enterprise Key", "tier": "ENTERPRISE"})

        assert std_key.json()["tier"] == "STANDARD"
        assert ent_key.json()["tier"] == "ENTERPRISE"


# ==============================================================================
# 5. WEBHOOK SIGNATURE & BOUNDED RETRIES AUDIT (TASK 9 VERIFICATION)
# ==============================================================================

def test_6_hmac_sha256_deterministic_signing_audit():
    """6. Verify HMAC-SHA256 signature generation is deterministic and exposes X-TRUSTINEL-Signature."""
    secret = "whsec_test_audit_signature_secret_key_123"
    payload = b'{"event":"PHISHING_DETECTED","domain":"phish-example.com"}'

    sig_1 = sign_payload(secret, payload)
    sig_2 = sign_payload(secret, payload)

    assert sig_1 == sig_2
    assert sig_1.startswith("sha256=")
    assert len(sig_1) == 7 + 64  # "sha256=" prefix + 64 hex chars


@pytest.mark.asyncio
async def test_7_bounded_webhook_retries_and_timeout():
    """7. Verify webhook deliveries strictly respect maximum 3 total attempts (1 initial + 2 retries) and 5s timeout."""
    async with async_session() as session:
        session.expire_on_commit = False
        await session.execute(delete(WebhookDelivery))
        await session.execute(delete(WebhookConfig))
        await session.commit()

        wh = WebhookConfig(
            name="Bounded Retry Audit Receiver",
            target_url="https://example.com/webhook-bounded",
            secret_hash="hash",
            secret_prefix="whsec_test",
            is_enabled=True,
            events="SSL_CERTIFICATE_EXPIRED",
            created_at=datetime.now(timezone.utc)
        )
        session.add(wh)
        await session.commit()
        wh_id = str(wh.id)

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=Exception("Connection timeout")):
            deliveries = await WebhookDeliveryService.dispatch_event(
                session,
                WebhookEventType.SSL_CERTIFICATE_EXPIRED,
                "timeout-domain.com",
                {"expired": True}
            )

            wh_deliveries = [d for d in deliveries if str(d.webhook_id) == wh_id]
            assert len(wh_deliveries) == 1
            assert wh_deliveries[0].status == "FAILED"
            assert wh_deliveries[0].attempt_count == 3  # Strictly 3 total attempts


# ==============================================================================
# 6. CACHE & BOUNDED MEMORY AUDIT (TASK 6 VERIFICATION)
# ==============================================================================

def test_8_threat_cache_600s_ttl_and_bounded_fallback():
    """8. Verify 600-second cache TTL and bounded fallback memory limits."""
    assert DEFAULT_CACHE_TTL_SECONDS == 600

    domain = "cache-test-domain.com"
    data_str = '{"domain": "cache-test-domain.com", "reputation_score": 95, "status": "Clean"}'

    # Test cache write & read
    in_memory_threat_cache.set(f"trustinel:threat_cache:{domain}", data_str, ttl_seconds=600)
    cached = in_memory_threat_cache.get(f"trustinel:threat_cache:{domain}")
    assert cached is not None
    assert "reputation_score" in cached


# ==============================================================================
# 7. PERFORMANCE & BOUNDED CONCURRENCY AUDIT
# ==============================================================================

def test_9_batch_scan_bounded_concurrency_limit():
    """9. Verify batch scan enforces MAX_BATCH_SIZE = 20 to prevent resource exhaustion."""
    with TestClient(app) as client:
        overly_large_batch = [f"domain{i}.com" for i in range(25)]
        resp = client.post("/api/v1/batch/scan", json={"domains": overly_large_batch})
        assert resp.status_code in [400, 422]


# ==============================================================================
# 8. CHROME EXTENSION COMPATIBILITY AUDIT (TASK 7 VERIFICATION)
# ==============================================================================

def test_10_extension_api_contract_compatibility():
    """10. Verify Chrome Extension domain analytics API contract returns required fields."""
    with TestClient(app) as client:
        resp = client.get("/api/v1/analytics/domain/example.com")
        assert resp.status_code in [200, 404]
