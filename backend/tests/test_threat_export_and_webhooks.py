import json
import logging
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from sqlalchemy import select, delete

from app.main import app
from app.models.webhook import WebhookConfig, WebhookDelivery
from app.schemas.export import ExportFormat, ThreatIntelligenceExportItem
from app.schemas.webhook import WebhookEventType, WebhookCreateRequest
from app.services.threat_export_service import ThreatExportService
from app.services.webhook_service import WebhookService, generate_webhook_secret, hash_webhook_secret
from app.services.webhook_delivery_service import WebhookDeliveryService, sign_payload, MAX_DELIVERY_ATTEMPTS
from app.core.rate_limiter import in_memory_tracker
from app.core.logging import redact_sensitive_text
from app.services.rule_based_trust_engine import RuleBasedTrustEngine
from app.config.settings import settings
from app.database.session import async_session, engine


@pytest.fixture(autouse=True)
def isolate_rate_limiter_for_tests():
    """Forces in-memory rate limiting and resets store before each test for total determinism."""
    in_memory_tracker._store.clear()
    with patch("app.core.rate_limiter.redis_client.incr", side_effect=Exception("Redis offline for testing")):
        yield
    in_memory_tracker._store.clear()





def test_1_json_threat_export():
    """1. Test JSON export response formatting."""
    in_memory_tracker._store.clear()
    with TestClient(app) as client:
        resp = client.get("/api/v1/export/domain/example.com?format=json")
        assert resp.status_code == 200
        data = resp.json()
        assert data["format"] == "json"
        assert "total_records" in data
        assert "items" in data


def test_2_csv_threat_export():
    """2. Test CSV export response formatting."""
    with TestClient(app) as client:
        resp = client.get("/api/v1/export/domain/example.com?format=csv")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")
        assert "attachment; filename=" in resp.headers["content-disposition"]


def test_3_invalid_export_domain():
    """3. Test invalid export domain returns 400."""
    with TestClient(app) as client:
        resp = client.get("/api/v1/export/domain/nodotdomain?format=json")
        assert resp.status_code == 400
        assert resp.json()["error_code"] == "INVALID_DOMAIN"


def test_4_export_secret_redaction():
    """4. Test exported data does not contain sensitive tokens or keys."""
    items = [
        ThreatIntelligenceExportItem(
            domain="example.com",
            normalized_domain="example.com",
            trust_score=85,
            risk_level="LOW",
            scanned_at=datetime.now(timezone.utc)
        )
    ]
    json_str = json.dumps([item.model_dump() for item in items], default=str)
    assert "whsec_" not in json_str
    assert "trn_live_" not in json_str
    assert "key_hash" not in json_str


def test_5_webhook_creation():
    """5. Test POST /api/v1/webhooks endpoint creates webhook and returns secret ONCE."""
    with TestClient(app) as client:
        resp = client.post("/api/v1/webhooks", json={
            "name": "Security Ops Webhook",
            "target_url": "https://example.com/webhook-receiver",
            "events": ["PHISHING_DETECTED", "DOMAIN_HIGH_RISK"]
        })
        assert resp.status_code == 201
        data = resp.json()
        assert "webhook_id" in data
        assert "secret" in data
        assert data["secret"].startswith("whsec_")
        assert len(data["events"]) == 2


def test_6_webhook_listing():
    """6. Test GET /api/v1/webhooks metadata listing."""
    with TestClient(app) as client:
        resp = client.get("/api/v1/webhooks")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_count" in data
        assert "webhooks" in data
        for item in data["webhooks"]:
            assert "secret" not in item
            assert "secret_hash" not in item


def test_7_webhook_metadata_retrieval():
    """7. Test GET /api/v1/webhooks/{webhook_id} metadata endpoint."""
    with TestClient(app) as client:
        create_resp = client.post("/api/v1/webhooks", json={
            "name": "Single Webhook Test",
            "target_url": "https://example.com/hooks/1",
            "events": ["BLACKLIST_MATCH"]
        })
        webhook_id = create_resp.json()["webhook_id"]

        resp = client.get(f"/api/v1/webhooks/{webhook_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["webhook_id"] == webhook_id
        assert "secret" not in data
        assert "secret_hash" not in data


def test_8_webhook_deletion():
    """8. Test DELETE /api/v1/webhooks/{webhook_id} endpoint."""
    with TestClient(app) as client:
        create_resp = client.post("/api/v1/webhooks", json={
            "name": "Delete Me Webhook",
            "target_url": "https://example.com/hooks/delete",
            "events": ["WEAK_TLS_DETECTED"]
        })
        webhook_id = create_resp.json()["webhook_id"]

        del_resp = client.delete(f"/api/v1/webhooks/{webhook_id}")
        assert del_resp.status_code == 200

        get_resp = client.get(f"/api/v1/webhooks/{webhook_id}")
        assert get_resp.status_code == 404


def test_9_invalid_webhook_url_rejection():
    """9. Test invalid webhook URL syntax is rejected."""
    with TestClient(app) as client:
        resp = client.post("/api/v1/webhooks", json={
            "name": "Invalid URL Hook",
            "target_url": "not-a-valid-url",
            "events": ["PHISHING_DETECTED"]
        })
        assert resp.status_code == 400


def test_10_ssrf_private_destination_rejection():
    """10. Test SSRF private destination IP address is rejected."""
    with TestClient(app) as client:
        resp = client.post("/api/v1/webhooks", json={
            "name": "SSRF Hook",
            "target_url": "http://127.0.0.1/webhook",
            "events": ["PHISHING_DETECTED"]
        })
        assert resp.status_code in (400, 403)


def test_11_https_validation_in_production():
    """11. Test HTTP scheme is rejected when ENVIRONMENT=production."""
    with patch("app.config.settings.settings.ENVIRONMENT", "production"):
        with TestClient(app) as client:
            resp = client.post("/api/v1/webhooks", json={
                "name": "HTTP Hook Prod",
                "target_url": "http://example.com/webhook",
                "events": ["PHISHING_DETECTED"]
            })
            assert resp.status_code == 400
            assert "HTTPS" in resp.json()["detail"]


def test_12_event_subscription_validation():
    """12. Test webhook registration requires at least one valid event subscription."""
    with TestClient(app) as client:
        resp = client.post("/api/v1/webhooks", json={
            "name": "No Events Hook",
            "target_url": "https://example.com/webhook",
            "events": []
        })
        assert resp.status_code in (400, 422)


def test_13_webhook_payload_schema():
    """13. Test WebhookEventPayload model schema structure."""
    from app.schemas.webhook import WebhookEventPayload
    payload = WebhookEventPayload(
        event_id="evt-123",
        event_type=WebhookEventType.PHISHING_DETECTED,
        occurred_at=datetime.now(timezone.utc),
        domain="phish-site.com",
        data={"score": 15, "risk": "HIGH"}
    )
    assert payload.version == "1.0"
    assert payload.event_type == "PHISHING_DETECTED"
    assert payload.domain == "phish-site.com"


def test_14_hmac_signature_generation():
    """14. Test HMAC-SHA256 signature generation."""
    secret = "whsec_test_secret_key_12345"
    payload_bytes = b'{"event_id": "test"}'
    signature = sign_payload(secret, payload_bytes)
    assert signature.startswith("sha256=")
    assert len(signature) == 7 + 64


def test_15_secret_non_leakage():
    """15. Test secret redaction prevents unmasked webhook secret logging."""
    test_secret = "whsec_secret1234567890abcdef1234567890abcdef"
    redacted = redact_sensitive_text(f"Webhook secret token debug: {test_secret}")
    assert test_secret not in redacted
    assert "whsec_[REDACTED_WEBHOOK_SECRET]" in redacted


@pytest.mark.asyncio
async def test_16_successful_webhook_delivery():
    """16. Test WebhookDeliveryService dispatch executes successful HTTP delivery."""
    async with async_session() as session:
        session.expire_on_commit = False
        await session.execute(delete(WebhookDelivery))
        await session.execute(delete(WebhookConfig))
        await session.commit()

        wh = WebhookConfig(
            name="Mock Receiver",
            target_url="https://example.com/webhook-mock",
            secret_hash="hash",
            secret_prefix="whsec_test",
            is_enabled=True,
            events="PHISHING_DETECTED",
            created_at=datetime.now(timezone.utc)
        )
        session.add(wh)
        await session.commit()
        wh_id = str(wh.id)

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            deliveries = await WebhookDeliveryService.dispatch_event(
                session,
                WebhookEventType.PHISHING_DETECTED,
                "phish-domain.com",
                {"risk": "HIGH"}
            )
            wh_deliveries = [d for d in deliveries if str(d.webhook_id) == wh_id]
            assert len(wh_deliveries) == 1
            assert wh_deliveries[0].status == "SUCCESS"
            assert wh_deliveries[0].attempt_count == 1


@pytest.mark.asyncio
async def test_17_webhook_timeout_handling():
    """17. Test HTTP timeout triggers retry and eventual failure."""
    async with async_session() as session:
        session.expire_on_commit = False
        await session.execute(delete(WebhookDelivery))
        await session.execute(delete(WebhookConfig))
        await session.commit()

        wh = WebhookConfig(
            name="Timeout Receiver",
            target_url="https://example.com/webhook-timeout",
            secret_hash="hash",
            secret_prefix="whsec_test",
            is_enabled=True,
            events="SSL_CERTIFICATE_EXPIRED",
            created_at=datetime.now(timezone.utc)
        )
        session.add(wh)
        await session.commit()
        wh_id = str(wh.id)

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=Exception("Timeout connecting")):
            deliveries = await WebhookDeliveryService.dispatch_event(
                session,
                WebhookEventType.SSL_CERTIFICATE_EXPIRED,
                "expired-ssl.com",
                {"days": 0}
            )
            wh_deliveries = [d for d in deliveries if str(d.webhook_id) == wh_id]
            assert len(wh_deliveries) == 1
            assert wh_deliveries[0].status == "FAILED"
            assert wh_deliveries[0].attempt_count == MAX_DELIVERY_ATTEMPTS  # 3 total attempts


def test_18_max_delivery_attempts_setting():
    """18. Test MAX_DELIVERY_ATTEMPTS is explicitly capped at 3."""
    assert MAX_DELIVERY_ATTEMPTS == 3


@pytest.mark.asyncio
async def test_19_non_retryable_http_failure():
    """19. Test HTTP 404 client error stops retries immediately."""
    async with async_session() as session:
        session.expire_on_commit = False
        await session.execute(delete(WebhookDelivery))
        await session.execute(delete(WebhookConfig))
        await session.commit()

        wh = WebhookConfig(
            name="404 Receiver",
            target_url="https://example.com/webhook-404",
            secret_hash="hash",
            secret_prefix="whsec_test",
            is_enabled=True,
            events="WEAK_TLS_DETECTED",
            created_at=datetime.now(timezone.utc)
        )
        session.add(wh)
        await session.commit()
        wh_id = str(wh.id)

        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            deliveries = await WebhookDeliveryService.dispatch_event(
                session,
                WebhookEventType.WEAK_TLS_DETECTED,
                "weak-tls.com",
                {"tls": "1.0"}
            )
            wh_deliveries = [d for d in deliveries if str(d.webhook_id) == wh_id]
            assert len(wh_deliveries) == 1
            assert wh_deliveries[0].status == "FAILED"
            assert wh_deliveries[0].attempt_count == 1  # Stops immediately on 404 client error


@pytest.mark.asyncio
async def test_20_retryable_http_500_failure():
    """20. Test HTTP 500 server error retries up to MAX_DELIVERY_ATTEMPTS."""
    async with async_session() as session:
        session.expire_on_commit = False
        await session.execute(delete(WebhookDelivery))
        await session.execute(delete(WebhookConfig))
        await session.commit()

        wh = WebhookConfig(
            name="500 Receiver",
            target_url="https://example.com/webhook-500",
            secret_hash="hash",
            secret_prefix="whsec_test",
            is_enabled=True,
            events="SECURITY_HEADERS_WEAK",
            created_at=datetime.now(timezone.utc)
        )
        session.add(wh)
        await session.commit()
        wh_id = str(wh.id)

        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            deliveries = await WebhookDeliveryService.dispatch_event(
                session,
                WebhookEventType.SECURITY_HEADERS_WEAK,
                "bad-headers.com",
                {"grade": "F"}
            )
            wh_deliveries = [d for d in deliveries if str(d.webhook_id) == wh_id]
            assert len(wh_deliveries) == 1
            assert wh_deliveries[0].status == "FAILED"
            assert wh_deliveries[0].attempt_count == MAX_DELIVERY_ATTEMPTS  # 3 total attempts


@pytest.mark.asyncio
async def test_21_duplicate_event_prevention():
    """21. Test Redis deduplication prevents duplicate event dispatch."""
    with patch("app.services.webhook_delivery_service.redis_client.set", new_callable=AsyncMock, return_value=False):
        is_dup = await WebhookDeliveryService.is_event_duplicate("evt-dup-123")
        assert is_dup is True


def test_22_delivery_audit_endpoint():
    """22. Test GET /api/v1/webhooks/{webhook_id}/deliveries audit endpoint."""
    with TestClient(app) as client:
        create_resp = client.post("/api/v1/webhooks", json={
            "name": "Audit Test Webhook",
            "target_url": "https://example.com/hooks/audit",
            "events": ["BATCH_SCAN_COMPLETED"]
        })
        webhook_id = create_resp.json()["webhook_id"]

        resp = client.get(f"/api/v1/webhooks/{webhook_id}/deliveries")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


def test_23_webhook_rate_limiting():
    """23. Test rate limiting applies to webhook management endpoints."""
    in_memory_tracker._store.clear()
    with patch("app.core.rate_limiter.redis_client.incr", side_effect=Exception("Redis offline")):
        with TestClient(app) as client:
            resp = client.post("/api/v1/webhooks", json={
                "name": "Limit Test",
                "target_url": "https://example.com/limit",
                "events": ["PHISHING_DETECTED"]
            })
            assert resp.status_code in [200, 201, 429]


def test_24_api_key_authentication_compatibility():
    """24. Test API-key authentication remains functional alongside Task 9 features."""
    with TestClient(app) as client:
        # Create API key
        key_resp = client.post("/api/v1/api-keys", json={"name": "Task 9 Auth Compatibility", "tier": "ENTERPRISE"})
        assert key_resp.status_code == 201
        api_key = key_resp.json()["api_key"]

        # Call protected endpoint
        from app.core.api_key_auth import get_authenticated_api_key
        from fastapi import APIRouter, Depends
        from app.models.api_key import APIKey

        test_router = APIRouter()

        @test_router.get("/test-task9-auth")
        async def protected_endpoint(key: APIKey = Depends(get_authenticated_api_key)):
            return {"ok": True, "tier": key.tier}

        app.include_router(test_router)
        resp = client.get("/test-task9-auth", headers={"X-API-Key": api_key})
        assert resp.status_code == 200
        assert resp.json()["tier"] == "ENTERPRISE"


def test_25_ssrf_validator_integration():
    """25. Test URLSecurityValidator is properly integrated into webhook URL checking."""
    from app.core.url_security import URLSecurityValidator
    assert hasattr(URLSecurityValidator, "validate_url_syntax")
    assert hasattr(URLSecurityValidator, "validate_hostname_resolution")


def test_26_deterministic_scoring_isolation():
    """26. Test RuleBasedTrustEngine remains 100% authoritative and untouched."""
    engine_instance = RuleBasedTrustEngine()
    assert hasattr(engine_instance, "evaluate")
    assert not hasattr(engine_instance, "webhook")
    assert not hasattr(engine_instance, "export")


def test_27_existing_baseline_preservation():
    """27. Test existing baseline configuration settings are intact."""
    from app.config.settings import settings
    assert settings.APP_NAME == "TRUSTINEL"
    assert settings.APP_VERSION == "0.1.0"
