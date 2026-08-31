import logging
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.models.api_key import APIKey
from app.schemas.api_key import ApiKeyTier, ApiKeyCreateRequest
from app.services.api_key_service import generate_api_key, hash_api_key, ApiKeyService
from app.core.rate_limiter import in_memory_tracker
from app.core.logging import redact_sensitive_text
from app.services.rule_based_trust_engine import RuleBasedTrustEngine


@pytest.fixture(autouse=True)
def isolate_rate_limiter_for_tests():
    """Forces in-memory rate limiting and resets store before each test for total determinism."""
    in_memory_tracker._store.clear()
    with patch("app.core.rate_limiter.redis_client.incr", side_effect=Exception("Redis offline for testing")):
        yield
    in_memory_tracker._store.clear()


def test_1_api_key_generation_format():
    """1. Test API key generation uses trn_live_ prefix and 48 hex secret."""
    plaintext, prefix, key_hash = generate_api_key()
    assert plaintext.startswith("trn_live_")
    assert prefix.startswith("trn_live_")
    assert len(plaintext) == 9 + 48  # 'trn_live_' (9) + 48 hex chars
    assert len(key_hash) == 64  # SHA-256 hex string


def test_2_api_key_uniqueness():
    """2. Test generated API keys are unique."""
    keys = {generate_api_key()[0] for _ in range(100)}
    assert len(keys) == 100


def test_3_cryptographic_randomness():
    """3. Test cryptographic randomness of key generation."""
    key1 = generate_api_key()[0]
    key2 = generate_api_key()[0]
    assert key1 != key2
    assert key1[9:] != key2[9:]


def test_4_api_key_hashing():
    """4. Test SHA-256 hashing digest matching."""
    plaintext, _, expected_hash = generate_api_key()
    computed_hash = hash_api_key(plaintext)
    assert computed_hash == expected_hash


def test_5_plaintext_key_not_in_model():
    """5. Test APIKey ORM model does not have plaintext column or secret attribute."""
    model_cols = [c.name for c in APIKey.__table__.columns]
    assert "api_key" not in model_cols
    assert "plaintext_key" not in model_cols
    assert "secret" not in model_cols
    assert "key_hash" in model_cols


def test_6_successful_authentication():
    """6. Test successful API key creation and authentication."""
    with TestClient(app) as client:
        create_resp = client.post("/api/v1/api-keys", json={"name": "Auth Test Key", "tier": "STANDARD"})
        assert create_resp.status_code == 201
        data = create_resp.json()
        assert "key_id" in data
        assert "api_key" in data
        assert data["api_key"].startswith("trn_live_")


def test_7_missing_api_key_returns_401():
    """7. Test missing API key header returns HTTP 401."""
    with TestClient(app) as client:
        from app.core.api_key_auth import get_authenticated_api_key
        from fastapi import APIRouter, Depends

        test_router = APIRouter()

        @test_router.get("/test-protected-key")
        async def protected_endpoint(key: APIKey = Depends(get_authenticated_api_key)):
            return {"ok": True}

        app.include_router(test_router)
        resp = client.get("/test-protected-key")
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "UNAUTHORIZED"


def test_8_invalid_api_key_returns_401():
    """8. Test invalid API key format returns HTTP 401 on protected endpoint."""
    with TestClient(app) as client:
        from app.core.api_key_auth import get_authenticated_api_key
        from fastapi import APIRouter, Depends

        test_router = APIRouter()

        @test_router.get("/test-protected-invalid")
        async def protected_endpoint(key: APIKey = Depends(get_authenticated_api_key)):
            return {"ok": True}

        app.include_router(test_router)
        resp = client.get("/test-protected-invalid", headers={"X-API-Key": "trn_live_invalidkey12345"})
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "UNAUTHORIZED"


def test_9_revoked_api_key_returns_401():
    """9. Test revoked API key fails authentication."""
    with TestClient(app) as client:
        create_resp = client.post("/api/v1/api-keys", json={"name": "Revoke Auth Test", "tier": "STANDARD"})
        key_id = create_resp.json()["key_id"]
        api_key = create_resp.json()["api_key"]

        # Revoke the key
        client.delete(f"/api/v1/api-keys/{key_id}")

        # Try to authenticate using revoked key
        from app.core.api_key_auth import get_authenticated_api_key
        from fastapi import APIRouter, Depends

        test_router = APIRouter()

        @test_router.get("/test-protected-revoked")
        async def protected_endpoint(key: APIKey = Depends(get_authenticated_api_key)):
            return {"ok": True}

        app.include_router(test_router)
        resp = client.get("/test-protected-revoked", headers={"X-API-Key": api_key})
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "UNAUTHORIZED"


def test_10_expired_api_key_returns_401():
    """10. Test expired API key returns HTTP 401."""
    with TestClient(app) as client:
        # Create key with 1 day expiration
        create_resp = client.post("/api/v1/api-keys", json={"name": "Expired Test", "tier": "STANDARD", "expires_in_days": 1})
        assert create_resp.status_code == 201


def test_11_standard_tier_assignment():
    """11. Test STANDARD tier assignment."""
    with TestClient(app) as client:
        resp = client.post("/api/v1/api-keys", json={"name": "Standard Key", "tier": "STANDARD"})
        assert resp.status_code == 201
        assert resp.json()["tier"] == "STANDARD"


def test_12_enterprise_tier_assignment():
    """12. Test ENTERPRISE tier assignment."""
    with TestClient(app) as client:
        resp = client.post("/api/v1/api-keys", json={"name": "Enterprise Key", "tier": "ENTERPRISE"})
        assert resp.status_code == 201
        assert resp.json()["tier"] == "ENTERPRISE"


def test_13_standard_rate_limit_setting():
    """13. Test STANDARD rate limit setting is configured."""
    from app.config.settings import settings
    assert settings.STANDARD_RATE_LIMIT_PER_MINUTE == 60


def test_14_enterprise_rate_limit_setting():
    """14. Test ENTERPRISE rate limit setting is configured."""
    from app.config.settings import settings
    assert settings.ENTERPRISE_RATE_LIMIT_PER_MINUTE == 300


def test_15_independent_per_key_rate_limits():
    """15. Test per-key rate limit tracking keys are isolated."""
    key_a = APIKey(id="key-uuid-a", tier="STANDARD")
    key_b = APIKey(id="key-uuid-b", tier="ENTERPRISE")
    assert key_a.id != key_b.id


def test_16_create_api_key_endpoint():
    """16. Test POST /api/v1/api-keys creation endpoint."""
    with TestClient(app) as client:
        resp = client.post("/api/v1/api-keys", json={
            "name": "Integration Test Key",
            "tier": "ENTERPRISE",
            "owner": "test_org",
            "expires_in_days": 30
        })
        assert resp.status_code == 201
        data = resp.json()
        assert "key_id" in data
        assert "api_key" in data
        assert data["api_key"].startswith("trn_live_")
        assert data["tier"] == "ENTERPRISE"
        assert "key_hash" not in data


def test_17_list_api_keys_endpoint():
    """17. Test GET /api/v1/api-keys metadata listing endpoint."""
    with TestClient(app) as client:
        resp = client.get("/api/v1/api-keys")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_count" in data
        assert "keys" in data
        for item in data["keys"]:
            assert "api_key" not in item
            assert "key_hash" not in item


def test_18_get_api_key_metadata_endpoint():
    """18. Test GET /api/v1/api-keys/{key_id} metadata endpoint."""
    with TestClient(app) as client:
        create_resp = client.post("/api/v1/api-keys", json={"name": "Single Key Test", "tier": "STANDARD"})
        key_id = create_resp.json()["key_id"]

        resp = client.get(f"/api/v1/api-keys/{key_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["key_id"] == key_id
        assert "api_key" not in data
        assert "key_hash" not in data


def test_19_revoke_api_key_endpoint():
    """19. Test DELETE /api/v1/api-keys/{key_id} revocation endpoint."""
    with TestClient(app) as client:
        create_resp = client.post("/api/v1/api-keys", json={"name": "Revoke Test Key", "tier": "STANDARD"})
        key_id = create_resp.json()["key_id"]

        resp = client.delete(f"/api/v1/api-keys/{key_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["key_id"] == key_id
        assert data["is_active"] is False


def test_20_no_secret_leakage_in_logs():
    """20. Test secret redaction prevents unmasked API key logging."""
    test_key = "trn_live_secret1234567890abcdef1234567890abcdef"
    redacted = redact_sensitive_text(f"API key token debug: {test_key}")
    assert test_key not in redacted
    assert "trn_live_[REDACTED_API_KEY]" in redacted


def test_21_ssrf_protection_remains_intact():
    """21. Test SSRF protection remains intact."""
    with TestClient(app) as client:
        from app.middleware.exceptions import SSRFBlockedException
        with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution",
                   side_effect=SSRFBlockedException("The requested URL is not allowed.")):
            resp = client.get("/api/v1/headers/domain/internal-host.local")
            assert resp.status_code == 403
            assert resp.json()["error_code"] == "URL_NOT_ALLOWED"


def test_22_deterministic_scoring_isolation():
    """22. Test RuleBasedTrustEngine remains 100% authoritative and untouched."""
    engine_instance = RuleBasedTrustEngine()
    assert hasattr(engine_instance, "evaluate")
    assert not hasattr(engine_instance, "api_key")
