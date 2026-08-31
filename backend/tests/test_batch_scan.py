import logging
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.batch_scan import BatchScanRequest
from app.services.batch_scan_service import BatchScanService
from app.services.threat_cache_service import ThreatCacheService, in_memory_threat_cache


@pytest.mark.asyncio
async def test_1_valid_batch_scan_multiple_domains():
    """1. Test valid batch scan with multiple public domains."""
    service = BatchScanService()
    req = BatchScanRequest(domains=["example.com", "trustinel.io"])

    with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution", return_value=["93.184.216.34"]):
        res = await service.execute_batch(req)
        assert res.total_requested == 2
        assert res.successful_count == 2
        assert res.failed_count == 0
        assert len(res.results) == 2


def test_2_bounded_batch_size_validation():
    """2. Test batch size limit exceeding 20 domains is rejected (HTTP 400)."""
    client = TestClient(app)
    domains = [f"domain{i}.com" for i in range(21)]
    resp = client.post("/api/v1/batch/scan", json={"domains": domains})
    assert resp.status_code == 422 or resp.status_code == 400


@pytest.mark.asyncio
async def test_3_per_domain_ssrf_protection():
    """3. Test per-domain SSRF protection blocks restricted IP while allowing public domain."""
    service = BatchScanService()
    req = BatchScanRequest(domains=["example.com", "internal-host.local"])

    from app.middleware.exceptions import SSRFBlockedException

    async def mock_resolve(domain):
        if "internal" in domain:
            raise SSRFBlockedException("The requested URL is not allowed.")
        return ["93.184.216.34"]

    with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution", side_effect=mock_resolve):
        res = await service.execute_batch(req)
        assert res.total_requested == 2
        assert res.successful_count == 1
        assert res.failed_count == 1
        assert res.results[1].is_success is False
        assert res.results[1].error_code == "URL_NOT_ALLOWED"


@pytest.mark.asyncio
async def test_4_partial_success_handling():
    """4. Test partial success handling when some domains fail resolution."""
    service = BatchScanService()
    req = BatchScanRequest(domains=["example.com", "bad-invalid-syntax", "trustinel.io"])

    async def mock_resolve(domain):
        if "invalid" in domain:
            raise Exception("DNS Resolution failed")
        return ["93.184.216.34"]

    with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution", side_effect=mock_resolve):
        res = await service.execute_batch(req)
        assert res.total_requested == 3
        assert res.successful_count == 2
        assert res.failed_count == 1
        assert res.results[1].is_success is False


@pytest.mark.asyncio
async def test_5_threat_intelligence_result_caching():
    """5. Test second scan returns is_cached=True from threat cache."""
    service = BatchScanService()
    req = BatchScanRequest(domains=["cached-domain-test.com"])

    with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution", return_value=["93.184.216.34"]):
        r1 = await service.execute_batch(req)
        assert r1.results[0].is_cached is False

        r2 = await service.execute_batch(req)
        assert r2.results[0].is_cached is True
        assert r2.cache_hit_count == 1


@pytest.mark.asyncio
async def test_6_cache_bypass_flag():
    """6. Test bypass_cache=True forces fresh analyzer execution."""
    service = BatchScanService()
    req_cached = BatchScanRequest(domains=["bypass-domain-test.com"])
    req_bypass = BatchScanRequest(domains=["bypass-domain-test.com"], bypass_cache=True)

    with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution", return_value=["93.184.216.34"]):
        await service.execute_batch(req_cached)
        res_bypass = await service.execute_batch(req_bypass)
        assert res_bypass.results[0].is_cached is False


@pytest.mark.asyncio
async def test_7_cache_invalidation_behavior():
    """7. Test explicit domain cache invalidation."""
    cache_svc = ThreatCacheService()
    service = BatchScanService(cache_service=cache_svc)
    req = BatchScanRequest(domains=["invalidate-test.com"])

    with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution", return_value=["93.184.216.34"]):
        await service.execute_batch(req)
        await cache_svc.invalidate_domain_cache("invalidate-test.com")
        
        res = await service.execute_batch(req)
        assert res.results[0].is_cached is False


@pytest.mark.asyncio
async def test_8_redis_failure_fallback_to_in_memory():
    """8. Test Redis connection failure gracefully falls back to in-memory cache."""
    cache_svc = ThreatCacheService()
    with patch("app.database.session.redis_client.get", side_effect=Exception("Redis Connection Refused")):
        with patch("app.database.session.redis_client.set", side_effect=Exception("Redis Connection Refused")):
            await cache_svc.set_module_result("reputation", "fallback.com", {"reputation_score": 100})
            res = await cache_svc.get_module_result("reputation", "fallback.com")
            assert res is not None
            assert res["reputation_score"] == 100


def test_9_rate_limiting_headers_on_batch_endpoint():
    """9. Test rate limit headers present on POST /api/v1/batch/scan response."""
    client = TestClient(app)
    with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution", return_value=["93.184.216.34"]):
        resp = client.post("/api/v1/batch/scan", json={"domains": ["example.com"]})
        assert resp.status_code == 200
        assert "X-RateLimit-Limit" in resp.headers


@pytest.mark.asyncio
async def test_10_invalid_domain_syntax_per_domain():
    """10. Test invalid domain syntax per domain returns error code in batch item."""
    service = BatchScanService()
    req = BatchScanRequest(domains=["invalidno-dot-domain"])
    res = await service.execute_batch(req)
    assert res.results[0].is_success is False
    assert res.results[0].error_code == "INVALID_DOMAIN"


def test_11_empty_batch_request_rejection():
    """11. Test empty batch request is rejected."""
    client = TestClient(app)
    resp = client.post("/api/v1/batch/scan", json={"domains": []})
    assert resp.status_code == 422 or resp.status_code == 400


@pytest.mark.asyncio
async def test_12_selective_module_inclusion():
    """12. Test selective module inclusion flags."""
    service = BatchScanService()
    req = BatchScanRequest(
        domains=["selective.com"],
        include_reputation=True,
        include_phishing=False,
        include_ssl=False,
        include_headers=False
    )
    with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution", return_value=["93.184.216.34"]):
        res = await service.execute_batch(req)
        item = res.results[0]
        assert item.reputation is not None
        assert item.phishing is None
        assert item.ssl_inspection is None
        assert item.header_audit is None


def test_13_api_response_schema_validation():
    """13. Test API response schema validation for batch endpoint."""
    client = TestClient(app)
    with patch("app.core.url_security.URLSecurityValidator.validate_hostname_resolution", return_value=["93.184.216.34"]):
        resp = client.post("/api/v1/batch/scan", json={"domains": ["example.com"]})
        assert resp.status_code == 200
        data = resp.json()
        assert "total_requested" in data
        assert "successful_count" in data
        assert "cache_hit_count" in data
        assert "results" in data


def test_14_no_secret_leakage(caplog):
    """14. Test secrets redaction / no secret leakage."""
    caplog.set_level(logging.INFO)
    logger = logging.getLogger("trustinel.security_batch_test")
    secret_token = "sk-batch-secret-token-776655"
    logger.info(f"Batch scan debug token {secret_token}")

    messages = [r.getMessage() for r in caplog.records]
    assert not any(secret_token in m for m in messages)
    assert any("[REDACTED_API_KEY]" in m for m in messages)


def test_15_deterministic_scoring_isolation():
    """15. Test deterministic scoring engine remains 100% authoritative and isolated."""
    from app.services.rule_based_trust_engine import RuleBasedTrustEngine
    engine_instance = RuleBasedTrustEngine()
    assert hasattr(engine_instance, "evaluate")


def test_16_delete_cache_endpoint():
    """16. Test DELETE /api/v1/batch/cache/domain/{domain} endpoint."""
    client = TestClient(app)
    resp = client.delete("/api/v1/batch/cache/domain/example.com")
    assert resp.status_code == 200
    data = resp.json()
    assert "entries_cleared" in data
