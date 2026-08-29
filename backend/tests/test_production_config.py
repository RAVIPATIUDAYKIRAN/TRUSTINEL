from pydantic import SecretStr
from app.config.settings import Settings


def test_settings_secret_str_masking():
    """Verify SecretStr prevents secret disclosure in string representation."""
    s = Settings(
        AI_THREAT_ANALYSIS_API_KEY=SecretStr("sk-super-secret-key-12345"),
        AI_EXPLANATION_API_KEY=SecretStr("sk-super-secret-key-67890"),
    )
    repr_str = repr(s)
    str_val = str(s.AI_THREAT_ANALYSIS_API_KEY)
    
    assert "sk-super-secret-key-12345" not in repr_str
    assert "sk-super-secret-key-67890" not in repr_str
    assert "sk-super-secret-key-12345" not in str_val
    assert s.AI_THREAT_ANALYSIS_API_KEY.get_secret_value() == "sk-super-secret-key-12345"


def test_get_safe_config_summary():
    """Verify get_safe_config_summary masks API keys and returns non-sensitive metadata."""
    s = Settings(
        AI_THREAT_ANALYSIS_API_KEY=SecretStr("sk-super-secret-key-12345"),
        AI_EXPLANATION_API_KEY=None,
    )
    summary = s.get_safe_config_summary()
    
    assert summary["ai_threat_analysis_api_key_configured"] is True
    assert summary["ai_explanation_api_key_configured"] is False
    assert summary["app_name"] == "TRUSTINEL"
    assert "sk-super-secret-key-12345" not in str(summary)


def test_is_production_property():
    """Verify is_production property correctly identifies production vs dev environments."""
    dev_s = Settings(ENVIRONMENT="development")
    prod_s = Settings(ENVIRONMENT="production")
    
    assert dev_s.is_production is False
    assert prod_s.is_production is True


def test_cors_origins_and_docs_defaults():
    """Verify CORS origins and ENABLE_DOCS default values."""
    s = Settings()
    
    assert "http://127.0.0.1:8000" in s.CORS_ORIGINS
    assert s.CORS_ORIGIN_REGEX == r"^chrome-extension://.*$"
    assert s.ENABLE_DOCS is True
    assert s.DB_POOL_SIZE == 10
    assert s.DB_MAX_OVERFLOW == 20
    assert s.DB_POOL_TIMEOUT == 30.0
