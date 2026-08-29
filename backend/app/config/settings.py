from typing import Any, Dict, List, Optional
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str = "TRUSTINEL"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"

    # Database Connection
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/trustinel"
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: float = 30.0

    # Redis Connection
    REDIS_URL: str = "redis://localhost:6379/0"

    # CORS and Network Hardening
    CORS_ORIGINS: List[str] = Field(
        default_factory=lambda: ["http://127.0.0.1:8000", "http://localhost:8000", "http://localhost:3000"]
    )
    CORS_ORIGIN_REGEX: Optional[str] = r"^chrome-extension://.*$"
    ENABLE_DOCS: bool = True

    # Rate Limiting Configuration
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_POST_SCAN: int = 10
    RATE_LIMIT_GET_SCAN: int = 60
    RATE_LIMIT_AI_STATUS: int = 30
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # AI Risk Explanation Configuration
    AI_EXPLANATION_ENABLED: bool = False
    AI_EXPLANATION_PROVIDER: str = "openai"
    AI_EXPLANATION_MODEL: str = ""
    AI_EXPLANATION_API_KEY: Optional[SecretStr] = None

    # AI Threat Analysis Configuration
    AI_THREAT_ANALYSIS_ENABLED: bool = False
    AI_THREAT_ANALYSIS_PROVIDER: str = "openai"
    AI_THREAT_ANALYSIS_MODEL: str = ""
    AI_THREAT_ANALYSIS_API_KEY: Optional[SecretStr] = None
    AI_THREAT_ANALYSIS_TIMEOUT_SECONDS: float = 10.0
    AI_THREAT_ANALYSIS_CACHE_TTL_SECONDS: int = 600

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    def get_safe_config_summary(self) -> Dict[str, Any]:
        """
        Returns a non-sensitive dictionary summary of current app configuration
        with secret fields strictly masked.
        """
        return {
            "app_name": self.APP_NAME,
            "app_version": self.APP_VERSION,
            "environment": self.ENVIRONMENT,
            "is_production": self.is_production,
            "log_level": self.LOG_LEVEL,
            "enable_docs": self.ENABLE_DOCS,
            "cors_origins": self.CORS_ORIGINS,
            "cors_origin_regex": self.CORS_ORIGIN_REGEX,
            "db_pool_size": self.DB_POOL_SIZE,
            "db_max_overflow": self.DB_MAX_OVERFLOW,
            "db_pool_timeout": self.DB_POOL_TIMEOUT,
            "rate_limit_enabled": self.RATE_LIMIT_ENABLED,
            "rate_limit_post_scan": self.RATE_LIMIT_POST_SCAN,
            "rate_limit_get_scan": self.RATE_LIMIT_GET_SCAN,
            "rate_limit_ai_status": self.RATE_LIMIT_AI_STATUS,
            "rate_limit_window_seconds": self.RATE_LIMIT_WINDOW_SECONDS,
            "ai_explanation_enabled": self.AI_EXPLANATION_ENABLED,
            "ai_explanation_provider": self.AI_EXPLANATION_PROVIDER,
            "ai_explanation_model": self.AI_EXPLANATION_MODEL,
            "ai_explanation_api_key_configured": bool(self.AI_EXPLANATION_API_KEY),
            "ai_threat_analysis_enabled": self.AI_THREAT_ANALYSIS_ENABLED,
            "ai_threat_analysis_provider": self.AI_THREAT_ANALYSIS_PROVIDER,
            "ai_threat_analysis_model": self.AI_THREAT_ANALYSIS_MODEL,
            "ai_threat_analysis_api_key_configured": bool(self.AI_THREAT_ANALYSIS_API_KEY),
            "ai_threat_analysis_timeout_seconds": self.AI_THREAT_ANALYSIS_TIMEOUT_SECONDS,
            "ai_threat_analysis_cache_ttl_seconds": self.AI_THREAT_ANALYSIS_CACHE_TTL_SECONDS,
        }


settings = Settings()
