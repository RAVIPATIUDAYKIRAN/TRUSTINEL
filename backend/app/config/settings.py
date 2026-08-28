from typing import Optional

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

    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/trustinel"
    REDIS_URL: str = "redis://localhost:6379/0"

    # AI Risk Explanation Configuration
    AI_EXPLANATION_ENABLED: bool = False
    AI_EXPLANATION_PROVIDER: str = "openai"
    AI_EXPLANATION_MODEL: str = ""
    AI_EXPLANATION_API_KEY: Optional[str] = None

    # AI Threat Analysis Configuration
    AI_THREAT_ANALYSIS_ENABLED: bool = False
    AI_THREAT_ANALYSIS_PROVIDER: str = "openai"
    AI_THREAT_ANALYSIS_MODEL: str = ""
    AI_THREAT_ANALYSIS_API_KEY: Optional[str] = None
    AI_THREAT_ANALYSIS_TIMEOUT_SECONDS: float = 10.0


settings = Settings()
