from enum import Enum
from typing import List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict


class ApiKeyTier(str, Enum):
    STANDARD = "STANDARD"
    ENTERPRISE = "ENTERPRISE"


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Name/label for the API key")
    tier: ApiKeyTier = Field(ApiKeyTier.STANDARD, description="Rate limit tier: STANDARD (60 req/min) or ENTERPRISE (300 req/min)")
    owner: str = Field("default_owner", min_length=1, max_length=100, description="Owner identifier")
    expires_in_days: Optional[int] = Field(365, ge=1, le=3650, description="Expiration duration in days (1 to 3650)")


class ApiKeyCreateResponse(BaseModel):
    key_id: str = Field(..., description="Unique Key ID")
    api_key: str = Field(..., description="Plaintext API Key (RETURNED ONCE UPON CREATION, NEVER STORED)")
    key_prefix: str = Field(..., description="Safe prefix for visual key identification")
    name: str = Field(..., description="API key name")
    tier: ApiKeyTier = Field(..., description="API key rate limit tier")
    owner: str = Field(..., description="Owner identifier")
    created_at: datetime = Field(..., description="Creation timestamp")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")


class ApiKeyMetadata(BaseModel):
    key_id: str = Field(..., description="Unique Key ID")
    key_prefix: str = Field(..., description="Safe prefix for visual key identification")
    name: str = Field(..., description="API key name")
    tier: ApiKeyTier = Field(..., description="API key rate limit tier")
    owner: str = Field(..., description="Owner identifier")
    is_active: bool = Field(..., description="Active status flag")
    created_at: datetime = Field(..., description="Creation timestamp")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")
    last_used_at: Optional[datetime] = Field(None, description="Last usage timestamp")
    revoked_at: Optional[datetime] = Field(None, description="Revocation timestamp")

    model_config = ConfigDict(from_attributes=True)


class ApiKeyListResponse(BaseModel):
    total_count: int = Field(..., ge=0, description="Total count of API keys")
    keys: List[ApiKeyMetadata] = Field(default_factory=list, description="List of API key metadata records")


class ApiKeyRevokeResponse(BaseModel):
    key_id: str = Field(..., description="Unique Key ID")
    name: str = Field(..., description="API key name")
    is_active: bool = Field(False, description="Active status flag")
    revoked_at: datetime = Field(..., description="Revocation timestamp")
    message: str = Field(..., description="Status message")
