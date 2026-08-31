from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict, HttpUrl


class WebhookEventType(str, Enum):
    DOMAIN_HIGH_RISK = "DOMAIN_HIGH_RISK"
    PHISHING_DETECTED = "PHISHING_DETECTED"
    BLACKLIST_MATCH = "BLACKLIST_MATCH"
    SSL_CERTIFICATE_EXPIRING = "SSL_CERTIFICATE_EXPIRING"
    SSL_CERTIFICATE_EXPIRED = "SSL_CERTIFICATE_EXPIRED"
    WEAK_TLS_DETECTED = "WEAK_TLS_DETECTED"
    SECURITY_HEADERS_WEAK = "SECURITY_HEADERS_WEAK"
    BATCH_SCAN_COMPLETED = "BATCH_SCAN_COMPLETED"


class WebhookCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Webhook label")
    target_url: str = Field(..., description="Destination URL for webhook HTTP POST payloads")
    events: List[WebhookEventType] = Field(..., min_length=1, description="Subscribed security event types")
    owner: Optional[str] = Field("default_owner", min_length=1, max_length=100, description="Webhook owner/organization")


class WebhookCreateResponse(BaseModel):
    webhook_id: str = Field(..., description="Unique Webhook ID")
    name: str = Field(..., description="Webhook label")
    target_url: str = Field(..., description="Destination URL")
    secret: str = Field(..., description="Plaintext HMAC Signing Secret (RETURNED ONCE UPON CREATION, NEVER STORED)")
    secret_prefix: str = Field(..., description="Safe prefix for visual secret identification")
    events: List[WebhookEventType] = Field(..., description="Subscribed security event types")
    is_enabled: bool = Field(True, description="Active status flag")
    created_at: datetime = Field(..., description="Creation timestamp")


class WebhookMetadata(BaseModel):
    webhook_id: str = Field(..., description="Unique Webhook ID")
    name: str = Field(..., description="Webhook label")
    target_url: str = Field(..., description="Destination URL")
    secret_prefix: str = Field(..., description="Safe prefix for visual secret identification")
    events: List[WebhookEventType] = Field(..., description="Subscribed security event types")
    is_enabled: bool = Field(..., description="Active status flag")
    failure_count: int = Field(0, description="Consecutive failure count")
    created_at: datetime = Field(..., description="Creation timestamp")
    last_delivery_at: Optional[datetime] = Field(None, description="Last delivery timestamp")

    model_config = ConfigDict(from_attributes=True)


class WebhookListResponse(BaseModel):
    total_count: int = Field(..., ge=0, description="Total count of webhooks")
    webhooks: List[WebhookMetadata] = Field(default_factory=list, description="List of webhook metadata records")


class WebhookDeliveryLog(BaseModel):
    delivery_id: str = Field(..., description="Unique Delivery Log ID")
    webhook_id: str = Field(..., description="Parent Webhook ID")
    event_id: str = Field(..., description="Unique Event ID")
    event_type: WebhookEventType = Field(..., description="Event Type")
    attempt_count: int = Field(..., description="Total delivery attempts executed (maximum 3 total)")
    status: str = Field(..., description="Delivery status: PENDING, SUCCESS, FAILED")
    response_status_code: Optional[int] = Field(None, description="HTTP response status code")
    error_message: Optional[str] = Field(None, description="Error message if delivery failed")
    created_at: datetime = Field(..., description="Dispatch timestamp")
    delivered_at: Optional[datetime] = Field(None, description="Final delivery timestamp")

    model_config = ConfigDict(from_attributes=True)


class WebhookEventPayload(BaseModel):
    event_id: str = Field(..., description="Unique Event ID")
    event_type: WebhookEventType = Field(..., description="Security event type")
    version: str = Field("1.0", description="Schema payload version")
    occurred_at: datetime = Field(..., description="Event timestamp")
    domain: str = Field(..., description="Target domain name")
    data: Dict[str, Any] = Field(default_factory=dict, description="Structured event payload data")
