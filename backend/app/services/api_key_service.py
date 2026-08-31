import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import APIKey
from app.schemas.api_key import (
    ApiKeyCreateRequest,
    ApiKeyCreateResponse,
    ApiKeyMetadata,
    ApiKeyListResponse,
    ApiKeyRevokeResponse,
    ApiKeyTier,
)

logger = logging.getLogger("trustinel.services.api_key")

KEY_PREFIX_HEADER = "trn_live_"


def generate_api_key() -> Tuple[str, str, str]:
    """
    Generates a cryptographically secure API key.
    Format: trn_live_<48_hex_chars>
    Returns: (plaintext_key, key_prefix, key_hash)
    """
    random_secret = secrets.token_hex(24)
    plaintext_key = f"{KEY_PREFIX_HEADER}{random_secret}"
    key_prefix = f"{KEY_PREFIX_HEADER}{random_secret[:4]}"
    key_hash = hashlib.sha256(plaintext_key.encode("utf-8")).hexdigest()
    return plaintext_key, key_prefix, key_hash


def hash_api_key(plaintext_key: str) -> str:
    """
    Computes the SHA-256 digest of a plaintext API key.
    """
    return hashlib.sha256(plaintext_key.strip().encode("utf-8")).hexdigest()


class ApiKeyService:
    """
    Service layer handling API key generation, secure storage, verification,
    metadata retrieval, and revocation.
    """

    @staticmethod
    async def create_api_key(
        session: AsyncSession,
        request: ApiKeyCreateRequest
    ) -> ApiKeyCreateResponse:
        plaintext_key, key_prefix, key_hash = generate_api_key()

        now = datetime.now(timezone.utc)
        expires_at = None
        if request.expires_in_days and request.expires_in_days > 0:
            expires_at = now + timedelta(days=request.expires_in_days)

        api_key_record = APIKey(
            key_hash=key_hash,
            key_prefix=key_prefix,
            name=request.name.strip(),
            owner=request.owner.strip(),
            tier=request.tier.value,
            is_active=True,
            created_at=now,
            expires_at=expires_at
        )

        session.add(api_key_record)
        await session.commit()
        await session.refresh(api_key_record)

        logger.info(f"[TRUSTINEL API Key Created] KeyID='{api_key_record.id}', Prefix='{key_prefix}', Tier='{request.tier.value}'")

        return ApiKeyCreateResponse(
            key_id=api_key_record.id,
            api_key=plaintext_key,  # RETURNED ONCE UPON CREATION ONLY
            key_prefix=key_prefix,
            name=api_key_record.name,
            tier=ApiKeyTier(api_key_record.tier),
            owner=api_key_record.owner,
            created_at=api_key_record.created_at,
            expires_at=api_key_record.expires_at
        )

    @staticmethod
    async def list_api_keys(
        session: AsyncSession,
        owner: Optional[str] = None
    ) -> ApiKeyListResponse:
        stmt = select(APIKey)
        if owner:
            stmt = stmt.where(APIKey.owner == owner)
        stmt = stmt.order_by(APIKey.created_at.desc())

        result = await session.execute(stmt)
        records = result.scalars().all()

        metadata_list = [
            ApiKeyMetadata(
                key_id=rec.id,
                key_prefix=rec.key_prefix,
                name=rec.name,
                tier=ApiKeyTier(rec.tier),
                owner=rec.owner,
                is_active=rec.is_active,
                created_at=rec.created_at,
                expires_at=rec.expires_at,
                last_used_at=rec.last_used_at,
                revoked_at=rec.revoked_at
            )
            for rec in records
        ]

        return ApiKeyListResponse(
            total_count=len(metadata_list),
            keys=metadata_list
        )

    @staticmethod
    async def get_api_key_metadata(
        session: AsyncSession,
        key_id: str
    ) -> Optional[ApiKeyMetadata]:
        stmt = select(APIKey).where(APIKey.id == key_id)
        result = await session.execute(stmt)
        rec = result.scalar_one_or_none()

        if not rec:
            return None

        return ApiKeyMetadata(
            key_id=rec.id,
            key_prefix=rec.key_prefix,
            name=rec.name,
            tier=ApiKeyTier(rec.tier),
            owner=rec.owner,
            is_active=rec.is_active,
            created_at=rec.created_at,
            expires_at=rec.expires_at,
            last_used_at=rec.last_used_at,
            revoked_at=rec.revoked_at
        )

    @staticmethod
    async def revoke_api_key(
        session: AsyncSession,
        key_id: str
    ) -> Optional[ApiKeyRevokeResponse]:
        stmt = select(APIKey).where(APIKey.id == key_id)
        result = await session.execute(stmt)
        rec = result.scalar_one_or_none()

        if not rec:
            return None

        now = datetime.now(timezone.utc)
        rec.is_active = False
        rec.revoked_at = now

        await session.commit()
        await session.refresh(rec)

        logger.info(f"[TRUSTINEL API Key Revoked] KeyID='{rec.id}', Prefix='{rec.key_prefix}'")

        return ApiKeyRevokeResponse(
            key_id=rec.id,
            name=rec.name,
            is_active=False,
            revoked_at=now,
            message=f"API Key '{rec.id}' has been revoked successfully."
        )

    @staticmethod
    async def authenticate_api_key(
        session: AsyncSession,
        plaintext_key: str
    ) -> Optional[APIKey]:
        clean_key = plaintext_key.strip()
        if not clean_key.startswith(KEY_PREFIX_HEADER):
            return None

        kh = hash_api_key(clean_key)
        stmt = select(APIKey).where(APIKey.key_hash == kh)
        result = await session.execute(stmt)
        rec = result.scalar_one_or_none()

        if not rec or not rec.is_active:
            return None

        now = datetime.now(timezone.utc)
        if rec.expires_at and now >= rec.expires_at:
            logger.warning(f"[TRUSTINEL API Key Expired] KeyID='{rec.id}' expired at {rec.expires_at}")
            return None

        # Update last_used_at
        rec.last_used_at = now
        await session.commit()
        await session.refresh(rec)

        return rec
