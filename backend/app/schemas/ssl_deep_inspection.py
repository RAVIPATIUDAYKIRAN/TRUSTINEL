from enum import Enum
from typing import List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class ExpirationStatus(str, Enum):
    VALID = "VALID"
    EXPIRING_SOON = "EXPIRING_SOON"
    EXPIRED = "EXPIRED"
    UNKNOWN = "UNKNOWN"


class SSLCertificateSubject(BaseModel):
    common_name: Optional[str] = Field(None, description="Certificate common name (CN)")
    organization: Optional[str] = Field(None, description="Subject organization name (O)")
    subject_alt_names: List[str] = Field(default_factory=list, description="Subject Alternative Names (SANs)")


class SSLCertificateIssuer(BaseModel):
    common_name: Optional[str] = Field(None, description="Issuer common name (CN)")
    organization: Optional[str] = Field(None, description="Issuer Certificate Authority organization (O)")
    country: Optional[str] = Field(None, description="Issuer country (C)")
    is_self_signed: bool = Field(False, description="Flag indicating if certificate is self-signed")


class PublicKeyInfo(BaseModel):
    algorithm: str = Field("RSA", description="Public key algorithm (e.g. RSA, EC)")
    key_size_bits: Optional[int] = Field(None, description="Public key size in bits (e.g. 2048, 4096, 256)")
    is_weak_key: bool = Field(False, description="Flag indicating if public key size is weak (<2048 RSA)")


class TLSSessionInfo(BaseModel):
    version: str = Field("TLSv1.3", description="Negotiated TLS protocol version")
    cipher_name: Optional[str] = Field(None, description="Negotiated cipher suite name")
    cipher_bits: Optional[int] = Field(None, description="Cipher strength in bits")
    is_weak_protocol: bool = Field(False, description="Flag indicating if negotiated TLS version is obsolete (<= TLSv1.1)")


class SSLDeepInspectionResult(BaseModel):
    domain: str = Field(..., description="Target domain name evaluated")
    ip_address: Optional[str] = Field(None, description="Resolved destination IP address")
    is_valid: bool = Field(False, description="Overall certificate validity flag")
    trust_verified: bool = Field(False, description="Indicates whether trust chain verified against trusted CAs")
    hostname_matches: bool = Field(False, description="Indicates whether domain matches Common Name or SANs")
    subject: Optional[SSLCertificateSubject] = Field(None, description="Certificate Subject details")
    issuer: Optional[SSLCertificateIssuer] = Field(None, description="Certificate Authority Issuer details")
    valid_from: Optional[datetime] = Field(None, description="Certificate validity start date")
    expires_on: Optional[datetime] = Field(None, description="Certificate expiration date")
    days_remaining: Optional[int] = Field(None, description="Days remaining until certificate expiration")
    expiration_status: ExpirationStatus = Field(ExpirationStatus.UNKNOWN, description="Categorized expiration status")
    serial_number: Optional[str] = Field(None, description="Certificate serial number string")
    fingerprint_sha256: Optional[str] = Field(None, description="SHA-256 fingerprint string")
    public_key: Optional[PublicKeyInfo] = Field(None, description="Public key specifications")
    signature_algorithm: Optional[str] = Field(None, description="Signature algorithm")
    certificate_chain: List[str] = Field(default_factory=list, description="Chain of Certificate Authority issuers")
    tls_session: Optional[TLSSessionInfo] = Field(None, description="TLS session negotiation parameters")
    is_weak_tls: bool = Field(False, description="Overall flag indicating weak or obsolete TLS configuration")
    security_findings: List[str] = Field(default_factory=list, description="List of human-readable security warning findings")
    error: Optional[str] = Field(None, description="Error message if inspection or TLS handshake failed")
    inspected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Inspection timestamp")
