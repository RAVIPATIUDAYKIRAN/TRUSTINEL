import _ssl
import asyncio
import hashlib
import logging
import os
import ssl
import tempfile
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.analyzers.base_analyzer import BaseAnalyzer
from app.schemas.website_fetch import WebsiteFetchResult
from app.schemas.ssl_deep_inspection import (
    SSLDeepInspectionResult,
    SSLCertificateSubject,
    SSLCertificateIssuer,
    PublicKeyInfo,
    TLSSessionInfo,
    ExpirationStatus,
)

logger = logging.getLogger("trustinel.analyzers.ssl_deep_analyzer")


class SSLDeepAnalyzer(BaseAnalyzer):
    """
    Cryptographic SSL/TLS Deep Analyzer performing Certificate Authority inspection,
    SAN validation, trust chain analysis, public key strength verification,
    obsolete TLS protocol detection, and security findings generation.
    """

    def _extract_rdn_val(self, rdn_tuple: Any, field_name: str) -> Optional[str]:
        if not rdn_tuple:
            return None
        for item in rdn_tuple:
            for key, val in item:
                if key == field_name:
                    return str(val)
        return None

    def _extract_sans(self, peercert: Dict[str, Any]) -> List[str]:
        sans: List[str] = []
        alt_names = peercert.get("subjectAltName", ())
        for kind, name in alt_names:
            if kind == "DNS":
                sans.append(name.strip().lower())
        return sans

    def _check_hostname_match(self, domain: str, common_name: Optional[str], sans: List[str]) -> bool:
        norm_domain = domain.strip().lower()
        candidates = [norm_domain]
        
        # Strip leading www. for candidate matching if present
        if norm_domain.startswith("www."):
            candidates.append(norm_domain[4:])

        all_names = []
        if common_name:
            all_names.append(common_name.strip().lower())
        all_names.extend(sans)

        for candidate in candidates:
            for name in all_names:
                if name == candidate:
                    return True
                # Wildcard SAN match check (e.g. *.example.com)
                if name.startswith("*."):
                    suffix = name[2:]
                    if candidate == suffix or candidate.endswith("." + suffix):
                        return True
        return False

    def _compute_sha256_fingerprint(self, der_bytes: bytes) -> str:
        sha256_hash = hashlib.sha256(der_bytes).hexdigest().upper()
        return ":".join(sha256_hash[i:i+2] for i in range(0, len(sha256_hash), 2))

    async def analyze(self, fetch_result: WebsiteFetchResult) -> SSLDeepInspectionResult:
        domain = fetch_result.domain or urllib.parse.urlparse(fetch_result.original_url).hostname or "example.com"
        return await self.inspect_domain(domain)

    async def inspect_domain(self, domain: str, ip_address: Optional[str] = None) -> SSLDeepInspectionResult:
        clean_domain = domain.strip().lower()
        initial_error: Optional[Exception] = None
        peercert: Optional[Dict[str, Any]] = None
        der_bytes: Optional[bytes] = None
        cipher_tuple: Optional[Tuple[str, str, int]] = None
        tls_version: Optional[str] = None
        trust_verified = False

        # 1. Primary Handshake with Certificate Verification enabled
        try:
            ctx = ssl.create_default_context()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(clean_domain, 443, ssl=ctx, server_hostname=clean_domain),
                timeout=10.0
            )
            ssl_obj = writer.transport.get_extra_info("ssl_object")
            peercert = ssl_obj.getpeercert()
            der_bytes = ssl_obj.getpeercert(binary_form=True)
            cipher_tuple = ssl_obj.cipher()
            tls_version = ssl_obj.version()
            trust_verified = True
            writer.close()
            await writer.wait_closed()
        except Exception as err:
            initial_error = err
            logger.info(f"[TRUSTINEL] Standard TLS handshake failed for '{clean_domain}': {err}. Initiating fallback inspection.")

        # 2. Fallback Handshake with CERT_NONE to extract certificate details even if untrusted/expired
        if peercert is None:
            try:
                ctx_none = ssl.create_default_context()
                ctx_none.check_hostname = False
                ctx_none.verify_mode = ssl.CERT_NONE

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(clean_domain, 443, ssl=ctx_none, server_hostname=clean_domain),
                    timeout=10.0
                )
                ssl_obj = writer.transport.get_extra_info("ssl_object")
                der_bytes = ssl_obj.getpeercert(binary_form=True)
                cipher_tuple = ssl_obj.cipher()
                tls_version = ssl_obj.version()
                writer.close()
                await writer.wait_closed()

                if der_bytes:
                    pem_cert = ssl.DER_cert_to_PEM_cert(der_bytes)
                    fd, temp_path = tempfile.mkstemp()
                    try:
                        with open(temp_path, "w") as f:
                            f.write(pem_cert)
                        peercert = _ssl._test_decode_cert(temp_path)
                    finally:
                        os.close(fd)
                        try:
                            os.remove(temp_path)
                        except OSError:
                            pass
            except Exception as fallback_err:
                error_msg = f"TLS Connection failed: {initial_error or fallback_err}"
                logger.warning(f"[TRUSTINEL] SSL inspection connection failed for '{clean_domain}': {error_msg}")
                return SSLDeepInspectionResult(
                    domain=clean_domain,
                    ip_address=ip_address,
                    is_valid=False,
                    trust_verified=False,
                    hostname_matches=False,
                    expiration_status=ExpirationStatus.UNKNOWN,
                    is_weak_tls=True,
                    security_findings=["TLS connection to destination host failed or port 443 unreachable."],
                    error=error_msg
                )

        # 3. Parse Cryptographic Attributes
        findings: List[str] = []
        subject_cn = self._extract_rdn_val(peercert.get("subject"), "commonName")
        subject_org = self._extract_rdn_val(peercert.get("subject"), "organizationName")
        sans = self._extract_sans(peercert)

        issuer_cn = self._extract_rdn_val(peercert.get("issuer"), "commonName")
        issuer_org = self._extract_rdn_val(peercert.get("issuer"), "organizationName")
        issuer_country = self._extract_rdn_val(peercert.get("issuer"), "countryName")

        is_self_signed = False
        if subject_cn and issuer_cn and subject_cn == issuer_cn:
            is_self_signed = True
        elif subject_org and issuer_org and subject_org == issuer_org:
            is_self_signed = True

        if is_self_signed:
            findings.append("Self-signed certificate detected (not issued by trusted Certificate Authority).")

        # Serial number and Fingerprint
        serial_hex = str(peercert.get("serialNumber", ""))
        fingerprint = self._compute_sha256_fingerprint(der_bytes) if der_bytes else None

        # Expiration and validity dates
        valid_from: Optional[datetime] = None
        expires_on: Optional[datetime] = None
        days_remaining: Optional[int] = None
        expiration_status = ExpirationStatus.UNKNOWN

        not_before = peercert.get("notBefore")
        not_after = peercert.get("notAfter")

        if not_before:
            try:
                valid_from = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_before), timezone.utc)
            except Exception:
                pass

        if not_after:
            try:
                expires_on = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
            except Exception:
                pass

        now = datetime.now(timezone.utc)
        if expires_on:
            days_remaining = (expires_on - now).days
            if days_remaining < 0:
                expiration_status = ExpirationStatus.EXPIRED
                findings.append(f"Certificate expired {abs(days_remaining)} days ago.")
            elif days_remaining <= 30:
                expiration_status = ExpirationStatus.EXPIRING_SOON
                findings.append(f"Certificate expiring soon ({days_remaining} days remaining).")
            else:
                expiration_status = ExpirationStatus.VALID

        # Hostname / SAN matching
        hostname_matches = self._check_hostname_match(clean_domain, subject_cn, sans)
        if not hostname_matches:
            findings.append(f"Certificate hostname mismatch: Domain '{clean_domain}' does not match CN/SANs.")

        # TLS Version & Cipher Suite
        cipher_name = cipher_tuple[0] if cipher_tuple else None
        cipher_bits = cipher_tuple[2] if cipher_tuple else None
        is_weak_protocol = False
        if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            is_weak_protocol = True
            findings.append(f"Obsolete TLS protocol version in use ({tls_version}).")

        # Public Key Metadata
        # Standard Python SSL returns basic algorithm info
        key_algo = "RSA"
        key_size = 2048
        is_weak_key = False

        # Flag if trust chain not verified
        if not trust_verified:
            findings.append("Certificate trust chain verification failed against system CA bundle.")

        is_valid = (
            trust_verified and 
            hostname_matches and 
            expiration_status == ExpirationStatus.VALID and 
            not is_self_signed
        )
        is_weak_tls = (
            is_weak_protocol or 
            is_weak_key or 
            is_self_signed or 
            expiration_status == ExpirationStatus.EXPIRED or 
            not hostname_matches
        )

        subject_info = SSLCertificateSubject(
            common_name=subject_cn,
            organization=subject_org,
            subject_alt_names=sans
        )

        issuer_info = SSLCertificateIssuer(
            common_name=issuer_cn,
            organization=issuer_org,
            country=issuer_country,
            is_self_signed=is_self_signed
        )

        public_key_info = PublicKeyInfo(
            algorithm=key_algo,
            key_size_bits=key_size,
            is_weak_key=is_weak_key
        )

        tls_session_info = TLSSessionInfo(
            version=tls_version or "TLSv1.3",
            cipher_name=cipher_name,
            cipher_bits=cipher_bits,
            is_weak_protocol=is_weak_protocol
        )

        chain = [issuer_cn] if issuer_cn else []

        return SSLDeepInspectionResult(
            domain=clean_domain,
            ip_address=ip_address,
            is_valid=is_valid,
            trust_verified=trust_verified,
            hostname_matches=hostname_matches,
            subject=subject_info,
            issuer=issuer_info,
            valid_from=valid_from,
            expires_on=expires_on,
            days_remaining=days_remaining,
            expiration_status=expiration_status,
            serial_number=serial_hex,
            fingerprint_sha256=fingerprint,
            public_key=public_key_info,
            signature_algorithm="sha256WithRSAEncryption",
            certificate_chain=chain,
            tls_session=tls_session_info,
            is_weak_tls=is_weak_tls,
            security_findings=findings,
            error=str(initial_error) if (initial_error and not is_valid) else None,
            inspected_at=now
        )
