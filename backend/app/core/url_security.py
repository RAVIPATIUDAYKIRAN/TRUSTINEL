import asyncio
import ipaddress
import logging
import socket
import urllib.parse
from typing import List, Union

from app.middleware.exceptions import InvalidURLException, SSRFBlockedException

logger = logging.getLogger("trustinel.url_security")

ALLOWED_SCHEMES = {"http", "https"}

RESTRICTED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "loopback",
}

RESTRICTED_DOMAIN_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".home",
    ".broadband",
)

# Additional non-public IPv4 networks not strictly flagged as is_private/is_loopback in older Python versions
NON_PUBLIC_IPV4_NETWORKS = [
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier-Grade NAT (RFC 6598)
    ipaddress.ip_network("169.254.0.0/16"),    # Link-Local / Cloud Metadata (RFC 3927)
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments (RFC 6890)
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved for Future Use (RFC 1112)
    ipaddress.ip_network("0.0.0.0/8"),         # This host on this network (RFC 1122)
]


class URLSecurityValidator:
    """
    Security validator providing robust URL syntax checking, scheme enforcement,
    and IP/DNS SSRF protection.
    """

    @staticmethod
    def validate_url_syntax(url_str: str) -> str:
        """
        Validates URL syntax, structure, scheme, and userinfo.
        Returns cleaned URL string or raises InvalidURLException.
        """
        if not url_str or not isinstance(url_str, str):
            raise InvalidURLException("URL cannot be empty.")

        cleaned = url_str.strip()
        if not cleaned:
            raise InvalidURLException("URL cannot be empty or whitespace.")

        # Rejects embedded credentials in text before full parse
        if "@" in cleaned:
            # Parse userinfo check
            try:
                parsed_check = urllib.parse.urlparse(cleaned)
                if parsed_check.username or parsed_check.password:
                    raise InvalidURLException("URL cannot contain embedded credentials (username/password).")
            except InvalidURLException:
                raise
            except Exception:
                pass

        try:
            parsed = urllib.parse.urlparse(cleaned)
        except Exception as e:
            raise InvalidURLException(f"Malformed URL: {e}")

        scheme = (parsed.scheme or "").lower()
        if not scheme:
            raise InvalidURLException("URL must include a scheme (http:// or https://).")

        if scheme not in ALLOWED_SCHEMES:
            raise InvalidURLException(f"Unsupported URL scheme '{scheme}'. Only http:// and https:// are allowed.")

        if parsed.username or parsed.password:
            raise InvalidURLException("URL cannot contain embedded credentials (username/password).")

        hostname = parsed.hostname
        if not hostname:
            raise InvalidURLException("URL must contain a valid hostname.")

        # Validate explicit port range if present
        if parsed.port is not None:
            if not (1 <= parsed.port <= 65535):
                raise InvalidURLException(f"Invalid URL port number: {parsed.port}.")

        return cleaned

    @staticmethod
    def is_ip_public(ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
        """
        Evaluates whether an IPv4 or IPv6 address is a legitimate public destination.
        Returns False if the IP address is loopback, private, link-local, multicast,
        reserved, unspecified, or Carrier-Grade NAT.
        """
        # Handle IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
        if isinstance(ip_obj, ipaddress.IPv6Address):
            if ip_obj.ipv4_mapped:
                return URLSecurityValidator.is_ip_public(ip_obj.ipv4_mapped)

        if (
            ip_obj.is_loopback
            or ip_obj.is_private
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            return False

        # Additional IPv4 network checks
        if isinstance(ip_obj, ipaddress.IPv4Address):
            for net in NON_PUBLIC_IPV4_NETWORKS:
                if ip_obj in net:
                    return False

        return True

    @staticmethod
    def is_hostname_restricted(hostname: str) -> bool:
        """
        Checks if a textual hostname matches restricted local or internal patterns.
        """
        if not hostname:
            return True

        norm_host = hostname.lower().strip().rstrip(".")

        if norm_host in RESTRICTED_HOSTNAMES:
            return True

        for suffix in RESTRICTED_DOMAIN_SUFFIXES:
            if norm_host.endswith(suffix):
                return True

        return False

    @classmethod
    async def validate_hostname_resolution(cls, hostname: str) -> List[str]:
        """
        Performs DNS resolution on a hostname and validates ALL resolved IP addresses.
        If ANY resolved IP is private/restricted, raises SSRFBlockedException.
        Returns list of validated public IP address strings.
        """
        clean_host = hostname.strip().rstrip(".")
        if clean_host.startswith("[") and "]" in clean_host:
            clean_host = clean_host[1:clean_host.index("]")]
        elif ":" in clean_host and clean_host.count(":") == 1:
            clean_host = clean_host.split(":")[0]

        if cls.is_hostname_restricted(clean_host):
            logger.warning(
                f"[TRUSTINEL] Restricted hostname blocked: '{hostname}'",
                extra={"event": "ssrf_blocked", "category": "restricted_hostname"}
            )
            raise SSRFBlockedException("The requested URL is not allowed.")

        # If hostname is directly an IP literal address string
        try:
            ip_obj = ipaddress.ip_address(clean_host)
            if not cls.is_ip_public(ip_obj):
                logger.warning(
                    f"[TRUSTINEL] Direct restricted IP blocked: '{clean_host}'",
                    extra={"event": "ssrf_blocked", "category": "restricted_ip"}
                )
                raise SSRFBlockedException("The requested URL is not allowed.")
            return [str(ip_obj)]
        except ValueError:
            # Not an IP literal, proceed to DNS resolution
            pass

        loop = asyncio.get_running_loop()
        try:
            # Resolve both IPv4 and IPv6 addresses
            addr_info = await loop.getaddrinfo(clean_host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            logger.warning(
                f"[TRUSTINEL] DNS resolution failed for '{clean_host}': {exc}",
                extra={"event": "invalid_url_rejected", "category": "dns_resolution_failed"}
            )
            raise InvalidURLException(f"Invalid hostname or host could not be resolved: '{hostname}'")

        if not addr_info:
            raise InvalidURLException(f"No DNS records found for host: '{hostname}'")

        resolved_ips: List[str] = []

        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip_str = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if not cls.is_ip_public(ip_obj):
                    logger.warning(
                        f"[TRUSTINEL] SSRF Blocked: Hostname '{clean_host}' resolved to restricted IP '{ip_str}'"
                    )
                    raise SSRFBlockedException("The requested URL is not allowed.")
                resolved_ips.append(ip_str)
            except ValueError:
                raise SSRFBlockedException("The requested URL is not allowed.")

        return resolved_ips
