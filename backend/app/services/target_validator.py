"""
Target URL validation service for DAST testing.
Enforces SSRF prevention, DNS resolution checks, and private IP restrictions.
"""
import ipaddress
import socket
from urllib.parse import urlparse
from app.core.config import settings


class TargetValidationError(Exception):
    """Raised when a DAST target URL fails safety or authorization checks."""
    pass


class TargetValidator:
    BLOCKED_NETWORKS = [
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),  # Link-local / Cloud metadata
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("224.0.0.0/4"),    # Multicast
        ipaddress.ip_network("240.0.0.0/4"),    # Reserved
        ipaddress.ip_network("::1/128"),        # IPv6 loopback
        ipaddress.ip_network("fc00::/7"),       # IPv6 private
        ipaddress.ip_network("fe80::/10"),      # IPv6 link-local
    ]

    CLOUD_METADATA_IPS = {"169.254.169.254"}

    @classmethod
    def validate_target_url(cls, url: str, allow_local_override: bool = False) -> str:
        """
        Validates the URL for DAST scanning.
        Returns the normalized URL if valid.
        Raises TargetValidationError if invalid or unauthorized.
        """
        if not url:
            raise TargetValidationError("Target URL cannot be empty.")

        parsed = urlparse(url.strip())
        if parsed.scheme.lower() not in ("http", "https"):
            raise TargetValidationError(
                f"Unsupported URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."
            )

        hostname = parsed.hostname
        if not hostname:
            raise TargetValidationError("Invalid URL: missing hostname.")

        # Always block cloud metadata
        if hostname in cls.CLOUD_METADATA_IPS:
            raise TargetValidationError("Access to cloud metadata endpoints (169.254.169.254) is strictly prohibited.")

        # Resolve hostname to IP to protect against DNS rebinding & private IP access
        try:
            addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        except socket.gaierror as e:
            raise TargetValidationError(f"Could not resolve hostname '{hostname}': {str(e)}")

        effective_allow_local = allow_local_override or settings.ALLOW_LOCAL_TARGETS

        for info in addr_info:
            ip_str = info[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue

            # Always block metadata IP
            if str(ip) in cls.CLOUD_METADATA_IPS:
                raise TargetValidationError("Resolved IP is cloud metadata endpoint. Blocked.")

            is_blocked = any(ip in net for net in cls.BLOCKED_NETWORKS)

            if is_blocked:
                if effective_allow_local and (ip.is_loopback or ip.is_private):
                    # Permitted only in explicit local lab mode
                    continue
                raise TargetValidationError(
                    f"Target resolved to private/restricted IP ({ip_str}). "
                    "DAST scanning of internal network targets is forbidden by default. "
                    "For controlled local lab targets, enable ALLOW_LOCAL_TARGETS in configuration."
                )

        return url.strip()
