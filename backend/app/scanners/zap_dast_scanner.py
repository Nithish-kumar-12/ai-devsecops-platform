"""
OWASP ZAP DAST Scanner and Passive Baseline Auditor.
Strictly requires target authorization confirmation and enforces SSRF/private network boundaries.
Never performs destructive or denial-of-service actions.
"""
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx
import structlog
from app.core.config import settings
from app.scanners.base import BaseScanner
from app.services.target_validator import TargetValidationError, TargetValidator

logger = structlog.get_logger(__name__)


class DASTAuthorizationError(Exception):
    """Raised when DAST scan is attempted without explicit authorization."""
    pass


class DASTUnavailableError(Exception):
    """Raised when ZAP is unavailable and active scan cannot be performed."""
    pass


class ZapDastScanner(BaseScanner):
    def __init__(self, zap_base_url: Optional[str] = None):
        self.zap_base_url = (zap_base_url or settings.ZAP_BASE_URL).rstrip("/")

    @property
    def name(self) -> str:
        return "zap"

    @property
    def category(self) -> str:
        return "dast"

    def is_available(self) -> bool:
        """Checks whether the OWASP ZAP daemon API is reachable."""
        try:
            with httpx.Client(timeout=2.0) as client:
                res = client.get(f"{self.zap_base_url}/JSON/core/view/version/")
                return res.status_code == 200
        except Exception:
            return False

    async def scan(self, target_path: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Executes DAST scan on target_path (which represents the target URL).
        kwargs:
            confirm_authorization: bool (Mandatory True)
            mode: 'zap' or 'passive_probe'
        """
        target_url = target_path
        confirm_auth = kwargs.get("confirm_authorization", False)
        if not confirm_auth:
            raise DASTAuthorizationError(
                "DAST scanning strictly requires explicit user confirmation that the target is authorized for testing."
            )

        # 1. SSRF and network validation
        validated_url = TargetValidator.validate_target_url(target_url)

        # 2. Check ZAP availability
        if self.is_available():
            return await self._scan_with_zap(validated_url)
        else:
            logger.info("OWASP ZAP daemon is not reachable at ZAP_BASE_URL. Running safe passive HTTP security baseline.")
            return await self._run_passive_http_audit(validated_url)

    async def _scan_with_zap(self, target_url: str) -> List[Dict[str, Any]]:
        """Interacts with genuine OWASP ZAP API for Spider and Alert collection."""
        findings: List[Dict[str, Any]] = []
        parsed = urlparse(target_url)
        base_endpoint = f"{parsed.scheme}://{parsed.netloc}"

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Trigger passive/spider scan
                spider_res = await client.get(
                    f"{self.zap_base_url}/JSON/spider/action/scan/",
                    params={"url": target_url, "maxChildren": 10},
                )
                logger.info("Triggered ZAP Spider scan", status=spider_res.status_code)

                # Fetch recorded alerts for this target
                alerts_res = await client.get(
                    f"{self.zap_base_url}/JSON/core/view/alerts/",
                    params={"baseurl": base_endpoint, "count": 50},
                )

                if alerts_res.status_code == 200:
                    data = alerts_res.json()
                    alerts = data.get("alerts", [])

                    for alert in alerts:
                        risk = (alert.get("risk") or "Low").lower()
                        severity_map = {
                            "high": "high",
                            "medium": "medium",
                            "low": "low",
                            "informational": "low",
                        }
                        sev = severity_map.get(risk, "medium")

                        findings.append({
                            "scanner": self.name,
                            "rule_id": f"ZAP-{alert.get('pluginId', 'ALERT')}",
                            "title": alert.get("name", "Dynamic Security Finding"),
                            "description": alert.get("description", "DAST finding discovered during runtime inspection."),
                            "category": self.category,
                            "severity": sev,
                            "confidence": (alert.get("confidence") or "medium").lower(),
                            "file_path": None,
                            "line_number": None,
                            "column_number": None,
                            "endpoint": alert.get("url"),
                            "param": alert.get("param") or None,
                            "evidence": alert.get("evidence") or alert.get("attack") or None,
                            "package_name": None,
                            "package_version": None,
                            "fixed_version": None,
                            "cve_id": alert.get("cweid"),
                            "remediation": alert.get("solution") or "Consult OWASP guidelines for this vulnerability category.",
                            "raw_payload": alert,
                        })

            return findings

        except Exception as e:
            logger.error("Error communicating with OWASP ZAP", error=str(e))
            raise DASTUnavailableError(f"ZAP communication failed: {str(e)}")

    async def _run_passive_http_audit(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Safe, non-destructive passive probe of HTTP response headers and TLS configuration.
        Provides genuine real-world baseline findings without modifying application state.
        """
        findings: List[Dict[str, Any]] = []
        try:
            # Safe single-request probe with each redirect destination revalidated.
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
                current_url = validated_url = target_url
                res = None
                for _ in range(4):
                    res = await client.get(
                        current_url,
                        headers={"User-Agent": "AI-DevSecOps-Platform-Auditor/1.0"},
                    )
                    location = res.headers.get("location") if res.is_redirect else None
                    if not location:
                        break
                    next_url = urljoin(current_url, location)
                    current_url = TargetValidator.validate_target_url(next_url)
                if res is None:
                    return findings

                headers = {k.lower(): v for k, v in res.headers.items()}
                parsed = urlparse(str(res.url))
                endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"

                # 1. Missing Content-Security-Policy
                if "content-security-policy" not in headers:
                    findings.append({
                        "scanner": "passive-dast",
                        "rule_id": "DAST-SEC-HEADER-CSP",
                        "title": "Missing Content-Security-Policy (CSP) Header",
                        "description": "The Content-Security-Policy header provides a layer of defense against Cross-Site Scripting (XSS) and data injection attacks by restricting source origins.",
                        "category": self.category,
                        "severity": "medium",
                        "confidence": "high",
                        "file_path": None,
                        "line_number": None,
                        "column_number": None,
                        "endpoint": endpoint,
                        "param": "Content-Security-Policy",
                        "evidence": f"Response headers for {endpoint} did not contain Content-Security-Policy.",
                        "package_name": None,
                        "package_version": None,
                        "fixed_version": None,
                        "cve_id": "CWE-693",
                        "remediation": "Configure a Content-Security-Policy header, e.g. `default-src 'self'; script-src 'self'; object-src 'none';`.",
                        "raw_payload": {"headers": dict(res.headers)},
                    })

                # 2. Missing Strict-Transport-Security on HTTPS
                if parsed.scheme == "https" and "strict-transport-security" not in headers:
                    findings.append({
                        "scanner": "passive-dast",
                        "rule_id": "DAST-SEC-HEADER-HSTS",
                        "title": "Missing Strict-Transport-Security (HSTS) Header",
                        "description": "HTTP Strict Transport Security ensures browsers communicate with the site only over HTTPS, preventing SSL-stripping man-in-the-middle attacks.",
                        "category": self.category,
                        "severity": "medium",
                        "confidence": "high",
                        "file_path": None,
                        "line_number": None,
                        "column_number": None,
                        "endpoint": endpoint,
                        "param": "Strict-Transport-Security",
                        "evidence": f"HTTPS response from {endpoint} omitted Strict-Transport-Security.",
                        "package_name": None,
                        "package_version": None,
                        "fixed_version": None,
                        "cve_id": "CWE-319",
                        "remediation": "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` header to HTTPS responses.",
                        "raw_payload": {"headers": dict(res.headers)},
                    })

                # 3. Missing X-Frame-Options or frame-ancestors
                if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
                    findings.append({
                        "scanner": "passive-dast",
                        "rule_id": "DAST-SEC-HEADER-CLICKJACKING",
                        "title": "Missing Anti-Clickjacking Header (X-Frame-Options)",
                        "description": "The page does not explicitly prevent itself from being embedded in an iframe on third-party sites, making users vulnerable to clickjacking attacks.",
                        "category": self.category,
                        "severity": "low",
                        "confidence": "high",
                        "file_path": None,
                        "line_number": None,
                        "column_number": None,
                        "endpoint": endpoint,
                        "param": "X-Frame-Options",
                        "evidence": f"X-Frame-Options header not found on {endpoint}.",
                        "package_name": None,
                        "package_version": None,
                        "fixed_version": None,
                        "cve_id": "CWE-1021",
                        "remediation": "Send `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN` with responses.",
                        "raw_payload": {"headers": dict(res.headers)},
                    })

                # 4. Missing X-Content-Type-Options
                if headers.get("x-content-type-options", "").lower() != "nosniff":
                    findings.append({
                        "scanner": "passive-dast",
                        "rule_id": "DAST-SEC-HEADER-NOSNIFF",
                        "title": "Missing X-Content-Type-Options: nosniff Header",
                        "description": "Without X-Content-Type-Options: nosniff, browsers may MIME-sniff response content, potentially executing malicious scripts disguised as text or images.",
                        "category": self.category,
                        "severity": "low",
                        "confidence": "high",
                        "file_path": None,
                        "line_number": None,
                        "column_number": None,
                        "endpoint": endpoint,
                        "param": "X-Content-Type-Options",
                        "evidence": f"Header 'X-Content-Type-Options: nosniff' was absent on {endpoint}.",
                        "package_name": None,
                        "package_version": None,
                        "fixed_version": None,
                        "cve_id": "CWE-16",
                        "remediation": "Add `X-Content-Type-Options: nosniff` to all HTTP responses.",
                        "raw_payload": {"headers": dict(res.headers)},
                    })

                # 5. Dangerous Server banner disclosure
                server_hdr = headers.get("server", "")
                if server_hdr and any(c.isdigit() for c in server_hdr):
                    findings.append({
                        "scanner": "passive-dast",
                        "rule_id": "DAST-INFO-SERVER-VERSION",
                        "title": "Web Server Detailed Version Disclosure",
                        "description": f"The HTTP Server header reveals specific software version information ({server_hdr}), aiding attackers in fingerprinting target vulnerabilities.",
                        "category": self.category,
                        "severity": "low",
                        "confidence": "high",
                        "file_path": None,
                        "line_number": None,
                        "column_number": None,
                        "endpoint": endpoint,
                        "param": "Server",
                        "evidence": f"Server header value: '{server_hdr}'",
                        "package_name": None,
                        "package_version": None,
                        "fixed_version": None,
                        "cve_id": "CWE-200",
                        "remediation": "Configure web server or reverse proxy to omit detailed version banners.",
                        "raw_payload": {"server": server_hdr},
                    })

        except httpx.RequestError as e:
            logger.warning("Passive DAST probe connection error", target=target_url, error=str(e))
        except Exception as e:
            logger.error("Unexpected error in passive DAST probe", error=str(e))

        return findings
