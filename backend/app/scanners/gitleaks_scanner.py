"""
Secret Scanner adapter — Gitleaks integration with high-precision regex fallback engine.
Redacts sensitive secrets in evidence and records rule ID and file locations.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Tuple

import structlog
from app.scanners.base import BaseScanner

logger = structlog.get_logger(__name__)


def redact_secret(secret_str: str) -> str:
    """Safely redact secret value, keeping small prefix and suffix for reference."""
    s = secret_str.strip()
    if len(s) <= 8:
        return "***REDACTED***"
    return f"{s[:4]}***{s[-4:]}"


# Built-in high-confidence secret rules when Gitleaks binary is not installed
BUILTIN_SECRET_RULES: List[Tuple[str, str, str, re.Pattern]] = [
    (
        "aws-access-key-id",
        "AWS Access Key ID exposed",
        "critical",
        re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
    ),
    (
        "aws-secret-access-key",
        "AWS Secret Access Key exposed",
        "critical",
        re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
    ),
    (
        "github-pat",
        "GitHub Personal Access Token",
        "critical",
        re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
    ),
    (
        "private-key",
        "Unencrypted Private Key detected",
        "critical",
        re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY"),
    ),
    (
        "slack-token",
        "Slack Bot/User Token exposed",
        "high",
        re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"),
    ),
    (
        "google-api-key",
        "Google API Key exposed",
        "high",
        re.compile(r"AIza[0-9A-Za-z\\-_]{35}"),
    ),
    (
        "stripe-api-key",
        "Stripe Secret Key exposed",
        "critical",
        re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
    ),
    (
        "hardcoded-db-password",
        "Hardcoded Database Connection URI with password",
        "high",
        re.compile(r"(?i)(?:postgres|mysql|mongodb)://[^:]+:([^@]+)@"),
    ),
    (
        "generic-secret-token",
        "Suspected generic API secret / password",
        "medium",
        re.compile(r"(?i)(?:api_key|secret_key|auth_token)\s*=\s*['\"][A-Za-z0-9_\-]{20,80}['\"]"),
    ),
]


class GitleaksScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "gitleaks"

    @property
    def category(self) -> str:
        return "secret"

    def is_available(self) -> bool:
        return shutil.which("gitleaks") is not None

    async def scan(self, target_path: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Scans target_path for exposed secrets.
        Uses Gitleaks binary if available, otherwise uses built-in high-confidence regex engine.
        """
        if self.is_available():
            return await self._scan_with_cli(target_path)
        else:
            logger.info("Gitleaks binary not found on host. Executing built-in secret detection engine.")
            return await self._scan_with_builtin_engine(target_path)

    async def _scan_with_cli(self, target_path: str) -> List[Dict[str, Any]]:
        temp_report = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        temp_report_path = temp_report.name
        temp_report.close()

        cmd = [
            "gitleaks",
            "detect",
            "--no-git",
            "--source", target_path,
            "--report-format", "json",
            "--report-path", temp_report_path,
            "--exit-code", "0",
        ]

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if not os.path.exists(temp_report_path) or os.path.getsize(temp_report_path) == 0:
                return []

            with open(temp_report_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            findings: List[Dict[str, Any]] = []
            for item in data:
                raw_secret = item.get("Secret", "")
                rule_id = item.get("RuleID", "gitleaks-secret")
                file_path = item.get("File", "")
                try:
                    if os.path.isabs(file_path):
                        file_path = os.path.relpath(file_path, target_path)
                except Exception:
                    pass

                findings.append({
                    "scanner": self.name,
                    "rule_id": rule_id,
                    "title": item.get("Description", f"Exposed secret ({rule_id})"),
                    "description": f"Potential exposed secret detected: {item.get('Description', rule_id)}",
                    "category": self.category,
                    "severity": "critical" if "key" in rule_id.lower() or "token" in rule_id.lower() else "high",
                    "confidence": "high",
                    "file_path": file_path,
                    "line_number": item.get("StartLine"),
                    "column_number": item.get("StartColumn"),
                    "endpoint": None,
                    "param": None,
                    "evidence": redact_secret(raw_secret),
                    "package_name": None,
                    "package_version": None,
                    "fixed_version": None,
                    "cve_id": None,
                    "remediation": "Revoke the exposed credential immediately, rotate to a new key, and store secrets using environment variables or a vault.",
                    "raw_payload": item,
                })

            return findings
        except Exception as e:
            logger.error("Error executing Gitleaks CLI", error=str(e))
            return []
        finally:
            if os.path.exists(temp_report_path):
                try:
                    os.remove(temp_report_path)
                except Exception:
                    pass

    async def _scan_with_builtin_engine(self, target_path: str) -> List[Dict[str, Any]]:
        """Walks target directory and runs compiled high-confidence secret regexes."""
        findings: List[Dict[str, Any]] = []
        ignored_extensions = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz", ".lock", ".pyc", ".db"}

        for root, dirs, files in os.walk(target_path):
            # Skip hidden and cache dirs
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "dist", "build", "venv", "__pycache__")]
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in ignored_extensions:
                    continue

                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, target_path)

                # Skip files larger than 5MB
                try:
                    if os.path.getsize(full_path) > 5 * 1024 * 1024:
                        continue
                except Exception:
                    continue

                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line_idx, line in enumerate(f, start=1):
                            for rule_id, title, severity, pattern in BUILTIN_SECRET_RULES:
                                match = pattern.search(line)
                                if match:
                                    raw_match = match.group(0)
                                    findings.append({
                                        "scanner": self.name,
                                        "rule_id": rule_id,
                                        "title": title,
                                        "description": f"Potential hardcoded credential or secret detected: {title}",
                                        "category": self.category,
                                        "severity": severity,
                                        "confidence": "high",
                                        "file_path": rel_path,
                                        "line_number": line_idx,
                                        "column_number": match.start() + 1,
                                        "endpoint": None,
                                        "param": None,
                                        "evidence": redact_secret(raw_match),
                                        "package_name": None,
                                        "package_version": None,
                                        "fixed_version": None,
                                        "cve_id": None,
                                        "remediation": "Do not commit secrets into source control. Revoke this secret and migrate to environment variables or secret management services.",
                                        "raw_payload": {"rule": rule_id, "line": line_idx},
                                    })
                except Exception:
                    continue

        logger.info("Secret scanning finished", findings_found=len(findings))
        return findings
