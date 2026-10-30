
"""
Semgrep SAST Scanner adapter.
Executes Semgrep CLI on source directories and normalizes findings.
"""
import json
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional

import structlog

from app.scanners.base import BaseScanner

logger = structlog.get_logger(__name__)


class SemgrepScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "semgrep"

    @property
    def category(self) -> str:
        return "sast"

    def _get_executable(self) -> str:
        """Find the Semgrep executable."""
        path = shutil.which("semgrep")
        if path:
            return path

        venv_scripts = os.path.dirname(sys.executable)
        candidate = os.path.join(
            venv_scripts,
            "semgrep.exe" if os.name == "nt" else "semgrep",
        )

        if os.path.exists(candidate):
            return candidate

        return "semgrep"

    def is_available(self) -> bool:
        """Check whether Semgrep is installed and runnable."""
        try:
            result = subprocess.run(
                [self._get_executable(), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _normalize_severity(
        self,
        semgrep_severity: str,
        metadata: Dict[str, Any],
    ) -> str:
        """Map Semgrep severity to the platform severity levels."""
        severity = (semgrep_severity or "").upper()
        impact = str(metadata.get("impact", "")).upper()
        cwe = str(metadata.get("cwe", "")).upper()

        if (
            impact == "CRITICAL"
            or "RCE" in cwe
            or "SQL" in cwe
        ):
            return "critical"

        if severity == "ERROR":
            return "high"
        if severity == "WARNING":
            return "medium"
        if severity == "INFO":
            return "low"

        return "medium"

    def _get_source_snippet(
        self,
        target_path: str,
        raw_path: str,
        line_number: Any,
        semgrep_lines: Any,
    ) -> Optional[str]:
        """
        Return source-code evidence from the source tree that was scanned.

        The Semgrep payload is not authoritative for evidence because it
        cannot establish which source snapshot a result belongs to. Never
        read files outside the scan directory.
        """
        if not line_number:
            return None

        try:
            target_root = os.path.realpath(target_path)

            if os.path.isabs(raw_path):
                source_path = os.path.realpath(raw_path)
            else:
                source_path = os.path.realpath(
                    os.path.join(target_root, raw_path)
                )

            # Ensure the source file is inside the scan directory.
            if os.path.commonpath(
                [target_root, source_path]
            ) != target_root:
                logger.warning(
                    "Skipping source evidence outside scan directory",
                    file_path=raw_path,
                )
                return None

            if not os.path.isfile(source_path):
                return None

            with open(
                source_path,
                "r",
                encoding="utf-8",
                errors="replace",
            ) as source_file:
                source_lines = source_file.readlines()

            index = int(line_number) - 1

            if not (0 <= index < len(source_lines)):
                return None

            # Keep the evidence span aligned with Semgrep's reported match
            # length, but take its contents only from the scanned file.
            reported_lines = (
                semgrep_lines.splitlines()
                if isinstance(semgrep_lines, str) and semgrep_lines.strip()
                else []
            )
            line_count = max(1, len(reported_lines))
            start = index
            end = min(len(source_lines), index + line_count)

            snippet = "".join(source_lines[start:end]).rstrip()
            return snippet or None

        except (OSError, ValueError, TypeError, IndexError) as exc:
            logger.warning(
                "Could not retrieve source-code evidence",
                file_path=raw_path,
                line_number=line_number,
                error=str(exc),
            )
            return None

    async def scan(
        self,
        target_path: str,
        **kwargs,
    ) -> List[Dict[str, Any]]:
        """Run Semgrep and normalize its findings."""
        if not self.is_available():
            logger.warning(
                "Semgrep CLI is not available on this system."
            )
            return []

        target_path = os.path.realpath(target_path)

        command = [
            self._get_executable(),
            "scan",
            "--json",
            "--quiet",
            "--config",
            "auto",
            "--no-git-ignore",
            target_path,
        ]

        logger.info(
            "Executing Semgrep scan",
            target=target_path,
        )

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=180,
                cwd=target_path,
            )

            stdout = process.stdout.strip()

            if not stdout:
                if process.stderr:
                    logger.error(
                        "Semgrep scan produced no JSON output",
                        stderr=process.stderr,
                    )
                return []

            data = json.loads(stdout)
            results = data.get("results", [])

            normalized: List[Dict[str, Any]] = []

            for item in results:
                extra = item.get("extra") or {}
                metadata = extra.get("metadata") or {}

                rule_id = item.get("check_id", "semgrep-rule")
                raw_path = item.get("path", "")

                # Normalize the file path relative to the scan root.
                try:
                    if os.path.isabs(raw_path):
                        relative_path = os.path.relpath(
                            raw_path,
                            target_path,
                        )
                    else:
                        relative_path = raw_path
                except (ValueError, OSError):
                    relative_path = raw_path

                severity = self._normalize_severity(
                    extra.get("severity", "WARNING"),
                    metadata,
                )

                confidence = str(
                    metadata.get("confidence", "unknown")
                ).lower()

                if confidence not in ("high", "medium", "low"):
                    confidence = "medium"

                start = item.get("start") or {}
                line_number = start.get("line")
                column_number = start.get("col")

                message = extra.get(
                    "message",
                    "Semgrep security finding",
                )

                # Retrieve actual source code instead of displaying
                # placeholder text as scanner evidence.
                snippet = self._get_source_snippet(
                    target_path=target_path,
                    raw_path=raw_path,
                    line_number=line_number,
                    semgrep_lines=extra.get("lines"),
                )

                references = metadata.get("references") or []
                fix_guidance = (
                    metadata.get("fix")
                    or (references[0] if references else None)
                )

                normalized.append(
                    {
                        "scanner": self.name,
                        "rule_id": rule_id,
                        "title": (
                            rule_id.split(".")[-1]
                            .replace("-", " ")
                            .title()
                        ),
                        "description": message,
                        "category": self.category,
                        "severity": severity,
                        "confidence": confidence,
                        "file_path": relative_path,
                        "line_number": line_number,
                        "column_number": column_number,
                        "endpoint": None,
                        "param": None,
                        "evidence": snippet,
                        "package_name": None,
                        "package_version": None,
                        "fixed_version": None,
                        "cve_id": metadata.get("cve"),
                        "remediation": fix_guidance,
                        "raw_payload": item,
                    }
                )

            logger.info(
                "Semgrep scan completed",
                finding_count=len(normalized),
            )

            return normalized

        except subprocess.TimeoutExpired:
            logger.error(
                "Semgrep scan timed out after 180 seconds."
            )
            return []

        except json.JSONDecodeError as exc:
            logger.error(
                "Failed to parse Semgrep JSON output",
                error=str(exc),
            )
            return []

        except Exception as exc:
            logger.error(
                "Unexpected error running Semgrep scan",
                error=str(exc),
            )
            return []
