"""
Dependency / SCA Scanner adapter.
Integrates OSV-Scanner CLI when present, with manifest parsing and OSV database API lookup fallback.
"""
import json
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

import httpx
import structlog
from app.scanners.base import BaseScanner

logger = structlog.get_logger(__name__)

# Known vulnerable baseline fixtures for offline / network-isolated testing
OFFLINE_VULNERABILITY_CATALOG = {
    "requests": {
        "affected": "<2.31.0",
        "cve": "CVE-2023-32681",
        "title": "Unintended leak of Proxy-Authorization header in requests",
        "severity": "medium",
        "fixed": "2.31.0",
        "advisory": "GHSA-j8r2-6x86-q33q",
    },
    "urllib3": {
        "affected": "<2.0.7",
        "cve": "CVE-2023-45803",
        "title": "Request body not stripped on HTTP redirect in urllib3",
        "severity": "high",
        "fixed": "2.0.7",
        "advisory": "GHSA-g4mx-q9vg-27p4",
    },
    "flask": {
        "affected": [
            {
                "constraint": ">=2.3.0,<2.3.2",
                "fixed": "2.3.2",
                "remediation": "Upgrade Flask to version 2.3.2 or later.",
            },
            {
                "constraint": "<2.2.5",
                "fixed": "2.2.5",
                "remediation": (
                    "Upgrade Flask to version 2.2.5 or later in the 2.2.x series, "
                    "or to version 2.3.2 or later."
                ),
            },
        ],
        "cve": "CVE-2023-30861",
        "title": "Flask session cookie disclosure via cached responses",
        "severity": "high",
        "advisory": "GHSA-m2bg-fq63-5h7f",
    },
    "lodash": {
        "affected": "<4.17.21",
        "cve": "CVE-2021-23337",
        "title": "Command Injection in lodash template",
        "severity": "critical",
        "fixed": "4.17.21",
        "advisory": "GHSA-35jh-r3h4-6jhm",
    },
    "axios": {
        "affected": "<1.7.4",
        "cve": "CVE-2024-39338",
        "title": "Axios Server-Side Request Forgery vulnerability",
        "severity": "high",
        "fixed": "1.7.4",
        "advisory": "GHSA-8hc4-vh64-cxmj",
    },
    "scikit-learn": {
        "affected": "<1.5.0",
        "cve": "CVE-2024-5206",
        "title": "scikit-learn sensitive data leakage vulnerability",
        "severity": "medium",
        "fixed": "1.5.0",
        "advisory": "GHSA-jw8x-6495-233v",
    },
}


class DependencyScanner(BaseScanner):
    @staticmethod
    def _compare_versions(version: str, boundary: str) -> Optional[int]:
        """Compare numeric release versions, including common Python prereleases."""
        version_match = re.fullmatch(
            r"(\d+(?:\.\d+)*)(?:(a|b|rc)(\d*)|\.dev(\d+)|\.post(\d+))?(?:\+[a-zA-Z0-9.-]+)?",
            version.strip(),
            re.IGNORECASE,
        )
        boundary_match = re.fullmatch(
            r"(\d+(?:\.\d+)*)(?:(a|b|rc)(\d*)|\.dev(\d+)|\.post(\d+))?(?:\+[a-zA-Z0-9.-]+)?",
            boundary.strip(),
            re.IGNORECASE,
        )
        if not version_match or not boundary_match:
            return None

        def version_key(match: re.Match) -> tuple:
            release = tuple(int(part) for part in match.group(1).split("."))
            prerelease = match.group(2)
            if prerelease:
                phase = {"a": 0, "b": 1, "rc": 2}[prerelease.lower()]
                suffix = int(match.group(3) or 0)
            elif match.group(4):
                phase, suffix = -1, int(match.group(4))
            elif match.group(5):
                phase, suffix = 4, int(match.group(5))
            else:
                phase, suffix = 3, 0
            return release, phase, suffix

        current, limit = version_key(version_match), version_key(boundary_match)
        width = max(len(current[0]), len(limit[0]))
        current_release = current[0] + (0,) * (width - len(current[0]))
        limit_release = limit[0] + (0,) * (width - len(limit[0]))
        current_key = (current_release, current[1], current[2])
        limit_key = (limit_release, limit[1], limit[2])
        return (current_key > limit_key) - (current_key < limit_key)

    @staticmethod
    def _version_matches_constraint(version: str, constraint: str) -> bool:
        """Match comma-separated constraints, with ``||`` separating alternatives."""
        for alternative in constraint.split("||"):
            clauses = [clause.strip() for clause in alternative.split(",")]
            if not clauses or any(not clause for clause in clauses):
                continue
            matches = True
            for clause in clauses:
                match = re.fullmatch(r"(<=|>=|<|>)\s*(\S+)", clause)
                if not match:
                    matches = False
                    break
                operator, boundary = match.groups()
                comparison = DependencyScanner._compare_versions(version, boundary)
                if comparison is None or not {
                    "<": comparison < 0,
                    "<=": comparison <= 0,
                    ">": comparison > 0,
                    ">=": comparison >= 0,
                }[operator]:
                    matches = False
                    break
            if matches:
                return True
        return False

    @classmethod
    def _matching_osv_range(
        cls, version: str, affected: List[Dict[str, Any]]
    ) -> tuple[bool, Optional[str]]:
        """Return whether an OSV range includes a version and its verified fixed event."""
        for item in affected:
            if version in item.get("versions", []):
                return True, None
            for version_range in item.get("ranges", []):
                if version_range.get("type") not in {"ECOSYSTEM", "SEMVER"}:
                    continue
                active = False
                introduced = "0"
                for event in version_range.get("events", []):
                    if "introduced" in event:
                        introduced = event["introduced"]
                        active = True
                    elif "fixed" in event and active:
                        start_comparison = cls._compare_versions(version, introduced)
                        end_comparison = cls._compare_versions(version, event["fixed"])
                        if start_comparison is not None and end_comparison is not None:
                            if start_comparison >= 0 and end_comparison < 0:
                                return True, event["fixed"]
                        active = False
                    elif "last_affected" in event and active:
                        start_comparison = cls._compare_versions(version, introduced)
                        end_comparison = cls._compare_versions(version, event["last_affected"])
                        if start_comparison is not None and end_comparison is not None:
                            if start_comparison >= 0 and end_comparison <= 0:
                                return True, None
                        active = False
                    elif "limit" in event and active:
                        start_comparison = cls._compare_versions(version, introduced)
                        end_comparison = cls._compare_versions(version, event["limit"])
                        if start_comparison is not None and end_comparison is not None:
                            if start_comparison >= 0 and end_comparison < 0:
                                return True, None
                        active = False
        return False, None

    @classmethod
    def _matching_catalog_entry(
        cls, version: str, catalog_entry: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        affected = catalog_entry["affected"]
        if isinstance(affected, str):
            if not cls._version_matches_constraint(version, affected):
                return None
            result = dict(catalog_entry)
            fixed = catalog_entry.get("fixed")
            if fixed and any(
                clause.strip() == f"<{fixed}"
                for clause in affected.split(",")
            ):
                result["fixed"] = fixed
            else:
                result["fixed"] = None
            return result

        for affected_range in affected:
            constraint = affected_range["constraint"]
            if not cls._version_matches_constraint(version, constraint):
                continue
            result = dict(catalog_entry)
            fixed = affected_range.get("fixed")
            verified_boundary = any(
                clause.strip() == f"<{fixed}"
                for clause in constraint.split(",")
            ) if fixed else False
            result["fixed"] = fixed if verified_boundary else None
            result["remediation"] = affected_range.get("remediation")
            return result
        return None

    @property
    def name(self) -> str:
        return "osv-scanner"

    @property
    def category(self) -> str:
        return "sca"

    def is_available(self) -> bool:
        return shutil.which("osv-scanner") is not None

    async def scan(self, target_path: str, **kwargs) -> List[Dict[str, Any]]:
        """Scans project dependencies using OSV-Scanner or intelligent manifest analysis."""
        if self.is_available():
            return await self._scan_with_cli(target_path)
        else:
            logger.info("OSV-Scanner CLI not found. Falling back to manifest dependency analyzer.")
            return await self._scan_manifests(target_path)

    async def _scan_with_cli(self, target_path: str) -> List[Dict[str, Any]]:
        try:
            cmd = ["osv-scanner", "--json", "-r", target_path]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            stdout = proc.stdout.strip()
            if not stdout:
                return []

            data = json.loads(stdout)
            results = data.get("results", [])
            findings: List[Dict[str, Any]] = []

            for res in results:
                package_source = res.get("source", {}).get("path", "")
                rel_path = package_source
                try:
                    if os.path.isabs(package_source):
                        rel_path = os.path.relpath(package_source, target_path)
                except Exception:
                    pass

                for pkg in res.get("packages", []):
                    pkg_info = pkg.get("package", {})
                    pkg_name = pkg_info.get("name")
                    pkg_version = pkg_info.get("version")

                    for vuln in pkg.get("vulnerabilities", []):
                        vuln_id = vuln.get("id", "OSV-ADVISORY")
                        summary = vuln.get("summary") or vuln.get("details", f"Vulnerability in {pkg_name}")
                        aliases = vuln.get("aliases", [])
                        cve = next((a for a in aliases if a.startswith("CVE-")), None)

                        is_affected, fixed_ver = self._matching_osv_range(
                            pkg_version or "", vuln.get("affected", [])
                        )
                        if not is_affected:
                            continue

                        findings.append({
                            "scanner": self.name,
                            "rule_id": vuln_id,
                            "title": f"Vulnerable dependency: {pkg_name}@{pkg_version}",
                            "description": summary,
                            "category": self.category,
                            "severity": "high",
                            "confidence": "high",
                            "file_path": rel_path,
                            "line_number": None,
                            "column_number": None,
                            "endpoint": None,
                            "param": None,
                            "evidence": f"Package: {pkg_name} ({pkg_version})\nAdvisory: {vuln_id}",
                            "package_name": pkg_name,
                            "package_version": pkg_version,
                            "fixed_version": fixed_ver,
                            "cve_id": cve,
                            "remediation": f"Upgrade {pkg_name} to {fixed_ver or 'the latest patched version'}." if fixed_ver else f"Review advisory {vuln_id} and update {pkg_name}.",
                            "raw_payload": vuln,
                        })

            return findings
        except Exception as e:
            logger.error("OSV-Scanner CLI failed, falling back to manifest analyzer", error=str(e))
            return await self._scan_manifests(target_path)

    async def _scan_manifests(self, target_path: str) -> List[Dict[str, Any]]:
        """Parses requirements.txt and package.json to identify known vulnerable packages."""
        findings: List[Dict[str, Any]] = []

        # 1. Look for requirements.txt files
        for root, _, files in os.walk(target_path):
            if "requirements.txt" in files:
                req_path = os.path.join(root, "requirements.txt")
                rel_path = os.path.relpath(req_path, target_path)
                findings.extend(await self._check_python_requirements(req_path, rel_path))

            if "package.json" in files and "node_modules" not in root:
                pkg_path = os.path.join(root, "package.json")
                rel_path = os.path.relpath(pkg_path, target_path)
                findings.extend(await self._check_package_json(pkg_path, rel_path))

        return findings

    async def _check_python_requirements(self, full_path: str, rel_path: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Parse e.g. requests==2.28.1
                    match = re.match(r"^([a-zA-Z0-9_\-]+)\s*(?:==|<=|>=|<|>)\s*([0-9a-zA-Z\.\-]+)", line)
                    if match:
                        name, version = match.group(1).lower(), match.group(2)
                        vuln = await self._query_osv_or_catalog(name, version, "PyPI")
                        if vuln:
                            findings.append(self._build_finding(name, version, vuln, rel_path, line_num))
        except Exception as e:
            logger.warning("Failed to parse requirements.txt", error=str(e))
        return findings

    async def _check_package_json(self, full_path: str, rel_path: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
                deps = {}
                deps.update(data.get("dependencies", {}))
                deps.update(data.get("devDependencies", {}))

                for name, ver_str in deps.items():
                    # Clean e.g. "^4.17.15" -> "4.17.15"
                    clean_ver = re.sub(r"[^0-9\.]", "", ver_str)
                    if clean_ver:
                        vuln = await self._query_osv_or_catalog(name.lower(), clean_ver, "npm")
                        if vuln:
                            findings.append(self._build_finding(name, clean_ver, vuln, rel_path, None))
        except Exception as e:
            logger.warning("Failed to parse package.json", error=str(e))
        return findings

    async def _query_osv_or_catalog(self, name: str, version: str, ecosystem: str) -> Optional[Dict[str, Any]]:
        """Queries OSV.dev public API with graceful fallback to offline catalog if offline."""
        # Check offline catalog first for immediate, version-aware matches.
        if name in OFFLINE_VULNERABILITY_CATALOG:
            match = self._matching_catalog_entry(
                version, OFFLINE_VULNERABILITY_CATALOG[name]
            )
            if match:
                return match

        # Try OSV online API
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                res = await client.post(
                    "https://api.osv.dev/v1/query",
                    json={"package": {"name": name, "ecosystem": ecosystem}, "version": version},
                )
                if res.status_code == 200:
                    data = res.json()
                    vulns = data.get("vulns", [])
                    for v in vulns:
                        is_affected, fixed = self._matching_osv_range(
                            version, v.get("affected", [])
                        )
                        if not is_affected:
                            continue
                        return {
                            "title": v.get("summary") or f"Vulnerability in {name}",
                            "cve": next((a for a in v.get("aliases", []) if a.startswith("CVE-")), None),
                            "severity": "high",
                            "fixed": fixed,
                            "advisory": v.get("id"),
                        }
        except Exception:
            pass  # Graceful fallback on network timeout/offline
        return None

    def _build_finding(self, name: str, version: str, vuln: Dict[str, Any], file_path: str, line: Optional[int]) -> Dict[str, Any]:
        return {
            "scanner": self.name,
            "rule_id": vuln.get("advisory", f"SCA-{name.upper()}"),
            "title": f"Vulnerable dependency: {name}@{version}",
            "description": vuln.get("title", f"Known security vulnerability affecting {name}"),
            "category": self.category,
            "severity": vuln.get("severity", "high"),
            "confidence": "high",
            "file_path": file_path,
            "line_number": line,
            "column_number": None,
            "endpoint": None,
            "param": None,
            "evidence": f"Package: {name}=={version}\nAdvisory: {vuln.get('advisory')}\nCVE: {vuln.get('cve')}",
            "package_name": name,
            "package_version": version,
            "fixed_version": vuln.get("fixed"),
            "cve_id": vuln.get("cve"),
            "remediation": vuln.get("remediation") or (
                f"Upgrade {name} to version {vuln.get('fixed')} or higher."
                if vuln.get("fixed")
                else f"Update {name} to a secure version."
            ),
            "raw_payload": vuln,
        }
