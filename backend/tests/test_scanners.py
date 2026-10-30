"""
Automated tests for scanner adapters: Semgrep, Gitleaks, Dependency Scanner, and DAST.
"""
import json
import os
import tempfile
from types import SimpleNamespace
import pytest

from app.scanners.dependency_scanner import DependencyScanner
from app.scanners.gitleaks_scanner import GitleaksScanner, redact_secret
from app.scanners.semgrep_scanner import SemgrepScanner
from app.scanners.zap_dast_scanner import DASTAuthorizationError, ZapDastScanner


class TestScanners:
    def test_secret_redaction(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        redacted = redact_secret(secret)
        assert "AKIA***MPLE" == redacted
        assert "IOSFODNN7" not in redacted

    @pytest.mark.asyncio
    async def test_gitleaks_builtin_engine_detects_secret(self):
        scanner = GitleaksScanner()
        temp_dir = tempfile.mkdtemp()
        sample_file = os.path.join(temp_dir, "config.py")

        try:
            with open(sample_file, "w", encoding="utf-8") as f:
                f.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

            findings = await scanner.scan(temp_dir)
            assert len(findings) >= 1
            f = findings[0]
            assert f["category"] == "secret"
            assert "AKIA***MPLE" in f["evidence"]
            assert f["severity"] == "critical"
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_dependency_scanner_manifest_detection(self):
        scanner = DependencyScanner()
        temp_dir = tempfile.mkdtemp()
        sample_req = os.path.join(temp_dir, "requirements.txt")

        try:
            with open(sample_req, "w", encoding="utf-8") as f:
                f.write("requests==2.28.1\n")

            findings = await scanner.scan(temp_dir)
            assert len(findings) >= 1
            f = findings[0]
            assert f["category"] == "sca"
            assert f["package_name"] == "requests"
            assert f["package_version"] == "2.28.1"
            assert f["fixed_version"] == "2.31.0"
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_scikit_learn_offline_catalog_is_version_aware(self):
        scanner = DependencyScanner()

        vulnerable = await scanner._query_osv_or_catalog("scikit-learn", "1.4.1", "PyPI")
        fixed = await scanner._query_osv_or_catalog("scikit-learn", "1.5.0", "PyPI")

        assert vulnerable["advisory"] == "GHSA-jw8x-6495-233v"
        assert vulnerable["cve"] == "CVE-2024-5206"
        assert vulnerable["fixed"] == "1.5.0"
        assert fixed is None

    @pytest.mark.asyncio
    async def test_flask_offline_catalog_matches_both_affected_ranges(self, monkeypatch, tmp_path):
        response_data = {"vulns": []}

        class MockResponse:
            status_code = 200

            def json(self):
                return response_data

        class MockAsyncClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def post(self, *args, **kwargs):
                return MockResponse()

        monkeypatch.setattr(
            "app.scanners.dependency_scanner.httpx.AsyncClient", MockAsyncClient
        )
        scanner = DependencyScanner()

        for version, fixed in (
            ("2.2.4", "2.2.5"),
            ("2.3.0", "2.3.2"),
            ("2.3.1", "2.3.2"),
        ):
            finding = await scanner._query_osv_or_catalog("flask", version, "PyPI")
            assert finding["cve"] == "CVE-2023-30861"
            assert finding["fixed"] == fixed
            built_finding = scanner._build_finding(
                "flask", version, finding, "requirements.txt", 1
            )
            if version == "2.2.4":
                assert "2.2.x series" in built_finding["remediation"]
                assert "2.3.2 or later" in built_finding["remediation"]
            else:
                assert built_finding["remediation"] == (
                    "Upgrade Flask to version 2.3.2 or later."
                )

        for version in ("2.2.5", "2.3.2", "3.0.0"):
            assert await scanner._query_osv_or_catalog("flask", version, "PyPI") is None

        requirements = tmp_path / "requirements.txt"
        requirements.write_text("flask==3.0.0\n", encoding="utf-8")
        assert await scanner._check_python_requirements(
            str(requirements), "requirements.txt"
        ) == []

    @pytest.mark.asyncio
    async def test_osv_result_must_match_affected_version_range(self, monkeypatch):
        response_data = {
            "vulns": [
                {
                    "id": "GHSA-m2bg-fq63-5h7f",
                    "aliases": ["CVE-2023-30861"],
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {"introduced": "2.3.0"},
                                        {"fixed": "2.3.2"},
                                    ],
                                }
                            ]
                        }
                    ],
                }
            ]
        }

        class MockResponse:
            status_code = 200

            def json(self):
                return response_data

        class MockAsyncClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def post(self, *args, **kwargs):
                return MockResponse()

        monkeypatch.setattr(
            "app.scanners.dependency_scanner.httpx.AsyncClient", MockAsyncClient
        )
        scanner = DependencyScanner()

        assert await scanner._query_osv_or_catalog("flask", "3.0.0", "PyPI") is None

        cli_payload = {
            "results": [
                {
                    "source": {"path": "requirements.txt"},
                    "packages": [
                        {
                            "package": {"name": "flask", "version": version},
                            "vulnerabilities": response_data["vulns"],
                        }
                        for version in ("3.0.0", "2.3.1")
                    ],
                }
            ]
        }
        monkeypatch.setattr(
            "app.scanners.dependency_scanner.subprocess.run",
            lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(cli_payload)),
        )
        findings = await scanner._scan_with_cli("project")
        assert len(findings) == 1
        assert findings[0]["package_version"] == "2.3.1"
        assert findings[0]["fixed_version"] == "2.3.2"

    async def test_dast_requires_authorization(self):
        dast = ZapDastScanner()
        with pytest.raises(DASTAuthorizationError):
            await dast.scan("https://example.com", confirm_authorization=False)

    def test_semgrep_availability(self):
        semgrep = SemgrepScanner()
        # Semgrep was installed in .venv earlier; verify is_available works
        avail = semgrep.is_available()
        assert isinstance(avail, bool)
